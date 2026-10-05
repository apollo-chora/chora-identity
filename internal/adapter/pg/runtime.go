// Package pg is the pgx-backed adapter for chora-identity repository
// ports defined in internal/domain/identity.
//
// Architecture:
//
//   - Domain ports (Save, GetByGcid, AddMembership, …) defined in
//     internal/domain/identity/repository.go
//   - This package implements those ports against a *pgxpool.Pool
//   - A small `Querier` interface decouples the SQL emit-and-scan layer
//     from pgx so unit tests can stub the SQL surface without a live DB
//   - PgxQuerier wraps a *pgxpool.Pool and is what cmd/server constructs
//     in production
//
// Resilience-priority directive (`feedback_resilience_priority`):
//
//   - Every read/write path that touches a tenant-scoped table runs
//     inside a transaction, with `SET LOCAL chora.tenant_id` applied
//     BEFORE the user query, so concurrent multi-tenant traffic is
//     transaction-isolated under PgBouncer transaction-pooling
//   - Soft-delete: queries default to `WHERE deleted_at IS NULL`
//   - All errors wrap, never lose context
//
// Cross-DB queries forbidden — chora-identity reads only chora_identity.
// Inter-domain side effects flow through Pub/Sub (see ../events).
package pg

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Querier is the minimal Exec + QueryRow surface this package needs from
// pgx. Production wires PgxPoolQuerier (wraps *pgxpool.Pool); tests inject
// a stub.
type Querier interface {
	Exec(ctx context.Context, sql string, args ...any) error
	QueryRow(ctx context.Context, sql string, args ...any) Row
}

// Row is the minimal Scan surface used by the repos. pgx.Row + database/sql
// rows both satisfy a thin wrapper.
type Row interface {
	Scan(dest ...any) error
}

// Rows is the minimal multi-row iteration surface used by the repos
// (B6.1 — searchTenantMembers needs page-sized SELECTs).
type Rows interface {
	Next() bool
	Scan(dest ...any) error
	Close() error
	Err() error
}

// Tx is the minimal Exec + QueryRow + Query surface a repository needs
// inside an open, tenant-scoped transaction. See RunInTenantTx below.
type Tx interface {
	Exec(ctx context.Context, sql string, args ...any) error
	QueryRow(ctx context.Context, sql string, args ...any) Row
	Query(ctx context.Context, sql string, args ...any) (Rows, error)
}

// PlainTxQuerier opens a plain transaction (NO SET LOCAL GUC) and runs fn
// against it. For atomic multi-statement writes within chora_identity that
// touch NO tenant/user-RLS-scoped table needing a GUC — e.g. the users UPDATE
// + the outbox_events INSERT of UpdateDisplayName: `users` carries no RLS, and
// `outbox_events`' tenant-isolation policy is permissive when the
// app.current_tenant GUC is unset (migration 0008). fn returning an error rolls
// the tx back; nil commits.
type PlainTxQuerier interface {
	RunInTx(ctx context.Context, fn func(context.Context, Tx) error) error
}

// TxQuerier opens a transaction with `SET LOCAL chora.tenant_id` already
// applied and runs fn against it. fn returning an error rolls the tx back;
// nil commits. Mirrors the chora-creation / chora-tenancy pattern.
//
// Mandatory for any query against tenant-scoped tables (RLS-policied) under
// PgBouncer transaction-pooling — SET LOCAL is transaction-scoped, never
// session-scoped, so the GUC cannot leak across pool siblings.
type TxQuerier interface {
	RunInTenantTx(ctx context.Context, tenantID string, fn func(context.Context, Tx) error) error
}

// ErrNoRows is the pg-package-local sentinel for a not-found row. Repos
// translate this to domain-level not-found (e.g. identity.ErrUserNotFound).
var ErrNoRows = errors.New("pg: no rows in result set")

// PgxPoolQuerier wraps a *pgxpool.Pool with the local Querier shape.
type PgxPoolQuerier struct {
	pool *pgxpool.Pool
}

// NewPgxPoolQuerier wraps a pgxpool.Pool.
func NewPgxPoolQuerier(pool *pgxpool.Pool) *PgxPoolQuerier {
	return &PgxPoolQuerier{pool: pool}
}

// Exec runs a non-returning SQL statement. Wraps the pgx error in a stable
// shape.
func (q *PgxPoolQuerier) Exec(ctx context.Context, sql string, args ...any) error {
	if _, err := q.pool.Exec(ctx, sql, args...); err != nil {
		return fmt.Errorf("pg.Exec: %w", err)
	}
	return nil
}

// QueryRow runs a single-row SQL query and returns a Row whose Scan maps
// pgx.ErrNoRows to ErrNoRows.
func (q *PgxPoolQuerier) QueryRow(ctx context.Context, sql string, args ...any) Row {
	return &pgxPoolRow{r: q.pool.QueryRow(ctx, sql, args...)}
}

type pgxPoolRow struct {
	r pgx.Row
}

func (r *pgxPoolRow) Scan(dest ...any) error {
	err := r.r.Scan(dest...)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNoRows
	}
	return err
}

// Pool returns the underlying pool. Used by callers that need to begin
// transactions for SET LOCAL chora.tenant_id wrapping.
func (q *PgxPoolQuerier) Pool() *pgxpool.Pool {
	return q.pool
}

// -----------------------------------------------------------------------------
// Tenant-scoped transaction surface (B6.1 — searchTenantMembers RLS path).
//
// tenant_memberships + closure_sagas + course_role_assignments all carry the
// `tenant_isolation` RLS policy (migration 0001). When chora_identity_app_rw
// is NOBYPASSRLS (production wiring), a bare query against the pool silently
// returns 0 rows. Repositories that touch those tables MUST wrap their SQL
// in RunInTenantTx so SET LOCAL chora.tenant_id runs in the SAME transaction
// under PgBouncer transaction-pooling.
//
// Mirrors services/chora-creation/internal/adapter/pg/runtime.go §"Tenant-
// scoped transaction surface" — same defence-in-depth identifier guard, same
// rollback-on-error semantics.
// -----------------------------------------------------------------------------

// RunInTenantTx satisfies TxQuerier for the production pgxpool wrapper.
//
// Sequence: pool.Begin → SET LOCAL chora.tenant_id → fn(tx) → Commit
// (or Rollback when fn errors / Commit fails). tenantID is interpolated
// into the SET LOCAL statement after a UUID-shape check — Postgres parses
// SET LOCAL (not the prepared-stmt path), so the identifier guard rejects
// anything that is not hex + dash before it reaches the wire.
func (q *PgxPoolQuerier) RunInTenantTx(ctx context.Context, tenantID string, fn func(context.Context, Tx) error) error {
	if err := validateTenantID(tenantID); err != nil {
		return err
	}
	if q.pool == nil {
		return errors.New("pg.RunInTenantTx: nil pool")
	}
	tx, err := q.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("pg.RunInTenantTx: begin: %w", err)
	}
	// Roll back on any non-committed exit. After a successful Commit the
	// Rollback is a no-op (pgx returns ErrTxClosed, swallowed here).
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback(ctx)
		}
	}()

	if _, err := tx.Exec(ctx, fmt.Sprintf("SET LOCAL chora.tenant_id = '%s'", tenantID)); err != nil {
		return fmt.Errorf("pg.RunInTenantTx: SET LOCAL chora.tenant_id: %w", err)
	}

	if err := fn(ctx, &pgxTx{tx: tx}); err != nil {
		return err
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("pg.RunInTenantTx: commit: %w", err)
	}
	committed = true
	return nil
}

// RunInTx satisfies PlainTxQuerier: pool.Begin → fn → Commit (or Rollback on
// fn error / Commit failure). No SET LOCAL — see PlainTxQuerier for when this
// is the correct primitive (users UPDATE + outbox_events INSERT atomicity).
func (q *PgxPoolQuerier) RunInTx(ctx context.Context, fn func(context.Context, Tx) error) error {
	if q.pool == nil {
		return errors.New("pg.RunInTx: nil pool")
	}
	tx, err := q.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("pg.RunInTx: begin: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback(ctx)
		}
	}()

	if err := fn(ctx, &pgxTx{tx: tx}); err != nil {
		return err
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("pg.RunInTx: commit: %w", err)
	}
	committed = true
	return nil
}

// UserTxQuerier is the per-USER RLS transaction surface. Unlike RunInTenantTx
// (which scopes by chora.tenant_id), the user_mana / mana_ledger /
// mana_subsidy_allocations tables carry the `user_isolation` RLS policy keyed
// on chora.user_gcid (migration 0003). The pg-backed mana wallet store wraps
// every query in RunInUserTx so the per-user RLS scopes the row set under
// PgBouncer transaction-pooling.
type UserTxQuerier interface {
	RunInUserTx(ctx context.Context, userGcid, role string, fn func(context.Context, Tx) error) error
}

// RunInUserTx opens a tx with `SET LOCAL chora.user_gcid` (+ `chora.role` when
// non-empty) applied and runs fn against it. fn returning an error rolls the
// tx back; nil commits. For the per-user RLS axis (user_mana / mana_ledger /
// mana_subsidy_allocations user_isolation policy, migration 0003).
//
// userGcid is interpolated into the SET LOCAL statement after a UUID-shape
// check (Postgres parses SET LOCAL, not the prepared-stmt path). role, when
// set, is validated against the closed {learner|instructor|admin|auditor} set.
func (q *PgxPoolQuerier) RunInUserTx(ctx context.Context, userGcid, role string, fn func(context.Context, Tx) error) error {
	if err := validateUserGcid(userGcid); err != nil {
		return err
	}
	if err := validateRLSRole(role); err != nil {
		return err
	}
	if q.pool == nil {
		return errors.New("pg.RunInUserTx: nil pool")
	}
	tx, err := q.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("pg.RunInUserTx: begin: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback(ctx)
		}
	}()

	if _, err := tx.Exec(ctx, fmt.Sprintf("SET LOCAL chora.user_gcid = '%s'", userGcid)); err != nil {
		return fmt.Errorf("pg.RunInUserTx: SET LOCAL chora.user_gcid: %w", err)
	}
	if role != "" {
		if _, err := tx.Exec(ctx, fmt.Sprintf("SET LOCAL chora.role = '%s'", role)); err != nil {
			return fmt.Errorf("pg.RunInUserTx: SET LOCAL chora.role: %w", err)
		}
	}

	if err := fn(ctx, &pgxTx{tx: tx}); err != nil {
		return err
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("pg.RunInUserTx: commit: %w", err)
	}
	committed = true
	return nil
}

// validateUserGcid rejects values unsafe to interpolate into SET LOCAL — same
// hex+dash UUID-shape guard as validateTenantID.
func validateUserGcid(id string) error {
	if id == "" {
		return errors.New("pg.RunInUserTx: empty user_gcid")
	}
	for _, r := range id {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f', r >= 'A' && r <= 'F', r == '-':
			continue
		default:
			return fmt.Errorf("pg.RunInUserTx: user_gcid %q has forbidden characters", id)
		}
	}
	return nil
}

// validateRLSRole gates the chora.role GUC against the closed set the RLS
// policies recognise (migration 0003). Empty role = unset (skip).
func validateRLSRole(role string) error {
	switch role {
	case "", "learner", "instructor", "admin", "auditor":
		return nil
	default:
		return fmt.Errorf("pg.RunInUserTx: role %q not in {learner,instructor,admin,auditor}", role)
	}
}

// validateTenantID rejects values unsafe to interpolate into a SET LOCAL
// statement: anything other than hex digits + dash (UUID shape). Mirrors
// libs/chora-go-common/rls.ValidateTenantID without pulling that package
// into the adapter import graph for one helper.
func validateTenantID(id string) error {
	if id == "" {
		return errors.New("pg.RunInTenantTx: empty tenant_id")
	}
	for _, r := range id {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f', r >= 'A' && r <= 'F', r == '-':
			continue
		default:
			return fmt.Errorf("pg.RunInTenantTx: tenant_id %q has forbidden characters", id)
		}
	}
	return nil
}

// pgxTx adapts pgx.Tx to the local Tx surface.
type pgxTx struct {
	tx pgx.Tx
}

func (t *pgxTx) Exec(ctx context.Context, sql string, args ...any) error {
	if _, err := t.tx.Exec(ctx, sql, args...); err != nil {
		return fmt.Errorf("pg.Tx.Exec: %w", err)
	}
	return nil
}

func (t *pgxTx) QueryRow(ctx context.Context, sql string, args ...any) Row {
	return &pgxPoolRow{r: t.tx.QueryRow(ctx, sql, args...)}
}

func (t *pgxTx) Query(ctx context.Context, sql string, args ...any) (Rows, error) {
	rs, err := t.tx.Query(ctx, sql, args...)
	if err != nil {
		return nil, fmt.Errorf("pg.Tx.Query: %w", err)
	}
	return &pgxRows{r: rs}, nil
}

// pgxRows adapts pgx.Rows to the local Rows surface.
type pgxRows struct {
	r pgx.Rows
}

func (r *pgxRows) Next() bool             { return r.r.Next() }
func (r *pgxRows) Scan(dest ...any) error { return r.r.Scan(dest...) }
func (r *pgxRows) Close() error           { r.r.Close(); return nil }
func (r *pgxRows) Err() error             { return r.r.Err() }

// Compile-time check: PgxPoolQuerier satisfies TxQuerier.
var _ TxQuerier = (*PgxPoolQuerier)(nil)

// Compile-time check: PgxPoolQuerier satisfies PlainTxQuerier.
var _ PlainTxQuerier = (*PgxPoolQuerier)(nil)
