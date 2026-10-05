// Package pg_test exercises the pgx-backed UserRepository.
//
// Two test surfaces:
//
//  1. Unit tests against a stub Querier — exercise the SQL the adapter
//     emits + scan logic without a live database. Run on every `go test`.
//
//  2. Integration tests against a live chora_identity database — gated
//     behind the `integration` build tag. Run with:
//
//     go test -tags integration ./internal/adapter/pg/...
//
// The integration test verifies RLS isolation end-to-end (insert under
// tenant A, query under tenant B → 0 rows).
package pg_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/apollo-chora/chora-identity/internal/adapter/pg"
	"github.com/apollo-chora/chora-identity/internal/domain/identity"
)

// ----------------------------------------------------------------------------
// stub Querier — captures emitted SQL + canned rows
// ----------------------------------------------------------------------------

type stubExecCall struct {
	sql  string
	args []any
}

type stubQueryRowCall struct {
	sql  string
	args []any
}

type stubQuerier struct {
	execCalls []stubExecCall
	rowCalls  []stubQueryRowCall

	// Scan response: per-call sequenced.
	rowResponses []func(dest ...any) error
}

func (s *stubQuerier) Exec(_ context.Context, sql string, args ...any) error {
	s.execCalls = append(s.execCalls, stubExecCall{sql: sql, args: args})
	return nil
}

func (s *stubQuerier) QueryRow(_ context.Context, sql string, args ...any) pg.Row {
	s.rowCalls = append(s.rowCalls, stubQueryRowCall{sql: sql, args: args})
	if len(s.rowResponses) == 0 {
		return &stubRow{scanFn: func(dest ...any) error { return pg.ErrNoRows }}
	}
	r := s.rowResponses[0]
	s.rowResponses = s.rowResponses[1:]
	return &stubRow{scanFn: r}
}

type stubRow struct {
	scanFn func(dest ...any) error
}

func (r *stubRow) Scan(dest ...any) error { return r.scanFn(dest...) }

// ----------------------------------------------------------------------------
// Tests
// ----------------------------------------------------------------------------

func TestUserRepository_Save_InsertsExpectedColumns(t *testing.T) {
	t.Parallel()

	q := &stubQuerier{}
	r := pg.NewUserRepositoryWithQuerier(q)

	u, err := identity.NewUser(identity.NewUserParams{
		Email:            "phyllis@chora.dev",
		IdentityProvider: identity.ProviderWebAuthn,
		FederatedSubject: "sub-phyllis",
	})
	if err != nil {
		t.Fatalf("NewUser: %v", err)
	}

	if err := r.Save(context.Background(), u); err != nil {
		t.Fatalf("Save: %v", err)
	}

	if len(q.execCalls) != 1 {
		t.Fatalf("expected 1 Exec call, got %d", len(q.execCalls))
	}
	got := q.execCalls[0]
	if want := "INSERT INTO users"; !contains(got.sql, want) {
		t.Errorf("expected SQL to contain %q, got %q", want, got.sql)
	}
	if !contains(got.sql, "ON CONFLICT") {
		t.Errorf("Save must be UPSERT (ON CONFLICT clause); got %q", got.sql)
	}
	if got.args[0] != u.Gcid {
		t.Errorf("first arg want gcid %q, got %v", u.Gcid, got.args[0])
	}
}

func TestUserRepository_GetByGcid_HappyPath(t *testing.T) {
	t.Parallel()

	now := time.Now().UTC()
	q := &stubQuerier{
		rowResponses: []func(dest ...any) error{
			func(dest ...any) error {
				// Match column order: gcid, email, display_name, identity_provider,
				// federated_subject, status, kyc_method, kyc_verified_at,
				// verification_status, created_at, updated_at
				*dest[0].(*string) = "01970000-0000-7000-8000-aaaaaaaaaaaa"
				*dest[1].(*string) = "phyllis@chora.dev"
				*dest[2].(*string) = ""
				*dest[3].(*string) = "webauthn"
				*dest[4].(*string) = "sub-phyllis"
				*dest[5].(*string) = "active"
				*dest[6].(*string) = ""
				if v, ok := dest[7].(**time.Time); ok {
					_ = v
				}
				*dest[8].(*string) = "unverified"
				*dest[9].(*time.Time) = now
				*dest[10].(*time.Time) = now
				return nil
			},
		},
	}
	r := pg.NewUserRepositoryWithQuerier(q)

	u, err := r.GetByGcid(context.Background(), "01970000-0000-7000-8000-aaaaaaaaaaaa")
	if err != nil {
		t.Fatalf("GetByGcid: %v", err)
	}
	if u.Email != "phyllis@chora.dev" {
		t.Errorf("Email = %q, want phyllis@chora.dev", u.Email)
	}
	if u.IdentityProvider != identity.ProviderWebAuthn {
		t.Errorf("IdentityProvider = %q, want webauthn", u.IdentityProvider)
	}
}

func TestUserRepository_GetByGcid_NotFoundMapsToDomainError(t *testing.T) {
	t.Parallel()

	q := &stubQuerier{} // Empty rowResponses → ErrNoRows.
	r := pg.NewUserRepositoryWithQuerier(q)

	_, err := r.GetByGcid(context.Background(), "missing")
	if err == nil {
		t.Fatalf("expected error")
	}
	if !errors.Is(err, identity.ErrUserNotFound) {
		t.Errorf("expected identity.ErrUserNotFound, got %T %v", err, err)
	}
}

func TestUserRepository_FindByFederatedSubject_HappyPath(t *testing.T) {
	t.Parallel()

	now := time.Now().UTC()
	q := &stubQuerier{
		rowResponses: []func(dest ...any) error{
			func(dest ...any) error {
				*dest[0].(*string) = "01970000-0000-7000-8000-aaaaaaaaaaaa"
				*dest[1].(*string) = "phyllis@chora.dev"
				*dest[2].(*string) = ""
				*dest[3].(*string) = "webauthn"
				*dest[4].(*string) = "sub-phyllis"
				*dest[5].(*string) = "active"
				*dest[6].(*string) = ""
				*dest[8].(*string) = "unverified"
				*dest[9].(*time.Time) = now
				*dest[10].(*time.Time) = now
				return nil
			},
		},
	}
	r := pg.NewUserRepositoryWithQuerier(q)

	u, ok, err := r.FindByFederatedSubject(context.Background(), "sub-phyllis")
	if err != nil {
		t.Fatalf("FindByFederatedSubject: %v", err)
	}
	if !ok {
		t.Fatalf("expected found=true")
	}
	if u.FederatedSubject != "sub-phyllis" {
		t.Errorf("FederatedSubject = %q, want sub-phyllis", u.FederatedSubject)
	}
}

func TestUserRepository_FindByFederatedSubject_NotFound(t *testing.T) {
	t.Parallel()

	q := &stubQuerier{}
	r := pg.NewUserRepositoryWithQuerier(q)

	_, ok, err := r.FindByFederatedSubject(context.Background(), "missing")
	if err != nil {
		t.Fatalf("expected nil error on not-found, got %v", err)
	}
	if ok {
		t.Fatalf("expected found=false")
	}
}

// ----------------------------------------------------------------------------
// UpdateDisplayName — Q3 GCID→display-name projection. The display-name write
// and the chora.identity.user.profile_updated.v1 outbox enqueue must commit in
// ONE transaction (transactional outbox); the event fires only on an actual
// change; a missing user maps to the domain not-found error.
// ----------------------------------------------------------------------------

// txStub records Exec (the outbox INSERT) + serves sequenced QueryRow scans
// (SELECT old name, then UPDATE RETURNING updated_at). Satisfies pg.Tx.
//
// queryResult (CHO-2327) backs tx.Query for the directory-backfill list read;
// querySQL captures the emitted SELECT so the projectable-user WHERE contract
// (display_name <> ” AND deleted_at IS NULL) is assertable.
type txStub struct {
	rowResponses []func(dest ...any) error
	execSQL      []string
	execArgs     [][]any
	queryResult  *rowsStub
	querySQL     []string
	execErr      error // when set, Exec records then fails (outbox INSERT failure)
	queryErr     error // when set, Query fails before returning a rowset
}

func (t *txStub) Exec(_ context.Context, sql string, args ...any) error {
	t.execSQL = append(t.execSQL, sql)
	t.execArgs = append(t.execArgs, args)
	return t.execErr
}

func (t *txStub) QueryRow(_ context.Context, sql string, args ...any) pg.Row {
	if len(t.rowResponses) == 0 {
		return &stubRow{scanFn: func(dest ...any) error { return pg.ErrNoRows }}
	}
	r := t.rowResponses[0]
	t.rowResponses = t.rowResponses[1:]
	return &stubRow{scanFn: r}
}

func (t *txStub) Query(_ context.Context, sql string, _ ...any) (pg.Rows, error) {
	t.querySQL = append(t.querySQL, sql)
	if t.queryErr != nil {
		return nil, t.queryErr
	}
	if t.queryResult == nil {
		return &rowsStub{}, nil
	}
	return t.queryResult, nil
}

// rowsStub serves a canned set of (gcid, email, display_name, updated_at) rows
// for the directory-backfill list read (CHO-2327). Satisfies pg.Rows.
type rowsStub struct {
	rows    [][]any // each: {gcid string, email string, displayName string, updatedAt time.Time}
	idx     int
	closed  bool
	err     error
	scanErr error // when set, every Scan fails after assigning
}

func (r *rowsStub) Next() bool {
	if r.idx >= len(r.rows) {
		return false
	}
	r.idx++
	return true
}

func (r *rowsStub) Scan(dest ...any) error {
	row := r.rows[r.idx-1]
	*dest[0].(*string) = row[0].(string)
	*dest[1].(*string) = row[1].(string)
	*dest[2].(*string) = row[2].(string)
	*dest[3].(*time.Time) = row[3].(time.Time)
	return r.scanErr
}

func (r *rowsStub) Close() error { r.closed = true; return nil }
func (r *rowsStub) Err() error   { return r.err }

// txStubQuerier satisfies BOTH pg.Querier and pg.PlainTxQuerier so
// NewUserRepositoryWithQuerier auto-detects the tx runner.
type txStubQuerier struct {
	stubQuerier
	tx *txStub
}

func (s *txStubQuerier) RunInTx(ctx context.Context, fn func(context.Context, pg.Tx) error) error {
	return fn(ctx, s.tx)
}

const udnGcid = "01970000-0000-7000-8000-0000000000aa"
const udnTenant = "01970000-0000-7000-8000-0000000000bb"

func TestUpdateDisplayName_Changed_EmitsProfileUpdatedInSameTx(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	tx := &txStub{rowResponses: []func(dest ...any) error{
		// 1) SELECT email, display_name FOR UPDATE — old name is empty (first set).
		func(dest ...any) error {
			*dest[0].(*string) = "alice@example.com"
			*dest[1].(*string) = ""
			return nil
		},
		// 2) UPDATE ... RETURNING updated_at.
		func(dest ...any) error {
			*dest[0].(*time.Time) = now
			return nil
		},
	}}
	q := &txStubQuerier{tx: tx}
	r := pg.NewUserRepositoryWithQuerier(q)

	if err := r.UpdateDisplayName(context.Background(), udnGcid, "Alice Wonder", udnTenant); err != nil {
		t.Fatalf("UpdateDisplayName: %v", err)
	}

	// Exactly one outbox INSERT, in the same tx as the UPDATE.
	if len(tx.execSQL) != 1 {
		t.Fatalf("expected exactly 1 tx Exec (the outbox INSERT), got %d: %v", len(tx.execSQL), tx.execSQL)
	}
	if !contains(tx.execSQL[0], "INSERT INTO outbox_events") {
		t.Errorf("emit must INSERT INTO outbox_events; got %q", tx.execSQL[0])
	}
	// Args carry the canonical topic + a JSON payload with the new name.
	var sawTopic, sawName bool
	for _, a := range tx.execArgs[0] {
		if s, ok := a.(string); ok && s == "chora.identity.user.profile_updated.v1" {
			sawTopic = true
		}
		if b, ok := a.([]byte); ok && contains(string(b), "Alice Wonder") {
			sawName = true
		}
	}
	if !sawTopic {
		t.Errorf("outbox INSERT args must carry the profile_updated topic; args=%v", tx.execArgs[0])
	}
	if !sawName {
		t.Errorf("outbox INSERT args must carry a JSON payload with the new display_name; args=%v", tx.execArgs[0])
	}
}

func TestUpdateDisplayName_Unchanged_SkipsEmit(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	tx := &txStub{rowResponses: []func(dest ...any) error{
		func(dest ...any) error {
			*dest[0].(*string) = "alice@example.com"
			*dest[1].(*string) = "Alice Wonder" // old == new
			return nil
		},
		func(dest ...any) error {
			*dest[0].(*time.Time) = now
			return nil
		},
	}}
	q := &txStubQuerier{tx: tx}
	r := pg.NewUserRepositoryWithQuerier(q)

	if err := r.UpdateDisplayName(context.Background(), udnGcid, "Alice Wonder", udnTenant); err != nil {
		t.Fatalf("UpdateDisplayName: %v", err)
	}
	if len(tx.execSQL) != 0 {
		t.Errorf("unchanged name must NOT emit an event (no outbox INSERT); got %v", tx.execSQL)
	}
}

func TestUpdateDisplayName_NotFound_MapsToDomainError(t *testing.T) {
	t.Parallel()
	tx := &txStub{} // empty rowResponses → SELECT yields ErrNoRows.
	q := &txStubQuerier{tx: tx}
	r := pg.NewUserRepositoryWithQuerier(q)

	err := r.UpdateDisplayName(context.Background(), udnGcid, "Alice Wonder", udnTenant)
	if !errors.Is(err, identity.ErrUserNotFound) {
		t.Fatalf("expected identity.ErrUserNotFound, got %T %v", err, err)
	}
	if len(tx.execSQL) != 0 {
		t.Errorf("no outbox INSERT on a missing user; got %v", tx.execSQL)
	}
}

func TestUpdateDisplayName_EmptyGcid_Rejected(t *testing.T) {
	t.Parallel()
	q := &txStubQuerier{tx: &txStub{}}
	r := pg.NewUserRepositoryWithQuerier(q)
	if err := r.UpdateDisplayName(context.Background(), "  ", "Alice", udnTenant); err == nil {
		t.Fatalf("expected error for empty gcid")
	}
}

// contains is a tiny helper to avoid pulling in strings; keeps the test file
// dependency-free w.r.t. internals.
func contains(haystack, needle string) bool {
	return len(needle) > 0 && len(haystack) >= len(needle) && indexOf(haystack, needle) >= 0
}

func indexOf(haystack, needle string) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}

// ----------------------------------------------------------------------------
// CHO-1719 — closure terminal step: Save must persist the soft-delete marker
// + the tombstoned federated subject, or pseudonymisation never frees the
// partial unique email index (idx_users_email ... WHERE deleted_at IS NULL)
// nor the UNIQUE (identity_provider, federated_subject) pair.
// ----------------------------------------------------------------------------

func TestUserRepository_Save_PersistsSoftDeleteAndSubjectTombstone(t *testing.T) {
	t.Parallel()

	q := &stubQuerier{}
	r := pg.NewUserRepositoryWithQuerier(q)

	u, err := identity.NewUser(identity.NewUserParams{
		Email:            "phyllis@chora.dev",
		IdentityProvider: identity.ProviderOIDC,
		FederatedSubject: "fed-sub-phyllis",
	})
	if err != nil {
		t.Fatalf("NewUser: %v", err)
	}
	u.Pseudonymise("user-abc@redacted.invalid", "Former member")

	if err := r.Save(context.Background(), u); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if len(q.execCalls) != 1 {
		t.Fatalf("expected 1 Exec call, got %d", len(q.execCalls))
	}
	got := q.execCalls[0]
	if !contains(got.sql, "deleted_at") {
		t.Errorf("Save SQL must write deleted_at; got %q", got.sql)
	}
	if !contains(got.sql, "federated_subject = EXCLUDED.federated_subject") {
		t.Errorf("Save UPSERT must update federated_subject (subject tombstone); got %q", got.sql)
	}
	if !contains(got.sql, "deleted_at = EXCLUDED.deleted_at") {
		t.Errorf("Save UPSERT must update deleted_at (soft delete); got %q", got.sql)
	}
	// The bound deleted_at arg carries the aggregate's soft-delete time.
	found := false
	for _, a := range got.args {
		if ts, ok := a.(*time.Time); ok && ts != nil && ts.Equal(*u.DeletedAt) {
			found = true
		}
	}
	if !found {
		t.Errorf("Save args must bind the aggregate's DeletedAt; args=%v", got.args)
	}
}

// ----------------------------------------------------------------------------
// CHO-2327 — directory-projection backfill. Re-emits
// chora.identity.user.profile_updated.v1 for every live user with a non-empty
// display_name so downstream directories (chora-delivery.user_directory) that
// only ever saw the UpdateDisplayName-triggered events catch up for members
// whose name predates the projection. Read-then-emit; each batch enqueues via
// the transactional outbox; the acting tenant is carried as envelope provenance.
// ----------------------------------------------------------------------------

const backfillTenant = "01970000-0000-7000-8000-0000000000bb"

func newRowsStub(rows ...[]any) *rowsStub { return &rowsStub{rows: rows} }

func TestBackfillProfileDirectory_EmitsOnePerUser(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	tx := &txStub{queryResult: newRowsStub(
		[]any{"01970000-0000-7000-8000-000000000a01", "alice@example.com", "Alice Wonder", now},
		[]any{"01970000-0000-7000-8000-000000000a02", "bob@example.com", "Bob Stone", now},
		[]any{"01970000-0000-7000-8000-000000000a03", "cara@example.com", "Cara Lyn", now},
	)}
	q := &txStubQuerier{tx: tx}
	r := pg.NewUserRepositoryWithQuerier(q)

	scanned, emitted, err := r.BackfillProfileDirectory(context.Background(), backfillTenant)
	if err != nil {
		t.Fatalf("BackfillProfileDirectory: %v", err)
	}
	if scanned != 3 || emitted != 3 {
		t.Fatalf("scanned/emitted = %d/%d, want 3/3", scanned, emitted)
	}
	// One outbox INSERT per user.
	if len(tx.execSQL) != 3 {
		t.Fatalf("expected 3 outbox INSERTs (one per user), got %d: %v", len(tx.execSQL), tx.execSQL)
	}
	for i, sql := range tx.execSQL {
		if !contains(sql, "INSERT INTO outbox_events") {
			t.Errorf("emit %d must INSERT INTO outbox_events; got %q", i, sql)
		}
	}
	// Every emit carries the canonical topic + a name in its JSON payload, and
	// the acting tenant rides the envelope (provenance).
	names := []string{"Alice Wonder", "Bob Stone", "Cara Lyn"}
	for i, args := range tx.execArgs {
		var sawTopic, sawName, sawTenant bool
		for _, a := range args {
			// The acting tenant rides BOTH the outbox tenant_id column (a string
			// arg) AND the envelope JSON (also a string arg); the display_name
			// rides the payload ([]byte). Inspect both arg shapes.
			if s, ok := a.(string); ok {
				if s == "chora.identity.user.profile_updated.v1" {
					sawTopic = true
				}
				if contains(s, backfillTenant) {
					sawTenant = true
				}
				if contains(s, names[i]) {
					sawName = true
				}
			}
			if b, ok := a.([]byte); ok {
				if contains(string(b), backfillTenant) {
					sawTenant = true
				}
				if contains(string(b), names[i]) {
					sawName = true
				}
			}
		}
		if !sawTopic {
			t.Errorf("emit %d must carry the profile_updated topic; args=%v", i, args)
		}
		if !sawName {
			t.Errorf("emit %d must carry the display_name %q; args=%v", i, names[i], args)
		}
		if !sawTenant {
			t.Errorf("emit %d envelope must carry the acting tenant %q; args=%v", i, backfillTenant, args)
		}
	}
}

func TestBackfillProfileDirectory_ListSQLExcludesBlankAndSoftDeleted(t *testing.T) {
	t.Parallel()
	tx := &txStub{queryResult: newRowsStub()}
	q := &txStubQuerier{tx: tx}
	r := pg.NewUserRepositoryWithQuerier(q)

	if _, _, err := r.BackfillProfileDirectory(context.Background(), backfillTenant); err != nil {
		t.Fatalf("BackfillProfileDirectory: %v", err)
	}
	if len(tx.querySQL) != 1 {
		t.Fatalf("expected exactly 1 list SELECT, got %d: %v", len(tx.querySQL), tx.querySQL)
	}
	sql := tx.querySQL[0]
	if !contains(sql, "display_name <> ''") {
		t.Errorf("list SELECT must exclude blank display_name; got %q", sql)
	}
	if !contains(sql, "deleted_at IS NULL") {
		t.Errorf("list SELECT must exclude soft-deleted users; got %q", sql)
	}
}

func TestBackfillProfileDirectory_EmptyStore_NoEmit(t *testing.T) {
	t.Parallel()
	tx := &txStub{queryResult: newRowsStub()}
	q := &txStubQuerier{tx: tx}
	r := pg.NewUserRepositoryWithQuerier(q)

	scanned, emitted, err := r.BackfillProfileDirectory(context.Background(), backfillTenant)
	if err != nil {
		t.Fatalf("BackfillProfileDirectory: %v", err)
	}
	if scanned != 0 || emitted != 0 {
		t.Fatalf("scanned/emitted = %d/%d, want 0/0", scanned, emitted)
	}
	if len(tx.execSQL) != 0 {
		t.Errorf("empty store must emit nothing; got %v", tx.execSQL)
	}
}

func TestBackfillProfileDirectory_EmptyTenant_Rejected(t *testing.T) {
	t.Parallel()
	q := &txStubQuerier{tx: &txStub{queryResult: newRowsStub()}}
	r := pg.NewUserRepositoryWithQuerier(q)
	if _, _, err := r.BackfillProfileDirectory(context.Background(), "  "); err == nil {
		t.Fatalf("expected error for empty acting tenant (envelope provenance is mandatory)")
	}
}

func TestBackfillProfileDirectory_NoTxRunner_FailsLoud(t *testing.T) {
	t.Parallel()
	// A bare stubQuerier does NOT satisfy pg.PlainTxQuerier, so the tx runner
	// stays unwired — the atomic outbox emit must refuse, never silently no-op.
	r := pg.NewUserRepositoryWithQuerier(&stubQuerier{})
	if _, _, err := r.BackfillProfileDirectory(context.Background(), backfillTenant); err == nil {
		t.Fatalf("expected error when the transactional runner is not wired")
	}
}

func TestBackfillProfileDirectory_EmitError_FailsLoudWithPartialCount(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	// The outbox INSERT fails — the batch tx rolls back (in prod) and the whole
	// call must return the error, NOT a silent success, with emitted reflecting
	// only committed batches (0 here — the sole batch failed).
	tx := &txStub{
		queryResult: newRowsStub(
			[]any{"01970000-0000-7000-8000-000000000a01", "alice@example.com", "Alice Wonder", now},
			[]any{"01970000-0000-7000-8000-000000000a02", "bob@example.com", "Bob Stone", now},
		),
		execErr: errors.New("pg: outbox INSERT timeout"),
	}
	q := &txStubQuerier{tx: tx}
	r := pg.NewUserRepositoryWithQuerier(q)

	scanned, emitted, err := r.BackfillProfileDirectory(context.Background(), backfillTenant)
	if err == nil {
		t.Fatalf("expected a loud error when the outbox emit fails")
	}
	if scanned != 2 {
		t.Errorf("scanned = %d, want 2 (the read succeeded before the emit failed)", scanned)
	}
	if emitted != 0 {
		t.Errorf("emitted = %d, want 0 (a rolled-back batch must not be counted)", emitted)
	}
}
