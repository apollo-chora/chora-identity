//go:build integration

// main_integration_test.go — live-database specs for the seed's demo mana
// grant. Run with:
//
//	export CHORA_TEST_DSN=<chora_identity DSN with write access>
//	go test -tags integration ./cmd/seed/...
//
// The stub-based unit tests in main_test.go cover the same behaviours without
// a database; these prove them against real Postgres, including that the
// grant commits inside the seed transaction and rolls back with it.
package main

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/apollo-chora/chora-identity/internal/domain/authn"
	"github.com/apollo-chora/chora-identity/internal/domain/identity"
)

// seedDemoPool returns a pool for the integration DSN, skipping when unset.
func seedDemoPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("CHORA_TEST_DSN")
	if dsn == "" {
		t.Skip("set CHORA_TEST_DSN to run the seed integration tests")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Skipf("set CHORA_TEST_DSN to a reachable chora_identity DSN: %v", err)
	}
	t.Cleanup(func() { pool.Close() })
	return pool
}

// seedDemoTx opens a transaction with the tenant GUC set, the way cmd/seed's
// run() does.
func seedDemoTx(t *testing.T, pool *pgxpool.Pool, tenantID string) (pgx.Tx, context.Context) {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	t.Cleanup(func() { _ = tx.Rollback(ctx) })
	if _, err := tx.Exec(ctx, "SET LOCAL chora.tenant_id = '"+tenantID+"'"); err != nil {
		t.Fatalf("set tenant guc: %v", err)
	}
	return tx, ctx
}

// rowQuerier is the read surface shared by pgx.Tx and *pgxpool.Pool.
type rowQuerier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// scopedReadTx opens a transaction scoped to a GCID. Reads that happen AFTER
// the seed transaction has ended need it twice over: a committed or rolled-back
// pgx.Tx is closed, and user_mana / mana_ledger carry the user_isolation policy,
// so an unscoped pooled read sees nothing.
func scopedReadTx(t *testing.T, pool *pgxpool.Pool, ctx context.Context, gcid string) pgx.Tx {
	t.Helper()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin read tx: %v", err)
	}
	t.Cleanup(func() { _ = tx.Rollback(ctx) })
	if _, err := tx.Exec(ctx, "SET LOCAL chora.user_gcid = '"+gcid+"'"); err != nil {
		t.Fatalf("set user guc: %v", err)
	}
	return tx
}

func seedDemoTenant(t *testing.T, tx pgx.Tx, ctx context.Context, tenantID string) {
	t.Helper()
	// tenants.slug is UNIQUE and shared by every spec in this file, so it is
	// derived from the (fresh) tenant id rather than a fixed literal.
	slug := "demo-it-" + tenantID[:8]
	if _, err := tx.Exec(ctx, `
		INSERT INTO tenants (id, slug, name, status)
		VALUES ($1::uuid, $2, $2, 'active')
		ON CONFLICT (id) DO NOTHING`, tenantID, slug); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
}

func walletBalance(t *testing.T, q rowQuerier, ctx context.Context, gcid string) int64 {
	t.Helper()
	var bal int64
	err := q.QueryRow(ctx,
		`SELECT COALESCE(balance_units, 0) FROM user_mana WHERE gcid = $1`, gcid).Scan(&bal)
	if err == nil {
		return bal
	}
	if err == pgx.ErrNoRows {
		return 0
	}
	t.Fatalf("read wallet: %v", err)
	return 0
}

func ledgerCount(t *testing.T, q rowQuerier, ctx context.Context, gcid string) int {
	t.Helper()
	var n int
	if err := q.QueryRow(ctx,
		`SELECT count(*) FROM mana_ledger WHERE gcid = $1 AND idempotency_key = $2`,
		gcid, demoSeedGrantKey(gcid)).Scan(&n); err != nil {
		t.Fatalf("read ledger: %v", err)
	}
	return n
}

// userRowCount counts the seeded user rows — the third write the seed's
// transaction must roll back with the wallet and the ledger.
func userRowCount(t *testing.T, q rowQuerier, ctx context.Context, gcid string) int {
	t.Helper()
	var n int
	if err := q.QueryRow(ctx, `SELECT count(*) FROM users WHERE gcid = $1`, gcid).Scan(&n); err != nil {
		t.Fatalf("read user: %v", err)
	}
	return n
}

// TestIntegration_SeedDemoGrant_CreditsWalletAndLedger proves the first seed
// run credits the wallet and appends exactly one demo_grant ledger row.
func TestIntegration_SeedDemoGrant_CreditsWalletAndLedger(t *testing.T) {

	tenantID := uuid.NewString()
	pool := seedDemoPool(t)
	tx, ctx := seedDemoTx(t, pool, tenantID)
	seedDemoTenant(t, tx, ctx, tenantID)

	u := seedUser{
		Username: "demoit-" + uuid.NewString()[:8],
		Email:    "demoit-" + uuid.NewString()[:8] + "@example.com",
		Password: "hunter2",
		Role:     identity.RoleAdmin,
	}
	gcid := seedGcid(authn.NormalizeUsername(u.Username))

	if err := upsertUser(ctx, tx, tenantID, u); err != nil {
		t.Fatalf("upsertUser: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}

	read := scopedReadTx(t, pool, ctx, gcid)
	if got := walletBalance(t, read, ctx, gcid); got != demoSeedGrantUnits {
		t.Errorf("balance = %d, want %d", got, demoSeedGrantUnits)
	}
	if n := ledgerCount(t, read, ctx, gcid); n != 1 {
		t.Errorf("ledger rows = %d, want 1", n)
	}
	if n := userRowCount(t, read, ctx, gcid); n != 1 {
		t.Errorf("user rows = %d, want 1", n)
	}
}

// TestIntegration_SeedDemoGrant_RerunAddsNothing proves a second seed run is a
// no-op: no second ledger row, no second credit.
func TestIntegration_SeedDemoGrant_RerunAddsNothing(t *testing.T) {

	tenantID := uuid.NewString()
	pool := seedDemoPool(t)
	tx, ctx := seedDemoTx(t, pool, tenantID)
	seedDemoTenant(t, tx, ctx, tenantID)

	u := seedUser{
		Username: "demoit-" + uuid.NewString()[:8],
		Email:    "demoit2-" + uuid.NewString()[:8] + "@example.com",
		Password: "hunter2",
		Role:     identity.RoleLearner,
	}
	gcid := seedGcid(authn.NormalizeUsername(u.Username))

	if err := upsertUser(ctx, tx, tenantID, u); err != nil {
		t.Fatalf("first upsertUser: %v", err)
	}
	if err := upsertUser(ctx, tx, tenantID, u); err != nil {
		t.Fatalf("second upsertUser: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}

	read := scopedReadTx(t, pool, ctx, gcid)
	if got := walletBalance(t, read, ctx, gcid); got != demoSeedGrantUnits {
		t.Errorf("balance = %d, want %d (credited once)", got, demoSeedGrantUnits)
	}
	if n := ledgerCount(t, read, ctx, gcid); n != 1 {
		t.Errorf("ledger rows = %d, want 1", n)
	}
}

// TestIntegration_SeedDemoGrant_AfterSpendingPreservesSpentBalance proves the
// grant never resets a balance the user has since spent.
func TestIntegration_SeedDemoGrant_AfterSpendingPreservesSpentBalance(t *testing.T) {

	tenantID := uuid.NewString()
	pool := seedDemoPool(t)
	tx, ctx := seedDemoTx(t, pool, tenantID)
	seedDemoTenant(t, tx, ctx, tenantID)

	u := seedUser{
		Username: "demoit-" + uuid.NewString()[:8],
		Email:    "demoit3-" + uuid.NewString()[:8] + "@example.com",
		Password: "hunter2",
		Role:     identity.RoleInstructor,
	}
	gcid := seedGcid(authn.NormalizeUsername(u.Username))

	if err := upsertUser(ctx, tx, tenantID, u); err != nil {
		t.Fatalf("upsertUser: %v", err)
	}
	// Spend part of the grant through the ordinary debit path.
	if _, err := tx.Exec(ctx,
		`UPDATE user_mana SET balance_units = balance_units - 400000000, lifetime_spent = 400000000 WHERE gcid = $1`,
		gcid); err != nil {
		t.Fatalf("spend: %v", err)
	}
	// Read INSIDE the seed transaction: the uncommitted credit is not visible
	// to any other connection.
	before := walletBalance(t, tx, ctx, gcid)

	if err := upsertUser(ctx, tx, tenantID, u); err != nil {
		t.Fatalf("rerun upsertUser: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}

	read := scopedReadTx(t, pool, ctx, gcid)
	if got := walletBalance(t, read, ctx, gcid); got != before {
		t.Errorf("balance = %d, want the spent balance %d (never reset)", got, before)
	}
	if n := ledgerCount(t, read, ctx, gcid); n != 1 {
		t.Errorf("ledger rows = %d, want 1", n)
	}
}

// TestIntegration_SeedDemoGrant_TransactionFailureChangesNeither proves the
// grant is part of the seed transaction: a later failure rolls it back.
func TestIntegration_SeedDemoGrant_TransactionFailureChangesNeither(t *testing.T) {

	tenantID := uuid.NewString()
	pool := seedDemoPool(t)
	tx, ctx := seedDemoTx(t, pool, tenantID)
	seedDemoTenant(t, tx, ctx, tenantID)

	u := seedUser{
		Username: "demoit-" + uuid.NewString()[:8],
		Email:    "demoit4-" + uuid.NewString()[:8] + "@example.com",
		Password: "hunter2",
		Role:     identity.RoleAdmin,
	}
	gcid := seedGcid(authn.NormalizeUsername(u.Username))

	if err := upsertUser(ctx, tx, tenantID, u); err != nil {
		t.Fatalf("upsertUser: %v", err)
	}
	// A later statement in the SAME transaction fails: the whole thing rolls
	// back, demo grant included.
	if _, err := tx.Exec(ctx, `INSERT INTO nonexistent_table (x) VALUES (1)`); err == nil {
		t.Fatal("expected the forced failure to error")
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatalf("rollback: %v", err)
	}

	read := scopedReadTx(t, pool, ctx, gcid)
	if got := walletBalance(t, read, ctx, gcid); got != 0 {
		t.Errorf("balance = %d, want 0 — a failed seed must not credit", got)
	}
	if n := ledgerCount(t, read, ctx, gcid); n != 0 {
		t.Errorf("ledger rows = %d, want 0", n)
	}
	// The user row and its credential/membership rows roll back with the grant:
	// a failed seed must not leave a half-provisioned account behind.
	if n := userRowCount(t, read, ctx, gcid); n != 0 {
		t.Errorf("user rows = %d, want 0", n)
	}
}
