//go:build integration

// main_integration_test.go — live-database specs for the one-off demo mana
// seed-grant command. Run with:
//
//	export CHORA_TEST_DSN=<chora_identity DSN with write access>
//	export CHORA_TEST_APP_DSN=<optional: the NOBYPASSRLS app-role DSN>
//	go test -tags integration ./cmd/seed-demo-mana/...
//
// The stub-based unit tests in main_test.go cover the same behaviours without a
// database; these prove them against real Postgres, including that the grant is
// scoped to the GCID's RLS context and that no identity row is ever created.
package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/apollo-chora/chora-identity/internal/adapter/pg"
)

func poolFromEnv(t *testing.T, env string) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv(env)
	if dsn == "" {
		t.Skipf("set %s to run this spec", env)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Skipf("set %s to a reachable chora_identity DSN: %v", env, err)
	}
	t.Cleanup(func() { pool.Close() })
	return pool
}

func seedManaPool(t *testing.T) *pgxpool.Pool { return poolFromEnv(t, "CHORA_TEST_DSN") }

// newTestGcid returns a fresh GCID. `users` rejects AGID-shaped identifiers
// (a `0197a` prefix), which a UUIDv7 minted today could collide with.
func newTestGcid(t *testing.T) string {
	t.Helper()
	for i := 0; i < 100; i++ {
		g := uuid.NewString()
		if !strings.HasPrefix(g, "0197a") {
			return g
		}
	}
	t.Fatal("could not generate a non-AGID gcid")
	return ""
}

// createAccount inserts the users row the command requires. It deliberately
// writes ONLY `users` — no credential, no membership.
func createAccount(t *testing.T, pool *pgxpool.Pool, gcid string) {
	t.Helper()
	ctx := context.Background()
	if _, err := pool.Exec(ctx, `
		INSERT INTO users (gcid, email, display_name, identity_provider, federated_subject, status)
		VALUES ($1::uuid, $2, $3, 'password'::identity_provider, $4, 'active')`,
		gcid, "seed-demo-mana+"+gcid[:8]+"@example.com", "seed-demo-mana", gcid); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	t.Cleanup(func() {
		// The wallet row is removable; the mana_ledger row is append-only by
		// trigger, so it is left behind (the GCID is fresh per run).
		cleanupScoped(t, pool, gcid, `DELETE FROM user_mana WHERE gcid = $1`)
		_, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE gcid = $1`, gcid)
	})
}

// scopedTx opens a transaction with the GCID's RLS context applied, the way
// RunInUserTx does.
func scopedTx(t *testing.T, pool *pgxpool.Pool, gcid string) (context.Context, pgx.Tx) {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	t.Cleanup(func() { _ = tx.Rollback(ctx) })
	if _, err := tx.Exec(ctx, fmt.Sprintf("SET LOCAL chora.user_gcid = '%s'", gcid)); err != nil {
		t.Fatalf("set user guc: %v", err)
	}
	return ctx, tx
}

func cleanupScoped(t *testing.T, pool *pgxpool.Pool, gcid, stmt string) {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		return
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if _, err := tx.Exec(ctx, fmt.Sprintf("SET LOCAL chora.user_gcid = '%s'", gcid)); err != nil {
		return
	}
	_, _ = tx.Exec(ctx, stmt, gcid)
	_ = tx.Commit(ctx)
}

// scopedBalance reads the wallet balance under the GCID's RLS scope.
func scopedBalance(t *testing.T, pool *pgxpool.Pool, gcid string) int64 {
	t.Helper()
	ctx, tx := scopedTx(t, pool, gcid)
	var bal int64
	err := tx.QueryRow(ctx, `SELECT COALESCE(balance_units, 0) FROM user_mana WHERE gcid = $1`, gcid).Scan(&bal)
	if err == pgx.ErrNoRows {
		return 0
	}
	if err != nil {
		t.Fatalf("read balance: %v", err)
	}
	return bal
}

// scopedSeedLedgerCount counts the seed ledger rows under the GCID's RLS scope.
func scopedSeedLedgerCount(t *testing.T, pool *pgxpool.Pool, gcid string) int {
	t.Helper()
	ctx, tx := scopedTx(t, pool, gcid)
	var n int
	if err := tx.QueryRow(ctx,
		`SELECT count(*) FROM mana_ledger WHERE gcid = $1 AND idempotency_key = $2`,
		gcid, demoSeedGrantKey(gcid)).Scan(&n); err != nil {
		t.Fatalf("read ledger: %v", err)
	}
	return n
}

func accountExists(t *testing.T, pool *pgxpool.Pool, gcid string) bool {
	t.Helper()
	var exists bool
	if err := pool.QueryRow(context.Background(),
		`SELECT EXISTS (SELECT 1 FROM users WHERE gcid = $1)`, gcid).Scan(&exists); err != nil {
		t.Fatalf("read user: %v", err)
	}
	return exists
}

func runCommand(t *testing.T, pool *pgxpool.Pool, cfg config) (string, error) {
	t.Helper()
	var out bytes.Buffer
	err := run(context.Background(), pg.NewPgxPoolQuerier(pool), cfg, &out)
	return out.String(), err
}

// TestIntegration_SeedDemoMana_DryRunMakesNoChanges proves the dry run reads
// the real wallet/ledger state and writes nothing.
func TestIntegration_SeedDemoMana_DryRunMakesNoChanges(t *testing.T) {
	pool := seedManaPool(t)
	gcid := newTestGcid(t)
	createAccount(t, pool, gcid)

	cfg := config{Gcids: []string{gcid}, Units: 1_000_000_000, DryRun: true}
	out, err := runCommand(t, pool, cfg)
	if err != nil {
		t.Fatalf("dry run: %v\n%s", err, out)
	}
	if !strings.Contains(out, "status=would-apply") || !strings.Contains(out, "after=1000000000") {
		t.Errorf("dry run report:\n%s", out)
	}
	if got := scopedBalance(t, pool, gcid); got != 0 {
		t.Errorf("balance = %d, want 0 — the dry run must not credit", got)
	}
	if n := scopedSeedLedgerCount(t, pool, gcid); n != 0 {
		t.Errorf("ledger rows = %d, want 0 — the dry run must not write", n)
	}
}

// TestIntegration_SeedDemoMana_FirstRunAppliesThenReplays proves the grant
// lands once, and that a re-run replays with no double credit.
func TestIntegration_SeedDemoMana_FirstRunAppliesThenReplays(t *testing.T) {
	pool := seedManaPool(t)
	gcid := newTestGcid(t)
	createAccount(t, pool, gcid)

	cfg := config{Gcids: []string{gcid}, Units: 1_000_000_000}
	out, err := runCommand(t, pool, cfg)
	if err != nil {
		t.Fatalf("first run: %v\n%s", err, out)
	}
	if !strings.Contains(out, "status=applied") {
		t.Errorf("first run report:\n%s", out)
	}
	if got := scopedBalance(t, pool, gcid); got != 1_000_000_000 {
		t.Fatalf("balance = %d, want 1000000000", got)
	}
	if n := scopedSeedLedgerCount(t, pool, gcid); n != 1 {
		t.Fatalf("ledger rows = %d, want exactly 1", n)
	}

	out, err = runCommand(t, pool, cfg)
	if err != nil {
		t.Fatalf("rerun: %v\n%s", err, out)
	}
	if !strings.Contains(out, "status=replayed") || !strings.Contains(out, "units_credited=0") {
		t.Errorf("rerun report:\n%s", out)
	}
	if got := scopedBalance(t, pool, gcid); got != 1_000_000_000 {
		t.Errorf("balance = %d, want 1000000000 — no double credit", got)
	}
	if n := scopedSeedLedgerCount(t, pool, gcid); n != 1 {
		t.Errorf("ledger rows = %d, want 1", n)
	}
}

// TestIntegration_SeedDemoMana_UnknownGcidIsNotCreated proves a GCID with no
// account is refused and that no identity row is conjured for it.
func TestIntegration_SeedDemoMana_UnknownGcidIsNotCreated(t *testing.T) {
	pool := seedManaPool(t)
	good, missing := newTestGcid(t), newTestGcid(t)
	createAccount(t, pool, good)

	out, err := runCommand(t, pool, config{Gcids: []string{good, missing}, Units: 1_000_000_000})
	if err == nil {
		t.Fatalf("an unknown GCID must fail the run:\n%s", out)
	}
	if !strings.Contains(out, "gcid="+missing+" status=unknown-gcid") {
		t.Errorf("the unknown GCID must be reported:\n%s", out)
	}
	if accountExists(t, pool, missing) {
		t.Error("the command created a user row")
	}
	if got := scopedBalance(t, pool, missing); got != 0 {
		t.Errorf("balance for the unknown GCID = %d, want 0", got)
	}
	// The valid GCID in the same batch is still granted.
	if got := scopedBalance(t, pool, good); got != 1_000_000_000 {
		t.Errorf("balance for %s = %d, want 1000000000", good, got)
	}
}

// TestIntegration_SeedDemoMana_AppRoleRLS runs the command as the NOBYPASSRLS
// application role: the grant must succeed through the SET LOCAL
// chora.user_gcid scope, and the resulting rows must be invisible under another
// GCID's scope.
func TestIntegration_SeedDemoMana_AppRoleRLS(t *testing.T) {
	pool := poolFromEnv(t, "CHORA_TEST_APP_DSN")
	gcid, other := newTestGcid(t), newTestGcid(t)
	createAccount(t, pool, gcid)

	out, err := runCommand(t, pool, config{Gcids: []string{gcid}, Units: 1_000_000_000})
	if err != nil {
		t.Fatalf("app-role run: %v\n%s", err, out)
	}
	if got := scopedBalance(t, pool, gcid); got != 1_000_000_000 {
		t.Fatalf("balance = %d, want 1000000000", got)
	}

	// Under a DIFFERENT GCID's scope the rows must not be visible.
	ctx, tx := scopedTx(t, pool, other)
	var wallets, ledger int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM user_mana WHERE gcid = $1`, gcid).Scan(&wallets); err != nil {
		t.Fatalf("cross-gcid wallet read: %v", err)
	}
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM mana_ledger WHERE gcid = $1`, gcid).Scan(&ledger); err != nil {
		t.Fatalf("cross-gcid ledger read: %v", err)
	}
	if wallets != 0 || ledger != 0 {
		t.Errorf("RLS LEAK: another GCID saw %d wallet(s) and %d ledger row(s)", wallets, ledger)
	}
}
