//go:build integration

// demo_grant_budget_integration_test.go — live-database specs for the demo
// mana grant's caps, budget counters and elevated read. Run with:
//
//	export CHORA_TEST_DSN=<chora_identity app_rw DSN>
//	go test -tags integration ./internal/adapter/pg/...
//
// These are the round-3 review's mandatory gate: the caps are only real if
// concurrent transactions are serialized by the database, which a stub Tx
// cannot demonstrate. Every case runs as the RUNTIME role
// (chora_identity_app_rw — NOBYPASSRLS, migration 0025), not as the owner.
package pg_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/apollo-chora/chora-identity/internal/adapter/pg"
	"github.com/apollo-chora/chora-identity/internal/domain/identity"
	mana "github.com/apollo-chora/chora-identity/internal/domain/user_mana"
)

// integrationGcid provisions a real `users` row and returns its GCID.
//
// user_mana.gcid and mana_ledger.gcid carry an FK to users(gcid), so a credit
// for an arbitrary UUID is rejected outright — every spec that credits a wallet
// has to start from a provisioned account. Saved through the repository, which
// scopes the RLS GUC the way production does.
func integrationGcid(t *testing.T, pool *pgxpool.Pool) string {
	t.Helper()
	u, err := identity.NewUser(identity.NewUserParams{
		Email:            fmt.Sprintf("demo-it+%s@chora.dev", uuid.NewString()[:8]),
		IdentityProvider: identity.ProviderWebAuthn,
		FederatedSubject: "sub-demo-it-" + uuid.NewString(),
	})
	if err != nil {
		t.Fatalf("NewUser: %v", err)
	}
	if err := pg.NewUserRepository(pg.NewPgxPoolQuerier(pool)).Save(context.Background(), u); err != nil {
		t.Fatalf("provision user %s: %v", u.Gcid, err)
	}
	return u.Gcid
}

// demoGrantInput is one INTERACTIVE demo grant (POST /me/mana/demo-grant).
func demoGrantInput(gcid, key string, units int64, caps *mana.DemoGrantCaps) mana.CreditWalletInput {
	return mana.CreditWalletInput{
		Gcid:           gcid,
		Units:          units,
		Direction:      mana.DirectionMint,
		Reason:         mana.ReasonDemoGrant,
		IdempotencyKey: key,
		DemoGrantCaps:  caps,
	}
}

// budgetRow reads one consumed-counter row.
func budgetRow(t *testing.T, pool *pgxpool.Pool, key string) (units, grants int64) {
	t.Helper()
	err := pool.QueryRow(context.Background(),
		`SELECT consumed_units, consumed_grants FROM demo_grant_budget WHERE budget_key = $1`, key).
		Scan(&units, &grants)
	if err != nil {
		t.Fatalf("read demo_grant_budget[%s]: %v", key, err)
	}
	return units, grants
}

// ledgerRowCount counts a GCID's demo_grant rows.
//
// It runs inside a user-scoped transaction: mana_ledger carries the
// user_isolation policy, and a plain pooled query would both be filtered to
// nothing and — on a connection whose `chora.user_gcid` placeholder GUC has
// already been materialized and reverted to '' — fail outright.
func ledgerRowCount(t *testing.T, pool *pgxpool.Pool, gcid string) int {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, fmt.Sprintf("SET LOCAL chora.user_gcid = '%s'", gcid)); err != nil {
		t.Fatalf("set guc: %v", err)
	}
	var n int
	if err := tx.QueryRow(ctx,
		`SELECT count(*) FROM mana_ledger WHERE gcid = $1::uuid AND reason = 'demo_grant'::mana_reason`,
		gcid).Scan(&n); err != nil {
		t.Fatalf("count ledger rows (gcid=%q): %v", gcid, err)
	}
	return n
}

// resetGlobalBudget zeroes the platform-wide demo-grant counter. The counter is
// shared by every grant in the database (and by every spec in this file), so a
// spec that asserts on the budget starts from a known state.
func resetGlobalBudget(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	if _, err := pool.Exec(context.Background(),
		`UPDATE demo_grant_budget SET consumed_units = 0, consumed_grants = 0, updated_at = now()
		  WHERE budget_key = 'global'`); err != nil {
		t.Fatalf("reset global demo budget: %v", err)
	}
}

// TestIntegration_DemoGrant_SameKeyConcurrentGrantsOnce — a burst of retries of
// ONE grant produces exactly one ledger row, one credit and one charged budget
// grant.
func TestIntegration_DemoGrant_SameKeyConcurrentGrantsOnce(t *testing.T) {
	pool := liveDB(t)
	ctx := context.Background()

	gcid := integrationGcid(t, pool)
	store := pg.NewManaStore(pg.NewPgxPoolQuerier(pool))
	caps := &mana.DemoGrantCaps{MaxPerGcid: 5, BudgetUnits: 1_000_000}

	const workers = 12
	var wg sync.WaitGroup
	results := make([]*mana.CreditWalletResult, workers)
	errs := make([]error, workers)
	for i := range workers {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i], errs[i] = store.CreditWallet(ctx, demoGrantInput(gcid, "same-key", 100, caps))
		}(i)
	}
	wg.Wait()

	for i := range workers {
		if errs[i] != nil {
			t.Fatalf("worker %d: %v", i, errs[i])
		}
	}
	var fresh, replayed int
	for _, r := range results {
		if r.Replayed {
			replayed++
		} else {
			fresh++
		}
	}
	if fresh != 1 || replayed != workers-1 {
		t.Errorf("fresh = %d, replayed = %d; want 1 and %d", fresh, replayed, workers-1)
	}
	if n := ledgerRowCount(t, pool, gcid); n != 1 {
		t.Errorf("ledger rows = %d, want exactly 1", n)
	}
	w, err := store.GetMana(ctx, gcid)
	if err != nil {
		t.Fatalf("GetMana: %v", err)
	}
	if w == nil || w.BalanceUnits != 100 {
		t.Errorf("balance = %+v, want exactly 100", w)
	}
	if units, grants := budgetRow(t, pool, "gcid:"+gcid); units != 100 || grants != 1 {
		t.Errorf("per-gcid counter = (%d,%d), want (100,1)", units, grants)
	}
}

// TestIntegration_DemoGrant_DifferentKeysSameGcidNoLostUpdates — concurrent
// grants with DISTINCT keys for one GCID all land: the wallet row lock
// serializes them instead of one overwriting another (the lost-update race the
// reviewer called out).
func TestIntegration_DemoGrant_DifferentKeysSameGcidNoLostUpdates(t *testing.T) {
	pool := liveDB(t)
	ctx := context.Background()

	gcid := integrationGcid(t, pool)
	store := pg.NewManaStore(pg.NewPgxPoolQuerier(pool))
	// Uncapped: this case is about lost updates, not about the caps.
	caps := &mana.DemoGrantCaps{}

	const workers = 12
	const units = 7
	var wg sync.WaitGroup
	errs := make([]error, workers)
	for i := range workers {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, errs[i] = store.CreditWallet(ctx,
				demoGrantInput(gcid, fmt.Sprintf("lost-update-%d", i), units, caps))
		}(i)
	}
	wg.Wait()
	for i := range workers {
		if errs[i] != nil {
			t.Fatalf("worker %d: %v", i, errs[i])
		}
	}

	w, err := store.GetMana(ctx, gcid)
	if err != nil {
		t.Fatalf("GetMana: %v", err)
	}
	if w == nil || w.BalanceUnits != workers*units {
		t.Errorf("balance = %+v, want %d — no update may be lost", w, workers*units)
	}
	if n := ledgerRowCount(t, pool, gcid); n != workers {
		t.Errorf("ledger rows = %d, want %d", n, workers)
	}
}

// TestIntegration_DemoGrant_SameGcidCapNeverExceeded — many concurrent grants
// with DISTINCT keys for one GCID: the per-GCID cap holds exactly.
func TestIntegration_DemoGrant_SameGcidCapNeverExceeded(t *testing.T) {
	pool := liveDB(t)
	ctx := context.Background()

	gcid := integrationGcid(t, pool)
	store := pg.NewManaStore(pg.NewPgxPoolQuerier(pool))
	const cap = 3
	const units = 100
	caps := &mana.DemoGrantCaps{MaxPerGcid: cap, BudgetUnits: 1_000_000}

	const workers = 20
	var wg sync.WaitGroup
	errs := make([]error, workers)
	for i := range workers {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, errs[i] = store.CreditWallet(ctx,
				demoGrantInput(gcid, fmt.Sprintf("cap-key-%d", i), units, caps))
		}(i)
	}
	wg.Wait()

	granted, limited := 0, 0
	for i := range workers {
		switch {
		case errs[i] == nil:
			granted++
		case errors.Is(errs[i], mana.ErrDemoGrantLimitReached):
			limited++
		default:
			t.Fatalf("worker %d: unexpected error %v", i, errs[i])
		}
	}
	if granted != cap {
		t.Errorf("granted = %d, want exactly %d", granted, cap)
	}
	if limited != workers-cap {
		t.Errorf("limited = %d, want %d", limited, workers-cap)
	}
	w, err := store.GetMana(ctx, gcid)
	if err != nil {
		t.Fatalf("GetMana: %v", err)
	}
	if w == nil || w.BalanceUnits != cap*units {
		t.Errorf("balance = %+v, want %d — the cap must hold", w, cap*units)
	}
	if n := ledgerRowCount(t, pool, gcid); n != cap {
		t.Errorf("ledger rows = %d, want %d", n, cap)
	}
	if units_, grants := budgetRow(t, pool, "gcid:"+gcid); units_ != cap*units || grants != cap {
		t.Errorf("per-gcid counter = (%d,%d), want (%d,%d)", units_, grants, cap*units, cap)
	}
}

// TestIntegration_DemoGrant_DifferentGcidBudgetNeverExceeded — many concurrent
// grants from DISTINCT GCIDs: the shared budget row serializes them and the
// platform-wide budget is never exceeded.
func TestIntegration_DemoGrant_DifferentGcidBudgetNeverExceeded(t *testing.T) {
	pool := liveDB(t)
	ctx := context.Background()

	store := pg.NewManaStore(pg.NewPgxPoolQuerier(pool))
	resetGlobalBudget(t, pool)
	const units = 100
	const budget = 1_000 // exactly 10 grants
	caps := &mana.DemoGrantCaps{MaxPerGcid: 100, BudgetUnits: budget}

	const workers = 30
	gcids := make([]string, workers)
	var wg sync.WaitGroup
	errs := make([]error, workers)
	for i := range workers {
		gcids[i] = integrationGcid(t, pool)
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, errs[i] = store.CreditWallet(ctx,
				demoGrantInput(gcids[i], fmt.Sprintf("budget-key-%d", i), units, caps))
		}(i)
	}
	wg.Wait()

	granted, exhausted := 0, 0
	for i := range workers {
		switch {
		case errs[i] == nil:
			granted++
		case errors.Is(errs[i], mana.ErrDemoGrantBudgetExhausted):
			exhausted++
		default:
			t.Fatalf("worker %d: unexpected error %v", i, errs[i])
		}
	}
	if wantGranted := budget / units; granted != wantGranted {
		t.Errorf("granted = %d, want exactly %d (budget %d / %d units)", granted, wantGranted, budget, units)
	}
	if exhausted != workers-granted {
		t.Errorf("exhausted = %d, want %d", exhausted, workers-granted)
	}
	consumed, grants := budgetRow(t, pool, "global")
	if consumed > budget {
		t.Errorf("global consumed = %d, want <= budget %d", consumed, budget)
	}
	if consumed != int64(granted)*units || grants != int64(granted) {
		t.Errorf("global counter = (%d,%d), want (%d,%d)", consumed, grants, int64(granted)*units, granted)
	}
	// Every credit that returned success is actually in a wallet, and no
	// rejected grant left a ledger row behind.
	total := int64(0)
	for i, g := range gcids {
		if errs[i] != nil {
			if n := ledgerRowCount(t, pool, g); n != 0 {
				t.Errorf("rejected gcid %s has %d ledger rows, want 0", g, n)
			}
			continue
		}
		w, err := store.GetMana(ctx, g)
		if err != nil {
			t.Fatalf("GetMana(%s): %v", g, err)
		}
		if w == nil || w.BalanceUnits != units {
			t.Errorf("gcid %s balance = %+v, want %d", g, w, units)
			continue
		}
		total += w.BalanceUnits
	}
	if total != consumed {
		t.Errorf("credited total = %d, consumed counter = %d — they must agree", total, consumed)
	}
}

// TestIntegration_DemoGrant_SeedDoesNotConsumeBudget — the one-time seed grant
// shares the `demo_grant` reason but must NOT charge the interactive budget or
// the per-GCID allowance, otherwise seeding a demo account would consume the
// button's allowance.
func TestIntegration_DemoGrant_SeedDoesNotConsumeBudget(t *testing.T) {
	pool := liveDB(t)
	ctx := context.Background()

	store := pg.NewManaStore(pg.NewPgxPoolQuerier(pool))
	gcid := integrationGcid(t, pool)
	resetGlobalBudget(t, pool)

	// The seed path: caller-owned transaction + the seed's deterministic key.
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if _, err := tx.Exec(ctx, fmt.Sprintf("SET LOCAL chora.user_gcid = '%s'", gcid)); err != nil {
		_ = tx.Rollback(ctx)
		t.Fatalf("set user guc: %v", err)
	}
	if _, err := pg.SeedDemoGrant(ctx, pg.NewTxBridge(tx), gcid, "demo-seed:v1:"+gcid, 1_000_000_000); err != nil {
		_ = tx.Rollback(ctx)
		t.Fatalf("SeedDemoGrant: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}

	// No budget row was created for this GCID.
	var n int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM demo_grant_budget WHERE budget_key = $1`, "gcid:"+gcid).Scan(&n); err != nil {
		t.Fatalf("count budget rows: %v", err)
	}
	if n != 0 {
		t.Errorf("seed created %d budget row(s) for the gcid, want 0", n)
	}

	// The interactive grant still has its full allowance.
	caps := &mana.DemoGrantCaps{MaxPerGcid: 1, BudgetUnits: 100}
	res, err := store.CreditWallet(ctx, demoGrantInput(gcid, "interactive-after-seed", 100, caps))
	if err != nil {
		t.Fatalf("interactive grant after seed: %v — the seed must not consume the budget", err)
	}
	if res.Replayed {
		t.Error("interactive grant reported a replay")
	}
	w, err := store.GetMana(ctx, gcid)
	if err != nil {
		t.Fatalf("GetMana: %v", err)
	}
	if w.BalanceUnits != 1_000_000_100 {
		t.Errorf("balance = %d, want 1000000100 (seed + interactive)", w.BalanceUnits)
	}

	// The elevated total DOES include the seed row — it reports demo mana
	// minted, while the budget counter reports interactive grants only.
	total, err := store.DemoGrantTotalUnits(ctx)
	if err != nil {
		t.Fatalf("DemoGrantTotalUnits: %v", err)
	}
	if total < 1_000_000_100 {
		t.Errorf("elevated total = %d, want >= 1000000100 (seed + interactive)", total)
	}
}

// TestIntegration_DemoGrantTotalUnits_ElevatedSumWhileCrossGcidReadsDenied —
// the SECURITY DEFINER helper sums demo grants across GCIDs for the runtime
// role, while an ordinary RLS-scoped read of another GCID's rows stays empty.
func TestIntegration_DemoGrantTotalUnits_ElevatedSumWhileCrossGcidReadsDenied(t *testing.T) {
	pool := liveDB(t)
	ctx := context.Background()

	store := pg.NewManaStore(pg.NewPgxPoolQuerier(pool))
	gcidA, gcidB := integrationGcid(t, pool), integrationGcid(t, pool)
	caps := &mana.DemoGrantCaps{}

	if _, err := store.CreditWallet(ctx, demoGrantInput(gcidA, "elev-a", 200, caps)); err != nil {
		t.Fatalf("credit A: %v", err)
	}
	if _, err := store.CreditWallet(ctx, demoGrantInput(gcidB, "elev-b", 300, caps)); err != nil {
		t.Fatalf("credit B: %v", err)
	}

	before, err := store.DemoGrantTotalUnits(ctx)
	if err != nil {
		t.Fatalf("DemoGrantTotalUnits: %v", err)
	}
	if before < 500 {
		t.Errorf("elevated total = %d, want >= 500 (A's 200 + B's 300)", before)
	}

	// An ordinary read scoped to A sees A's rows only — never B's.
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, fmt.Sprintf("SET LOCAL chora.user_gcid = '%s'", gcidA)); err != nil {
		t.Fatalf("set guc: %v", err)
	}
	var visible int64
	if err := tx.QueryRow(ctx,
		`SELECT COALESCE(sum(units),0)::bigint FROM mana_ledger WHERE reason = 'demo_grant'::mana_reason`).
		Scan(&visible); err != nil {
		t.Fatalf("scoped sum: %v", err)
	}
	if visible != 200 {
		t.Errorf("A-scoped demo_grant sum = %d, want 200 — RLS must hide B", visible)
	}
	var bRows int
	if err := tx.QueryRow(ctx,
		`SELECT count(*) FROM mana_ledger WHERE gcid = $1::uuid`, gcidB).Scan(&bRows); err != nil {
		t.Fatalf("count B rows as A: %v", err)
	}
	if bRows != 0 {
		t.Errorf("A sees %d of B's ledger rows, want 0 (RLS leak)", bRows)
	}
	// ... and B's wallet is invisible and un-creditable from A's scope.
	var bBalance int64
	if err := tx.QueryRow(ctx,
		`SELECT balance_units FROM user_mana WHERE gcid = $1::uuid`, gcidB).Scan(&bBalance); !errors.Is(err, pgx.ErrNoRows) {
		t.Errorf("reading B's wallet as A: err = %v, want no rows", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO user_mana (gcid, balance_units, lifetime_earned, lifetime_spent, version)
		VALUES ($1::uuid, 1, 1, 0, 1)`, gcidB); err == nil {
		t.Error("crediting B's wallet from A's scope: err = nil, want an RLS violation")
	}
}
