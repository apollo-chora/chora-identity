//go:build integration

// user_mana_credit_integration_test.go — live-database specs for the atomic
// credit primitive. Run with:
//
//	export CHORA_TEST_DSN=<chora_identity app_rw DSN>
//	go test -tags integration ./internal/adapter/pg/...
//
// These cover what a stub Tx cannot: real RLS isolation between GCIDs, the
// real pg_advisory_xact_lock under concurrent duplicates, and real
// transactional ROLLBACK when the ledger insert fails.
package pg_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/apollo-chora/chora-identity/internal/adapter/pg"
	mana "github.com/apollo-chora/chora-identity/internal/domain/user_mana"
)

func creditWalletInput(gcid, key string, units int64) mana.CreditWalletInput {
	return mana.CreditWalletInput{
		Gcid:           gcid,
		Units:          units,
		Direction:      mana.DirectionMint,
		Reason:         mana.ReasonDemoGrant,
		IdempotencyKey: key,
	}
}

// TestIntegration_CreditWallet_RLSIsolation proves the app role (NOBYPASSRLS)
// cannot read or credit another GCID's wallet: the user_isolation policy
// (migration 0003) filters both the SELECT and the INSERT.
func TestIntegration_CreditWallet_RLSIsolation(t *testing.T) {
	pool := liveDB(t)
	ctx := context.Background()

	gcidA := uuid.NewString()
	gcidB := uuid.NewString()

	store := pg.NewManaStore(pg.NewPgxPoolQuerier(pool))
	if _, err := store.CreditWallet(ctx, creditWalletInput(gcidA, "rls-a", 100)); err != nil {
		t.Fatalf("credit A: %v", err)
	}

	// A can read its own wallet.
	a, err := store.GetMana(ctx, gcidA)
	if err != nil {
		t.Fatalf("GetMana(A): %v", err)
	}
	if a == nil || a.BalanceUnits != 100 {
		t.Fatalf("A wallet = %+v, want balance 100", a)
	}

	// With the GUC scoped to A, B's wallet row is invisible.
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, "SET LOCAL chora.user_gcid = '"+gcidA+"'"); err != nil {
		t.Fatalf("set guc: %v", err)
	}
	var bal int64
	err = tx.QueryRow(ctx, `SELECT balance_units FROM user_mana WHERE gcid = $1`, gcidB).Scan(&bal)
	if !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("reading B as A: err = %v, want no rows (RLS-filtered)", err)
	}

	// With the GUC scoped to A, a direct write for B is rejected by RLS.
	_, err = tx.Exec(ctx, `
		INSERT INTO user_mana (gcid, balance_units, lifetime_earned, lifetime_spent, version)
		VALUES ($1, 1, 1, 0, 1)`, gcidB)
	if err == nil {
		t.Fatal("inserting B's wallet as A: err = nil, want an RLS violation")
	}
	if !strings.Contains(err.Error(), "row-level security") && !strings.Contains(err.Error(), "new row") {
		t.Fatalf("insert B as A: err = %v, want an RLS policy violation", err)
	}

	// B's wallet must still not exist.
	b, err := store.GetMana(ctx, gcidB)
	if err != nil {
		t.Fatalf("GetMana(B): %v", err)
	}
	if b != nil {
		t.Fatalf("B wallet = %+v, want nil — A must not be able to credit B", b)
	}
}

// TestIntegration_CreditWallet_ConcurrentDuplicatesGrantExactlyOnce proves the
// advisory-lock + in-tx re-check closes the race left by the caller's pre-write
// idempotency lookup: N concurrent grants with the SAME key produce exactly one
// ledger row and one credit.
func TestIntegration_CreditWallet_ConcurrentDuplicatesGrantExactlyOnce(t *testing.T) {
	pool := liveDB(t)
	ctx := context.Background()

	gcid := uuid.NewString()
	store := pg.NewManaStore(pg.NewPgxPoolQuerier(pool))

	const workers = 12
	var wg sync.WaitGroup
	errs := make([]error, workers)
	for i := range workers {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, errs[i] = store.CreditWallet(ctx, creditWalletInput(gcid, "race-key", 1_000))
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
	if w == nil || w.BalanceUnits != 1_000 {
		t.Fatalf("balance = %+v, want exactly 1000 (granted once)", w)
	}
	entries, err := store.FindLedgerByIdempotencyKey(ctx, gcid, "race-key")
	if err != nil {
		t.Fatalf("FindLedgerByIdempotencyKey: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("ledger rows = %d, want exactly 1", len(entries))
	}
}

// TestIntegration_CreditWallet_LedgerFailureLeavesWalletUnchanged proves the
// wallet write and the ledger insert really are one transaction: a ledger
// failure rolls the wallet credit back.
func TestIntegration_CreditWallet_LedgerFailureLeavesWalletUnchanged(t *testing.T) {
	pool := liveDB(t)
	ctx := context.Background()

	gcid := uuid.NewString()
	store := pg.NewManaStore(pg.NewPgxPoolQuerier(pool))

	// A key that is already 129 chars long overflows idempotency_key
	// VARCHAR(128), so the ledger INSERT fails after the wallet row is written.
	overLongKey := strings.Repeat("k", 129)
	_, err := store.CreditWallet(ctx, creditWalletInput(gcid, overLongKey, 1_000))
	if err == nil {
		t.Fatal("CreditWallet err = nil, want the ledger insert to fail")
	}

	w, err := store.GetMana(ctx, gcid)
	if err != nil {
		t.Fatalf("GetMana: %v", err)
	}
	if w != nil {
		t.Fatalf("wallet = %+v, want nil — the credit must roll back with the ledger failure", w)
	}
	entries, err := store.FindLedgerByIdempotencyKey(ctx, gcid, overLongKey)
	if err != nil {
		t.Fatalf("FindLedgerByIdempotencyKey: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("ledger rows = %d, want 0", len(entries))
	}
}

// TestIntegration_CreditWallet_ReplayAfterSpendingPreservesSpentBalance proves
// the grant is additive, never a reset: replaying the key after the user has
// spent part of it reports and preserves the spent balance.
func TestIntegration_CreditWallet_ReplayAfterSpendingPreservesSpentBalance(t *testing.T) {
	pool := liveDB(t)
	ctx := context.Background()

	gcid := uuid.NewString()
	store := pg.NewManaStore(pg.NewPgxPoolQuerier(pool))

	if _, err := store.CreditWallet(ctx, creditWalletInput(gcid, "spend-key", 1_000_000)); err != nil {
		t.Fatalf("first credit: %v", err)
	}
	// Spend 400k through the ordinary debit path.
	q := mana.NewQuoter(store)
	if _, err := q.DeductMana(ctx, mana.DeductInput{
		Gcid: gcid, ActionCode: "x", Units: 400_000, IdempotencyKey: "spend-1",
	}); err != nil {
		t.Fatalf("deduct: %v", err)
	}

	res, err := store.CreditWallet(ctx, creditWalletInput(gcid, "spend-key", 1_000_000))
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if !res.Replayed {
		t.Fatal("replay must report Replayed=true")
	}
	if res.BalanceAfterUnits != 600_000 {
		t.Errorf("BalanceAfterUnits = %d, want 600000 (the spent balance)", res.BalanceAfterUnits)
	}
	entries, _ := store.FindLedgerByIdempotencyKey(ctx, gcid, "spend-key")
	if len(entries) != 1 {
		t.Errorf("ledger rows = %d, want 1", len(entries))
	}
}
