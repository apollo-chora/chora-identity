// Package user_mana_test exercises the UserMana aggregate + ManaLedger
// append-only invariant + Quoter Spend FIFO (subsidy first, personal last).
package user_mana_test

import (
	"context"
	"strings"
	"testing"
	"time"

	mana "github.com/apollo-chora/chora-identity/internal/domain/user_mana"
)

const (
	gcidA = "01970000-0000-7000-9000-00000000000a"
	gcidB = "01970000-0000-7000-9000-00000000000b"
)

// -----------------------------------------------------------------------------
// UserMana aggregate
// -----------------------------------------------------------------------------

func TestNewUserMana_StartsAtZero(t *testing.T) {
	t.Parallel()
	m := mana.NewUserMana(gcidA)
	if m.Gcid != gcidA {
		t.Errorf("Gcid=%q want %s", m.Gcid, gcidA)
	}
	if m.BalanceUnits != 0 || m.LifetimeEarned != 0 || m.LifetimeSpent != 0 {
		t.Errorf("non-zero initial balance")
	}
	if m.Version != 1 {
		t.Errorf("Version=%d want 1", m.Version)
	}
}

func TestUserMana_Credit_IncreasesBalanceAndLifetimeEarned(t *testing.T) {
	t.Parallel()
	m := mana.NewUserMana(gcidA)
	if err := m.Credit(500); err != nil {
		t.Fatalf("Credit: %v", err)
	}
	if m.BalanceUnits != 500 {
		t.Errorf("BalanceUnits=%d want 500", m.BalanceUnits)
	}
	if m.LifetimeEarned != 500 {
		t.Errorf("LifetimeEarned=%d want 500", m.LifetimeEarned)
	}
	if m.LastCreditedAt == nil {
		t.Errorf("LastCreditedAt should be set")
	}
}

func TestUserMana_Credit_RejectsZeroOrNegative(t *testing.T) {
	t.Parallel()
	m := mana.NewUserMana(gcidA)
	if err := m.Credit(0); err == nil {
		t.Errorf("expected error for 0 credit")
	}
	if err := m.Credit(-10); err == nil {
		t.Errorf("expected error for negative credit")
	}
}

func TestUserMana_Debit_DecreasesBalanceAndLifetimeSpent(t *testing.T) {
	t.Parallel()
	m := mana.NewUserMana(gcidA)
	_ = m.Credit(1000)
	if err := m.Debit(250); err != nil {
		t.Fatalf("Debit: %v", err)
	}
	if m.BalanceUnits != 750 {
		t.Errorf("BalanceUnits=%d want 750", m.BalanceUnits)
	}
	if m.LifetimeSpent != 250 {
		t.Errorf("LifetimeSpent=%d want 250", m.LifetimeSpent)
	}
}

func TestUserMana_Debit_InsufficientBalance(t *testing.T) {
	t.Parallel()
	m := mana.NewUserMana(gcidA)
	_ = m.Credit(50)
	if err := m.Debit(100); err == nil {
		t.Errorf("expected error for insufficient balance")
	}
	if !mana.IsInsufficientBalance(m.Debit(100)) {
		t.Errorf("error should classify as insufficient_balance")
	}
}

func TestUserMana_Debit_RejectsZeroOrNegative(t *testing.T) {
	t.Parallel()
	m := mana.NewUserMana(gcidA)
	_ = m.Credit(100)
	if err := m.Debit(0); err == nil {
		t.Errorf("expected error for 0 debit")
	}
	if err := m.Debit(-1); err == nil {
		t.Errorf("expected error for negative debit")
	}
}

func TestUserMana_Refund_BehavesLikeCredit(t *testing.T) {
	t.Parallel()
	m := mana.NewUserMana(gcidA)
	_ = m.Credit(500)
	_ = m.Debit(200)
	if err := m.Refund(100); err != nil {
		t.Fatalf("Refund: %v", err)
	}
	// Refund increases balance but reduces lifetime_spent (logical reversal).
	if m.BalanceUnits != 400 {
		t.Errorf("BalanceUnits=%d want 400", m.BalanceUnits)
	}
	if m.LifetimeSpent != 100 {
		t.Errorf("LifetimeSpent=%d want 100", m.LifetimeSpent)
	}
}

// -----------------------------------------------------------------------------
// LedgerEntry append-only
// -----------------------------------------------------------------------------

func TestNewLedgerEntry_AssignsUUIDv7(t *testing.T) {
	t.Parallel()
	e, err := mana.NewLedgerEntry(mana.NewLedgerParams{
		Gcid:                 gcidA,
		Direction:            mana.DirectionCredit,
		Units:                250,
		Reason:               mana.ReasonSubscriptionGrant,
		SourceSubscriptionID: "sub-1",
	})
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if e.EntryID == "" || len(e.EntryID) != 36 || e.EntryID[14] != '7' {
		t.Errorf("EntryID not UUIDv7: %q", e.EntryID)
	}
	if e.RecordedAt.IsZero() {
		t.Errorf("RecordedAt should be set")
	}
}

func TestNewLedgerEntry_RejectsZeroUnits(t *testing.T) {
	t.Parallel()
	_, err := mana.NewLedgerEntry(mana.NewLedgerParams{
		Gcid: gcidA, Direction: mana.DirectionCredit, Units: 0, Reason: mana.ReasonPromo,
	})
	if err == nil {
		t.Errorf("expected error for 0 units")
	}
}

func TestNewLedgerEntry_RejectsInvalidDirection(t *testing.T) {
	t.Parallel()
	_, err := mana.NewLedgerEntry(mana.NewLedgerParams{
		Gcid: gcidA, Direction: mana.Direction("sideways"), Units: 1, Reason: mana.ReasonPromo,
	})
	if err == nil {
		t.Errorf("expected error for invalid direction")
	}
}

func TestNewLedgerEntry_RejectsInvalidReason(t *testing.T) {
	t.Parallel()
	_, err := mana.NewLedgerEntry(mana.NewLedgerParams{
		Gcid: gcidA, Direction: mana.DirectionCredit, Units: 1, Reason: mana.Reason("magic"),
	})
	if err == nil {
		t.Errorf("expected error for invalid reason")
	}
}

func TestNewLedgerEntry_RejectsEmptyGcid(t *testing.T) {
	t.Parallel()
	_, err := mana.NewLedgerEntry(mana.NewLedgerParams{
		Gcid: "", Direction: mana.DirectionCredit, Units: 1, Reason: mana.ReasonPromo,
	})
	if err == nil {
		t.Errorf("expected error for empty gcid")
	}
}

func TestDirection_Valid(t *testing.T) {
	t.Parallel()
	for _, d := range []mana.Direction{
		mana.DirectionCredit, mana.DirectionDebit, mana.DirectionMint,
		mana.DirectionRefund, mana.DirectionRollover,
	} {
		if !d.Valid() {
			t.Errorf("%q.Valid()=false", d)
		}
	}
}

func TestReason_Valid(t *testing.T) {
	t.Parallel()
	for _, r := range []mana.Reason{
		mana.ReasonSubscriptionGrant, mana.ReasonFamiliarAction, mana.ReasonRefund,
		mana.ReasonAccountClosure, mana.ReasonPromo, mana.ReasonTenantSubsidy,
		mana.ReasonTopup, mana.ReasonRollover,
	} {
		if !r.Valid() {
			t.Errorf("%q.Valid()=false", r)
		}
	}
}

// -----------------------------------------------------------------------------
// SubsidyAllocation FIFO Spend Order — Quoter
// -----------------------------------------------------------------------------

func makeAllocation(id string, units int64, expiresAt *time.Time, allocAt time.Time) *mana.Allocation {
	return &mana.Allocation{
		AllocationID:   id,
		TenantID:       "tenant-x",
		RemainingUnits: units,
		ExpiresAt:      expiresAt,
		AllocatedAt:    allocAt,
	}
}

func TestQuoter_DeductMana_DrainsSubsidiesBeforePersonal(t *testing.T) {
	t.Parallel()
	store := mana.NewInMemoryStore()
	m := mana.NewUserMana(gcidA)
	_ = m.Credit(1000) // personal balance
	store.SaveMana(context.Background(), m)

	t1 := time.Now().UTC().Add(7 * 24 * time.Hour)
	t2 := time.Now().UTC().Add(14 * 24 * time.Hour)
	store.AddAllocation(gcidA, makeAllocation("alloc-A", 200, &t2, time.Now().Add(-2*time.Hour))) // newer expiry, earlier alloc
	store.AddAllocation(gcidA, makeAllocation("alloc-B", 150, &t1, time.Now().Add(-time.Hour)))   // older expiry, later alloc

	q := mana.NewQuoter(store)
	res, err := q.DeductMana(context.Background(), mana.DeductInput{
		Gcid:           gcidA,
		ActionCode:     "familiar_chat",
		Units:          400,
		IdempotencyKey: "key-1",
	})
	if err != nil {
		t.Fatalf("DeductMana: %v", err)
	}
	// Expected: alloc-B (oldest expiry) drained first 150, then alloc-A 200,
	// then 50 from personal (1000 - 50 = 950).
	if res.BalanceAfterUnits != 950 {
		t.Errorf("BalanceAfterUnits=%d want 950", res.BalanceAfterUnits)
	}
	if len(res.Entries) != 3 {
		t.Fatalf("expected 3 ledger entries (subsidyB + subsidyA + personal); got %d", len(res.Entries))
	}
	if res.Entries[0].SourceAllocationID != "alloc-B" {
		t.Errorf("first debit should be alloc-B (oldest expiry); got %q", res.Entries[0].SourceAllocationID)
	}
	if res.Entries[1].SourceAllocationID != "alloc-A" {
		t.Errorf("second debit should be alloc-A; got %q", res.Entries[1].SourceAllocationID)
	}
	if res.Entries[2].SourceAllocationID != "" {
		t.Errorf("third debit should be personal (no allocation); got %q", res.Entries[2].SourceAllocationID)
	}
}

func TestQuoter_DeductMana_InsufficientBalance(t *testing.T) {
	t.Parallel()
	store := mana.NewInMemoryStore()
	m := mana.NewUserMana(gcidA)
	_ = m.Credit(50)
	store.SaveMana(context.Background(), m)

	q := mana.NewQuoter(store)
	_, err := q.DeductMana(context.Background(), mana.DeductInput{
		Gcid: gcidA, ActionCode: "x", Units: 100, IdempotencyKey: "k",
	})
	if !mana.IsInsufficientBalance(err) {
		t.Fatalf("expected insufficient_balance, got: %v", err)
	}
}

func TestQuoter_DeductMana_IdempotentReplay(t *testing.T) {
	t.Parallel()
	store := mana.NewInMemoryStore()
	m := mana.NewUserMana(gcidA)
	_ = m.Credit(500)
	store.SaveMana(context.Background(), m)

	q := mana.NewQuoter(store)
	res1, err := q.DeductMana(context.Background(), mana.DeductInput{
		Gcid: gcidA, ActionCode: "x", Units: 100, IdempotencyKey: "key-replay",
	})
	if err != nil {
		t.Fatalf("first DeductMana: %v", err)
	}
	res2, err := q.DeductMana(context.Background(), mana.DeductInput{
		Gcid: gcidA, ActionCode: "x", Units: 100, IdempotencyKey: "key-replay",
	})
	if err != nil {
		t.Fatalf("replay DeductMana: %v", err)
	}
	if res1.BalanceAfterUnits != res2.BalanceAfterUnits {
		t.Errorf("replay produced different balance: %d vs %d", res1.BalanceAfterUnits, res2.BalanceAfterUnits)
	}
	// Balance must remain debited only once.
	got, _ := store.GetMana(context.Background(), gcidA)
	if got.BalanceUnits != 400 {
		t.Errorf("replay caused double-debit: balance=%d want 400", got.BalanceUnits)
	}
}

func TestQuoter_CreditMana_AppendsLedgerAndIncreasesBalance(t *testing.T) {
	t.Parallel()
	store := mana.NewInMemoryStore()
	m := mana.NewUserMana(gcidA)
	store.SaveMana(context.Background(), m)

	q := mana.NewQuoter(store)
	res, err := q.CreditMana(context.Background(), mana.CreditInput{
		Gcid:                 gcidA,
		Source:               mana.SourceSubscriptionGrant,
		Units:                500,
		Reason:               mana.ReasonSubscriptionGrant,
		IdempotencyKey:       "ck-1",
		SourceSubscriptionID: "sub-1",
	})
	if err != nil {
		t.Fatalf("CreditMana: %v", err)
	}
	if res.BalanceAfterUnits != 500 {
		t.Errorf("BalanceAfterUnits=%d want 500", res.BalanceAfterUnits)
	}
	got, _ := store.GetMana(context.Background(), gcidA)
	if got.BalanceUnits != 500 {
		t.Errorf("balance=%d want 500", got.BalanceUnits)
	}
}

func TestQuoter_CreditMana_TenantSubsidy_AddsAllocation(t *testing.T) {
	t.Parallel()
	store := mana.NewInMemoryStore()
	m := mana.NewUserMana(gcidA)
	store.SaveMana(context.Background(), m)

	q := mana.NewQuoter(store)
	expires := time.Now().UTC().Add(30 * 24 * time.Hour)
	_, err := q.CreditMana(context.Background(), mana.CreditInput{
		Gcid:               gcidA,
		Source:             mana.SourceTenantSubsidy,
		Units:              1000,
		Reason:             mana.ReasonTenantSubsidy,
		IdempotencyKey:     "ck-sub",
		SourceAllocationID: "alloc-XYZ",
		TenantID:           "tenant-1",
		ExpiresAt:          &expires,
	})
	if err != nil {
		t.Fatalf("CreditMana(tenant_subsidy): %v", err)
	}
	allocs := store.AllocationsFor(gcidA)
	if len(allocs) != 1 {
		t.Fatalf("allocations=%d want 1", len(allocs))
	}
	if allocs[0].AllocationID != "alloc-XYZ" || allocs[0].RemainingUnits != 1000 {
		t.Errorf("allocation not stored: %+v", allocs[0])
	}
}

func TestQuoter_CreditMana_RejectsZeroUnits(t *testing.T) {
	t.Parallel()
	store := mana.NewInMemoryStore()
	q := mana.NewQuoter(store)
	_, err := q.CreditMana(context.Background(), mana.CreditInput{
		Gcid: gcidA, Source: mana.SourcePromo, Units: 0,
		Reason: mana.ReasonPromo, IdempotencyKey: "k",
	})
	if err == nil {
		t.Fatalf("expected error for 0 credit")
	}
}

func TestQuoter_CreditMana_RejectsEmptyGcid(t *testing.T) {
	t.Parallel()
	store := mana.NewInMemoryStore()
	q := mana.NewQuoter(store)
	_, err := q.CreditMana(context.Background(), mana.CreditInput{
		Gcid: "", Source: mana.SourcePromo, Units: 10,
		Reason: mana.ReasonPromo, IdempotencyKey: "k",
	})
	if err == nil {
		t.Fatalf("expected error for empty gcid")
	}
}

func TestQuoter_DeductMana_RejectsEmptyIdempotencyKey(t *testing.T) {
	t.Parallel()
	store := mana.NewInMemoryStore()
	m := mana.NewUserMana(gcidA)
	_ = m.Credit(500)
	store.SaveMana(context.Background(), m)
	q := mana.NewQuoter(store)
	_, err := q.DeductMana(context.Background(), mana.DeductInput{
		Gcid: gcidA, ActionCode: "x", Units: 10, IdempotencyKey: "",
	})
	if err == nil {
		t.Fatalf("expected error for empty idempotency_key")
	}
	if !strings.Contains(err.Error(), "idempotency") {
		t.Errorf("error should mention idempotency: %v", err)
	}
}

// -----------------------------------------------------------------------------
// SubsidyBreakdown
// -----------------------------------------------------------------------------

func TestQuoter_GetBreakdown_ReturnsSubsidyAndPersonalSlices(t *testing.T) {
	t.Parallel()
	store := mana.NewInMemoryStore()
	m := mana.NewUserMana(gcidA)
	_ = m.Credit(800)
	store.SaveMana(context.Background(), m)

	expires := time.Now().UTC().Add(7 * 24 * time.Hour)
	store.AddAllocation(gcidA, makeAllocation("alloc-Z", 250, &expires, time.Now()))

	q := mana.NewQuoter(store)
	bal, slices, err := q.Breakdown(context.Background(), gcidA)
	if err != nil {
		t.Fatalf("Breakdown: %v", err)
	}
	if bal != 1050 {
		t.Errorf("balance=%d want 1050", bal)
	}
	if len(slices) != 2 {
		t.Fatalf("slices=%d want 2 (1 subsidy + 1 personal)", len(slices))
	}
	// Subsidy slice MUST come first (FIFO order)
	if slices[0].Source != mana.SourceTenantSubsidy {
		t.Errorf("first slice source=%q want tenant_subsidy", slices[0].Source)
	}
	// Second slice is the learner's personal base balance (NOT a subsidy/grant).
	if slices[1].Source != mana.SourcePersonal {
		t.Errorf("second slice source=%q want personal", slices[1].Source)
	}
}
