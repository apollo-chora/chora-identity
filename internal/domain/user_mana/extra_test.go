// Additional coverage tests for user_mana — events helpers, edge cases.
package user_mana_test

import (
	"context"
	"testing"
	"time"

	mana "github.com/apollo-chora/chora-identity/internal/domain/user_mana"
)

func TestTopicName_AllEvents(t *testing.T) {
	t.Parallel()
	cases := map[mana.EventType]string{
		mana.EventCredited:      "chora.identity.user_mana.credited.v1",
		mana.EventDebited:       "chora.identity.user_mana.debited.v1",
		mana.EventRefunded:      "chora.identity.user_mana.refunded.v1",
		mana.EventSnapshotTaken: "chora.identity.user_mana.snapshot_taken.v1",
	}
	for evt, want := range cases {
		if got := mana.TopicName(evt); got != want {
			t.Errorf("TopicName(%q)=%q want %q", evt, got, want)
		}
	}
}

func TestLedgerEntryPayloadFrom_PopulatesFields(t *testing.T) {
	t.Parallel()
	e, err := mana.NewLedgerEntry(mana.NewLedgerParams{
		Gcid: "g1", Direction: mana.DirectionCredit, Units: 25,
		Reason: mana.ReasonTopup, SourceTopupID: "topup-1",
		BalanceAfterUnits: 525,
	})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	p := mana.LedgerEntryPayloadFrom(e)
	if p.EntryID != e.EntryID {
		t.Errorf("EntryID mismatch")
	}
	if p.Direction != "credit" {
		t.Errorf("Direction=%q", p.Direction)
	}
	if p.Reason != "topup" {
		t.Errorf("Reason=%q", p.Reason)
	}
	if p.SourceTopupID != "topup-1" {
		t.Errorf("SourceTopupID=%q", p.SourceTopupID)
	}
	if p.BalanceAfterUnits != 525 {
		t.Errorf("BalanceAfterUnits=%d", p.BalanceAfterUnits)
	}
}

func TestSource_Valid_AllSources(t *testing.T) {
	t.Parallel()
	for _, s := range []mana.Source{
		mana.SourceSubscriptionGrant, mana.SourceTopup, mana.SourceTenantSubsidy,
		mana.SourcePromo, mana.SourceRollover, mana.SourceRefund,
		mana.SourceMint, mana.SourcePersonal,
	} {
		if !s.Valid() {
			t.Errorf("%q.Valid()=false", s)
		}
	}
	if mana.Source("dragon").Valid() {
		t.Errorf("invalid source accepted")
	}
}

func TestUserMana_Refund_RejectsZeroOrNegative(t *testing.T) {
	t.Parallel()
	m := mana.NewUserMana("g")
	if err := m.Refund(0); err == nil {
		t.Errorf("expected error for 0")
	}
	if err := m.Refund(-5); err == nil {
		t.Errorf("expected error for negative")
	}
}

func TestUserMana_Refund_ExceedsLifetimeSpent(t *testing.T) {
	t.Parallel()
	m := mana.NewUserMana("g")
	_ = m.Credit(100)
	if err := m.Refund(50); err == nil {
		t.Errorf("expected error refunding more than lifetime_spent")
	}
}

func TestQuoter_CreditMana_MintAndRollover(t *testing.T) {
	t.Parallel()
	store := mana.NewInMemoryStore()
	q := mana.NewQuoter(store)
	ctx := context.Background()

	for _, src := range []mana.Source{mana.SourceMint, mana.SourceRollover, mana.SourceRefund, mana.SourcePromo} {
		_, err := q.CreditMana(ctx, mana.CreditInput{
			Gcid: "g-" + string(src), Source: src, Units: 100,
			Reason: mana.ReasonPromo, IdempotencyKey: "k-" + string(src),
		})
		if err != nil {
			t.Errorf("CreditMana(%q): %v", src, err)
		}
	}
}

func TestQuoter_CreditMana_IdempotentReplay(t *testing.T) {
	t.Parallel()
	store := mana.NewInMemoryStore()
	q := mana.NewQuoter(store)
	ctx := context.Background()
	in := mana.CreditInput{
		Gcid: "g", Source: mana.SourceTopup, Units: 100,
		Reason: mana.ReasonTopup, IdempotencyKey: "ck-replay",
	}
	r1, _ := q.CreditMana(ctx, in)
	r2, _ := q.CreditMana(ctx, in)
	if r1.BalanceAfterUnits != r2.BalanceAfterUnits {
		t.Errorf("replay produced different balance: %d vs %d", r1.BalanceAfterUnits, r2.BalanceAfterUnits)
	}
	got, _ := store.GetMana(ctx, "g")
	if got.BalanceUnits != 100 {
		t.Errorf("replay caused double-credit: balance=%d", got.BalanceUnits)
	}
}

func TestQuoter_CreditMana_TenantSubsidy_AutoAllocationID(t *testing.T) {
	t.Parallel()
	store := mana.NewInMemoryStore()
	q := mana.NewQuoter(store)
	ctx := context.Background()
	expires := time.Now().UTC().Add(7 * 24 * time.Hour)
	_, err := q.CreditMana(ctx, mana.CreditInput{
		Gcid: "g", Source: mana.SourceTenantSubsidy, Units: 50,
		Reason: mana.ReasonTenantSubsidy, IdempotencyKey: "ck-auto",
		// no SourceAllocationID — Quoter must mint one.
		TenantID: "t-1", ExpiresAt: &expires,
	})
	if err != nil {
		t.Fatalf("CreditMana: %v", err)
	}
	allocs, _ := store.ListAllocations(ctx, "g")
	if len(allocs) != 1 || allocs[0].AllocationID == "" {
		t.Errorf("auto allocation_id not minted: %+v", allocs)
	}
}

func TestQuoter_Breakdown_EmptyUser(t *testing.T) {
	t.Parallel()
	store := mana.NewInMemoryStore()
	q := mana.NewQuoter(store)
	bal, slices, err := q.Breakdown(context.Background(), "new-user")
	if err != nil {
		t.Fatalf("Breakdown: %v", err)
	}
	if bal != 0 {
		t.Errorf("balance=%d want 0", bal)
	}
	if len(slices) != 0 {
		t.Errorf("slices=%d want 0", len(slices))
	}
}

func TestQuoter_Breakdown_NilExpirySorts(t *testing.T) {
	t.Parallel()
	store := mana.NewInMemoryStore()
	q := mana.NewQuoter(store)
	earlier := time.Now().UTC().Add(7 * 24 * time.Hour)
	store.AddAllocation("g", &mana.Allocation{
		AllocationID: "no-expiry", RemainingUnits: 50, AllocatedAt: time.Now().UTC(),
	})
	store.AddAllocation("g", &mana.Allocation{
		AllocationID: "with-expiry", RemainingUnits: 50, ExpiresAt: &earlier,
		AllocatedAt: time.Now().UTC(),
	})
	_, slices, _ := q.Breakdown(context.Background(), "g")
	if len(slices) != 2 {
		t.Fatalf("slices=%d", len(slices))
	}
	// Earlier expiry must come first.
	if slices[0].SourceAllocationID != "with-expiry" {
		t.Errorf("FIFO order wrong: %s came first", slices[0].SourceAllocationID)
	}
}

func TestQuoter_DeductMana_SubsidyOnly(t *testing.T) {
	t.Parallel()
	store := mana.NewInMemoryStore()
	q := mana.NewQuoter(store)
	expires := time.Now().UTC().Add(time.Hour)
	store.AddAllocation("g", &mana.Allocation{
		AllocationID: "alloc-1", RemainingUnits: 200,
		ExpiresAt: &expires, AllocatedAt: time.Now().UTC(),
	})
	res, err := q.DeductMana(context.Background(), mana.DeductInput{
		Gcid: "g", ActionCode: "x", Units: 50, IdempotencyKey: "k",
	})
	if err != nil {
		t.Fatalf("DeductMana: %v", err)
	}
	if len(res.Entries) != 1 {
		t.Errorf("entries=%d want 1", len(res.Entries))
	}
	if res.BalanceAfterUnits != 150 {
		t.Errorf("balance_after=%d want 150", res.BalanceAfterUnits)
	}
}

func TestQuoter_DeductMana_RejectsNegativeUnits(t *testing.T) {
	t.Parallel()
	store := mana.NewInMemoryStore()
	q := mana.NewQuoter(store)
	_, err := q.DeductMana(context.Background(), mana.DeductInput{
		Gcid: "g", ActionCode: "x", Units: -10, IdempotencyKey: "k",
	})
	if err == nil {
		t.Errorf("expected error for negative units")
	}
}

func TestInMemoryStore_ListLedger_Filters(t *testing.T) {
	t.Parallel()
	store := mana.NewInMemoryStore()
	q := mana.NewQuoter(store)
	ctx := context.Background()
	_, _ = q.CreditMana(ctx, mana.CreditInput{
		Gcid: "g", Source: mana.SourceSubscriptionGrant, Units: 500,
		Reason: mana.ReasonSubscriptionGrant, IdempotencyKey: "ck1",
	})
	_, _ = q.CreditMana(ctx, mana.CreditInput{
		Gcid: "g", Source: mana.SourceTopup, Units: 100,
		Reason: mana.ReasonTopup, IdempotencyKey: "ck2",
	})

	all, err := store.ListLedger(ctx, mana.LedgerFilter{Gcid: "g"})
	if err != nil {
		t.Fatalf("ListLedger: %v", err)
	}
	if len(all) != 2 {
		t.Errorf("all=%d want 2", len(all))
	}

	dir := mana.DirectionCredit
	credits, _ := store.ListLedger(ctx, mana.LedgerFilter{Gcid: "g", Direction: &dir})
	if len(credits) != 2 {
		t.Errorf("credits=%d want 2", len(credits))
	}

	rs := mana.ReasonTopup
	topups, _ := store.ListLedger(ctx, mana.LedgerFilter{Gcid: "g", Reason: &rs})
	if len(topups) != 1 {
		t.Errorf("topups=%d want 1", len(topups))
	}
}

func TestInMemoryStore_UpdateAllocationRemaining_Missing(t *testing.T) {
	t.Parallel()
	store := mana.NewInMemoryStore()
	if err := store.UpdateAllocationRemaining(context.Background(), "g", "missing", 0); err == nil {
		t.Errorf("expected error for missing allocation")
	}
}

func TestInMemoryStore_SaveAllocation_Upsert(t *testing.T) {
	t.Parallel()
	store := mana.NewInMemoryStore()
	expires := time.Now().UTC().Add(time.Hour)
	a := &mana.Allocation{AllocationID: "alloc-up", RemainingUnits: 100, ExpiresAt: &expires, AllocatedAt: time.Now().UTC()}
	_ = store.SaveAllocation(context.Background(), "g", a)
	a.RemainingUnits = 50
	_ = store.SaveAllocation(context.Background(), "g", a)
	allocs := store.AllocationsFor("g")
	if len(allocs) != 1 || allocs[0].RemainingUnits != 50 {
		t.Errorf("upsert failed: %+v", allocs)
	}
}
