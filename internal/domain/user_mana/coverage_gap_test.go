// Coverage top-up for user_mana — typed-error formatting helpers, the
// DeductMana replay/personal-balance/zero-cost paths, store error branches
// (via a fault-injecting stub), CreditMana validation, Breakdown edge cases,
// ListLedger filters/cursor, and DecodeLedgerCursor malformed inputs.
package user_mana_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	mana "github.com/apollo-chora/chora-identity/internal/domain/user_mana"
)

// -----------------------------------------------------------------------------
// faultStore — InMemoryStore with per-method error injection
// -----------------------------------------------------------------------------

type faultStore struct {
	*mana.InMemoryStore

	getManaErr  error
	saveManaErr error
	listAlloc   error
	saveAlloc   error
	updateAlloc error
	appendLed   error
	findKeyErr  error
	listLedErr  error
}

func (s *faultStore) GetMana(ctx context.Context, gcid string) (*mana.UserMana, error) {
	if s.getManaErr != nil {
		return nil, s.getManaErr
	}
	return s.InMemoryStore.GetMana(ctx, gcid)
}

func (s *faultStore) SaveMana(ctx context.Context, m *mana.UserMana) error {
	if s.saveManaErr != nil {
		return s.saveManaErr
	}
	return s.InMemoryStore.SaveMana(ctx, m)
}

func (s *faultStore) ListAllocations(ctx context.Context, gcid string) ([]*mana.Allocation, error) {
	if s.listAlloc != nil {
		return nil, s.listAlloc
	}
	return s.InMemoryStore.ListAllocations(ctx, gcid)
}

func (s *faultStore) SaveAllocation(ctx context.Context, gcid string, a *mana.Allocation) error {
	if s.saveAlloc != nil {
		return s.saveAlloc
	}
	return s.InMemoryStore.SaveAllocation(ctx, gcid, a)
}

func (s *faultStore) UpdateAllocationRemaining(ctx context.Context, gcid, allocationID string, remaining int64) error {
	if s.updateAlloc != nil {
		return s.updateAlloc
	}
	return s.InMemoryStore.UpdateAllocationRemaining(ctx, gcid, allocationID, remaining)
}

func (s *faultStore) AppendLedger(ctx context.Context, e *mana.LedgerEntry) error {
	if s.appendLed != nil {
		return s.appendLed
	}
	return s.InMemoryStore.AppendLedger(ctx, e)
}

func (s *faultStore) FindLedgerByIdempotencyKey(ctx context.Context, gcid, key string) ([]*mana.LedgerEntry, error) {
	if s.findKeyErr != nil {
		return nil, s.findKeyErr
	}
	return s.InMemoryStore.FindLedgerByIdempotencyKey(ctx, gcid, key)
}

func (s *faultStore) ListLedger(ctx context.Context, f mana.LedgerFilter) ([]*mana.LedgerEntry, error) {
	if s.listLedErr != nil {
		return nil, s.listLedErr
	}
	return s.InMemoryStore.ListLedger(ctx, f)
}

func newFaultStore() *faultStore {
	return &faultStore{InMemoryStore: mana.NewInMemoryStore()}
}

func zeroPricer() mana.Pricer {
	return pricerFunc(func(_ context.Context, _ string) (int64, error) { return 0, nil })
}

type pricerFunc func(ctx context.Context, actionCode string) (int64, error)

func (f pricerFunc) CostForAction(ctx context.Context, actionCode string) (int64, error) {
	return f(ctx, actionCode)
}

// -----------------------------------------------------------------------------
// Typed-error helpers
// -----------------------------------------------------------------------------

func TestInsufficientBalanceError_ErrorAndUnwrap(t *testing.T) {
	t.Parallel()
	ibe := &mana.InsufficientBalanceError{RequiredUnits: 5, AvailableUnits: 3}
	if got := ibe.Error(); got != "user_mana: insufficient balance: need 5, have 3" {
		t.Errorf("Error() = %q", got)
	}
	if !errors.Is(ibe, mana.ErrInsufficientBalance) {
		t.Error("errors.Is must match ErrInsufficientBalance via Unwrap")
	}
	if !mana.IsInsufficientBalance(ibe) {
		t.Error("IsInsufficientBalance must accept the typed error")
	}
}

func TestIsUnknownActionCode(t *testing.T) {
	t.Parallel()
	if !mana.IsUnknownActionCode(mana.ErrUnknownActionCode) {
		t.Error("direct sentinel must classify")
	}
	if !mana.IsUnknownActionCode(fmt.Errorf("wrapped: %w", mana.ErrUnknownActionCode)) {
		t.Error("wrapped sentinel must classify")
	}
	if mana.IsUnknownActionCode(errors.New("unrelated")) {
		t.Error("unrelated error must not classify")
	}
}

// -----------------------------------------------------------------------------
// DeductMana — replay, personal-balance, split-drain, validation
// -----------------------------------------------------------------------------

func TestQuoter_DeductMana_IdempotentReplay_Gap(t *testing.T) {
	t.Parallel()
	store := mana.NewInMemoryStore()
	q := mana.NewQuoter(store)
	seedWallet(t, store, "g", 100)

	in := mana.DeductInput{Gcid: "g", ActionCode: "x", Units: 30, IdempotencyKey: "dk-replay"}
	first, err := q.DeductMana(context.Background(), in)
	if err != nil {
		t.Fatalf("first deduct: %v", err)
	}
	if first.Replayed {
		t.Error("first call must not be a replay")
	}
	second, err := q.DeductMana(context.Background(), in)
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if !second.Replayed {
		t.Error("second call must replay")
	}
	if second.BalanceAfterUnits != 70 {
		t.Errorf("replay balance = %d; want 70 (not double-debited)", second.BalanceAfterUnits)
	}
	if got, _ := store.GetMana(context.Background(), "g"); got.BalanceUnits != 70 {
		t.Errorf("wallet balance = %d; want 70", got.BalanceUnits)
	}
	rows, _ := store.ListLedger(context.Background(), mana.LedgerFilter{Gcid: "g"})
	if len(rows) != 1 {
		t.Errorf("ledger rows = %d; want 1", len(rows))
	}
}

func TestQuoter_DeductMana_PersonalBalanceOnly(t *testing.T) {
	t.Parallel()
	store := mana.NewInMemoryStore()
	q := mana.NewQuoter(store)
	seedWallet(t, store, "g", 100)

	res, err := q.DeductMana(context.Background(), mana.DeductInput{
		Gcid: "g", ActionCode: "x", Units: 30, IdempotencyKey: "dk-pers",
	})
	if err != nil {
		t.Fatalf("DeductMana: %v", err)
	}
	if res.BalanceAfterUnits != 70 {
		t.Errorf("balance = %d; want 70", res.BalanceAfterUnits)
	}
	if len(res.Entries) != 1 || res.Entries[0].SourceAllocationID != "" {
		t.Errorf("expected 1 personal-balance entry, got %+v", res.Entries)
	}
	if got, _ := store.GetMana(context.Background(), "g"); got.LifetimeSpent != 30 {
		t.Errorf("lifetime_spent = %d; want 30", got.LifetimeSpent)
	}
}

func TestQuoter_DeductMana_SplitSubsidyThenPersonal(t *testing.T) {
	t.Parallel()
	store := mana.NewInMemoryStore()
	q := mana.NewQuoter(store)
	seedWallet(t, store, "g", 100)
	store.AddAllocation("g", &mana.Allocation{
		AllocationID: "alloc-1", RemainingUnits: 50, AllocatedAt: time.Now().UTC(),
	})

	res, err := q.DeductMana(context.Background(), mana.DeductInput{
		Gcid: "g", ActionCode: "x", Units: 120, IdempotencyKey: "dk-split",
	})
	if err != nil {
		t.Fatalf("DeductMana: %v", err)
	}
	if len(res.Entries) != 2 {
		t.Fatalf("entries = %d; want 2 (subsidy 50 + personal 70)", len(res.Entries))
	}
	if res.Entries[0].Units != 50 || res.Entries[0].SourceAllocationID != "alloc-1" {
		t.Errorf("first entry = %+v; want 50-unit subsidy entry", res.Entries[0])
	}
	if res.Entries[1].Units != 70 || res.Entries[1].SourceAllocationID != "" {
		t.Errorf("second entry = %+v; want 70-unit personal entry", res.Entries[1])
	}
	if res.BalanceAfterUnits != 30 {
		t.Errorf("balance = %d; want 30", res.BalanceAfterUnits)
	}
}

func TestQuoter_DeductMana_ValidationErrors(t *testing.T) {
	t.Parallel()
	store := mana.NewInMemoryStore()
	q := mana.NewQuoter(store)
	ctx := context.Background()

	if _, err := q.DeductMana(ctx, mana.DeductInput{Gcid: "  ", Units: 5, IdempotencyKey: "k"}); err == nil {
		t.Error("expected error for blank gcid")
	}
	if _, err := q.DeductMana(ctx, mana.DeductInput{Gcid: "g", Units: 5, IdempotencyKey: ""}); err == nil {
		t.Error("expected error for empty idempotency key")
	}
}

func TestQuoter_DeductMana_ResolverCostZeroIsFree(t *testing.T) {
	t.Parallel()
	store := mana.NewInMemoryStore()
	q := mana.NewQuoter(store, mana.WithPriceResolver(zeroResolver{}))
	seedWallet(t, store, "g", 100)

	res, err := q.DeductMana(context.Background(), mana.DeductInput{
		Gcid: "g", ActionCode: "free_of_cost", Units: 0, IdempotencyKey: "dk-zero",
	})
	if err != nil {
		t.Fatalf("DeductMana: %v", err)
	}
	if len(res.Entries) != 0 || res.BalanceAfterUnits != 100 {
		t.Errorf("entries=%d balance=%d; want no-op at 100", len(res.Entries), res.BalanceAfterUnits)
	}
}

type zeroResolver struct{}

func (zeroResolver) Resolve(_ context.Context, _ mana.ResolveInput) (mana.Resolved, error) {
	return mana.Resolved{}, nil
}

// -----------------------------------------------------------------------------
// DeductMana — resolveCost error branches
// -----------------------------------------------------------------------------

func TestQuoter_DeductMana_EmptyActionCode_UnitsZero(t *testing.T) {
	t.Parallel()
	store := mana.NewInMemoryStore()
	q := mana.NewQuoter(store, mana.WithPricer(zeroPricer()))
	_, err := q.DeductMana(context.Background(), mana.DeductInput{
		Gcid: "g", ActionCode: "   ", Units: 0, IdempotencyKey: "k-empty",
	})
	if !mana.IsUnknownActionCode(err) {
		t.Errorf("err = %v; want ErrUnknownActionCode", err)
	}
}

func TestQuoter_DeductMana_NegativeCatalogueCost(t *testing.T) {
	t.Parallel()
	store := mana.NewInMemoryStore()
	neg := pricerFunc(func(_ context.Context, _ string) (int64, error) { return -4, nil })
	q := mana.NewQuoter(store, mana.WithPricer(neg))
	_, err := q.DeductMana(context.Background(), mana.DeductInput{
		Gcid: "g", ActionCode: "neg_action", Units: 0, IdempotencyKey: "k-neg",
	})
	if err == nil || !strings.Contains(err.Error(), "negative") {
		t.Errorf("err = %v; want negative-catalogue-cost error", err)
	}
}

// -----------------------------------------------------------------------------
// DeductMana / quote / zeroCostResult — store error branches
// -----------------------------------------------------------------------------

func TestQuoter_DeductMana_StoreErrors(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	run := func(name string, inject func(*faultStore), input func() mana.DeductInput) {
		t.Run(name, func(t *testing.T) {
			store := newFaultStore()
			inject(store)
			store.AddAllocation("g", &mana.Allocation{AllocationID: "a1", RemainingUnits: 50, AllocatedAt: time.Now().UTC()})
			q := mana.NewQuoter(store, mana.WithPricer(pricerFunc(func(_ context.Context, _ string) (int64, error) { return 10, nil })))
			if _, err := q.DeductMana(ctx, input()); err == nil {
				t.Errorf("expected store error, got nil")
			}
		})
	}

	base := func() mana.DeductInput {
		return mana.DeductInput{Gcid: "g", ActionCode: "action", Units: 10, IdempotencyKey: "k-err"}
	}

	run("get mana", func(s *faultStore) { s.getManaErr = errors.New("get mana down") }, func() mana.DeductInput {
		return mana.DeductInput{Gcid: "g", Units: 10, IdempotencyKey: "k-err"}
	})
	run("list allocations", func(s *faultStore) { s.listAlloc = errors.New("list alloc down") }, base)
	run("update allocation", func(s *faultStore) { s.updateAlloc = errors.New("update alloc down") }, base)
	run("append ledger", func(s *faultStore) { s.appendLed = errors.New("append down") }, base)
	run("save mana", func(s *faultStore) { s.saveManaErr = errors.New("save down") }, func() mana.DeductInput {
		return mana.DeductInput{Gcid: "g", Units: 10, IdempotencyKey: "k-err"}
	})
}

func TestQuoter_DeductMana_IdempotencyLookupErrorIgnored(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	// DeductMana deliberately swallows FindLedgerByIdempotencyKey errors (a
	// failed lookup must not block the debit). Verify the debit still lands.
	store := newFaultStore()
	store.findKeyErr = errors.New("find key down")
	seedWallet(t, store.InMemoryStore, "g", 100)
	q := mana.NewQuoter(store)
	res, err := q.DeductMana(ctx, mana.DeductInput{
		Gcid: "g", Units: 10, IdempotencyKey: "k-err",
	})
	if err != nil {
		t.Fatalf("DeductMana: %v", err)
	}
	if len(res.Entries) != 1 || res.Entries[0].Units != 10 {
		t.Errorf("entries = %+v; want a single 10-unit entry", res.Entries)
	}
}

func TestQuoter_DryRun_StoreErrors(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	in := mana.DeductInput{Gcid: "g", Units: 10, IdempotencyKey: "k-dry", DryRun: true}

	// GetMana error propagates.
	store := newFaultStore()
	store.getManaErr = errors.New("get down")
	q := mana.NewQuoter(store)
	if _, err := q.DeductMana(ctx, in); err == nil {
		t.Error("expected GetMana error on dry-run")
	}

	// ListAllocations error propagates.
	store2 := newFaultStore()
	store2.listAlloc = errors.New("alloc down")
	q2 := mana.NewQuoter(store2)
	if _, err := q2.DeductMana(ctx, in); err == nil {
		t.Error("expected ListAllocations error on dry-run")
	}

	// Dry-run on an empty wallet (mana==nil) reports 0 available → shortfall.
	store3 := mana.NewInMemoryStore()
	q3 := mana.NewQuoter(store3)
	_, err := q3.DeductMana(ctx, in)
	var ibe *mana.InsufficientBalanceError
	if !errors.As(err, &ibe) {
		t.Fatalf("err = %v; want *InsufficientBalanceError", err)
	}
	if ibe.RequiredUnits != 10 || ibe.AvailableUnits != 0 {
		t.Errorf("required/available = %d/%d; want 10/0", ibe.RequiredUnits, ibe.AvailableUnits)
	}
}

func TestQuoter_FreeAction_StoreErrors(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	// GetMana error inside zeroCostResult.
	store := newFaultStore()
	store.getManaErr = errors.New("get down")
	q := mana.NewQuoter(store, mana.WithPricer(zeroPricer()))
	if _, err := q.DeductMana(ctx, mana.DeductInput{
		Gcid: "g", ActionCode: "free", Units: 0, IdempotencyKey: "k-f1",
	}); err == nil {
		t.Error("expected GetMana error on free action")
	}

	// ListAllocations error inside zeroCostResult.
	store2 := newFaultStore()
	store2.listAlloc = errors.New("alloc down")
	q2 := mana.NewQuoter(store2, mana.WithPricer(zeroPricer()))
	if _, err := q2.DeductMana(ctx, mana.DeductInput{
		Gcid: "g", ActionCode: "free", Units: 0, IdempotencyKey: "k-f2",
	}); err == nil {
		t.Error("expected ListAllocations error on free action")
	}

	// Free action on an empty wallet → balance 0 reported.
	store3 := mana.NewInMemoryStore()
	q3 := mana.NewQuoter(store3, mana.WithPricer(zeroPricer()))
	res, err := q3.DeductMana(ctx, mana.DeductInput{
		Gcid: "g", ActionCode: "free", Units: 0, IdempotencyKey: "k-f3",
	})
	if err != nil {
		t.Fatalf("free action: %v", err)
	}
	if res.BalanceAfterUnits != 0 {
		t.Errorf("balance = %d; want 0", res.BalanceAfterUnits)
	}
}

// -----------------------------------------------------------------------------
// CreditMana — validation + store error branches
// -----------------------------------------------------------------------------

func TestQuoter_CreditMana_ValidationErrors(t *testing.T) {
	t.Parallel()
	store := mana.NewInMemoryStore()
	q := mana.NewQuoter(store)
	ctx := context.Background()

	if _, err := q.CreditMana(ctx, mana.CreditInput{Gcid: "", Source: mana.SourceTopup, Units: 5, Reason: mana.ReasonTopup, IdempotencyKey: "k"}); err == nil {
		t.Error("expected error for blank gcid")
	}
	if _, err := q.CreditMana(ctx, mana.CreditInput{Gcid: "g", Source: mana.SourceTopup, Units: 0, Reason: mana.ReasonTopup, IdempotencyKey: "k"}); err == nil {
		t.Error("expected error for zero units")
	}
	if _, err := q.CreditMana(ctx, mana.CreditInput{Gcid: "g", Source: mana.Source("dragon"), Units: 5, Reason: mana.ReasonTopup, IdempotencyKey: "k"}); err == nil {
		t.Error("expected error for invalid source")
	}
	if _, err := q.CreditMana(ctx, mana.CreditInput{Gcid: "g", Source: mana.SourceTopup, Units: 5, Reason: mana.Reason("magic"), IdempotencyKey: "k"}); err == nil {
		t.Error("expected error for invalid reason")
	}
	if _, err := q.CreditMana(ctx, mana.CreditInput{Gcid: "g", Source: mana.SourceTopup, Units: 5, Reason: mana.ReasonTopup, IdempotencyKey: " "}); err == nil {
		t.Error("expected error for empty idempotency key")
	}
}

func TestQuoter_CreditMana_StoreErrors(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	// GetMana error.
	store := newFaultStore()
	store.getManaErr = errors.New("get down")
	q := mana.NewQuoter(store)
	if _, err := q.CreditMana(ctx, mana.CreditInput{Gcid: "g", Source: mana.SourceTopup, Units: 5, Reason: mana.ReasonTopup, IdempotencyKey: "k"}); err == nil {
		t.Error("expected GetMana error on credit")
	}

	// SaveAllocation error (subsidy path).
	store2 := newFaultStore()
	store2.saveAlloc = errors.New("save alloc down")
	q2 := mana.NewQuoter(store2)
	if _, err := q2.CreditMana(ctx, mana.CreditInput{
		Gcid: "g", Source: mana.SourceTenantSubsidy, Units: 50,
		Reason: mana.ReasonTenantSubsidy, IdempotencyKey: "k-subsidy",
		TenantID: "t", SourceAllocationID: "alloc-explicit",
	}); err == nil {
		t.Error("expected SaveAllocation error on subsidy credit")
	}

	// SaveMana error (personal path).
	store3 := newFaultStore()
	store3.saveManaErr = errors.New("save mana down")
	q3 := mana.NewQuoter(store3)
	if _, err := q3.CreditMana(ctx, mana.CreditInput{Gcid: "g", Source: mana.SourceTopup, Units: 5, Reason: mana.ReasonTopup, IdempotencyKey: "k"}); err == nil {
		t.Error("expected SaveMana error on credit")
	}

	// AppendLedger error.
	store4 := newFaultStore()
	store4.appendLed = errors.New("append down")
	q4 := mana.NewQuoter(store4)
	if _, err := q4.CreditMana(ctx, mana.CreditInput{Gcid: "g", Source: mana.SourceTopup, Units: 5, Reason: mana.ReasonTopup, IdempotencyKey: "k"}); err == nil {
		t.Error("expected AppendLedger error on credit")
	}
}

func TestQuoter_CreditMana_ExplicitAllocationID_NoMint(t *testing.T) {
	t.Parallel()
	store := mana.NewInMemoryStore()
	q := mana.NewQuoter(store)
	ctx := context.Background()

	_, err := q.CreditMana(ctx, mana.CreditInput{
		Gcid: "g", Source: mana.SourceTenantSubsidy, Units: 50,
		Reason: mana.ReasonTenantSubsidy, IdempotencyKey: "k-expl",
		TenantID: "t", SourceAllocationID: "alloc-known",
	})
	if err != nil {
		t.Fatalf("CreditMana: %v", err)
	}
	allocs, _ := store.ListAllocations(ctx, "g")
	if len(allocs) != 1 || allocs[0].AllocationID != "alloc-known" {
		t.Errorf("allocs = %+v; want the explicit allocation_id", allocs)
	}
}

// -----------------------------------------------------------------------------
// Breakdown — edge branches + store errors
// -----------------------------------------------------------------------------

func TestQuoter_Breakdown_EdgeBranches(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	// Blank gcid → validation error.
	store := mana.NewInMemoryStore()
	q := mana.NewQuoter(store)
	if _, _, err := q.Breakdown(ctx, "  "); err == nil {
		t.Error("expected error for blank gcid")
	}

	// Zero-remaining allocation is skipped; personal balance slice emitted.
	store.AddAllocation("g", &mana.Allocation{AllocationID: "empty", RemainingUnits: 0, AllocatedAt: time.Now().UTC()})
	store.AddAllocation("g", &mana.Allocation{AllocationID: "live", RemainingUnits: 25, AllocatedAt: time.Now().UTC()})
	seedWallet(t, store, "g", 40)

	bal, slices, err := q.Breakdown(ctx, "g")
	if err != nil {
		t.Fatalf("Breakdown: %v", err)
	}
	if bal != 65 {
		t.Errorf("balance = %d; want 65", bal)
	}
	if len(slices) != 2 {
		t.Fatalf("slices = %d; want 2 (subsidy + personal)", len(slices))
	}
	if slices[0].Source != mana.SourceTenantSubsidy || slices[0].Units != 25 {
		t.Errorf("slice[0] = %+v; want tenant_subsidy 25", slices[0])
	}
	if slices[1].Source != mana.SourcePersonal || slices[1].Units != 40 {
		t.Errorf("slice[1] = %+v; want personal 40", slices[1])
	}
}

func TestQuoter_Breakdown_StoreErrors(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	store := newFaultStore()
	store.getManaErr = errors.New("get down")
	q := mana.NewQuoter(store)
	if _, _, err := q.Breakdown(ctx, "g"); err == nil {
		t.Error("expected GetMana error on breakdown")
	}

	store2 := newFaultStore()
	store2.listAlloc = errors.New("alloc down")
	q2 := mana.NewQuoter(store2)
	if _, _, err := q2.Breakdown(ctx, "g"); err == nil {
		t.Error("expected ListAllocations error on breakdown")
	}
}

// -----------------------------------------------------------------------------
// InMemoryStore — ListLedger time/type filters, bad cursor; FindLedger
// empty-key; DecodeLedgerCursor malformed inputs
// -----------------------------------------------------------------------------

func TestInMemoryStore_ListLedger_TimeFiltersAndBadCursor(t *testing.T) {
	t.Parallel()
	store := mana.NewInMemoryStore()
	ctx := context.Background()
	base := time.Date(2026, 6, 26, 12, 0, 0, 0, time.UTC)
	_ = store.AppendLedger(ctx, seedEntryLocal("e1", "g", base))
	_ = store.AppendLedger(ctx, seedEntryLocal("e2", "g", base.Add(time.Hour)))

	from := base.Add(30 * time.Minute)
	rows, err := store.ListLedger(ctx, mana.LedgerFilter{Gcid: "g", From: &from})
	if err != nil {
		t.Fatalf("From filter: %v", err)
	}
	if len(rows) != 1 || rows[0].EntryID != "e2" {
		t.Errorf("From filter rows = %+v; want [e2]", rows)
	}

	to := base.Add(30 * time.Minute)
	rows, err = store.ListLedger(ctx, mana.LedgerFilter{Gcid: "g", To: &to})
	if err != nil {
		t.Fatalf("To filter: %v", err)
	}
	if len(rows) != 1 || rows[0].EntryID != "e1" {
		t.Errorf("To filter rows = %+v; want [e1]", rows)
	}

	// Malformed cursor → ErrInvalidFilter surfaces from ListLedger.
	bad := "!!!not-base64!!!"
	if _, err := store.ListLedger(ctx, mana.LedgerFilter{Gcid: "g", Cursor: bad}); !errors.Is(err, mana.ErrInvalidFilter) {
		t.Errorf("bad-cursor err = %v; want ErrInvalidFilter", err)
	}

	// ListLedger error branch via fault store.
	fs := newFaultStore()
	fs.listLedErr = errors.New("list down")
	if _, err := fs.ListLedger(ctx, mana.LedgerFilter{Gcid: "g"}); err == nil {
		t.Error("expected ListLedger store error")
	}
}

func seedEntryLocal(id, gcid string, at time.Time) *mana.LedgerEntry {
	return &mana.LedgerEntry{
		EntryID: id, Gcid: gcid, Direction: mana.DirectionDebit, Units: 10,
		Reason: mana.ReasonFamiliarAction, RecordedAt: at,
	}
}

func TestInMemoryStore_FindLedgerByIdempotencyKey(t *testing.T) {
	t.Parallel()
	store := mana.NewInMemoryStore()
	ctx := context.Background()

	// Empty key short-circuits to (nil, nil).
	rows, err := store.FindLedgerByIdempotencyKey(ctx, "g", "")
	if err != nil || rows != nil {
		t.Errorf("empty key = (%v, %v); want (nil, nil)", rows, err)
	}

	// No match → empty non-nil slice.
	rows, err = store.FindLedgerByIdempotencyKey(ctx, "g", "missing-key")
	if err != nil || len(rows) != 0 {
		t.Errorf("no match = (%v, %v); want ([], nil)", rows, err)
	}
}

func TestDecodeLedgerCursor_MalformedParts(t *testing.T) {
	t.Parallel()

	cases := map[string]string{
		"base64-garbage": "!!!not-base64!!!",
		"no-pipe":        "bm9waXBl",                // base64("nopipe")
		"empty-id":       "cGlwZXw=",                // base64("pipe|")
		"bad-timestamp":  base64url("not-a-time|x"), // valid base64, bad time
	}
	for name, cur := range cases {
		if _, _, err := mana.DecodeLedgerCursor(cur); !errors.Is(err, mana.ErrInvalidFilter) {
			t.Errorf("[%s] err = %v; want ErrInvalidFilter", name, err)
		}
	}
}

func base64url(s string) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	b := []byte(s)
	out := make([]byte, 0, 4*((len(b)+2)/3))
	for i := 0; i < len(b); i += 3 {
		var chunk [3]byte
		n := copy(chunk[:], b[i:])
		out = append(out, alphabet[chunk[0]>>2])
		out = append(out, alphabet[((chunk[0]&0x03)<<4)|(chunk[1]>>4)])
		if n > 1 {
			out = append(out, alphabet[((chunk[1]&0x0f)<<2)|(chunk[2]>>6)])
		}
		if n > 2 {
			out = append(out, alphabet[chunk[2]&0x3f])
		}
	}
	return string(out)
}

// -----------------------------------------------------------------------------
// Second wave — FIFO comparator branches, loop skips, replay-subsidy loop,
// resolver failure, quote/zeroCost with allocations, ListLedger filters
// -----------------------------------------------------------------------------

func TestQuoter_DeductMana_FifoComparatorAndLoopSkips(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := mana.NewInMemoryStore()
	q := mana.NewQuoter(store)
	base := time.Now().UTC()

	// Allocations in insertion order deliberately NOT sorted:
	//   z0 expired-soon but 0 remaining (continue branch)
	//   p1 expires later (partial take + break after it drains)
	//   p2/p3 nil expiry, differing AllocatedAt (tie-break + nil-vs-exp sort)
	store.AddAllocation("g", &mana.Allocation{AllocationID: "z0", RemainingUnits: 0, ExpiresAt: ptrTime(base.Add(1 * time.Hour)), AllocatedAt: base})
	store.AddAllocation("g", &mana.Allocation{AllocationID: "p1", RemainingUnits: 5, ExpiresAt: ptrTime(base.Add(2 * time.Hour)), AllocatedAt: base})
	store.AddAllocation("g", &mana.Allocation{AllocationID: "p2", RemainingUnits: 5, AllocatedAt: base.Add(1 * time.Minute)})
	store.AddAllocation("g", &mana.Allocation{AllocationID: "p3", RemainingUnits: 5, AllocatedAt: base})

	res, err := q.DeductMana(ctx, mana.DeductInput{
		Gcid: "g", ActionCode: "x", Units: 10, IdempotencyKey: "dk-fifo",
	})
	if err != nil {
		t.Fatalf("DeductMana: %v", err)
	}
	// z0 skipped, p1 (5), then p3 (earlier AllocatedAt among nil-expiry) (5).
	if len(res.Entries) != 2 {
		t.Fatalf("entries = %d; want 2 (p1 + p3), got %+v", len(res.Entries), res.Entries)
	}
	if res.Entries[0].SourceAllocationID != "p1" || res.Entries[1].SourceAllocationID != "p3" {
		t.Errorf("FIFO order wrong: %+v", res.Entries)
	}
	if res.BalanceAfterUnits != 5 {
		t.Errorf("balance = %d; want 5 (p2 remains untouched)", res.BalanceAfterUnits)
	}
}

func ptrTime(t time.Time) *time.Time { return &t }

func TestQuoter_DeductMana_PersonalAppendLedgerError(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := newFaultStore()
	store.appendLed = errors.New("append down")
	seedWallet(t, store.InMemoryStore, "g", 100)
	q := mana.NewQuoter(store)

	if _, err := q.DeductMana(ctx, mana.DeductInput{
		Gcid: "g", Units: 10, IdempotencyKey: "k-pers-app",
	}); err == nil {
		t.Error("expected AppendLedger error on personal-balance drain")
	}
}

func TestQuoter_DeductMana_ResolverErrorSurfaces(t *testing.T) {
	t.Parallel()
	store := mana.NewInMemoryStore()
	seedWallet(t, store, "g", 100)
	resolver := &fakeResolver{err: errors.New("plan resolver down")}
	q := mana.NewQuoter(store, mana.WithPriceResolver(resolver))

	_, err := q.DeductMana(context.Background(), mana.DeductInput{
		Gcid: "g", ActionCode: "any", Units: 0, IdempotencyKey: "k-res-err",
	})
	if err == nil || err.Error() != "plan resolver down" {
		t.Errorf("err = %v; want the resolver error", err)
	}
}

func TestQuoter_DryRun_WithAllocations_ReportsTotals(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := mana.NewInMemoryStore()
	seedWallet(t, store, "g", 100)
	store.AddAllocation("g", &mana.Allocation{AllocationID: "a1", RemainingUnits: 10, AllocatedAt: time.Now().UTC()})
	q := mana.NewQuoter(store)

	res, err := q.DeductMana(ctx, mana.DeductInput{
		Gcid: "g", Units: 5, IdempotencyKey: "k-dr-alloc", DryRun: true,
	})
	if err != nil {
		t.Fatalf("dry-run: %v", err)
	}
	if res.BalanceAfterUnits != 110 {
		t.Errorf("dry-run balance = %d; want 110 (wallet + subsidy)", res.BalanceAfterUnits)
	}
	if len(res.Entries) != 0 {
		t.Errorf("dry-run wrote %d entries; want 0", len(res.Entries))
	}
}

func TestQuoter_FreeAction_WithAllocations_ReportsSubsidy(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := mana.NewInMemoryStore()
	store.AddAllocation("g", &mana.Allocation{AllocationID: "a1", RemainingUnits: 10, AllocatedAt: time.Now().UTC()})
	q := mana.NewQuoter(store, mana.WithPricer(zeroPricer()))

	res, err := q.DeductMana(ctx, mana.DeductInput{
		Gcid: "g", ActionCode: "free", Units: 0, IdempotencyKey: "k-free-alloc",
	})
	if err != nil {
		t.Fatalf("free action: %v", err)
	}
	if res.BalanceAfterUnits != 10 {
		t.Errorf("balance = %d; want 10 (subsidy total reported)", res.BalanceAfterUnits)
	}
}

func TestQuoter_CreditMana_Replay_WithSubsidy(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := mana.NewInMemoryStore()
	q := mana.NewQuoter(store)

	in := mana.CreditInput{
		Gcid: "g", Source: mana.SourceTenantSubsidy, Units: 50,
		Reason: mana.ReasonTenantSubsidy, IdempotencyKey: "ck-replay-subsidy",
		TenantID: "t-1", SourceAllocationID: "alloc-replay",
	}
	if _, err := q.CreditMana(ctx, in); err != nil {
		t.Fatalf("first credit: %v", err)
	}
	replay, err := q.CreditMana(ctx, in)
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if !replay.Replayed {
		t.Error("expected replay")
	}
	if replay.BalanceAfterUnits != 50 {
		t.Errorf("replay balance = %d; want 50 (subsidy summed exactly once)", replay.BalanceAfterUnits)
	}
	if got, _ := store.GetMana(ctx, "g"); got.LifetimeEarned != 50 {
		t.Errorf("lifetime_earned = %d; want 50 (no double-subsidy)", got.LifetimeEarned)
	}
}

func TestQuoter_Breakdown_ComparatorMix(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := mana.NewInMemoryStore()
	base := time.Now().UTC()
	store.AddAllocation("g", &mana.Allocation{AllocationID: "nil-late", RemainingUnits: 5, AllocatedAt: base.Add(2 * time.Minute)})
	store.AddAllocation("g", &mana.Allocation{AllocationID: "exp-far", RemainingUnits: 5, ExpiresAt: ptrTime(base.Add(2 * time.Hour)), AllocatedAt: base})
	store.AddAllocation("g", &mana.Allocation{AllocationID: "exp-soon", RemainingUnits: 5, ExpiresAt: ptrTime(base.Add(1 * time.Hour)), AllocatedAt: base})
	store.AddAllocation("g", &mana.Allocation{AllocationID: "nil-early", RemainingUnits: 5, AllocatedAt: base})

	q := mana.NewQuoter(store)
	_, slices, err := q.Breakdown(ctx, "g")
	if err != nil {
		t.Fatalf("Breakdown: %v", err)
	}
	if len(slices) != 4 {
		t.Fatalf("slices = %d; want 4", len(slices))
	}
	want := []string{"exp-soon", "exp-far", "nil-early", "nil-late"}
	for i, id := range want {
		if slices[i].SourceAllocationID != id {
			t.Errorf("slice[%d] = %s; want %s (full order %v)",
				i, slices[i].SourceAllocationID, id, want)
		}
	}
}

func TestInMemoryStore_ListLedger_GcidAndDirectionMismatch(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := mana.NewInMemoryStore()
	_ = store.AppendLedger(ctx, &mana.LedgerEntry{
		EntryID: "e1", Gcid: "g1", Direction: mana.DirectionDebit, Units: 10,
		Reason: mana.ReasonFamiliarAction, RecordedAt: time.Now().UTC(),
	})

	// Gcid filter mismatch → every row skipped.
	rows, err := store.ListLedger(ctx, mana.LedgerFilter{Gcid: "g2"})
	if err != nil {
		t.Fatalf("ListLedger(g2): %v", err)
	}
	if len(rows) != 0 {
		t.Errorf("gcid-mismatch rows = %d; want 0", len(rows))
	}

	// Direction filter mismatch → every row skipped.
	dir := mana.DirectionCredit
	rows, err = store.ListLedger(ctx, mana.LedgerFilter{Gcid: "g1", Direction: &dir})
	if err != nil {
		t.Fatalf("ListLedger(direction): %v", err)
	}
	if len(rows) != 0 {
		t.Errorf("direction-mismatch rows = %d; want 0", len(rows))
	}
}

// TestQuoter_DeductMana_FifoComparator_ExpBeforeNilInsertion — insertion-sort
// compares arr[2] (expires) against arr[1] (nil expiry), exercising the
// `ai.ExpiresAt != nil && aj.ExpiresAt == nil` comparator orientation.
func TestQuoter_DeductMana_FifoComparator_ExpBeforeNilInsertion(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := mana.NewInMemoryStore()
	base := time.Now().UTC()
	// Insertion order [exp, nil, exp] — raw slice order matters pre-sort.
	store.AddAllocation("g", &mana.Allocation{AllocationID: "exp-a", RemainingUnits: 5, ExpiresAt: ptrTime(base.Add(1 * time.Hour)), AllocatedAt: base})
	store.AddAllocation("g", &mana.Allocation{AllocationID: "nil-b", RemainingUnits: 5, AllocatedAt: base})
	store.AddAllocation("g", &mana.Allocation{AllocationID: "exp-c", RemainingUnits: 5, ExpiresAt: ptrTime(base.Add(2 * time.Hour)), AllocatedAt: base})

	q := mana.NewQuoter(store)
	res, err := q.DeductMana(ctx, mana.DeductInput{
		Gcid: "g", Units: 15, IdempotencyKey: "dk-exp-nil-exp",
	})
	if err != nil {
		t.Fatalf("DeductMana: %v", err)
	}
	if len(res.Entries) != 3 {
		t.Fatalf("entries = %d; want 3", len(res.Entries))
	}
	// Sorted: exp-a (1h), exp-c (2h), then nil-b.
	if res.Entries[0].SourceAllocationID != "exp-a" || res.Entries[1].SourceAllocationID != "exp-c" || res.Entries[2].SourceAllocationID != "nil-b" {
		t.Errorf("FIFO order = %+v", res.Entries)
	}
}
