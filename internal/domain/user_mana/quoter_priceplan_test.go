package user_mana_test

import (
	"context"
	"testing"

	mana "github.com/apollo-chora/chora-identity/internal/domain/user_mana"
)

// fakeResolver is a test double for the richer PriceResolver port (ADR-178
// price-plan rules layer). It records the resolution key it was called with so
// a test can assert tenant_id / tier / context were threaded through, and
// returns a canned Resolved.
type fakeResolver struct {
	out   mana.Resolved
	err   error
	calls []mana.ResolveInput
}

func (f *fakeResolver) Resolve(_ context.Context, in mana.ResolveInput) (mana.Resolved, error) {
	f.calls = append(f.calls, in)
	if f.err != nil {
		return mana.Resolved{}, f.err
	}
	return f.out, nil
}

// FU-4(b) — a units==0 debit with a PriceResolver wired resolves
// TENANT/TIER/CONTEXT-aware (the legacy Pricer shim dropped tenant_id, so
// tenant overrides were silently ignored). This is the cutover that makes the
// H+ price-plan layer actually govern qgen authoring prices.
func TestQuoter_DeductMana_ResolverThreadsTenantTierContext(t *testing.T) {
	t.Parallel()
	store := mana.NewInMemoryStore()
	seedWallet(t, store, "g", 100)
	res := &fakeResolver{out: mana.Resolved{Units: 10, Refundable: true, PerItem: false, Source: "tenant_override"}}
	q := mana.NewQuoter(store, mana.WithPriceResolver(res))

	got, err := q.DeductMana(context.Background(), mana.DeductInput{
		Gcid:           "g",
		ActionCode:     "question_authoring_ai_draft",
		Units:          0,
		IdempotencyKey: "k1",
		TenantID:       "11111111-1111-7111-8111-111111111111",
		Tier:           "high",
		Context:        map[string]string{"foo": "bar"},
	})
	if err != nil {
		t.Fatalf("DeductMana: %v", err)
	}
	if len(res.calls) != 1 {
		t.Fatalf("resolver consulted %d times, want 1", len(res.calls))
	}
	in := res.calls[0]
	if in.ActionCode != "question_authoring_ai_draft" {
		t.Errorf("action_code = %q, want question_authoring_ai_draft", in.ActionCode)
	}
	if in.TenantID != "11111111-1111-7111-8111-111111111111" {
		t.Errorf("tenant_id = %q — NOT threaded (tenant overrides would be ignored)", in.TenantID)
	}
	if in.Tier != "high" {
		t.Errorf("tier = %q, want high (forward-compat axis)", in.Tier)
	}
	if in.Context["foo"] != "bar" {
		t.Errorf("context not threaded: %+v", in.Context)
	}
	if got.BalanceAfterUnits != 90 {
		t.Errorf("balance after = %d, want 90 (100 - resolved 10)", got.BalanceAfterUnits)
	}
	// Resolved metadata is surfaced for the caller (gRPC response → meter home
	// decides refund-on-failure / per-item multiply).
	if !got.Refundable || got.PriceSource != "tenant_override" {
		t.Errorf("metadata not surfaced: refundable=%v price_source=%q", got.Refundable, got.PriceSource)
	}
}

// FU-4(b) — a per_item action multiplies the resolved per-unit cost by
// context.item_count server-side (ADR-178 §5.3 resolved: RPC-side multiply via
// the context map). Batch authoring (question_authoring_batch_per_item = 5×N)
// is the sole per_item action.
func TestQuoter_DeductMana_PerItemMultipliesByItemCount(t *testing.T) {
	t.Parallel()
	store := mana.NewInMemoryStore()
	seedWallet(t, store, "g", 100)
	res := &fakeResolver{out: mana.Resolved{Units: 5, PerItem: true, Refundable: true, Source: "plan_default"}}
	q := mana.NewQuoter(store, mana.WithPriceResolver(res))

	got, err := q.DeductMana(context.Background(), mana.DeductInput{
		Gcid:           "g",
		ActionCode:     "question_authoring_batch_per_item",
		Units:          0,
		IdempotencyKey: "k2",
		Context:        map[string]string{"item_count": "7"},
	})
	if err != nil {
		t.Fatalf("DeductMana: %v", err)
	}
	if got.BalanceAfterUnits != 65 {
		t.Errorf("balance after = %d, want 65 (100 - 5×7)", got.BalanceAfterUnits)
	}
	if len(got.Entries) != 1 || got.Entries[0].Units != 35 {
		t.Fatalf("expected 1 ledger entry of 35 units (5×7), got %+v", got.Entries)
	}
	if !got.PerItem {
		t.Errorf("PerItem flag not surfaced on result")
	}
}

// FU-4(b) — a per_item action with no item_count in context charges exactly one
// unit (×1), never zero (a missing/garbage count must not zero the charge).
func TestQuoter_DeductMana_PerItemDefaultsToOne(t *testing.T) {
	t.Parallel()
	store := mana.NewInMemoryStore()
	seedWallet(t, store, "g", 100)
	res := &fakeResolver{out: mana.Resolved{Units: 5, PerItem: true}}
	q := mana.NewQuoter(store, mana.WithPriceResolver(res))

	got, err := q.DeductMana(context.Background(), mana.DeductInput{
		Gcid: "g", ActionCode: "question_authoring_batch_per_item", Units: 0,
		IdempotencyKey: "k3", Context: map[string]string{"item_count": "not-a-number"},
	})
	if err != nil {
		t.Fatalf("DeductMana: %v", err)
	}
	if got.BalanceAfterUnits != 95 {
		t.Errorf("balance after = %d, want 95 (5×1 fallback on bad item_count)", got.BalanceAfterUnits)
	}
}

// FU-4(b) — an explicit Units>0 debit bypasses the resolver entirely (legacy
// caller-priced debit sites + tests keep working unchanged).
func TestQuoter_DeductMana_ExplicitUnitsBypassesResolver(t *testing.T) {
	t.Parallel()
	store := mana.NewInMemoryStore()
	seedWallet(t, store, "g", 100)
	res := &fakeResolver{out: mana.Resolved{Units: 5}}
	q := mana.NewQuoter(store, mana.WithPriceResolver(res))

	got, err := q.DeductMana(context.Background(), mana.DeductInput{
		Gcid: "g", ActionCode: "question_authoring_ai_draft", Units: 30, IdempotencyKey: "k4",
	})
	if err != nil {
		t.Fatalf("DeductMana: %v", err)
	}
	if len(res.calls) != 0 {
		t.Errorf("resolver consulted %d times on explicit-units debit, want 0", len(res.calls))
	}
	if got.BalanceAfterUnits != 70 {
		t.Errorf("balance after = %d, want 70 (explicit 30, not resolved 5)", got.BalanceAfterUnits)
	}
}

// FU-4(b) — when BOTH a resolver and a legacy Pricer are wired, the resolver
// wins (it is the richer, tenant-aware path).
func TestQuoter_DeductMana_ResolverPreferredOverPricer(t *testing.T) {
	t.Parallel()
	store := mana.NewInMemoryStore()
	seedWallet(t, store, "g", 100)
	res := &fakeResolver{out: mana.Resolved{Units: 7}}
	pricer := &fakePricer{prices: map[string]int64{"question_authoring_ai_draft": 99}}
	q := mana.NewQuoter(store, mana.WithPricer(pricer), mana.WithPriceResolver(res))

	got, err := q.DeductMana(context.Background(), mana.DeductInput{
		Gcid: "g", ActionCode: "question_authoring_ai_draft", Units: 0, IdempotencyKey: "k5",
	})
	if err != nil {
		t.Fatalf("DeductMana: %v", err)
	}
	if got.BalanceAfterUnits != 93 {
		t.Errorf("balance after = %d, want 93 (resolver 7 wins over pricer 99)", got.BalanceAfterUnits)
	}
	if len(pricer.calls) != 0 {
		t.Errorf("pricer consulted %d times, want 0 (resolver preferred)", len(pricer.calls))
	}
}

// FU-4(b) — a dry-run through the resolver checks affordability + surfaces the
// resolved metadata WITHOUT writing a ledger row.
func TestQuoter_DeductMana_ResolverDryRunSurfacesMetadata(t *testing.T) {
	t.Parallel()
	store := mana.NewInMemoryStore()
	seedWallet(t, store, "g", 100)
	res := &fakeResolver{out: mana.Resolved{Units: 10, Refundable: true, PerItem: false, Source: "plan_default"}}
	q := mana.NewQuoter(store, mana.WithPriceResolver(res))

	got, err := q.DeductMana(context.Background(), mana.DeductInput{
		Gcid: "g", ActionCode: "question_authoring_ai_draft", Units: 0,
		IdempotencyKey: "k6", DryRun: true,
	})
	if err != nil {
		t.Fatalf("DeductMana dry-run: %v", err)
	}
	if len(got.Entries) != 0 {
		t.Errorf("dry-run wrote %d ledger entries, want 0", len(got.Entries))
	}
	if !got.Refundable || got.PriceSource != "plan_default" {
		t.Errorf("dry-run metadata not surfaced: refundable=%v source=%q", got.Refundable, got.PriceSource)
	}
	if m, _ := store.GetMana(context.Background(), "g"); m.BalanceUnits != 100 {
		t.Errorf("balance mutated to %d on dry-run, want 100", m.BalanceUnits)
	}
}
