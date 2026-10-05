package user_mana_test

import (
	"context"
	"errors"
	"testing"

	mana "github.com/apollo-chora/chora-identity/internal/domain/user_mana"
)

// fakePricePlanStore is a hand-rolled PricePlanStore double. It records the
// last ResolveInput and returns a canned Resolved (or error). The precedence
// ladder itself is resolved in the SQL adapter (Appendix A.2); this double
// lets the pure-domain PricePlanResolver be tested in isolation.
type fakePricePlanStore struct {
	got    mana.ResolveInput
	out    mana.Resolved
	err    error
	called int
}

func (f *fakePricePlanStore) ResolvePrice(_ context.Context, in mana.ResolveInput) (mana.Resolved, error) {
	f.called++
	f.got = in
	if f.err != nil {
		return mana.Resolved{}, f.err
	}
	return f.out, nil
}

// CHO-1661 §7.1 — tenant override wins: the resolver returns whatever the
// store's precedence query chose, surfacing Units + Source verbatim.
func TestPricePlanResolver_TenantOverrideWins(t *testing.T) {
	t.Parallel()
	store := &fakePricePlanStore{out: mana.Resolved{
		Units: 12, Source: "tenant_override", Refundable: true, MeterHome: "creation",
	}}
	r := mana.NewPricePlanResolver(store)

	got, err := r.Resolve(context.Background(), mana.ResolveInput{
		ActionCode: "question_authoring_ai_draft", TenantID: "tenant-1",
	})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got.Units != 12 {
		t.Errorf("Units = %d, want 12", got.Units)
	}
	if got.Source != "tenant_override" {
		t.Errorf("Source = %q, want tenant_override", got.Source)
	}
	if !got.Refundable {
		t.Errorf("Refundable = false, want true")
	}
	// The resolver forwards the typed input to the store unchanged.
	if store.got.ActionCode != "question_authoring_ai_draft" || store.got.TenantID != "tenant-1" {
		t.Errorf("store got %+v, want action+tenant forwarded", store.got)
	}
}

// CHO-1661 §7.1 — plan default when no override: the store returns plan_default.
func TestPricePlanResolver_PlanDefaultWhenNoOverride(t *testing.T) {
	t.Parallel()
	store := &fakePricePlanStore{out: mana.Resolved{Units: 10, Source: "plan_default"}}
	r := mana.NewPricePlanResolver(store)

	got, err := r.Resolve(context.Background(), mana.ResolveInput{ActionCode: "question_authoring_ai_draft"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got.Units != 10 || got.Source != "plan_default" {
		t.Errorf("got {%d,%q}, want {10,plan_default}", got.Units, got.Source)
	}
}

// CHO-1661 §7.1 — catalogue fallback when no plan rule exists.
func TestPricePlanResolver_CatalogueFallback(t *testing.T) {
	t.Parallel()
	store := &fakePricePlanStore{out: mana.Resolved{Units: 50, Source: "catalogue_fallback"}}
	r := mana.NewPricePlanResolver(store)

	got, err := r.Resolve(context.Background(), mana.ResolveInput{ActionCode: "question_generation"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got.Units != 50 || got.Source != "catalogue_fallback" {
		t.Errorf("got {%d,%q}, want {50,catalogue_fallback}", got.Units, got.Source)
	}
}

// CHO-1661 §7.1 — unknown action anywhere ⇒ ErrUnknownActionCode (the gRPC
// adapter maps it to InvalidArgument, same as the legacy Pricer).
func TestPricePlanResolver_UnknownActionErrors(t *testing.T) {
	t.Parallel()
	store := &fakePricePlanStore{err: mana.ErrUnknownActionCode}
	r := mana.NewPricePlanResolver(store)

	_, err := r.Resolve(context.Background(), mana.ResolveInput{ActionCode: "does_not_exist"})
	if !errors.Is(err, mana.ErrUnknownActionCode) {
		t.Fatalf("err = %v, want ErrUnknownActionCode", err)
	}
}

// CHO-1661 §7.1 — empty action_code is rejected without consulting the store.
func TestPricePlanResolver_EmptyActionCode(t *testing.T) {
	t.Parallel()
	store := &fakePricePlanStore{}
	r := mana.NewPricePlanResolver(store)

	_, err := r.Resolve(context.Background(), mana.ResolveInput{ActionCode: "   "})
	if !errors.Is(err, mana.ErrUnknownActionCode) {
		t.Fatalf("err = %v, want ErrUnknownActionCode", err)
	}
	if store.called != 0 {
		t.Errorf("store consulted %d times on empty code, want 0", store.called)
	}
}

// CHO-1661 §7.1 — zero cost is a valid free action, NOT an error.
func TestPricePlanResolver_ZeroCostIsFree(t *testing.T) {
	t.Parallel()
	store := &fakePricePlanStore{out: mana.Resolved{Units: 0, Source: "plan_default"}}
	r := mana.NewPricePlanResolver(store)

	got, err := r.Resolve(context.Background(), mana.ResolveInput{ActionCode: "summon_familiar"})
	if err != nil {
		t.Fatalf("Resolve: %v (cost 0 is a free action, not an error)", err)
	}
	if got.Units != 0 {
		t.Errorf("Units = %d, want 0", got.Units)
	}
}

// CHO-1661 §7.1 — a negative resolved cost is a domain invariant violation
// (a price can never be < 0), surfaced as a hard error.
func TestPricePlanResolver_NegativeCostErrors(t *testing.T) {
	t.Parallel()
	store := &fakePricePlanStore{out: mana.Resolved{Units: -5, Source: "plan_default"}}
	r := mana.NewPricePlanResolver(store)

	_, err := r.Resolve(context.Background(), mana.ResolveInput{ActionCode: "boss_challenge_atom_gen"})
	if err == nil {
		t.Fatalf("expected error for negative resolved cost")
	}
}

// CHO-1661 §7.2 — refundable + per_item flags ride through from the action def.
func TestPricePlanResolver_RefundableAndPerItemFlags(t *testing.T) {
	t.Parallel()
	store := &fakePricePlanStore{out: mana.Resolved{
		Units: 5, Refundable: true, PerItem: true, Source: "plan_default",
	}}
	r := mana.NewPricePlanResolver(store)

	got, err := r.Resolve(context.Background(), mana.ResolveInput{ActionCode: "question_authoring_batch_per_item"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if !got.Refundable || !got.PerItem {
		t.Errorf("Refundable/PerItem = %v/%v, want true/true", got.Refundable, got.PerItem)
	}
	// Per-item cost is NOT pre-multiplied — the caller multiplies by item_count.
	if got.Units != 5 {
		t.Errorf("Units = %d, want 5 (per-unit, NOT pre-multiplied)", got.Units)
	}
}

// CHO-1661 §7.2 — EffectiveTotal is a caller-side helper: per-unit × N.
func TestResolved_EffectiveTotal(t *testing.T) {
	t.Parallel()
	perItem := mana.Resolved{Units: 5, PerItem: true}
	if got := perItem.EffectiveTotal(7); got != 35 {
		t.Errorf("EffectiveTotal(7) = %d, want 35 (5×7)", got)
	}
	// A non-per-item action ignores the count.
	upfront := mana.Resolved{Units: 50, PerItem: false}
	if got := upfront.EffectiveTotal(7); got != 50 {
		t.Errorf("EffectiveTotal(7) on non-per-item = %d, want 50 (count ignored)", got)
	}
	// item_count <= 0 is coerced to 1 for a per-item action (defensive).
	if got := perItem.EffectiveTotal(0); got != 5 {
		t.Errorf("EffectiveTotal(0) = %d, want 5 (count coerced to 1)", got)
	}
}

// CHO-1661 §7.3 — the tier axis is forwarded to the store verbatim (selection
// happens in SQL; the domain resolver is tier-agnostic about *which* rule wins).
func TestPricePlanResolver_TierForwarded(t *testing.T) {
	t.Parallel()
	store := &fakePricePlanStore{out: mana.Resolved{Units: 20, Tier: "high", Source: "plan_default"}}
	r := mana.NewPricePlanResolver(store)

	got, err := r.Resolve(context.Background(), mana.ResolveInput{ActionCode: "atom_authoring_assist", Tier: "high"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if store.got.Tier != "high" {
		t.Errorf("store got tier %q, want high", store.got.Tier)
	}
	if got.Tier != "high" || got.Units != 20 {
		t.Errorf("got {%d,%q}, want {20,high}", got.Units, got.Tier)
	}
}

// CHO-1661 §7.6 — the CostForAction shim makes PricePlanResolver a drop-in
// Pricer: tenant/tier-agnostic, returns just Units.
func TestPricePlanResolver_CostForActionShim(t *testing.T) {
	t.Parallel()
	store := &fakePricePlanStore{out: mana.Resolved{Units: 25, Source: "plan_default"}}
	r := mana.NewPricePlanResolver(store)

	cost, err := r.CostForAction(context.Background(), "atom_authoring_assist")
	if err != nil {
		t.Fatalf("CostForAction: %v", err)
	}
	if cost != 25 {
		t.Errorf("cost = %d, want 25", cost)
	}
	// The shim resolves tenant/tier-agnostic.
	if store.got.TenantID != "" || store.got.Tier != "" {
		t.Errorf("shim sent tenant/tier %q/%q, want both empty", store.got.TenantID, store.got.Tier)
	}
}

// CHO-1661 — compile-time guarantee: PricePlanResolver satisfies the legacy
// Pricer port so the Quoter can consume it unchanged.
func TestPricePlanResolver_SatisfiesPricer(t *testing.T) {
	t.Parallel()
	var _ mana.Pricer = mana.NewPricePlanResolver(&fakePricePlanStore{})
}

// CHO-1661 §7.6 — the CostForAction shim propagates a store error (it must not
// swallow ErrUnknownActionCode into a silent zero cost).
func TestPricePlanResolver_CostForActionShim_PropagatesError(t *testing.T) {
	t.Parallel()
	store := &fakePricePlanStore{err: mana.ErrUnknownActionCode}
	r := mana.NewPricePlanResolver(store)

	cost, err := r.CostForAction(context.Background(), "does_not_exist")
	if !errors.Is(err, mana.ErrUnknownActionCode) {
		t.Fatalf("err = %v, want ErrUnknownActionCode", err)
	}
	if cost != 0 {
		t.Errorf("cost = %d on error, want 0", cost)
	}
}

// CHO-1661 — a resolver with no store configured fails loud (a price resolution
// must never be a silent free pass).
func TestPricePlanResolver_NilStore(t *testing.T) {
	t.Parallel()
	r := mana.NewPricePlanResolver(nil)
	_, err := r.Resolve(context.Background(), mana.ResolveInput{ActionCode: "atom_authoring_assist"})
	if err == nil {
		t.Fatalf("expected error when resolver has no store")
	}
}
