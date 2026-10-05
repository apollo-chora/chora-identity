package exp_rules_test

import (
	"context"
	"errors"
	"testing"

	exprules "github.com/apollo-chora/chora-identity/internal/domain/exp_rules"
)

// fakeExpRuleStore is a hand-rolled ExpRuleStore double. It records the last
// ExpResolveInput and returns a canned ResolvedExpRule (or error). The
// precedence ladder itself (tenant > plan > catalogue) is resolved in the SQL
// adapter; this double lets the pure-domain ExpRuleResolver be tested in
// isolation. Mirrors fakePricePlanStore (ADR-178 / CHO-1661).
type fakeExpRuleStore struct {
	got    exprules.ExpResolveInput
	out    exprules.ResolvedExpRule
	err    error
	called int
}

func (f *fakeExpRuleStore) ResolveExpRule(_ context.Context, in exprules.ExpResolveInput) (exprules.ResolvedExpRule, error) {
	f.called++
	f.got = in
	if f.err != nil {
		return exprules.ResolvedExpRule{}, f.err
	}
	return f.out, nil
}

// ADR-201 §5 — tenant override wins: the resolver returns whatever the store's
// precedence query chose, surfacing the value + Source verbatim.
func TestExpRuleResolver_TenantOverrideWins(t *testing.T) {
	t.Parallel()
	store := &fakeExpRuleStore{out: exprules.ResolvedExpRule{
		SourceCode: "atom_correct", ExpValue: 5, DailyCap: 50, Enabled: true, Source: "tenant",
	}}
	r := exprules.NewExpRuleResolver(store)

	got, err := r.Resolve(context.Background(), exprules.ExpResolveInput{
		SourceCode: "atom_correct", TenantID: "tenant-1",
	})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got.ExpValue != 5 {
		t.Errorf("ExpValue = %d, want 5", got.ExpValue)
	}
	if got.Source != "tenant" {
		t.Errorf("Source = %q, want tenant", got.Source)
	}
	if got.DailyCap != 50 {
		t.Errorf("DailyCap = %d, want 50", got.DailyCap)
	}
	// The resolver forwards the typed input to the store unchanged.
	if store.got.SourceCode != "atom_correct" || store.got.TenantID != "tenant-1" {
		t.Errorf("store got %+v, want source+tenant forwarded", store.got)
	}
}

// ADR-201 §5 — platform plan default when no tenant override (Source=plan).
func TestExpRuleResolver_PlanDefaultWhenNoOverride(t *testing.T) {
	t.Parallel()
	store := &fakeExpRuleStore{out: exprules.ResolvedExpRule{ExpValue: 3, Enabled: true, Source: "plan"}}
	r := exprules.NewExpRuleResolver(store)

	got, err := r.Resolve(context.Background(), exprules.ExpResolveInput{SourceCode: "atom_correct"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got.ExpValue != 3 || got.Source != "plan" {
		t.Errorf("got {%d,%q}, want {3,plan}", got.ExpValue, got.Source)
	}
}

// ADR-201 §5 — catalogue default when no plan rule exists (behaviour-neutral
// rollout: with no plan rows, Resolve returns the exp_source_def default).
func TestExpRuleResolver_CatalogueFallback(t *testing.T) {
	t.Parallel()
	store := &fakeExpRuleStore{out: exprules.ResolvedExpRule{
		SourceCode: "certification_issued", ExpValue: 2000, Enabled: true, Source: "catalogue",
	}}
	r := exprules.NewExpRuleResolver(store)

	got, err := r.Resolve(context.Background(), exprules.ExpResolveInput{SourceCode: "certification_issued"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got.ExpValue != 2000 || got.Source != "catalogue" {
		t.Errorf("got {%d,%q}, want {2000,catalogue}", got.ExpValue, got.Source)
	}
}

// ADR-203 L16 invariant — an unknown source (absent from exp_source_def) is
// rejected with ErrUnknownSource. Overrides can only adjust KNOWN verified
// sources; the resolver can never mint a new (self-declare) source.
func TestExpRuleResolver_UnknownSourceErrors(t *testing.T) {
	t.Parallel()
	store := &fakeExpRuleStore{err: exprules.ErrUnknownSource}
	r := exprules.NewExpRuleResolver(store)

	_, err := r.Resolve(context.Background(), exprules.ExpResolveInput{SourceCode: "i_passed_the_real_pmp"})
	if !errors.Is(err, exprules.ErrUnknownSource) {
		t.Fatalf("err = %v, want ErrUnknownSource", err)
	}
	if !exprules.IsUnknownSource(err) {
		t.Errorf("IsUnknownSource = false, want true")
	}
}

// ADR-201 §5 — empty source_code is rejected without consulting the store.
func TestExpRuleResolver_EmptySourceCode(t *testing.T) {
	t.Parallel()
	store := &fakeExpRuleStore{}
	r := exprules.NewExpRuleResolver(store)

	_, err := r.Resolve(context.Background(), exprules.ExpResolveInput{SourceCode: "   "})
	if !errors.Is(err, exprules.ErrUnknownSource) {
		t.Fatalf("err = %v, want ErrUnknownSource", err)
	}
	if store.called != 0 {
		t.Errorf("store consulted %d times on empty code, want 0", store.called)
	}
}

// ADR-201 §5 — a zero EXP value is valid (a source tuned to 0), NOT an error.
func TestExpRuleResolver_ZeroExpIsValid(t *testing.T) {
	t.Parallel()
	store := &fakeExpRuleStore{out: exprules.ResolvedExpRule{ExpValue: 0, Enabled: true, Source: "plan"}}
	r := exprules.NewExpRuleResolver(store)

	got, err := r.Resolve(context.Background(), exprules.ExpResolveInput{SourceCode: "post_shared"})
	if err != nil {
		t.Fatalf("Resolve: %v (0 EXP is valid, not an error)", err)
	}
	if got.ExpValue != 0 {
		t.Errorf("ExpValue = %d, want 0", got.ExpValue)
	}
}

// ADR-201 §5 — a negative resolved EXP is a domain invariant violation
// (EXP can never be < 0), surfaced as a hard error.
func TestExpRuleResolver_NegativeExpErrors(t *testing.T) {
	t.Parallel()
	store := &fakeExpRuleStore{out: exprules.ResolvedExpRule{ExpValue: -5, Source: "plan"}}
	r := exprules.NewExpRuleResolver(store)

	_, err := r.Resolve(context.Background(), exprules.ExpResolveInput{SourceCode: "duel_won"})
	if err == nil {
		t.Fatalf("expected error for negative resolved EXP")
	}
}

// ADR-201 §5 — a negative resolved daily_cap is a domain invariant violation.
func TestExpRuleResolver_NegativeDailyCapErrors(t *testing.T) {
	t.Parallel()
	store := &fakeExpRuleStore{out: exprules.ResolvedExpRule{ExpValue: 3, DailyCap: -1, Source: "plan"}}
	r := exprules.NewExpRuleResolver(store)

	_, err := r.Resolve(context.Background(), exprules.ExpResolveInput{SourceCode: "atom_correct"})
	if err == nil {
		t.Fatalf("expected error for negative resolved daily_cap")
	}
}

// §12 EXP-editor "enabled" knob — a disabled source resolves successfully with
// Enabled=false (the caller skips the award); it is NOT an error.
func TestExpRuleResolver_DisabledSourcePassesThrough(t *testing.T) {
	t.Parallel()
	store := &fakeExpRuleStore{out: exprules.ResolvedExpRule{ExpValue: 30, Enabled: false, Source: "tenant"}}
	r := exprules.NewExpRuleResolver(store)

	got, err := r.Resolve(context.Background(), exprules.ExpResolveInput{SourceCode: "atom_authored", TenantID: "tenant-1"})
	if err != nil {
		t.Fatalf("Resolve: %v (disabled is a valid resolved state, not an error)", err)
	}
	if got.Enabled {
		t.Errorf("Enabled = true, want false (source disabled by tenant override)")
	}
}

// §12 EXP-editor "eligibility" knob — the eligibility hint + daily cap ride
// through from the resolved rule verbatim.
func TestExpRuleResolver_EligibilityAndCapRideThrough(t *testing.T) {
	t.Parallel()
	store := &fakeExpRuleStore{out: exprules.ResolvedExpRule{
		ExpValue: 4, DailyCap: 40, Eligibility: "growth_stage>=4", Enabled: true, Source: "plan",
	}}
	r := exprules.NewExpRuleResolver(store)

	got, err := r.Resolve(context.Background(), exprules.ExpResolveInput{SourceCode: "kg_hexagon_expanded"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got.Eligibility != "growth_stage>=4" {
		t.Errorf("Eligibility = %q, want growth_stage>=4", got.Eligibility)
	}
	if got.DailyCap != 40 {
		t.Errorf("DailyCap = %d, want 40", got.DailyCap)
	}
}

// ADR-201 §5 — the tenant + plan selectors are forwarded to the store verbatim
// (selection happens in SQL; the domain resolver is agnostic about which rung
// wins). Plan is the reserved forward-compat selector.
func TestExpRuleResolver_InputForwarded(t *testing.T) {
	t.Parallel()
	store := &fakeExpRuleStore{out: exprules.ResolvedExpRule{ExpValue: 10, Source: "plan"}}
	r := exprules.NewExpRuleResolver(store)

	_, err := r.Resolve(context.Background(), exprules.ExpResolveInput{
		SourceCode: "daily_dose_completed", TenantID: "tenant-9", Plan: "pro",
	})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if store.got.TenantID != "tenant-9" || store.got.Plan != "pro" {
		t.Errorf("store got tenant/plan %q/%q, want tenant-9/pro", store.got.TenantID, store.got.Plan)
	}
}

// ADR-201 — a resolver with no store configured fails loud (an EXP resolution
// must never be a silent zero-award pass).
func TestExpRuleResolver_NilStore(t *testing.T) {
	t.Parallel()
	r := exprules.NewExpRuleResolver(nil)
	_, err := r.Resolve(context.Background(), exprules.ExpResolveInput{SourceCode: "atom_correct"})
	if err == nil {
		t.Fatalf("expected error when resolver has no store")
	}
}
