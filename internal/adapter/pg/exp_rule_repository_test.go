package pg

import (
	"context"
	"errors"
	"strings"
	"testing"

	exprules "github.com/apollo-chora/chora-identity/internal/domain/exp_rules"
)

// expRuleStubTenantTxr records the tenant scope RunInTenantTx was invoked with
// + drives fn against a stub Tx. It satisfies TxQuerier. (Reuses the package's
// manaStubTx / manaStubRow row doubles.)
type expRuleStubTenantTxr struct {
	gotTenant string
	called    int
	tx        *manaStubTx
}

func (s *expRuleStubTenantTxr) RunInTenantTx(ctx context.Context, tenantID string, fn func(context.Context, Tx) error) error {
	s.called++
	s.gotTenant = tenantID
	return fn(ctx, s.tx)
}

// expPlanRow scripts a precedence-query row in scan order:
// exp_value, daily_cap, eligibility, enabled, src.
func expPlanRow(found bool, val int64, cap int32, elig, src string, enabled bool) func(dest ...any) error {
	return func(dest ...any) error {
		if !found {
			return ErrNoRows
		}
		if p, ok := dest[0].(*int64); ok {
			*p = val
		}
		if p, ok := dest[1].(*int32); ok {
			*p = cap
		}
		if p, ok := dest[2].(*string); ok {
			*p = elig
		}
		if p, ok := dest[3].(*bool); ok {
			*p = enabled
		}
		if p, ok := dest[4].(*string); ok {
			*p = src
		}
		return nil
	}
}

// expCatalogueRow scripts a catalogue-fallback row in scan order:
// default_exp_value, default_daily_cap, enabled.
func expCatalogueRow(val int64, cap int32, enabled bool) func(dest ...any) error {
	return func(dest ...any) error {
		if p, ok := dest[0].(*int64); ok {
			*p = val
		}
		if p, ok := dest[1].(*int32); ok {
			*p = cap
		}
		if p, ok := dest[2].(*bool); ok {
			*p = enabled
		}
		return nil
	}
}

// ADR-201 §5 — when a plan rule exists, ResolveExpRule returns it WITHOUT
// hitting the catalogue, and runs inside a tenant-scoped tx.
func TestExpRuleStore_ResolveExpRule_PlanRuleWins(t *testing.T) {
	tx := &manaStubTx{queryRow: func(sql string, _ ...any) Row {
		// The first (and only) QueryRow is the precedence query → found.
		return manaStubRow{scan: expPlanRow(true, 5, 50, "growth_stage>=4", "tenant", true)}
	}}
	txr := &expRuleStubTenantTxr{tx: tx}
	store := NewExpRuleStore(txr)

	got, err := store.ResolveExpRule(context.Background(), exprules.ExpResolveInput{
		SourceCode: "atom_correct", TenantID: "11111111-1111-1111-1111-111111111111",
	})
	if err != nil {
		t.Fatalf("ResolveExpRule: %v", err)
	}
	if got.ExpValue != 5 || got.Source != "tenant" {
		t.Errorf("got {%d,%q}, want {5,tenant}", got.ExpValue, got.Source)
	}
	if got.DailyCap != 50 || got.Eligibility != "growth_stage>=4" || !got.Enabled {
		t.Errorf("fields = {%d,%q,%v}, want {50,growth_stage>=4,true}", got.DailyCap, got.Eligibility, got.Enabled)
	}
	if got.SourceCode != "atom_correct" {
		t.Errorf("SourceCode = %q, want atom_correct", got.SourceCode)
	}
	if txr.gotTenant != "11111111-1111-1111-1111-111111111111" {
		t.Errorf("tenant scope = %q, want the input tenant", txr.gotTenant)
	}
}

// ADR-201 §5 / behaviour-neutral rollout — when NO plan rule exists,
// ResolveExpRule falls through to the exp_source_def catalogue default
// (Source=catalogue, Eligibility="").
func TestExpRuleStore_ResolveExpRule_CatalogueFallback(t *testing.T) {
	calls := 0
	tx := &manaStubTx{queryRow: func(sql string, _ ...any) Row {
		calls++
		if calls == 1 {
			// precedence query → miss
			return manaStubRow{scan: func(...any) error { return ErrNoRows }}
		}
		// catalogue fallback → found at 2000, uncapped, enabled
		return manaStubRow{scan: expCatalogueRow(2000, 0, true)}
	}}
	store := NewExpRuleStore(&expRuleStubTenantTxr{tx: tx})

	got, err := store.ResolveExpRule(context.Background(), exprules.ExpResolveInput{SourceCode: "certification_issued"})
	if err != nil {
		t.Fatalf("ResolveExpRule: %v", err)
	}
	if got.ExpValue != 2000 || got.Source != "catalogue" {
		t.Errorf("got {%d,%q}, want {2000,catalogue}", got.ExpValue, got.Source)
	}
	if got.Eligibility != "" {
		t.Errorf("Eligibility = %q, want \"\" (catalogue default is always-eligible)", got.Eligibility)
	}
	if calls != 2 {
		t.Errorf("queries = %d, want 2 (precedence miss → catalogue)", calls)
	}
}

// ADR-203 L16 — unknown everywhere (absent from exp_source_def, so no plan rule
// could exist) ⇒ ErrUnknownSource.
func TestExpRuleStore_ResolveExpRule_UnknownSource(t *testing.T) {
	tx := &manaStubTx{queryRow: func(string, ...any) Row {
		return manaStubRow{scan: func(...any) error { return ErrNoRows }}
	}}
	store := NewExpRuleStore(&expRuleStubTenantTxr{tx: tx})

	_, err := store.ResolveExpRule(context.Background(), exprules.ExpResolveInput{SourceCode: "i_passed_the_real_pmp"})
	if !errors.Is(err, exprules.ErrUnknownSource) {
		t.Fatalf("err = %v, want ErrUnknownSource", err)
	}
}

// ADR-201 §5 — empty source_code is rejected before any query.
func TestExpRuleStore_ResolveExpRule_EmptyCode(t *testing.T) {
	queried := false
	tx := &manaStubTx{queryRow: func(string, ...any) Row {
		queried = true
		return manaStubRow{scan: func(...any) error { return ErrNoRows }}
	}}
	store := NewExpRuleStore(&expRuleStubTenantTxr{tx: tx})

	_, err := store.ResolveExpRule(context.Background(), exprules.ExpResolveInput{SourceCode: "  "})
	if !errors.Is(err, exprules.ErrUnknownSource) {
		t.Fatalf("err = %v, want ErrUnknownSource", err)
	}
	if queried {
		t.Errorf("query ran on empty code, want none")
	}
}

// ADR-201 §5 — the precedence query carries the source_code + tenant params;
// the catalogue fallback carries the source_code.
func TestExpRuleStore_ResolveExpRule_PassesParams(t *testing.T) {
	var precedenceArgs []any
	tx := &manaStubTx{queryRow: func(sql string, args ...any) Row {
		if strings.Contains(sql, "exp_rule") && strings.Contains(sql, "exp_rule_plan") {
			precedenceArgs = args
			return manaStubRow{scan: expPlanRow(true, 10, 0, "", "plan", true)}
		}
		return manaStubRow{scan: func(...any) error { return ErrNoRows }}
	}}
	store := NewExpRuleStore(&expRuleStubTenantTxr{tx: tx})

	_, err := store.ResolveExpRule(context.Background(), exprules.ExpResolveInput{
		SourceCode: "daily_dose_completed", TenantID: "11111111-1111-1111-1111-111111111111",
	})
	if err != nil {
		t.Fatalf("ResolveExpRule: %v", err)
	}
	want := map[string]bool{"daily_dose_completed": false, "11111111-1111-1111-1111-111111111111": false}
	for _, a := range precedenceArgs {
		if s, ok := a.(string); ok {
			if _, tracked := want[s]; tracked {
				want[s] = true
			}
		}
	}
	for k, seen := range want {
		if !seen {
			t.Errorf("precedence query missing param %q (args=%v)", k, precedenceArgs)
		}
	}
}

// ADR-201 §5 — an empty tenant resolves against the platform plan + catalogue
// only; the tx opens with the zero-uuid sentinel scope (so SET LOCAL is
// well-formed and only scope='platform' rows can match).
func TestExpRuleStore_ResolveExpRule_EmptyTenantUsesZeroUUIDScope(t *testing.T) {
	tx := &manaStubTx{queryRow: func(string, ...any) Row {
		return manaStubRow{scan: expCatalogueRow(3, 30, true)}
	}}
	txr := &expRuleStubTenantTxr{tx: tx}
	store := NewExpRuleStore(txr)

	// Force the catalogue path (precedence miss) by scripting the first query as
	// a miss and the second as the catalogue hit.
	calls := 0
	tx.queryRow = func(string, ...any) Row {
		calls++
		if calls == 1 {
			return manaStubRow{scan: func(...any) error { return ErrNoRows }}
		}
		return manaStubRow{scan: expCatalogueRow(3, 30, true)}
	}

	_, err := store.ResolveExpRule(context.Background(), exprules.ExpResolveInput{SourceCode: "atom_correct"})
	if err != nil {
		t.Fatalf("ResolveExpRule: %v", err)
	}
	if txr.gotTenant != zeroUUID {
		t.Errorf("empty-tenant tx scope = %q, want zeroUUID sentinel %q", txr.gotTenant, zeroUUID)
	}
}

// ExpRuleStore is a drop-in ExpRuleStore for the domain resolver.
func TestExpRuleStore_SatisfiesPort(t *testing.T) {
	var _ exprules.ExpRuleStore = NewExpRuleStore(&expRuleStubTenantTxr{tx: &manaStubTx{}})
}

// A nil TxQuerier fails loud (mis-wiring guard).
func TestExpRuleStore_NilTxr(t *testing.T) {
	store := NewExpRuleStore(nil)
	_, err := store.ResolveExpRule(context.Background(), exprules.ExpResolveInput{SourceCode: "atom_correct"})
	if err == nil {
		t.Fatalf("expected error for nil TxQuerier")
	}
}

// ADR-201 §5 — a DB fault on the precedence query is wrapped (NOT swallowed into
// a silent miss).
func TestExpRuleStore_ResolveExpRule_PrecedenceDBError(t *testing.T) {
	boom := errors.New("connection reset")
	tx := &manaStubTx{queryRow: func(string, ...any) Row {
		return manaStubRow{scan: func(...any) error { return boom }}
	}}
	store := NewExpRuleStore(&expRuleStubTenantTxr{tx: tx})

	_, err := store.ResolveExpRule(context.Background(), exprules.ExpResolveInput{SourceCode: "atom_correct"})
	if err == nil || errors.Is(err, exprules.ErrUnknownSource) {
		t.Fatalf("err = %v, want a wrapped DB error (not unknown-source / nil)", err)
	}
	if !strings.Contains(err.Error(), "precedence") {
		t.Errorf("err = %v, want it to mention the precedence query", err)
	}
}

// ADR-201 §5 — a DB fault on the catalogue fallback query is wrapped.
func TestExpRuleStore_ResolveExpRule_CatalogueDBError(t *testing.T) {
	boom := errors.New("disk i/o error")
	calls := 0
	tx := &manaStubTx{queryRow: func(string, ...any) Row {
		calls++
		if calls == 1 {
			return manaStubRow{scan: func(...any) error { return ErrNoRows }} // precedence miss
		}
		return manaStubRow{scan: func(...any) error { return boom }} // catalogue fault
	}}
	store := NewExpRuleStore(&expRuleStubTenantTxr{tx: tx})

	_, err := store.ResolveExpRule(context.Background(), exprules.ExpResolveInput{SourceCode: "atom_correct"})
	if err == nil || errors.Is(err, exprules.ErrUnknownSource) {
		t.Fatalf("err = %v, want a wrapped DB error", err)
	}
	if !strings.Contains(err.Error(), "catalogue") {
		t.Errorf("err = %v, want it to mention the catalogue query", err)
	}
}
