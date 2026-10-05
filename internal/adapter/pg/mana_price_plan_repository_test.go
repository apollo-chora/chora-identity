package pg

import (
	"context"
	"errors"
	"strings"
	"testing"

	mana "github.com/apollo-chora/chora-identity/internal/domain/user_mana"
)

// pricePlanStubTenantTxr records the tenant scope RunInTenantTx was invoked
// with + drives fn against a stub Tx. It satisfies TxQuerier.
type pricePlanStubTenantTxr struct {
	gotTenant string
	called    int
	tx        *manaStubTx
}

func (s *pricePlanStubTenantTxr) RunInTenantTx(ctx context.Context, tenantID string, fn func(context.Context, Tx) error) error {
	s.called++
	s.gotTenant = tenantID
	return fn(ctx, s.tx)
}

// queryRowSeq returns a Tx whose QueryRow yields scripted rows in order. Each
// element either sets dest (found) or returns ErrNoRows (miss) — modelling the
// resolver's "try plan rules → fall through to catalogue" two-step.
func planRow(found bool, cost int64, src string) func(dest ...any) error {
	return func(dest ...any) error {
		if !found {
			return ErrNoRows
		}
		// ResolvePrice scans: mana_cost, src, tier, refundable, per_item, meter_home
		if p, ok := dest[0].(*int64); ok {
			*p = cost
		}
		if p, ok := dest[1].(*string); ok {
			*p = src
		}
		if p, ok := dest[2].(*string); ok {
			*p = "" // tier
		}
		if p, ok := dest[3].(*bool); ok {
			*p = true // refundable
		}
		if p, ok := dest[4].(*bool); ok {
			*p = false // per_item
		}
		if p, ok := dest[5].(*string); ok {
			*p = "creation" // meter_home
		}
		return nil
	}
}

func catalogueRow(cost int64) func(dest ...any) error {
	return func(dest ...any) error {
		// Catalogue fallback scans just mana_cost.
		if p, ok := dest[0].(*int64); ok {
			*p = cost
		}
		return nil
	}
}

// CHO-1661 §7.4 — when a plan rule exists, ResolvePrice returns it without
// hitting the catalogue, and runs inside a tenant-scoped tx.
func TestManaPricePlanStore_ResolvePrice_PlanRuleWins(t *testing.T) {
	tx := &manaStubTx{queryRow: func(sql string, _ ...any) Row {
		// The first (and only) QueryRow is the precedence query → found.
		return manaStubRow{scan: planRow(true, 12, "tenant_override")}
	}}
	txr := &pricePlanStubTenantTxr{tx: tx}
	store := NewManaPricePlanStore(txr)

	got, err := store.ResolvePrice(context.Background(), mana.ResolveInput{
		ActionCode: "question_authoring_ai_draft", TenantID: "11111111-1111-1111-1111-111111111111",
	})
	if err != nil {
		t.Fatalf("ResolvePrice: %v", err)
	}
	if got.Units != 12 || got.Source != "tenant_override" {
		t.Errorf("got {%d,%q}, want {12,tenant_override}", got.Units, got.Source)
	}
	if !got.Refundable || got.MeterHome != "creation" {
		t.Errorf("flags = {%v,%q}, want {true,creation}", got.Refundable, got.MeterHome)
	}
	if txr.gotTenant != "11111111-1111-1111-1111-111111111111" {
		t.Errorf("tenant scope = %q, want the input tenant", txr.gotTenant)
	}
}

// CHO-1661 §7.4 — when NO plan rule exists, ResolvePrice falls through to the
// UNCHANGED mana_action_pricing catalogue floor (Source=catalogue_fallback).
func TestManaPricePlanStore_ResolvePrice_CatalogueFallback(t *testing.T) {
	calls := 0
	tx := &manaStubTx{queryRow: func(sql string, _ ...any) Row {
		calls++
		if calls == 1 {
			// precedence query → miss
			return manaStubRow{scan: func(...any) error { return ErrNoRows }}
		}
		// catalogue fallback → found at 50
		return manaStubRow{scan: catalogueRow(50)}
	}}
	store := NewManaPricePlanStore(&pricePlanStubTenantTxr{tx: tx})

	got, err := store.ResolvePrice(context.Background(), mana.ResolveInput{ActionCode: "question_generation"})
	if err != nil {
		t.Fatalf("ResolvePrice: %v", err)
	}
	if got.Units != 50 || got.Source != "catalogue_fallback" {
		t.Errorf("got {%d,%q}, want {50,catalogue_fallback}", got.Units, got.Source)
	}
	if calls != 2 {
		t.Errorf("queries = %d, want 2 (precedence miss → catalogue)", calls)
	}
}

// CHO-1661 §7.4 — unknown everywhere (no plan rule AND no catalogue row) ⇒
// ErrUnknownActionCode.
func TestManaPricePlanStore_ResolvePrice_UnknownActionCode(t *testing.T) {
	tx := &manaStubTx{queryRow: func(string, ...any) Row {
		return manaStubRow{scan: func(...any) error { return ErrNoRows }}
	}}
	store := NewManaPricePlanStore(&pricePlanStubTenantTxr{tx: tx})

	_, err := store.ResolvePrice(context.Background(), mana.ResolveInput{ActionCode: "does_not_exist"})
	if !errors.Is(err, mana.ErrUnknownActionCode) {
		t.Fatalf("err = %v, want ErrUnknownActionCode", err)
	}
}

// CHO-1661 §7.4 — empty action_code is rejected before any query.
func TestManaPricePlanStore_ResolvePrice_EmptyCode(t *testing.T) {
	queried := false
	tx := &manaStubTx{queryRow: func(string, ...any) Row {
		queried = true
		return manaStubRow{scan: func(...any) error { return ErrNoRows }}
	}}
	store := NewManaPricePlanStore(&pricePlanStubTenantTxr{tx: tx})

	_, err := store.ResolvePrice(context.Background(), mana.ResolveInput{ActionCode: "  "})
	if !errors.Is(err, mana.ErrUnknownActionCode) {
		t.Fatalf("err = %v, want ErrUnknownActionCode", err)
	}
	if queried {
		t.Errorf("query ran on empty code, want none")
	}
}

// CHO-1661 §7.4 — the precedence query carries the action_code + tier params,
// and the catalogue fallback carries the action_code.
func TestManaPricePlanStore_ResolvePrice_PassesParams(t *testing.T) {
	var precedenceArgs []any
	tx := &manaStubTx{queryRow: func(sql string, args ...any) Row {
		if strings.Contains(sql, "mana_price_rule") {
			precedenceArgs = args
			return manaStubRow{scan: planRow(true, 20, "plan_default")}
		}
		return manaStubRow{scan: func(...any) error { return ErrNoRows }}
	}}
	store := NewManaPricePlanStore(&pricePlanStubTenantTxr{tx: tx})

	_, err := store.ResolvePrice(context.Background(), mana.ResolveInput{
		ActionCode: "atom_authoring_assist", TenantID: "11111111-1111-1111-1111-111111111111", Tier: "high",
	})
	if err != nil {
		t.Fatalf("ResolvePrice: %v", err)
	}
	// args contain action_code + tenant + tier (order is the adapter's choice;
	// assert all three present).
	want := map[string]bool{"atom_authoring_assist": false, "11111111-1111-1111-1111-111111111111": false, "high": false}
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

// CHO-1661 — ManaPricePlanStore is a drop-in PricePlanStore for the domain
// resolver.
func TestManaPricePlanStore_SatisfiesPort(t *testing.T) {
	var _ mana.PricePlanStore = NewManaPricePlanStore(&pricePlanStubTenantTxr{tx: &manaStubTx{}})
}

// CHO-1661 — a nil TxQuerier fails loud (mis-wiring guard).
func TestManaPricePlanStore_NilTxr(t *testing.T) {
	store := NewManaPricePlanStore(nil)
	_, err := store.ResolvePrice(context.Background(), mana.ResolveInput{ActionCode: "atom_authoring_assist"})
	if err == nil {
		t.Fatalf("expected error for nil TxQuerier")
	}
}

// CHO-1661 §7.4 — a DB fault on the precedence query is wrapped (NOT swallowed
// into a silent miss).
func TestManaPricePlanStore_ResolvePrice_PrecedenceDBError(t *testing.T) {
	boom := errors.New("connection reset")
	tx := &manaStubTx{queryRow: func(string, ...any) Row {
		return manaStubRow{scan: func(...any) error { return boom }}
	}}
	store := NewManaPricePlanStore(&pricePlanStubTenantTxr{tx: tx})

	_, err := store.ResolvePrice(context.Background(), mana.ResolveInput{ActionCode: "question_generation"})
	if err == nil || errors.Is(err, mana.ErrUnknownActionCode) {
		t.Fatalf("err = %v, want a wrapped DB error (not unknown-action / nil)", err)
	}
	if !strings.Contains(err.Error(), "precedence") {
		t.Errorf("err = %v, want it to mention the precedence query", err)
	}
}

// CHO-1661 §7.4 — a DB fault on the catalogue fallback query is wrapped.
func TestManaPricePlanStore_ResolvePrice_CatalogueDBError(t *testing.T) {
	boom := errors.New("disk i/o error")
	calls := 0
	tx := &manaStubTx{queryRow: func(string, ...any) Row {
		calls++
		if calls == 1 {
			return manaStubRow{scan: func(...any) error { return ErrNoRows }} // precedence miss
		}
		return manaStubRow{scan: func(...any) error { return boom }} // catalogue fault
	}}
	store := NewManaPricePlanStore(&pricePlanStubTenantTxr{tx: tx})

	_, err := store.ResolvePrice(context.Background(), mana.ResolveInput{ActionCode: "question_generation"})
	if err == nil || errors.Is(err, mana.ErrUnknownActionCode) {
		t.Fatalf("err = %v, want a wrapped DB error", err)
	}
	if !strings.Contains(err.Error(), "catalogue") {
		t.Errorf("err = %v, want it to mention the catalogue query", err)
	}
}
