package user_mana_test

import (
	"context"
	"errors"
	"testing"

	mana "github.com/apollo-chora/chora-identity/internal/domain/user_mana"
)

// fakePricer is a test double recording lookups + returning a fixed catalogue.
type fakePricer struct {
	prices map[string]int64
	calls  []string
}

func (f *fakePricer) CostForAction(_ context.Context, actionCode string) (int64, error) {
	f.calls = append(f.calls, actionCode)
	cost, ok := f.prices[actionCode]
	if !ok {
		return 0, mana.ErrUnknownActionCode
	}
	return cost, nil
}

func seedWallet(t *testing.T, store *mana.InMemoryStore, gcid string, balance int64) {
	t.Helper()
	m := mana.NewUserMana(gcid)
	m.BalanceUnits = balance
	if err := store.SaveMana(context.Background(), m); err != nil {
		t.Fatalf("seed wallet: %v", err)
	}
}

// WS-1.1 — a units==0 debit resolves its cost from the catalogue and debits
// exactly the resolved amount.
func TestQuoter_DeductMana_ResolvesCatalogueCost(t *testing.T) {
	t.Parallel()
	store := mana.NewInMemoryStore()
	seedWallet(t, store, "g", 100)
	pricer := &fakePricer{prices: map[string]int64{"familiar_chat_turn_basic": 5}}
	q := mana.NewQuoter(store, mana.WithPricer(pricer))

	res, err := q.DeductMana(context.Background(), mana.DeductInput{
		Gcid: "g", ActionCode: "familiar_chat_turn_basic", Units: 0, IdempotencyKey: "k1",
	})
	if err != nil {
		t.Fatalf("DeductMana: %v", err)
	}
	if res.BalanceAfterUnits != 95 {
		t.Errorf("balance after = %d, want 95 (100 - resolved 5)", res.BalanceAfterUnits)
	}
	if len(res.Entries) != 1 || res.Entries[0].Units != 5 {
		t.Fatalf("expected 1 ledger entry of 5 units, got %+v", res.Entries)
	}
	if res.Entries[0].SourceActionID != "familiar_chat_turn_basic" {
		t.Errorf("ledger source_action_id = %q, want the action_code", res.Entries[0].SourceActionID)
	}
	if len(pricer.calls) != 1 {
		t.Errorf("pricer consulted %d times, want 1", len(pricer.calls))
	}
}

// WS-1.1 — an unknown action_code (units==0) surfaces ErrUnknownActionCode
// (the gRPC adapter maps it to InvalidArgument), and debits nothing.
func TestQuoter_DeductMana_UnknownActionCode(t *testing.T) {
	t.Parallel()
	store := mana.NewInMemoryStore()
	seedWallet(t, store, "g", 100)
	pricer := &fakePricer{prices: map[string]int64{"familiar_chat_turn_basic": 5}}
	q := mana.NewQuoter(store, mana.WithPricer(pricer))

	_, err := q.DeductMana(context.Background(), mana.DeductInput{
		Gcid: "g", ActionCode: "does_not_exist", Units: 0, IdempotencyKey: "k2",
	})
	if !errors.Is(err, mana.ErrUnknownActionCode) {
		t.Fatalf("err = %v, want ErrUnknownActionCode", err)
	}
	if got, _ := store.GetMana(context.Background(), "g"); got.BalanceUnits != 100 {
		t.Errorf("balance = %d, want 100 (unchanged on unknown code)", got.BalanceUnits)
	}
}

// WS-1.1 — an explicit Units>0 debit bypasses the catalogue entirely (legacy
// ad-hoc debit sites keep working without a Pricer consult).
func TestQuoter_DeductMana_ExplicitUnitsBypassesCatalogue(t *testing.T) {
	t.Parallel()
	store := mana.NewInMemoryStore()
	seedWallet(t, store, "g", 100)
	pricer := &fakePricer{prices: map[string]int64{"familiar_chat_turn_basic": 5}}
	q := mana.NewQuoter(store, mana.WithPricer(pricer))

	res, err := q.DeductMana(context.Background(), mana.DeductInput{
		Gcid: "g", ActionCode: "familiar_chat_turn_basic", Units: 30, IdempotencyKey: "k3",
	})
	if err != nil {
		t.Fatalf("DeductMana: %v", err)
	}
	if res.BalanceAfterUnits != 70 {
		t.Errorf("balance after = %d, want 70 (explicit 30 debited, not catalogue 5)", res.BalanceAfterUnits)
	}
	if len(pricer.calls) != 0 {
		t.Errorf("pricer consulted %d times on explicit-units debit, want 0", len(pricer.calls))
	}
}

// WS-1.1 — a free action (catalogue cost 0) is a no-op success: no ledger row,
// balance unchanged.
func TestQuoter_DeductMana_FreeAction(t *testing.T) {
	t.Parallel()
	store := mana.NewInMemoryStore()
	seedWallet(t, store, "g", 100)
	pricer := &fakePricer{prices: map[string]int64{"summon_familiar": 0}}
	q := mana.NewQuoter(store, mana.WithPricer(pricer))

	res, err := q.DeductMana(context.Background(), mana.DeductInput{
		Gcid: "g", ActionCode: "summon_familiar", Units: 0, IdempotencyKey: "k4",
	})
	if err != nil {
		t.Fatalf("DeductMana: %v", err)
	}
	if len(res.Entries) != 0 {
		t.Errorf("free action wrote %d ledger entries, want 0", len(res.Entries))
	}
	if res.BalanceAfterUnits != 100 {
		t.Errorf("balance after = %d, want 100 (free action, no debit)", res.BalanceAfterUnits)
	}
}

// WS-1.1 — an insufficient catalogue-priced debit surfaces the RESOLVED cost
// (not req.Units==0) so the gRPC upsell payload is correct.
func TestQuoter_DeductMana_InsufficientCarriesResolvedCost(t *testing.T) {
	t.Parallel()
	store := mana.NewInMemoryStore()
	seedWallet(t, store, "g", 3) // only 3 units available
	pricer := &fakePricer{prices: map[string]int64{"familiar_chat_turn_premium": 30}}
	q := mana.NewQuoter(store, mana.WithPricer(pricer))

	_, err := q.DeductMana(context.Background(), mana.DeductInput{
		Gcid: "g", ActionCode: "familiar_chat_turn_premium", Units: 0, IdempotencyKey: "ki",
	})
	if !mana.IsInsufficientBalance(err) {
		t.Fatalf("err = %v, want insufficient balance", err)
	}
	var ibe *mana.InsufficientBalanceError
	if !errors.As(err, &ibe) {
		t.Fatalf("err = %v, want *InsufficientBalanceError", err)
	}
	if ibe.RequiredUnits != 30 {
		t.Errorf("required = %d, want 30 (resolved catalogue cost, not req.Units=0)", ibe.RequiredUnits)
	}
	if ibe.AvailableUnits != 3 {
		t.Errorf("available = %d, want 3", ibe.AvailableUnits)
	}
}

// WS-1.2 — a dry-run debit resolves cost + checks affordability WITHOUT
// writing a ledger row (the gateway pre-flight gate).
func TestQuoter_DeductMana_DryRunAffordable(t *testing.T) {
	t.Parallel()
	store := mana.NewInMemoryStore()
	seedWallet(t, store, "g", 100)
	pricer := &fakePricer{prices: map[string]int64{"familiar_chat_turn_standard": 15}}
	q := mana.NewQuoter(store, mana.WithPricer(pricer))

	res, err := q.DeductMana(context.Background(), mana.DeductInput{
		Gcid: "g", ActionCode: "familiar_chat_turn_standard", Units: 0, IdempotencyKey: "d1", DryRun: true,
	})
	if err != nil {
		t.Fatalf("DeductMana dry-run: %v", err)
	}
	if res.BalanceAfterUnits != 100 {
		t.Errorf("dry-run reported balance %d, want 100 (unchanged — no debit)", res.BalanceAfterUnits)
	}
	if len(res.Entries) != 0 {
		t.Errorf("dry-run wrote %d ledger entries, want 0", len(res.Entries))
	}
	if got, _ := store.GetMana(context.Background(), "g"); got.BalanceUnits != 100 {
		t.Errorf("balance mutated to %d on dry-run, want 100", got.BalanceUnits)
	}
}

// WS-1.2 — a dry-run on an unaffordable action surfaces the resolved required
// units + available balance and writes nothing.
func TestQuoter_DeductMana_DryRunInsufficient(t *testing.T) {
	t.Parallel()
	store := mana.NewInMemoryStore()
	seedWallet(t, store, "g", 10)
	pricer := &fakePricer{prices: map[string]int64{"boss_challenge_atom_gen": 200}}
	q := mana.NewQuoter(store, mana.WithPricer(pricer))

	_, err := q.DeductMana(context.Background(), mana.DeductInput{
		Gcid: "g", ActionCode: "boss_challenge_atom_gen", Units: 0, IdempotencyKey: "d2", DryRun: true,
	})
	var ibe *mana.InsufficientBalanceError
	if !errors.As(err, &ibe) {
		t.Fatalf("err = %v, want *InsufficientBalanceError", err)
	}
	if ibe.RequiredUnits != 200 || ibe.AvailableUnits != 10 {
		t.Errorf("required/available = %d/%d, want 200/10", ibe.RequiredUnits, ibe.AvailableUnits)
	}
	if got, _ := store.GetMana(context.Background(), "g"); got.BalanceUnits != 10 {
		t.Errorf("balance mutated to %d on dry-run, want 10", got.BalanceUnits)
	}
}

// WS-1.1 — a units==0 debit with no Pricer wired is a configuration error, not
// a silent free pass.
func TestQuoter_DeductMana_ZeroUnitsNoPricer(t *testing.T) {
	t.Parallel()
	store := mana.NewInMemoryStore()
	seedWallet(t, store, "g", 100)
	q := mana.NewQuoter(store) // no WithPricer

	_, err := q.DeductMana(context.Background(), mana.DeductInput{
		Gcid: "g", ActionCode: "familiar_chat_turn_basic", Units: 0, IdempotencyKey: "k5",
	})
	if err == nil {
		t.Fatalf("expected error for units==0 debit with no Pricer configured")
	}
}
