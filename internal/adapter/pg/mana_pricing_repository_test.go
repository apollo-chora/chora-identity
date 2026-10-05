package pg

import (
	"context"
	"errors"
	"testing"

	mana "github.com/apollo-chora/chora-identity/internal/domain/user_mana"
)

type pricingStubQuerier struct {
	gotSQL  string
	gotArgs []any
	row     Row
}

func (q *pricingStubQuerier) QueryRow(_ context.Context, sql string, args ...any) Row {
	q.gotSQL = sql
	q.gotArgs = args
	return q.row
}

func TestManaPricingStore_CostForAction_Found(t *testing.T) {
	q := &pricingStubQuerier{row: manaStubRow{scan: func(dest ...any) error {
		*(dest[0].(*int64)) = 15
		return nil
	}}}
	store := NewManaPricingStore(q)

	cost, err := store.CostForAction(context.Background(), "familiar_chat_turn_standard")
	if err != nil {
		t.Fatalf("CostForAction: %v", err)
	}
	if cost != 15 {
		t.Errorf("cost = %d, want 15", cost)
	}
	if len(q.gotArgs) != 1 || q.gotArgs[0] != "familiar_chat_turn_standard" {
		t.Errorf("query arg = %v, want [action_code]", q.gotArgs)
	}
}

func TestManaPricingStore_CostForAction_FreeActionZero(t *testing.T) {
	q := &pricingStubQuerier{row: manaStubRow{scan: func(dest ...any) error {
		*(dest[0].(*int64)) = 0
		return nil
	}}}
	store := NewManaPricingStore(q)

	cost, err := store.CostForAction(context.Background(), "summon_familiar")
	if err != nil {
		t.Fatalf("CostForAction: %v (cost 0 is a valid free action, not an error)", err)
	}
	if cost != 0 {
		t.Errorf("cost = %d, want 0", cost)
	}
}

func TestManaPricingStore_CostForAction_Unknown(t *testing.T) {
	q := &pricingStubQuerier{row: manaStubRow{scan: func(...any) error { return ErrNoRows }}}
	store := NewManaPricingStore(q)

	_, err := store.CostForAction(context.Background(), "does_not_exist")
	if !errors.Is(err, mana.ErrUnknownActionCode) {
		t.Fatalf("err = %v, want ErrUnknownActionCode", err)
	}
}

func TestManaPricingStore_CostForAction_EmptyCode(t *testing.T) {
	store := NewManaPricingStore(&pricingStubQuerier{})
	_, err := store.CostForAction(context.Background(), "   ")
	if !errors.Is(err, mana.ErrUnknownActionCode) {
		t.Fatalf("err = %v, want ErrUnknownActionCode", err)
	}
}
