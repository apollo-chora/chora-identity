package events

import (
	"context"
	"testing"
	"time"

	"github.com/apollo-chora/chora-common/idempotent"
	mana "github.com/apollo-chora/chora-identity/internal/domain/user_mana"

	commonv1 "github.com/apollo-chora/chora-contracts/gen/go/chora/common/v1"
	paymentsv1 "github.com/apollo-chora/chora-contracts/gen/go/chora/payments/v1"
)

const (
	topUpTestGcid   = "00000000-0000-7000-8000-000000001999"
	topUpTestTenant = "11111111-1111-7111-8111-111111111111"
)

func newTopUpSub(t *testing.T) (*UserManaTopUpSubscriber, mana.Store) {
	t.Helper()
	store := mana.NewInMemoryStore()
	q := mana.NewQuoter(store)
	sub := NewUserManaTopUpSubscriber(q, idempotent.NewMemoryStore())
	return sub, store
}

func capturedEvent(gcid, purchaseID, idem string, units int64) *paymentsv1.UserManaTopUpPaymentCaptured {
	return &paymentsv1.UserManaTopUpPaymentCaptured{
		Envelope: &commonv1.EventEnvelope{
			IdempotencyKey: idem,
			TenantId:       topUpTestTenant,
			Gcid:           gcid,
		},
		PurchaseId:  purchaseID,
		LearnerGcid: gcid,
		Sku:         "mana_pack_5000",
		ManaUnits:   units,
	}
}

func balanceOf(t *testing.T, store mana.Store, gcid string) int64 {
	t.Helper()
	m, err := store.GetMana(context.Background(), gcid)
	if err != nil {
		t.Fatalf("GetMana: %v", err)
	}
	if m == nil {
		return 0
	}
	return m.BalanceUnits
}

func TestUserManaTopUpSubscriber_CreditsWallet(t *testing.T) {
	sub, store := newTopUpSub(t)
	ev := capturedEvent(topUpTestGcid, "umt-1", "idem-1", 5000)

	if err := sub.HandlePaymentCaptured(context.Background(), ev); err != nil {
		t.Fatalf("HandlePaymentCaptured: %v", err)
	}
	if got := balanceOf(t, store, topUpTestGcid); got != 5000 {
		t.Fatalf("balance = %d, want 5000", got)
	}
}

func TestUserManaTopUpSubscriber_IdempotentReplay(t *testing.T) {
	sub, store := newTopUpSub(t)
	ev := capturedEvent(topUpTestGcid, "umt-1", "idem-replay", 5000)

	for i := 0; i < 3; i++ {
		if err := sub.HandlePaymentCaptured(context.Background(), ev); err != nil {
			t.Fatalf("replay %d: %v", i, err)
		}
	}
	if got := balanceOf(t, store, topUpTestGcid); got != 5000 {
		t.Fatalf("balance after 3 replays = %d, want 5000 (idempotent)", got)
	}
}

func TestUserManaTopUpSubscriber_RejectsBadPayloads(t *testing.T) {
	cases := []struct {
		name string
		ev   *paymentsv1.UserManaTopUpPaymentCaptured
	}{
		{"nil event", nil},
		{"zero units", capturedEvent(topUpTestGcid, "umt-1", "idem-1", 0)},
		{"negative units", capturedEvent(topUpTestGcid, "umt-1", "idem-1", -10)},
		{"missing gcid", capturedEvent("", "umt-1", "idem-1", 100)},
		{"missing purchase_id", capturedEvent(topUpTestGcid, "", "idem-1", 100)},
		{"agid caller", capturedEvent("0197A000-0000-7000-8000-000000000001", "umt-1", "idem-1", 100)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sub, store := newTopUpSub(t)
			if err := sub.HandlePaymentCaptured(context.Background(), tc.ev); err == nil {
				t.Fatalf("expected error for %s, got nil", tc.name)
			}
			if got := balanceOf(t, store, topUpTestGcid); got != 0 {
				t.Fatalf("balance = %d, want 0 (rejected event must not credit)", got)
			}
		})
	}
}

func TestUserManaTopUpSubscriber_SyntheticIdemFallback(t *testing.T) {
	sub, store := newTopUpSub(t)
	// No envelope idempotency_key — handler must synthesise one from purchase_id
	// and still dedupe across replays.
	ev := capturedEvent(topUpTestGcid, "umt-synthetic", "", 750)
	for i := 0; i < 2; i++ {
		if err := sub.HandlePaymentCaptured(context.Background(), ev); err != nil {
			t.Fatalf("replay %d: %v", i, err)
		}
	}
	if got := balanceOf(t, store, topUpTestGcid); got != 750 {
		t.Fatalf("balance = %d, want 750 (synthetic-idem dedupe)", got)
	}
}

func TestUserManaTopUpSubscriber_SubscribedTopics(t *testing.T) {
	sub, _ := newTopUpSub(t)
	topics := sub.SubscribedTopics()
	if len(topics) != 1 || topics[0] != TopicPaymentsUserManaTopUpCaptured {
		t.Fatalf("SubscribedTopics = %v", topics)
	}
}

func TestUserManaTopUpSubscriber_WithInboxTTL_Fluent(t *testing.T) {
	sub := NewUserManaTopUpSubscriber(nil, nil)
	if sub == nil {
		t.Fatal("expected non-nil subscriber")
	}
	fluent := sub.WithInboxTTL(90 * time.Second)
	if fluent != sub {
		t.Error("WithInboxTTL must return the same subscriber (fluent wiring)")
	}
	if sub.ttl != 90*time.Second {
		t.Errorf("ttl = %v, want 90s", sub.ttl)
	}
	sub.WithInboxTTL(0) // d<=0 keeps the TTL unchanged (no-op branch)
	if sub.ttl != 90*time.Second {
		t.Errorf("ttl changed on non-positive TTL: %v", sub.ttl)
	}
}

func TestUserManaTopUpSubscriber_NilGuard_Errors(t *testing.T) {
	var sub *UserManaTopUpSubscriber
	if err := sub.HandlePaymentCaptured(context.Background(), capturedEvent(topUpTestGcid, "umt-nil", "idem-nil", 100)); err == nil {
		t.Error("nil subscriber must error")
	}
	live := NewUserManaTopUpSubscriber(nil, nil) // nil quoter
	if err := live.HandlePaymentCaptured(context.Background(), capturedEvent(topUpTestGcid, "umt-nq", "idem-nq", 100)); err == nil {
		t.Error("nil quoter must error")
	}
}
