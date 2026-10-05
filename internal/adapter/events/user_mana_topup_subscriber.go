// Package events — Pub/Sub subscriber for the per-user mana top-up capture
// event flowing from chora-payments → chora-identity (ADR-142 + ADR-164).
//
// Topic: chora.payments.user_mana_topup.payment_captured.v1
//
// Per the owner decision (2026-06-04, "clean-DDD" consume seam): chora-identity
// owns the per-GCID user_mana wallet, so it consumes its OWN credit events
// rather than routing the credit through chora-delivery. The chora-payments
// outbox publishes the capture as Protobuf wire bytes (the EventEnvelope is
// proto-embedded — see services/chora-payments/internal/adapter/outbox/
// payload.go). The identity push handler proto.Unmarshal's the payload into
// *paymentsv1.UserManaTopUpPaymentCaptured and invokes HandlePaymentCaptured.
//
// Action: credit UserMana with source=topup + reason=topup. This is a PERSONAL
// credit (NOT a tenant subsidy) — no Allocation row, the units land directly in
// the wallet's spendable balance (ADR-142 §4 umbrella wallet).
//
// Idempotency: the handler runs under idempotent.Store keyed on the envelope's
// idempotency_key (falling back to a synthetic
// "user-mana-topup-captured:{purchase_id}" key when omitted). Defense-in-depth:
// the Quoter's own CreditMana is idempotent on (gcid, idempotency_key) too. The
// inbox protects against pod-restart + multi-replica redelivery; the Quoter key
// protects against a producer that re-emits with a fresh envelope.
//
// Hexagonal note: ADAPTER. Domain code (services/.../domain/user_mana) never
// imports this package; the subscriber consumes the mana.Quoter port.
package events

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/apollo-chora/chora-common/idempotent"
	"github.com/apollo-chora/chora-identity/internal/domain/identity"
	mana "github.com/apollo-chora/chora-identity/internal/domain/user_mana"

	paymentsv1 "github.com/apollo-chora/chora-contracts/gen/go/chora/payments/v1"
)

// TopicPaymentsUserManaTopUpCaptured is the canonical inbound topic this
// subscriber binds to.
const TopicPaymentsUserManaTopUpCaptured = "chora.payments.user_mana_topup.payment_captured.v1"

// UserManaTopUpSubscriber wires the chora.payments.user_mana_topup.
// payment_captured.v1 topic to the chora-identity-owned UserMana wallet via
// the mana.Quoter CreditMana path.
type UserManaTopUpSubscriber struct {
	quoter *mana.Quoter
	inbox  idempotent.Store
	ttl    time.Duration
}

// NewUserManaTopUpSubscriber constructs the subscriber with the Quoter + an
// inbox store. nil inbox triggers a defensive MemoryStore fallback (dev only;
// production passes a PostgresStore against chora_identity.idempotency_keys).
func NewUserManaTopUpSubscriber(quoter *mana.Quoter, inbox idempotent.Store) *UserManaTopUpSubscriber {
	if inbox == nil {
		inbox = idempotent.NewMemoryStore()
	}
	return &UserManaTopUpSubscriber{
		quoter: quoter,
		inbox:  inbox,
		ttl:    PaymentsInboxTTL,
	}
}

// WithInboxTTL overrides the inbox dedupe TTL. Returns the same subscriber for
// fluent wiring in tests.
func (s *UserManaTopUpSubscriber) WithInboxTTL(d time.Duration) *UserManaTopUpSubscriber {
	if d > 0 {
		s.ttl = d
	}
	return s
}

// SubscribedTopics returns the canonical topic(s) this subscriber binds to —
// surfaced so the cmd/server wiring can register the push subscription.
func (s *UserManaTopUpSubscriber) SubscribedTopics() []string {
	return []string{TopicPaymentsUserManaTopUpCaptured}
}

// HandlePaymentCaptured processes one user_mana_topup.payment_captured.v1
// event: it credits the learner's wallet by mana_units with source=topup.
//
// Idempotent on the envelope's idempotency_key (synthetic fallback keyed on
// purchase_id). A missing/zero mana_units, missing learner_gcid, or an AGID
// caller is rejected so the broker DLQs malformed events.
func (s *UserManaTopUpSubscriber) HandlePaymentCaptured(ctx context.Context, ev *paymentsv1.UserManaTopUpPaymentCaptured) error {
	if s == nil || s.quoter == nil || s.inbox == nil {
		return errors.New("events: UserManaTopUpSubscriber not initialised")
	}
	if ev == nil {
		return errors.New("events: user_mana_topup captured event is nil")
	}

	gcid := strings.TrimSpace(ev.GetLearnerGcid())
	if gcid == "" {
		return errors.New("events: user_mana_topup payload requires learner_gcid")
	}
	if identity.IsAGID(gcid) {
		return errors.New("events: AGID cannot hold a mana wallet")
	}
	units := ev.GetManaUnits()
	if units <= 0 {
		return fmt.Errorf("events: user_mana_topup mana_units must be > 0; got %d", units)
	}
	purchaseID := strings.TrimSpace(ev.GetPurchaseId())
	if purchaseID == "" {
		return errors.New("events: user_mana_topup payload requires purchase_id")
	}

	var tenantID, idem string
	if env := ev.GetEnvelope(); env != nil {
		tenantID = strings.TrimSpace(env.GetTenantId())
		idem = strings.TrimSpace(env.GetIdempotencyKey())
	}
	if idem == "" {
		idem = "user-mana-topup-captured:" + purchaseID
	}

	return s.inbox.Process(ctx, idem, s.ttl, func() error {
		res, err := s.quoter.CreditMana(ctx, mana.CreditInput{
			Gcid:           gcid,
			Source:         mana.SourceTopup,
			Units:          units,
			Reason:         mana.ReasonTopup,
			IdempotencyKey: idem,
			SourceTopupID:  purchaseID,
			TenantID:       tenantID,
		})
		if err != nil {
			return fmt.Errorf("events: user_mana_topup credit: %w", err)
		}
		// Happy-path observability (the consume-seam log a payment trace needs):
		// without this a successful credit leaves no trace and "did the top-up
		// persist?" can only be answered by a DB query. Distinguish a fresh credit
		// from an idempotent replay so a redelivery is obviously not a double-credit.
		verb := "credited"
		if res.Replayed {
			verb = "credit replayed (idempotent — no double-credit)"
		}
		log.Printf("identity: user_mana_topup %s gcid=%s units=%d reason=topup purchase_id=%s idempotency_key=%s balance_after=%d",
			verb, gcid, units, purchaseID, idem, res.BalanceAfterUnits)
		return nil
	})
}
