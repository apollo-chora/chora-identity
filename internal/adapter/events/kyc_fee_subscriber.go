// Package events — Pub/Sub subscriber for the
// chora.payments.identity_kyc_fee.*.v1 family flowing from chora-payments →
// chora-identity.
//
// Per ADR-142 + ADR-164 Stage A.5: the manual-doc KYC fee ($9.99; Singpass
// / SkillsFutures learners skip it) is collected by chora-payments (the
// canonical Stripe-SDK home). chora-identity charges the fee at submission
// via CreateIdentityKycFeeSession (a Stripe Checkout redirect) while the
// kyc.Verification stays PENDING. This subscriber consumes the capture
// outcome and gates entry into the manual-review queue on payment:
//
//	chora.payments.identity_kyc_fee.payment_captured.v1 → Submit (pending →
//	    submitted; the verification enters the review queue + emits
//	    chora.identity.kyc.submitted.v1). You pay for the manual-review
//	    effort up front; the fee is non-refundable on review rejection.
//
// payment_failed / refunded / expired are accepted as clean no-ops for now
// (the verification simply never leaves pending — it is not in the review
// queue and grants nothing). They are listed in SubscribedTopics so the
// Pub/Sub binding is complete and a future enhancement can act on them
// without a contract change.
//
// Idempotency: the capture handler runs under idempotent.Store keyed on the
// envelope's idempotency_key (falling back to a synthetic
// "payments-kyc_fee-captured:{purchase_id}" key when omitted). The 24h
// dedupe window matches the canonical PaymentsSubscriber.
//
// Hexagonal note: ADAPTER. Domain code (services/.../domain/kyc) never
// imports this package; the subscriber consumes the kyc.Repository port +
// the domain aggregate FSM.
package events

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/apollo-chora/chora-common/idempotent"
	"github.com/apollo-chora/chora-identity/internal/domain/identity"
	"github.com/apollo-chora/chora-identity/internal/domain/kyc"
)

// -----------------------------------------------------------------------------
// Topic constants
// -----------------------------------------------------------------------------

const (
	TopicPaymentsIdentityKycFeeCaptured = "chora.payments.identity_kyc_fee.payment_captured.v1"
	TopicPaymentsIdentityKycFeeFailed   = "chora.payments.identity_kyc_fee.payment_failed.v1"
	TopicPaymentsIdentityKycFeeRefunded = "chora.payments.identity_kyc_fee.refunded.v1"
	TopicPaymentsIdentityKycFeeExpired  = "chora.payments.identity_kyc_fee.expired.v1"
)

// -----------------------------------------------------------------------------
// Payload shape
// -----------------------------------------------------------------------------

// PaymentsIdentityKycFeePaymentCapturedPayload mirrors the wire shape of
// chora.payments.identity_kyc_fee.payment_captured.v1 payloads. The
// canonical Protobuf source-of-truth is
// chora-contracts/proto/events/payments/identity_kyc_fee.proto. This struct
// is the loose JSON projection the in-process subscriber consumes.
type PaymentsIdentityKycFeePaymentCapturedPayload struct {
	PurchaseID            string    `json:"purchase_id"`
	LearnerGcid           string    `json:"learner_gcid"`
	KycDocType            string    `json:"kyc_doc_type"`
	StripeSessionID       string    `json:"stripe_session_id"`
	StripePaymentIntentID string    `json:"stripe_payment_intent_id"`
	StripeChargeID        string    `json:"stripe_charge_id"`
	AmountCentsPaid       int64     `json:"amount_cents_paid"`
	Currency              string    `json:"currency"`
	PaidAt                time.Time `json:"paid_at"`
}

// -----------------------------------------------------------------------------
// KycFeeSubscriber
// -----------------------------------------------------------------------------

// KycFeeSubscriber wires the chora.payments.identity_kyc_fee.*.v1 topics to
// the chora-identity-owned kyc.Verification FSM.
type KycFeeSubscriber struct {
	kycRepo kyc.Repository
	pub     *EconomyPublisher
	inbox   idempotent.Store
	ttl     time.Duration
}

// NewKycFeeSubscriber constructs the subscriber. nil inbox triggers a
// defensive MemoryStore fallback (dev only; production passes a
// PostgresStore against chora_identity.idempotency_keys).
func NewKycFeeSubscriber(kycRepo kyc.Repository, pub *EconomyPublisher, inbox idempotent.Store) *KycFeeSubscriber {
	if inbox == nil {
		inbox = idempotent.NewMemoryStore()
	}
	return &KycFeeSubscriber{
		kycRepo: kycRepo,
		pub:     pub,
		inbox:   inbox,
		ttl:     PaymentsInboxTTL,
	}
}

// WithInboxTTL overrides the dedupe TTL.
func (s *KycFeeSubscriber) WithInboxTTL(d time.Duration) *KycFeeSubscriber {
	if d > 0 {
		s.ttl = d
	}
	return s
}

// SubscribedTopics returns the 4 canonical topics this subscriber binds to.
func (s *KycFeeSubscriber) SubscribedTopics() []string {
	return []string{
		TopicPaymentsIdentityKycFeeCaptured,
		TopicPaymentsIdentityKycFeeFailed,
		TopicPaymentsIdentityKycFeeRefunded,
		TopicPaymentsIdentityKycFeeExpired,
	}
}

// -----------------------------------------------------------------------------
// HandlePaymentCaptured — fee paid → enter the manual-review queue
// -----------------------------------------------------------------------------

// HandlePaymentCaptured processes payment_captured.v1. It correlates the
// payment to the learner's latest PENDING manual_doc verification and
// transitions it Submit (pending → submitted), recording the captured fee
// and emitting chora.identity.kyc.submitted.v1.
//
// FSM rules:
//   - pending manual_doc verification   → submitted (review queue) + emit
//   - already submitted / wrong method  → no-op (idempotent re-delivery)
//   - no verification on file           → drop cleanly (DLQ avoidance)
func (s *KycFeeSubscriber) HandlePaymentCaptured(
	ctx context.Context,
	env Envelope,
	payload PaymentsIdentityKycFeePaymentCapturedPayload,
) error {
	if s == nil || s.kycRepo == nil || s.inbox == nil {
		return errors.New("events: KycFeeSubscriber not initialised")
	}
	if err := s.validate(env, payload.LearnerGcid, payload.PurchaseID); err != nil {
		return err
	}
	idem := s.idempotencyKey(env, "captured", payload.PurchaseID)
	return s.inbox.Process(ctx, idem, s.ttl, func() error {
		v, err := s.kycRepo.GetLatestByGcid(ctx, payload.LearnerGcid)
		if err != nil {
			if errors.Is(err, kyc.ErrNotFound) {
				return nil // drop cleanly — DLQ avoidance
			}
			return fmt.Errorf("events: kyc_fee captured lookup: %w", err)
		}
		// Only the manual_doc path is fee-gated; only a pending verification
		// can enter the review queue. Anything else is an idempotent no-op.
		if v.Method != kyc.MethodManualDoc || v.Status != kyc.StatusPending {
			return nil
		}
		currency := strings.TrimSpace(payload.Currency)
		if currency == "" {
			currency = "USD"
		}
		docURI := strings.TrimSpace(v.DocumentURI)
		if docURI == "" {
			// Defensive: the document is attached at submission, but never
			// enter the review queue with an empty doc handle.
			docURI = "gs://chora-kyc-sandbox/" + v.VerificationID
		}
		if err := v.Submit(docURI, payload.AmountCentsPaid, currency); err != nil {
			return fmt.Errorf("events: kyc_fee captured submit: %w", err)
		}
		if err := s.kycRepo.Save(ctx, v); err != nil {
			return fmt.Errorf("events: kyc_fee captured save: %w", err)
		}
		if s.pub != nil {
			if err := s.pub.PublishKycSubmitted(env, v); err != nil {
				return fmt.Errorf("events: kyc_fee captured publish submitted: %w", err)
			}
		}
		return nil
	})
}

// -----------------------------------------------------------------------------
// Validation + idempotency helpers
// -----------------------------------------------------------------------------

func (s *KycFeeSubscriber) validate(env Envelope, learnerGcid, purchaseID string) error {
	if strings.TrimSpace(learnerGcid) == "" {
		return errors.New("events: kyc_fee envelope learner_gcid required")
	}
	if identity.IsAGID(learnerGcid) {
		return errors.New("events: AGID cannot hold a KYC verification")
	}
	if strings.TrimSpace(purchaseID) == "" {
		return errors.New("events: kyc_fee payload purchase_id required")
	}
	if strings.TrimSpace(env.TenantID) == "" {
		return errors.New("events: kyc_fee envelope.tenant_id required")
	}
	return nil
}

// idempotencyKey returns the envelope's IdempotencyKey when set; otherwise a
// stable synthetic key so deliveries from a producer that forgot to fill it
// still dedupe.
func (s *KycFeeSubscriber) idempotencyKey(env Envelope, eventType, purchaseID string) string {
	idem := strings.TrimSpace(env.IdempotencyKey)
	if idem != "" {
		return idem
	}
	return "payments-kyc_fee-" + eventType + ":" + purchaseID
}
