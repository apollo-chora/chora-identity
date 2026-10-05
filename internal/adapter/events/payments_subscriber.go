// Package events — Pub/Sub subscriber for the
// chora.payments.user_subscription.*.v1 family (4 topics) flowing from
// chora-payments → chora-identity.
//
// Per ADR-164 Wave 1 Stage E: chora-payments now owns the Stripe
// correlation half (Stripe Subscription / Customer / Invoice / Charge
// handles + payment-phase FSM + outbox publish). chora-identity retains
// the business-logic UserSubscription aggregate — mana entitlements +
// lifecycle FSM — and drives it from these Pub/Sub events.
//
// 4 topics consumed by this subscriber:
//
//	chora.payments.user_subscription.payment_captured.v1 → Activate /
//	    Renew (extend period). Maps to invoice.paid Stripe webhook.
//	chora.payments.user_subscription.payment_failed.v1   → EnterGrace.
//	    Maps to invoice.payment_failed Stripe webhook.
//	chora.payments.user_subscription.refunded.v1         → Cancel (revoke
//	    entitlement). Maps to charge.refunded Stripe webhook.
//	chora.payments.user_subscription.expired.v1          → MarkExpired or
//	    Cancel (initial Checkout Session abandoned). Maps to
//	    checkout.session.expired Stripe webhook.
//
// Idempotency: each handler runs under idempotent.Store keyed on the
// envelope's idempotency_key (falling back to a synthetic
// "payments-{event_type}:{stripe_subscription_id}" key when omitted).
// The 24h dedupe window matches the canonical EnrollmentSubscriber +
// ClosureSubscriber.
//
// Hexagonal note: ADAPTER. Domain code (services/.../domain/user_subscription)
// never imports this package; the subscriber consumes the usersub.Repository
// port + the domain aggregate FSM.
package events

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/apollo-chora/chora-common/idempotent"
	"github.com/apollo-chora/chora-identity/internal/domain/identity"
	usersub "github.com/apollo-chora/chora-identity/internal/domain/user_subscription"
)

// -----------------------------------------------------------------------------
// Topic constants
// -----------------------------------------------------------------------------

const (
	TopicPaymentsUserSubscriptionCaptured = "chora.payments.user_subscription.payment_captured.v1"
	TopicPaymentsUserSubscriptionFailed   = "chora.payments.user_subscription.payment_failed.v1"
	TopicPaymentsUserSubscriptionRefunded = "chora.payments.user_subscription.refunded.v1"
	TopicPaymentsUserSubscriptionExpired  = "chora.payments.user_subscription.expired.v1"
)

// PaymentsInboxTTL — dedupe-key retention window for the payments
// subscriber's inbox. 24h matches the canonical EnrollmentSubscriber +
// ClosureSubscriber.
const PaymentsInboxTTL = 24 * time.Hour

// -----------------------------------------------------------------------------
// Errors
// -----------------------------------------------------------------------------

// ErrPaymentsSubscriptionNotFound — the payments event references a
// stripe_subscription_id that does not exist in chora_identity's local
// UserSubscription store. Returned non-fatally so callers can decide
// whether to DLQ or drop cleanly.
var ErrPaymentsSubscriptionNotFound = errors.New("events: payments user_subscription not found in local store")

// -----------------------------------------------------------------------------
// Payload shapes
// -----------------------------------------------------------------------------

// PaymentsUserSubscriptionPaymentCapturedPayload mirrors the wire shape
// of chora.payments.user_subscription.payment_captured.v1 payloads.
//
// The canonical Protobuf source-of-truth is in
// chora-contracts/proto/events/payments/user_subscription.proto.
// This struct is the loose JSON projection consumed by the in-process
// subscriber during local dev / integration tests.
type PaymentsUserSubscriptionPaymentCapturedPayload struct {
	PurchaseID            string    `json:"purchase_id"`
	LearnerGcid           string    `json:"learner_gcid"`
	PlanSku               string    `json:"plan_sku"`
	BillingPeriod         string    `json:"billing_period"`
	StripeSubscriptionID  string    `json:"stripe_subscription_id"`
	StripeInvoiceID       string    `json:"stripe_invoice_id"`
	StripePaymentIntentID string    `json:"stripe_payment_intent_id"`
	StripeChargeID        string    `json:"stripe_charge_id"`
	AmountCentsPaid       int64     `json:"amount_cents_paid"`
	Currency              string    `json:"currency"`
	PeriodStart           time.Time `json:"period_start"`
	PeriodEnd             time.Time `json:"period_end"`
	PaidAt                time.Time `json:"paid_at"`
}

// PaymentsUserSubscriptionPaymentFailedPayload mirrors
// chora.payments.user_subscription.payment_failed.v1.
type PaymentsUserSubscriptionPaymentFailedPayload struct {
	PurchaseID           string    `json:"purchase_id"`
	LearnerGcid          string    `json:"learner_gcid"`
	PlanSku              string    `json:"plan_sku"`
	StripeSubscriptionID string    `json:"stripe_subscription_id"`
	StripeInvoiceID      string    `json:"stripe_invoice_id"`
	StripeFailureCode    string    `json:"stripe_failure_code"`
	StripeFailureMessage string    `json:"stripe_failure_message"`
	NextAttemptAt        time.Time `json:"next_attempt_at"`
	FailedAt             time.Time `json:"failed_at"`
}

// PaymentsUserSubscriptionRefundedPayload mirrors
// chora.payments.user_subscription.refunded.v1.
type PaymentsUserSubscriptionRefundedPayload struct {
	PurchaseID           string    `json:"purchase_id"`
	LearnerGcid          string    `json:"learner_gcid"`
	StripeSubscriptionID string    `json:"stripe_subscription_id"`
	StripeInvoiceID      string    `json:"stripe_invoice_id"`
	StripeChargeID       string    `json:"stripe_charge_id"`
	StripeRefundID       string    `json:"stripe_refund_id"`
	AmountCentsRefunded  int64     `json:"amount_cents_refunded"`
	Currency             string    `json:"currency"`
	Reason               string    `json:"reason"`
	RefundedAt           time.Time `json:"refunded_at"`
}

// PaymentsUserSubscriptionExpiredPayload mirrors
// chora.payments.user_subscription.expired.v1.
type PaymentsUserSubscriptionExpiredPayload struct {
	PurchaseID           string    `json:"purchase_id"`
	LearnerGcid          string    `json:"learner_gcid"`
	PlanSku              string    `json:"plan_sku"`
	StripeSessionID      string    `json:"stripe_session_id"`
	StripeSubscriptionID string    `json:"stripe_subscription_id"`
	ExpiredAt            time.Time `json:"expired_at"`
}

// -----------------------------------------------------------------------------
// PaymentsSubscriber
// -----------------------------------------------------------------------------

// PaymentsSubscriber wires the chora.payments.user_subscription.*.v1
// topics to the chora-identity-owned UserSubscription FSM.
//
// Inbox dedupe: each handler runs inside idempotent.Process keyed on the
// envelope's idempotency_key (or a synthetic
// "payments-{event_type}:{stripe_subscription_id}" fallback). Survives
// pod-restart + multi-replica failure modes when a PostgresStore is
// wired (production) instead of MemoryStore (dev / tests).
type PaymentsSubscriber struct {
	subs  usersub.Repository
	inbox idempotent.Store
	ttl   time.Duration
}

// NewPaymentsSubscriber constructs the subscriber with the usersub repo
// + inbox store. nil inbox triggers a defensive MemoryStore fallback
// (dev only; production passes PostgresStore against
// chora_identity.idempotency_keys).
func NewPaymentsSubscriber(subs usersub.Repository, inbox idempotent.Store) *PaymentsSubscriber {
	if inbox == nil {
		inbox = idempotent.NewMemoryStore()
	}
	return &PaymentsSubscriber{
		subs:  subs,
		inbox: inbox,
		ttl:   PaymentsInboxTTL,
	}
}

// WithInboxTTL overrides the dedupe TTL.
func (s *PaymentsSubscriber) WithInboxTTL(d time.Duration) *PaymentsSubscriber {
	if d > 0 {
		s.ttl = d
	}
	return s
}

// SubscribedTopics returns the 4 canonical topics this subscriber binds
// to — surfaced so cmd/server wiring can register the subscriptions with
// the Pub/Sub adapter.
func (s *PaymentsSubscriber) SubscribedTopics() []string {
	return []string{
		TopicPaymentsUserSubscriptionCaptured,
		TopicPaymentsUserSubscriptionFailed,
		TopicPaymentsUserSubscriptionRefunded,
		TopicPaymentsUserSubscriptionExpired,
	}
}

// -----------------------------------------------------------------------------
// HandlePaymentCaptured — invoice.paid → Activate / Renew
// -----------------------------------------------------------------------------

// HandlePaymentCaptured processes payment_captured.v1. Covers both the
// initial subscription activation AND every renewal invoice paid.
//
// FSM rules:
//   - pending_activation | grace        → active (Activate / RecoverFromGrace)
//   - active                            → extend CurrentPeriodEnd in place
//   - other terminal states             → ignored (idempotent re-delivery
//     after explicit cancellation is a no-op)
func (s *PaymentsSubscriber) HandlePaymentCaptured(
	ctx context.Context,
	env Envelope,
	payload PaymentsUserSubscriptionPaymentCapturedPayload,
) error {
	if s == nil || s.subs == nil || s.inbox == nil {
		return errors.New("events: PaymentsSubscriber not initialised")
	}
	if err := s.validateBase(env, payload.LearnerGcid, payload.StripeSubscriptionID); err != nil {
		return err
	}
	idem := s.idempotencyKey(env, "payment_captured", payload.StripeSubscriptionID, payload.PurchaseID)
	return s.inbox.Process(ctx, idem, s.ttl, func() error {
		sub, err := s.subs.GetByStripeSubscriptionID(ctx, payload.StripeSubscriptionID)
		if err != nil {
			if errors.Is(err, usersub.ErrNotFound) {
				return nil // drop cleanly — DLQ avoidance
			}
			return fmt.Errorf("events: payments captured lookup: %w", err)
		}
		switch sub.Status {
		case usersub.StatusPendingActivation:
			if err := sub.Activate(); err != nil {
				return fmt.Errorf("events: payments captured activate: %w", err)
			}
		case usersub.StatusGrace:
			if err := sub.RecoverFromGrace(); err != nil {
				return fmt.Errorf("events: payments captured recover_from_grace: %w", err)
			}
		case usersub.StatusActive:
			// Extend the current period in place (renewal invoice).
		case usersub.StatusCancelled, usersub.StatusExpired:
			// Terminal — no-op.
			return nil
		case usersub.StatusPaused:
			// Resume on payment capture (rare; Stripe webhook can fire after
			// admin-paused subscription is unpaused upstream).
			if err := sub.Resume(); err != nil {
				return fmt.Errorf("events: payments captured resume: %w", err)
			}
		}
		// Roll the period window — covers both first-activation and renewal.
		if !payload.PeriodStart.IsZero() && !payload.PeriodEnd.IsZero() {
			sub.CurrentPeriodStart = payload.PeriodStart.UTC()
			sub.CurrentPeriodEnd = payload.PeriodEnd.UTC()
		}
		return s.subs.Save(ctx, sub)
	})
}

// -----------------------------------------------------------------------------
// HandlePaymentFailed — invoice.payment_failed → EnterGrace
// -----------------------------------------------------------------------------

// HandlePaymentFailed processes payment_failed.v1. Transitions the
// chora-identity-owned UserSubscription FSM from active → grace per
// ADR-142.
//
// FSM rules:
//   - active                            → grace
//   - other states                      → ignored
func (s *PaymentsSubscriber) HandlePaymentFailed(
	ctx context.Context,
	env Envelope,
	payload PaymentsUserSubscriptionPaymentFailedPayload,
) error {
	if s == nil || s.subs == nil || s.inbox == nil {
		return errors.New("events: PaymentsSubscriber not initialised")
	}
	if err := s.validateBase(env, payload.LearnerGcid, payload.StripeSubscriptionID); err != nil {
		return err
	}
	idem := s.idempotencyKey(env, "payment_failed", payload.StripeSubscriptionID, payload.PurchaseID)
	return s.inbox.Process(ctx, idem, s.ttl, func() error {
		sub, err := s.subs.GetByStripeSubscriptionID(ctx, payload.StripeSubscriptionID)
		if err != nil {
			if errors.Is(err, usersub.ErrNotFound) {
				return nil
			}
			return fmt.Errorf("events: payments failed lookup: %w", err)
		}
		if sub.Status != usersub.StatusActive {
			return nil
		}
		reason := strings.TrimSpace(payload.StripeFailureCode)
		if reason == "" {
			reason = "payment_failed"
		}
		if err := sub.EnterGrace(reason); err != nil {
			return fmt.Errorf("events: payments failed enter_grace: %w", err)
		}
		return s.subs.Save(ctx, sub)
	})
}

// -----------------------------------------------------------------------------
// HandleRefunded — charge.refunded → Cancel (revoke entitlement)
// -----------------------------------------------------------------------------

// HandleRefunded processes refunded.v1. Revokes the entitlement by
// transitioning the chora-identity-owned UserSubscription FSM to
// cancelled (per ADR-142 the mana balance is preserved — Cancel only
// affects future drips).
//
// FSM rules:
//   - active | paused | grace | pending → cancelled
//   - cancelled | expired               → no-op (terminal)
func (s *PaymentsSubscriber) HandleRefunded(
	ctx context.Context,
	env Envelope,
	payload PaymentsUserSubscriptionRefundedPayload,
) error {
	if s == nil || s.subs == nil || s.inbox == nil {
		return errors.New("events: PaymentsSubscriber not initialised")
	}
	if err := s.validateBase(env, payload.LearnerGcid, payload.StripeSubscriptionID); err != nil {
		return err
	}
	idem := s.idempotencyKey(env, "refunded", payload.StripeSubscriptionID, payload.PurchaseID)
	return s.inbox.Process(ctx, idem, s.ttl, func() error {
		sub, err := s.subs.GetByStripeSubscriptionID(ctx, payload.StripeSubscriptionID)
		if err != nil {
			if errors.Is(err, usersub.ErrNotFound) {
				return nil
			}
			return fmt.Errorf("events: payments refunded lookup: %w", err)
		}
		reason := strings.TrimSpace(payload.Reason)
		if reason == "" {
			reason = "refunded"
		}
		effectiveAt := payload.RefundedAt
		if effectiveAt.IsZero() {
			effectiveAt = time.Now().UTC()
		}
		if err := sub.Cancel(reason, "", effectiveAt); err != nil {
			// Already terminal — Cancel is idempotent on cancelled; only
			// expired returns an error here.
			if sub.Status == usersub.StatusExpired || sub.Status == usersub.StatusCancelled {
				return nil
			}
			return fmt.Errorf("events: payments refunded cancel: %w", err)
		}
		return s.subs.Save(ctx, sub)
	})
}

// -----------------------------------------------------------------------------
// HandleExpired — checkout.session.expired → MarkExpired or Cancel
// -----------------------------------------------------------------------------

// HandleExpired processes expired.v1. Reaches chora-identity when the
// learner abandoned the INITIAL Stripe Checkout Session before paying.
// The corresponding UserSubscription is in pending_activation; we
// transition it to expired.
//
// FSM rules:
//   - pending_activation                → cancelled (initial checkout
//     never paid — never grant mana)
//   - active | other states             → MarkExpired (period rolled out
//     without renewal)
func (s *PaymentsSubscriber) HandleExpired(
	ctx context.Context,
	env Envelope,
	payload PaymentsUserSubscriptionExpiredPayload,
) error {
	if s == nil || s.subs == nil || s.inbox == nil {
		return errors.New("events: PaymentsSubscriber not initialised")
	}
	// Expired events may not carry a stripe_subscription_id if the
	// session never reached subscription-creation (rare for the user
	// subscription flow; defensive lookup via session_id is a future
	// enhancement). The base validator allows empty stripe_subscription_id
	// when stripe_session_id is set instead.
	stripeKey := strings.TrimSpace(payload.StripeSubscriptionID)
	if stripeKey == "" {
		stripeKey = strings.TrimSpace(payload.StripeSessionID)
	}
	if err := s.validateBaseExpired(env, payload.LearnerGcid, stripeKey); err != nil {
		return err
	}
	idem := s.idempotencyKey(env, "expired", stripeKey, payload.PurchaseID)
	return s.inbox.Process(ctx, idem, s.ttl, func() error {
		// Prefer stripe_subscription_id lookup; fall back to no-op
		// when only session_id is set (chora-payments owns the
		// session_id → purchase_id binding; identity's lookup is
		// keyed on subscription_id only).
		if payload.StripeSubscriptionID == "" {
			return nil // drop cleanly — no local handle to resolve
		}
		sub, err := s.subs.GetByStripeSubscriptionID(ctx, payload.StripeSubscriptionID)
		if err != nil {
			if errors.Is(err, usersub.ErrNotFound) {
				return nil
			}
			return fmt.Errorf("events: payments expired lookup: %w", err)
		}
		switch sub.Status {
		case usersub.StatusPendingActivation:
			// Initial Checkout Session abandoned before payment — cancel.
			if err := sub.Cancel("checkout_expired", "", time.Now().UTC()); err != nil {
				return fmt.Errorf("events: payments expired cancel: %w", err)
			}
		case usersub.StatusActive, usersub.StatusGrace, usersub.StatusPaused:
			if err := sub.MarkExpired(); err != nil {
				return fmt.Errorf("events: payments expired mark: %w", err)
			}
		case usersub.StatusCancelled, usersub.StatusExpired:
			return nil
		}
		return s.subs.Save(ctx, sub)
	})
}

// -----------------------------------------------------------------------------
// Validation helpers
// -----------------------------------------------------------------------------

func (s *PaymentsSubscriber) validateBase(env Envelope, learnerGcid, stripeSubscriptionID string) error {
	if strings.TrimSpace(learnerGcid) == "" {
		return errors.New("events: payments envelope learner_gcid required")
	}
	if identity.IsAGID(learnerGcid) {
		return errors.New("events: AGID cannot hold a UserSubscription")
	}
	if strings.TrimSpace(stripeSubscriptionID) == "" {
		return errors.New("events: payments payload stripe_subscription_id required")
	}
	if strings.TrimSpace(env.TenantID) == "" {
		return errors.New("events: payments envelope.tenant_id required")
	}
	return nil
}

// validateBaseExpired allows stripeSubscriptionID to be empty when the
// caller has already substituted stripe_session_id (the expired event
// may not have a subscription handle yet — initial Checkout abandoned).
func (s *PaymentsSubscriber) validateBaseExpired(env Envelope, learnerGcid, stripeKey string) error {
	if strings.TrimSpace(learnerGcid) == "" {
		return errors.New("events: payments envelope learner_gcid required")
	}
	if identity.IsAGID(learnerGcid) {
		return errors.New("events: AGID cannot hold a UserSubscription")
	}
	if strings.TrimSpace(stripeKey) == "" {
		return errors.New("events: payments payload requires stripe_subscription_id or stripe_session_id")
	}
	if strings.TrimSpace(env.TenantID) == "" {
		return errors.New("events: payments envelope.tenant_id required")
	}
	return nil
}

// idempotencyKey returns the envelope's IdempotencyKey when set;
// otherwise it synthesises a stable "payments-{event_type}:{stripe_id}:
// {purchase_id}" key so deliveries from a producer that forgot to fill
// IdempotencyKey still dedupe.
func (s *PaymentsSubscriber) idempotencyKey(env Envelope, eventType, stripeID, purchaseID string) string {
	idem := strings.TrimSpace(env.IdempotencyKey)
	if idem != "" {
		return idem
	}
	return "payments-" + eventType + ":" + stripeID + ":" + purchaseID
}
