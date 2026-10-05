// Tests for the chora.payments.user_subscription.*.v1 Pub/Sub subscriber.
//
// Per ADR-164 Wave 1 Stage E: chora-payments owns the Stripe correlation
// half (Stripe Subscription handle + payment-phase FSM + outbox).
// chora-identity owns the UserSubscription business-logic aggregate +
// drives its lifecycle FSM from the 4 incoming payment-outcome topics:
//
//	chora.payments.user_subscription.payment_captured.v1
//	chora.payments.user_subscription.payment_failed.v1
//	chora.payments.user_subscription.refunded.v1
//	chora.payments.user_subscription.expired.v1
//
// The subscriber:
//   - looks up the local UserSubscription by stripe_subscription_id;
//   - runs the appropriate FSM transition (Activate / EnterGrace /
//     SoftDelete-as-revoke / MarkExpired-or-Cancel);
//   - persists via the same usersub.Repository the HTTP handler uses;
//   - is idempotent on the envelope.event_id via inbox.Process;
//   - rejects AGID-shaped GCIDs;
//   - validates envelope mandatory fields.
//
// RED phase — types do not exist yet.
package events_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/apollo-chora/chora-common/idempotent"
	"github.com/apollo-chora/chora-identity/internal/adapter/events"
	"github.com/apollo-chora/chora-identity/internal/adapter/repo"
	usersub "github.com/apollo-chora/chora-identity/internal/domain/user_subscription"
)

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

const (
	psTestTenantID = "01935b5a-9bcf-7000-8000-000000000010"
	psTestGcid     = "01935b5a-9bcf-7000-8000-0000000000aa"
	psTestStripeID = "sub_test_payments_aaaa"
	psTraceparent  = "00-aabbccddeeff00112233445566778899-0011223344556677-01"
)

func seedActiveSubscription(t *testing.T, r usersub.Repository) *usersub.Subscription {
	t.Helper()
	s, err := usersub.NewSubscription(usersub.NewParams{
		Gcid:                 psTestGcid,
		TenantID:             psTestTenantID,
		PlanCode:             "familiar_standard",
		Tier:                 usersub.TierStandard,
		BillingPeriod:        usersub.BillingMonthly,
		ManaMonthlyUnits:     2500,
		OnboardingBonusUnits: 2500,
		StripeSubscriptionID: psTestStripeID,
		PeriodStart:          time.Now().UTC().Add(-24 * time.Hour),
		PeriodEnd:            time.Now().UTC().Add(29 * 24 * time.Hour),
	})
	if err != nil {
		t.Fatalf("seedActiveSubscription: %v", err)
	}
	if err := r.Save(context.Background(), s); err != nil {
		t.Fatalf("seed save: %v", err)
	}
	return s
}

func buildPaymentsSubscriber(_ *testing.T) (*events.PaymentsSubscriber, usersub.Repository) {
	subs := repo.NewInMemUserSubscriptionRepo()
	sub := events.NewPaymentsSubscriber(subs, idempotent.NewMemoryStore())
	return sub, subs
}

func paymentsEnvelope() events.Envelope {
	return events.NewEnvelope(psTestTenantID, psTestGcid, psTraceparent, "")
}

// -----------------------------------------------------------------------------
// Topic constants
// -----------------------------------------------------------------------------

func TestPaymentsSubscriber_TopicConstants(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"payment_captured": "chora.payments.user_subscription.payment_captured.v1",
		"payment_failed":   "chora.payments.user_subscription.payment_failed.v1",
		"refunded":         "chora.payments.user_subscription.refunded.v1",
		"expired":          "chora.payments.user_subscription.expired.v1",
	}
	if events.TopicPaymentsUserSubscriptionCaptured != cases["payment_captured"] {
		t.Errorf("payment_captured constant: got %q", events.TopicPaymentsUserSubscriptionCaptured)
	}
	if events.TopicPaymentsUserSubscriptionFailed != cases["payment_failed"] {
		t.Errorf("payment_failed constant: got %q", events.TopicPaymentsUserSubscriptionFailed)
	}
	if events.TopicPaymentsUserSubscriptionRefunded != cases["refunded"] {
		t.Errorf("refunded constant: got %q", events.TopicPaymentsUserSubscriptionRefunded)
	}
	if events.TopicPaymentsUserSubscriptionExpired != cases["expired"] {
		t.Errorf("expired constant: got %q", events.TopicPaymentsUserSubscriptionExpired)
	}
}

// -----------------------------------------------------------------------------
// payment_captured: pending_activation → active; grace → active
// -----------------------------------------------------------------------------

func TestPaymentsSubscriber_HandlePaymentCaptured_ActivatesPending(t *testing.T) {
	t.Parallel()
	sub, subs := buildPaymentsSubscriber(t)
	seedActiveSubscription(t, subs)

	env := paymentsEnvelope()
	payload := events.PaymentsUserSubscriptionPaymentCapturedPayload{
		PurchaseID:           "01970000-0000-7000-8000-bbbbbb000001",
		LearnerGcid:          psTestGcid,
		PlanSku:              "subscription.familiar.standard_monthly.v1",
		BillingPeriod:        "monthly",
		StripeSubscriptionID: psTestStripeID,
		StripeInvoiceID:      "in_test_1",
		AmountCentsPaid:      1499,
		Currency:             "USD",
		PeriodStart:          time.Now().UTC(),
		PeriodEnd:            time.Now().UTC().Add(30 * 24 * time.Hour),
		PaidAt:               time.Now().UTC(),
	}
	if err := sub.HandlePaymentCaptured(context.Background(), env, payload); err != nil {
		t.Fatalf("handle: %v", err)
	}
	got, err := subs.GetByStripeSubscriptionID(context.Background(), psTestStripeID)
	if err != nil {
		t.Fatalf("GetByStripeSubscriptionID: %v", err)
	}
	if got.Status != usersub.StatusActive {
		t.Errorf("expected active; got %v", got.Status)
	}
}

func TestPaymentsSubscriber_HandlePaymentCaptured_RecoversFromGrace(t *testing.T) {
	t.Parallel()
	sub, subs := buildPaymentsSubscriber(t)
	s := seedActiveSubscription(t, subs)
	// Move into grace state manually.
	_ = s.Activate()
	_ = s.EnterGrace("payment failure")
	if err := subs.Save(context.Background(), s); err != nil {
		t.Fatalf("seed save: %v", err)
	}
	if s.Status != usersub.StatusGrace {
		t.Fatalf("setup: expected grace; got %v", s.Status)
	}

	env := paymentsEnvelope()
	payload := events.PaymentsUserSubscriptionPaymentCapturedPayload{
		PurchaseID:           "01970000-0000-7000-8000-bbbbbb000002",
		LearnerGcid:          psTestGcid,
		StripeSubscriptionID: psTestStripeID,
		PeriodStart:          time.Now().UTC(),
		PeriodEnd:            time.Now().UTC().Add(30 * 24 * time.Hour),
		PaidAt:               time.Now().UTC(),
	}
	if err := sub.HandlePaymentCaptured(context.Background(), env, payload); err != nil {
		t.Fatalf("handle: %v", err)
	}
	got, _ := subs.GetByStripeSubscriptionID(context.Background(), psTestStripeID)
	if got.Status != usersub.StatusActive {
		t.Errorf("expected active after grace recovery; got %v", got.Status)
	}
}

func TestPaymentsSubscriber_HandlePaymentCaptured_ExtendsActivePeriod(t *testing.T) {
	t.Parallel()
	sub, subs := buildPaymentsSubscriber(t)
	s := seedActiveSubscription(t, subs)
	_ = s.Activate()
	if err := subs.Save(context.Background(), s); err != nil {
		t.Fatalf("seed save: %v", err)
	}

	newPeriodEnd := time.Now().UTC().Add(60 * 24 * time.Hour)
	env := paymentsEnvelope()
	payload := events.PaymentsUserSubscriptionPaymentCapturedPayload{
		PurchaseID:           "01970000-0000-7000-8000-bbbbbb000003",
		LearnerGcid:          psTestGcid,
		StripeSubscriptionID: psTestStripeID,
		PeriodStart:          time.Now().UTC(),
		PeriodEnd:            newPeriodEnd,
		PaidAt:               time.Now().UTC(),
	}
	if err := sub.HandlePaymentCaptured(context.Background(), env, payload); err != nil {
		t.Fatalf("handle: %v", err)
	}
	got, _ := subs.GetByStripeSubscriptionID(context.Background(), psTestStripeID)
	if !got.CurrentPeriodEnd.Equal(newPeriodEnd) {
		t.Errorf("period_end not extended: got %v want %v", got.CurrentPeriodEnd, newPeriodEnd)
	}
}

// -----------------------------------------------------------------------------
// payment_failed: active → grace
// -----------------------------------------------------------------------------

func TestPaymentsSubscriber_HandlePaymentFailed_EntersGrace(t *testing.T) {
	t.Parallel()
	sub, subs := buildPaymentsSubscriber(t)
	s := seedActiveSubscription(t, subs)
	_ = s.Activate()
	if err := subs.Save(context.Background(), s); err != nil {
		t.Fatalf("seed save: %v", err)
	}

	env := paymentsEnvelope()
	payload := events.PaymentsUserSubscriptionPaymentFailedPayload{
		PurchaseID:           "01970000-0000-7000-8000-ccccc0000001",
		LearnerGcid:          psTestGcid,
		StripeSubscriptionID: psTestStripeID,
		StripeFailureCode:    "card_declined",
		StripeFailureMessage: "Your card was declined.",
		FailedAt:             time.Now().UTC(),
	}
	if err := sub.HandlePaymentFailed(context.Background(), env, payload); err != nil {
		t.Fatalf("handle: %v", err)
	}
	got, _ := subs.GetByStripeSubscriptionID(context.Background(), psTestStripeID)
	if got.Status != usersub.StatusGrace {
		t.Errorf("expected grace; got %v", got.Status)
	}
}

// -----------------------------------------------------------------------------
// refunded: active|grace → cancelled (revoke entitlement)
// -----------------------------------------------------------------------------

func TestPaymentsSubscriber_HandleRefunded_RevokesEntitlement(t *testing.T) {
	t.Parallel()
	sub, subs := buildPaymentsSubscriber(t)
	s := seedActiveSubscription(t, subs)
	_ = s.Activate()
	if err := subs.Save(context.Background(), s); err != nil {
		t.Fatalf("seed save: %v", err)
	}

	env := paymentsEnvelope()
	payload := events.PaymentsUserSubscriptionRefundedPayload{
		PurchaseID:           "01970000-0000-7000-8000-dddd00000001",
		LearnerGcid:          psTestGcid,
		StripeSubscriptionID: psTestStripeID,
		StripeRefundID:       "re_test_aa",
		AmountCentsRefunded:  1499,
		Currency:             "USD",
		Reason:               "customer_request",
		RefundedAt:           time.Now().UTC(),
	}
	if err := sub.HandleRefunded(context.Background(), env, payload); err != nil {
		t.Fatalf("handle: %v", err)
	}
	got, _ := subs.GetByStripeSubscriptionID(context.Background(), psTestStripeID)
	if got.Status != usersub.StatusCancelled {
		t.Errorf("expected cancelled after refund; got %v", got.Status)
	}
	if got.CancellationReason == "" {
		t.Errorf("expected cancellation_reason to be set; got empty")
	}
}

// -----------------------------------------------------------------------------
// expired: any → expired
// -----------------------------------------------------------------------------

func TestPaymentsSubscriber_HandleExpired_CancelsEntitlement(t *testing.T) {
	t.Parallel()
	sub, subs := buildPaymentsSubscriber(t)
	seedActiveSubscription(t, subs)
	// Seed leaves the Subscription in pending_activation (initial state).

	env := paymentsEnvelope()
	payload := events.PaymentsUserSubscriptionExpiredPayload{
		PurchaseID:           "01970000-0000-7000-8000-eeee00000001",
		LearnerGcid:          psTestGcid,
		PlanSku:              "subscription.familiar.standard_monthly.v1",
		StripeSessionID:      "cs_test_expired_1",
		StripeSubscriptionID: psTestStripeID,
		ExpiredAt:            time.Now().UTC(),
	}
	if err := sub.HandleExpired(context.Background(), env, payload); err != nil {
		t.Fatalf("handle: %v", err)
	}
	got, _ := subs.GetByStripeSubscriptionID(context.Background(), psTestStripeID)
	if got.Status != usersub.StatusExpired && got.Status != usersub.StatusCancelled {
		t.Errorf("expected expired or cancelled after session expiry; got %v", got.Status)
	}
}

func TestPaymentsSubscriber_HandleExpired_NoSubscriptionHandleDropsCleanly(t *testing.T) {
	t.Parallel()
	sub, subs := buildPaymentsSubscriber(t)
	s := seedActiveSubscription(t, subs)
	initialStatus := s.Status

	env := paymentsEnvelope()
	// Only session_id — no subscription_id. Subscriber should drop cleanly
	// without errors + without state change (no local handle to resolve).
	payload := events.PaymentsUserSubscriptionExpiredPayload{
		PurchaseID:      "01970000-0000-7000-8000-eeee00000002",
		LearnerGcid:     psTestGcid,
		StripeSessionID: "cs_test_session_only",
		ExpiredAt:       time.Now().UTC(),
	}
	if err := sub.HandleExpired(context.Background(), env, payload); err != nil {
		t.Fatalf("handle: %v", err)
	}
	got, _ := subs.GetByStripeSubscriptionID(context.Background(), psTestStripeID)
	if got.Status != initialStatus {
		t.Errorf("expected status unchanged (drop-clean); got %v", got.Status)
	}
}

// -----------------------------------------------------------------------------
// Idempotency
// -----------------------------------------------------------------------------

func TestPaymentsSubscriber_PaymentCaptured_Idempotent(t *testing.T) {
	t.Parallel()
	sub, subs := buildPaymentsSubscriber(t)
	seedActiveSubscription(t, subs)

	env := paymentsEnvelope()
	payload := events.PaymentsUserSubscriptionPaymentCapturedPayload{
		PurchaseID:           "01970000-0000-7000-8000-aaaa11111111",
		LearnerGcid:          psTestGcid,
		StripeSubscriptionID: psTestStripeID,
		PeriodStart:          time.Now().UTC(),
		PeriodEnd:            time.Now().UTC().Add(30 * 24 * time.Hour),
		PaidAt:               time.Now().UTC(),
	}
	if err := sub.HandlePaymentCaptured(context.Background(), env, payload); err != nil {
		t.Fatalf("first handle: %v", err)
	}
	gotAfter1, _ := subs.GetByStripeSubscriptionID(context.Background(), psTestStripeID)
	verAfter1 := gotAfter1.Version

	// Replay — same envelope idempotency key.
	if err := sub.HandlePaymentCaptured(context.Background(), env, payload); err != nil {
		t.Fatalf("replay handle: %v", err)
	}
	gotAfter2, _ := subs.GetByStripeSubscriptionID(context.Background(), psTestStripeID)
	if gotAfter2.Version != verAfter1 {
		t.Errorf("replay incremented Version: %d → %d (expected no-op)", verAfter1, gotAfter2.Version)
	}
}

// -----------------------------------------------------------------------------
// Envelope validation
// -----------------------------------------------------------------------------

func TestPaymentsSubscriber_HandlePaymentCaptured_RejectsBlankStripeID(t *testing.T) {
	t.Parallel()
	sub, _ := buildPaymentsSubscriber(t)
	env := paymentsEnvelope()
	payload := events.PaymentsUserSubscriptionPaymentCapturedPayload{
		PurchaseID:           "01970000-0000-7000-8000-aaaa22222222",
		LearnerGcid:          psTestGcid,
		StripeSubscriptionID: "",
		PeriodStart:          time.Now().UTC(),
		PeriodEnd:            time.Now().UTC().Add(30 * 24 * time.Hour),
		PaidAt:               time.Now().UTC(),
	}
	if err := sub.HandlePaymentCaptured(context.Background(), env, payload); err == nil {
		t.Fatalf("expected error for empty stripe_subscription_id")
	}
}

func TestPaymentsSubscriber_HandlePaymentCaptured_RejectsAGID(t *testing.T) {
	t.Parallel()
	sub, _ := buildPaymentsSubscriber(t)
	agid := "0197a000-0000-0000-0000-000000000001"
	env := events.NewEnvelope(psTestTenantID, agid, psTraceparent, "")
	payload := events.PaymentsUserSubscriptionPaymentCapturedPayload{
		PurchaseID:           "01970000-0000-7000-8000-aaaa33333333",
		LearnerGcid:          agid,
		StripeSubscriptionID: psTestStripeID,
		PeriodStart:          time.Now().UTC(),
		PeriodEnd:            time.Now().UTC().Add(30 * 24 * time.Hour),
		PaidAt:               time.Now().UTC(),
	}
	if err := sub.HandlePaymentCaptured(context.Background(), env, payload); err == nil {
		t.Fatalf("expected AGID rejection")
	}
}

func TestPaymentsSubscriber_HandlePaymentCaptured_RejectsMissingTenant(t *testing.T) {
	t.Parallel()
	sub, _ := buildPaymentsSubscriber(t)
	env := paymentsEnvelope()
	env.TenantID = ""
	payload := events.PaymentsUserSubscriptionPaymentCapturedPayload{
		PurchaseID:           "01970000-0000-7000-8000-aaaa44444444",
		LearnerGcid:          psTestGcid,
		StripeSubscriptionID: psTestStripeID,
		PeriodStart:          time.Now().UTC(),
		PeriodEnd:            time.Now().UTC().Add(30 * 24 * time.Hour),
		PaidAt:               time.Now().UTC(),
	}
	if err := sub.HandlePaymentCaptured(context.Background(), env, payload); err == nil {
		t.Fatalf("expected envelope-validation rejection for missing tenant")
	}
}

// -----------------------------------------------------------------------------
// Subscription not found — unknown stripe_subscription_id
// -----------------------------------------------------------------------------

func TestPaymentsSubscriber_HandlePaymentCaptured_UnknownStripeID_DropsCleanly(t *testing.T) {
	t.Parallel()
	sub, subs := buildPaymentsSubscriber(t)
	// Don't seed — repo is empty.
	_ = subs

	env := paymentsEnvelope()
	payload := events.PaymentsUserSubscriptionPaymentCapturedPayload{
		PurchaseID:           "01970000-0000-7000-8000-aaaa55555555",
		LearnerGcid:          psTestGcid,
		StripeSubscriptionID: "sub_test_unknown",
		PeriodStart:          time.Now().UTC(),
		PeriodEnd:            time.Now().UTC().Add(30 * 24 * time.Hour),
		PaidAt:               time.Now().UTC(),
	}
	err := sub.HandlePaymentCaptured(context.Background(), env, payload)
	// Should not error — unknown sub_ids are dropped cleanly so the event
	// doesn't end up in DLQ on retries. The subscriber surfaces an
	// idempotent.Process style nil so the Pub/Sub adapter acks.
	if err != nil && !errors.Is(err, events.ErrPaymentsSubscriptionNotFound) {
		t.Fatalf("unexpected error: %v", err)
	}
}

// -----------------------------------------------------------------------------
// SubscribedTopics enumeration
// -----------------------------------------------------------------------------

func TestPaymentsSubscriber_SubscribedTopics(t *testing.T) {
	t.Parallel()
	sub, _ := buildPaymentsSubscriber(t)
	topics := sub.SubscribedTopics()
	if len(topics) != 4 {
		t.Errorf("expected 4 topics; got %d", len(topics))
	}
	want := map[string]bool{
		events.TopicPaymentsUserSubscriptionCaptured: true,
		events.TopicPaymentsUserSubscriptionFailed:   true,
		events.TopicPaymentsUserSubscriptionRefunded: true,
		events.TopicPaymentsUserSubscriptionExpired:  true,
	}
	for _, topic := range topics {
		if !want[topic] {
			t.Errorf("unexpected topic %q", topic)
		}
	}
}

// -----------------------------------------------------------------------------
// Nil guards
// -----------------------------------------------------------------------------

func TestPaymentsSubscriber_NilSubscriberRejects(t *testing.T) {
	t.Parallel()
	var sub *events.PaymentsSubscriber
	if err := sub.HandlePaymentCaptured(context.Background(), events.Envelope{}, events.PaymentsUserSubscriptionPaymentCapturedPayload{}); err == nil {
		t.Errorf("nil sub HandlePaymentCaptured should error")
	}
	if err := sub.HandlePaymentFailed(context.Background(), events.Envelope{}, events.PaymentsUserSubscriptionPaymentFailedPayload{}); err == nil {
		t.Errorf("nil sub HandlePaymentFailed should error")
	}
	if err := sub.HandleRefunded(context.Background(), events.Envelope{}, events.PaymentsUserSubscriptionRefundedPayload{}); err == nil {
		t.Errorf("nil sub HandleRefunded should error")
	}
	if err := sub.HandleExpired(context.Background(), events.Envelope{}, events.PaymentsUserSubscriptionExpiredPayload{}); err == nil {
		t.Errorf("nil sub HandleExpired should error")
	}
}

// -----------------------------------------------------------------------------
// Terminal-state idempotency: refund / expire on already-cancelled
// -----------------------------------------------------------------------------

func TestPaymentsSubscriber_HandleRefunded_AlreadyCancelled_IsNoOp(t *testing.T) {
	t.Parallel()
	sub, subs := buildPaymentsSubscriber(t)
	s := seedActiveSubscription(t, subs)
	_ = s.Activate()
	_ = s.Cancel("user_cancelled", "", time.Now().UTC())
	if err := subs.Save(context.Background(), s); err != nil {
		t.Fatalf("seed save: %v", err)
	}

	env := paymentsEnvelope()
	payload := events.PaymentsUserSubscriptionRefundedPayload{
		PurchaseID:           "01970000-0000-7000-8000-dddd00000099",
		LearnerGcid:          psTestGcid,
		StripeSubscriptionID: psTestStripeID,
		StripeRefundID:       "re_test_already_cancelled",
		AmountCentsRefunded:  1499,
		Currency:             "USD",
		RefundedAt:           time.Now().UTC(),
	}
	if err := sub.HandleRefunded(context.Background(), env, payload); err != nil {
		t.Fatalf("handle: %v", err)
	}
	got, _ := subs.GetByStripeSubscriptionID(context.Background(), psTestStripeID)
	if got.Status != usersub.StatusCancelled {
		t.Errorf("status changed: got %v", got.Status)
	}
}

func TestPaymentsSubscriber_HandleExpired_AlreadyExpired_IsNoOp(t *testing.T) {
	t.Parallel()
	sub, subs := buildPaymentsSubscriber(t)
	s := seedActiveSubscription(t, subs)
	_ = s.Activate()
	_ = s.MarkExpired()
	if err := subs.Save(context.Background(), s); err != nil {
		t.Fatalf("seed save: %v", err)
	}

	env := paymentsEnvelope()
	payload := events.PaymentsUserSubscriptionExpiredPayload{
		PurchaseID:           "01970000-0000-7000-8000-eeee00000099",
		LearnerGcid:          psTestGcid,
		StripeSubscriptionID: psTestStripeID,
		ExpiredAt:            time.Now().UTC(),
	}
	if err := sub.HandleExpired(context.Background(), env, payload); err != nil {
		t.Fatalf("handle: %v", err)
	}
	got, _ := subs.GetByStripeSubscriptionID(context.Background(), psTestStripeID)
	if got.Status != usersub.StatusExpired {
		t.Errorf("status changed: got %v", got.Status)
	}
}

// -----------------------------------------------------------------------------
// payment_failed: not-active is no-op
// -----------------------------------------------------------------------------

func TestPaymentsSubscriber_HandlePaymentFailed_NotActiveIsNoOp(t *testing.T) {
	t.Parallel()
	sub, subs := buildPaymentsSubscriber(t)
	// Leave subscription in pending_activation.
	seedActiveSubscription(t, subs)

	env := paymentsEnvelope()
	payload := events.PaymentsUserSubscriptionPaymentFailedPayload{
		PurchaseID:           "01970000-0000-7000-8000-ccccc0000099",
		LearnerGcid:          psTestGcid,
		StripeSubscriptionID: psTestStripeID,
		FailedAt:             time.Now().UTC(),
	}
	if err := sub.HandlePaymentFailed(context.Background(), env, payload); err != nil {
		t.Fatalf("handle: %v", err)
	}
	got, _ := subs.GetByStripeSubscriptionID(context.Background(), psTestStripeID)
	if got.Status != usersub.StatusPendingActivation {
		t.Errorf("expected no-op (status unchanged); got %v", got.Status)
	}
}

// -----------------------------------------------------------------------------
// payment_failed / refunded / expired: unknown stripe_id drops cleanly
// -----------------------------------------------------------------------------

func TestPaymentsSubscriber_HandlePaymentFailed_UnknownStripeID_DropsCleanly(t *testing.T) {
	t.Parallel()
	sub, _ := buildPaymentsSubscriber(t)
	env := paymentsEnvelope()
	payload := events.PaymentsUserSubscriptionPaymentFailedPayload{
		PurchaseID:           "01970000-0000-7000-8000-ccccc0000aaa",
		LearnerGcid:          psTestGcid,
		StripeSubscriptionID: "sub_unknown_xyz",
		FailedAt:             time.Now().UTC(),
	}
	if err := sub.HandlePaymentFailed(context.Background(), env, payload); err != nil {
		t.Fatalf("expected no error for unknown stripe_id; got %v", err)
	}
}

func TestPaymentsSubscriber_HandleRefunded_UnknownStripeID_DropsCleanly(t *testing.T) {
	t.Parallel()
	sub, _ := buildPaymentsSubscriber(t)
	env := paymentsEnvelope()
	payload := events.PaymentsUserSubscriptionRefundedPayload{
		PurchaseID:           "01970000-0000-7000-8000-dddd00000aaa",
		LearnerGcid:          psTestGcid,
		StripeSubscriptionID: "sub_unknown_xyz",
		StripeRefundID:       "re_unknown",
		AmountCentsRefunded:  1499,
		Currency:             "USD",
		RefundedAt:           time.Now().UTC(),
	}
	if err := sub.HandleRefunded(context.Background(), env, payload); err != nil {
		t.Fatalf("expected no error for unknown stripe_id; got %v", err)
	}
}

// -----------------------------------------------------------------------------
// Expired: pending_activation → cancelled (initial Checkout abandoned)
// -----------------------------------------------------------------------------

func TestPaymentsSubscriber_HandleExpired_PendingActivationCancels(t *testing.T) {
	t.Parallel()
	sub, subs := buildPaymentsSubscriber(t)
	seedActiveSubscription(t, subs)
	// Leave in pending_activation (initial seed state).

	env := paymentsEnvelope()
	payload := events.PaymentsUserSubscriptionExpiredPayload{
		PurchaseID:           "01970000-0000-7000-8000-eeee000000aa",
		LearnerGcid:          psTestGcid,
		StripeSubscriptionID: psTestStripeID,
		StripeSessionID:      "cs_test_pending_expired",
		ExpiredAt:            time.Now().UTC(),
	}
	if err := sub.HandleExpired(context.Background(), env, payload); err != nil {
		t.Fatalf("handle: %v", err)
	}
	got, _ := subs.GetByStripeSubscriptionID(context.Background(), psTestStripeID)
	if got.Status != usersub.StatusCancelled {
		t.Errorf("expected cancelled (initial checkout abandoned); got %v", got.Status)
	}
}

// -----------------------------------------------------------------------------
// WithInboxTTL
// -----------------------------------------------------------------------------

func TestPaymentsSubscriber_WithInboxTTL_Overrides(t *testing.T) {
	t.Parallel()
	subs := repo.NewInMemUserSubscriptionRepo()
	seedActiveSubscription(t, subs)
	inbox := idempotent.NewMemoryStore()
	sub := events.NewPaymentsSubscriber(subs, inbox).WithInboxTTL(50 * time.Millisecond)

	env := paymentsEnvelope()
	period1End := time.Now().UTC().Add(30 * 24 * time.Hour)
	period2End := time.Now().UTC().Add(60 * 24 * time.Hour)
	payload1 := events.PaymentsUserSubscriptionPaymentCapturedPayload{
		PurchaseID:           "01970000-0000-7000-8000-aaaa66666666",
		LearnerGcid:          psTestGcid,
		StripeSubscriptionID: psTestStripeID,
		PeriodStart:          time.Now().UTC(),
		PeriodEnd:            period1End,
		PaidAt:               time.Now().UTC(),
	}
	if err := sub.HandlePaymentCaptured(context.Background(), env, payload1); err != nil {
		t.Fatalf("first handle: %v", err)
	}
	gotAfter1, _ := subs.GetByStripeSubscriptionID(context.Background(), psTestStripeID)
	if !gotAfter1.CurrentPeriodEnd.Equal(period1End) {
		t.Fatalf("first handle should set period_end to %v; got %v", period1End, gotAfter1.CurrentPeriodEnd)
	}

	// Advance past short TTL — replay should re-run with NEW period boundaries.
	inbox.Advance(100 * time.Millisecond)
	payload2 := payload1
	payload2.PeriodEnd = period2End
	if err := sub.HandlePaymentCaptured(context.Background(), env, payload2); err != nil {
		t.Fatalf("replay handle: %v", err)
	}
	gotAfter2, _ := subs.GetByStripeSubscriptionID(context.Background(), psTestStripeID)
	if !gotAfter2.CurrentPeriodEnd.Equal(period2End) {
		t.Errorf("TTL expiry: expected period_end %v; got %v", period2End, gotAfter2.CurrentPeriodEnd)
	}
}

// TestPaymentsSubscriber_HandleExpired_ValidationBranches drives every error
// branch of validateBaseExpired: missing learner gcid, AGID-shaped gcid,
// missing subscription/session handle, and a missing envelope tenant_id.
func TestPaymentsSubscriber_HandleExpired_ValidationBranches(t *testing.T) {
	t.Parallel()
	sub, _ := buildPaymentsSubscriber(t)
	env := paymentsEnvelope()
	base := events.PaymentsUserSubscriptionExpiredPayload{
		LearnerGcid:          psTestGcid,
		StripeSubscriptionID: psTestStripeID,
	}
	cases := []struct {
		name    string
		env     events.Envelope
		payload events.PaymentsUserSubscriptionExpiredPayload
	}{
		{"missing learner gcid", env, events.PaymentsUserSubscriptionExpiredPayload{StripeSubscriptionID: psTestStripeID}},
		{"AGID learner", env, events.PaymentsUserSubscriptionExpiredPayload{LearnerGcid: "0197a000000000000000000000000000", StripeSubscriptionID: psTestStripeID}},
		{"missing stripe handle", env, events.PaymentsUserSubscriptionExpiredPayload{LearnerGcid: psTestGcid}},
		{"missing tenant", events.Envelope{}, base},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			if err := sub.HandleExpired(context.Background(), tc.env, tc.payload); err == nil {
				t.Errorf("expected validation error")
			}
		})
	}
}

// TestPaymentsSubscriber_New_NilInboxFallsBack drives the MemoryStore
// fallback in NewPaymentsSubscriber.
func TestPaymentsSubscriber_New_NilInboxFallsBack(t *testing.T) {
	t.Parallel()
	subs := repo.NewInMemUserSubscriptionRepo()
	sub := events.NewPaymentsSubscriber(subs, nil)
	if sub == nil {
		t.Fatal("expected non-nil subscriber")
	}
}

// TestPaymentsSubscriber_HandlePaymentCaptured_AGIDRejected drives the AGID
// branch of validateBase.
func TestPaymentsSubscriber_HandlePaymentCaptured_AGIDRejected(t *testing.T) {
	t.Parallel()
	sub, _ := buildPaymentsSubscriber(t)
	env := paymentsEnvelope()
	payload := events.PaymentsUserSubscriptionPaymentCapturedPayload{
		LearnerGcid:          "0197a000000000000000000000000000",
		StripeSubscriptionID: psTestStripeID,
	}
	if err := sub.HandlePaymentCaptured(context.Background(), env, payload); err == nil {
		t.Error("AGID learner must be rejected")
	}
}

// TestPaymentsSubscriber_SyntheticIdempotencyKey drives the fallback key
// path (envelope without idempotency_key → synthetic
// "payments-{event_type}:{stripe_id}:{purchase_id}"). An unknown stripe id
// drops cleanly afterwards, so the whole path runs without side effects.
func TestPaymentsSubscriber_SyntheticIdempotencyKey(t *testing.T) {
	t.Parallel()
	sub, _ := buildPaymentsSubscriber(t)
	env := paymentsEnvelope()
	env.IdempotencyKey = ""
	payload := events.PaymentsUserSubscriptionPaymentCapturedPayload{
		PurchaseID:           "p-synth-1",
		LearnerGcid:          psTestGcid,
		StripeSubscriptionID: "sub_does_not_exist",
	}
	if err := sub.HandlePaymentCaptured(context.Background(), env, payload); err != nil {
		t.Fatalf("HandlePaymentCaptured: %v", err)
	}
}

// TestPaymentsSubscriber_HandleExpired_SessionOnlyHandleDropsCleanly drives
// the empty-subscription-id drop inside HandleExpired (session-id-only
// payloads have no local handle to resolve).
func TestPaymentsSubscriber_HandleExpired_SessionOnlyHandleDropsCleanly(t *testing.T) {
	t.Parallel()
	sub, _ := buildPaymentsSubscriber(t)
	env := paymentsEnvelope()
	payload := events.PaymentsUserSubscriptionExpiredPayload{
		LearnerGcid:     psTestGcid,
		StripeSessionID: "cs_test_expired_session",
		ExpiredAt:       time.Now().UTC(),
	}
	if err := sub.HandleExpired(context.Background(), env, payload); err != nil {
		t.Fatalf("HandleExpired: %v", err)
	}
}

// TestPaymentsSubscriber_HandleExpired_AlreadyTerminalIsNoOp seeds an
// already-cancelled subscription so the terminal switch branch short-circuits.
func TestPaymentsSubscriber_HandleExpired_AlreadyTerminalIsNoOp(t *testing.T) {
	t.Parallel()
	sub, subs := buildPaymentsSubscriber(t)
	s := seedActiveSubscription(t, subs)
	if err := s.Cancel("already_done", "", time.Now().UTC()); err != nil {
		t.Fatalf("cancel seed: %v", err)
	}
	if err := subs.Save(context.Background(), s); err != nil {
		t.Fatalf("save seed: %v", err)
	}
	env := paymentsEnvelope()
	payload := events.PaymentsUserSubscriptionExpiredPayload{
		LearnerGcid:          psTestGcid,
		StripeSubscriptionID: psTestStripeID,
		ExpiredAt:            time.Now().UTC(),
	}
	if err := sub.HandleExpired(context.Background(), env, payload); err != nil {
		t.Fatalf("HandleExpired: %v", err)
	}
	got, _ := subs.GetByStripeSubscriptionID(context.Background(), psTestStripeID)
	if got.Status != usersub.StatusCancelled {
		t.Errorf("status = %v, want cancelled (unchanged)", got.Status)
	}
}

// -----------------------------------------------------------------------------
// FSM transition coverage (gaps left by the existing suite)
// -----------------------------------------------------------------------------

// TestPaymentsSubscriber_HandlePaymentFailed_ActiveEntersGrace drives the
// active → grace transition (the existing NotActiveIsNoOp test leaves the
// seed sub in pending_activation and never actually calls EnterGrace).
func TestPaymentsSubscriber_HandlePaymentFailed_ActiveEntersGrace(t *testing.T) {
	t.Parallel()
	sub, subs := buildPaymentsSubscriber(t)
	s := seedActiveSubscription(t, subs)
	if err := s.Activate(); err != nil {
		t.Fatalf("activate seed: %v", err)
	}
	if err := subs.Save(context.Background(), s); err != nil {
		t.Fatalf("save seed: %v", err)
	}

	env := paymentsEnvelope()
	payload := events.PaymentsUserSubscriptionPaymentFailedPayload{
		PurchaseID:           "01970000-0000-7000-8000-ccccc0000100",
		LearnerGcid:          psTestGcid,
		StripeSubscriptionID: psTestStripeID,
		StripeFailureCode:    "", // fallback reason "payment_failed"
		FailedAt:             time.Now().UTC(),
	}
	if err := sub.HandlePaymentFailed(context.Background(), env, payload); err != nil {
		t.Fatalf("HandlePaymentFailed: %v", err)
	}
	got, _ := subs.GetByStripeSubscriptionID(context.Background(), psTestStripeID)
	if got.Status != usersub.StatusGrace {
		t.Errorf("status = %v, want grace", got.Status)
	}
}

// TestPaymentsSubscriber_HandlePaymentCaptured_TerminalNoOp seeds a cancelled
// subscription — payment capture on a terminal sub is an idempotent no-op.
func TestPaymentsSubscriber_HandlePaymentCaptured_TerminalNoOp(t *testing.T) {
	t.Parallel()
	sub, subs := buildPaymentsSubscriber(t)
	s := seedActiveSubscription(t, subs)
	if err := s.Cancel("user_requested", "", time.Now().UTC()); err != nil {
		t.Fatalf("cancel seed: %v", err)
	}
	if err := subs.Save(context.Background(), s); err != nil {
		t.Fatalf("save seed: %v", err)
	}

	env := paymentsEnvelope()
	payload := events.PaymentsUserSubscriptionPaymentCapturedPayload{
		PurchaseID:           "p-terminal-1",
		LearnerGcid:          psTestGcid,
		StripeSubscriptionID: psTestStripeID,
		PeriodStart:          time.Now().UTC(),
		PeriodEnd:            time.Now().UTC().Add(30 * 24 * time.Hour),
	}
	if err := sub.HandlePaymentCaptured(context.Background(), env, payload); err != nil {
		t.Fatalf("HandlePaymentCaptured: %v", err)
	}
	got, _ := subs.GetByStripeSubscriptionID(context.Background(), psTestStripeID)
	if got.Status != usersub.StatusCancelled {
		t.Errorf("status = %v, want cancelled (unchanged)", got.Status)
	}
}

// TestPaymentsSubscriber_HandlePaymentCaptured_PausedResumes drives the
// paused → active resume-on-capture branch.
func TestPaymentsSubscriber_HandlePaymentCaptured_PausedResumes(t *testing.T) {
	t.Parallel()
	sub, subs := buildPaymentsSubscriber(t)
	s := seedActiveSubscription(t, subs)
	if err := s.Activate(); err != nil {
		t.Fatalf("activate seed: %v", err)
	}
	if err := s.Pause("admin_hold"); err != nil {
		t.Fatalf("pause seed: %v", err)
	}
	if err := subs.Save(context.Background(), s); err != nil {
		t.Fatalf("save seed: %v", err)
	}

	env := paymentsEnvelope()
	payload := events.PaymentsUserSubscriptionPaymentCapturedPayload{
		PurchaseID:           "p-resume-1",
		LearnerGcid:          psTestGcid,
		StripeSubscriptionID: psTestStripeID,
		PeriodStart:          time.Now().UTC(),
		PeriodEnd:            time.Now().UTC().Add(30 * 24 * time.Hour),
	}
	if err := sub.HandlePaymentCaptured(context.Background(), env, payload); err != nil {
		t.Fatalf("HandlePaymentCaptured: %v", err)
	}
	got, _ := subs.GetByStripeSubscriptionID(context.Background(), psTestStripeID)
	if got.Status != usersub.StatusActive {
		t.Errorf("status = %v, want active (resumed)", got.Status)
	}
}

// TestPaymentsSubscriber_HandleExpired_UnknownStripeID_DropsCleanly drives
// the ErrNotFound drop inside HandleExpired.
func TestPaymentsSubscriber_HandleExpired_UnknownStripeID_DropsCleanly(t *testing.T) {
	t.Parallel()
	sub, _ := buildPaymentsSubscriber(t)
	env := paymentsEnvelope()
	payload := events.PaymentsUserSubscriptionExpiredPayload{
		LearnerGcid:          psTestGcid,
		StripeSubscriptionID: "sub_expired_unknown_000",
		ExpiredAt:            time.Now().UTC(),
	}
	if err := sub.HandleExpired(context.Background(), env, payload); err != nil {
		t.Fatalf("HandleExpired: %v", err)
	}
}

// TestPaymentsSubscriber_HandlePaymentCaptured_EmptyLearnerGcid drives the
// empty-learner branch of validateBase.
func TestPaymentsSubscriber_HandlePaymentCaptured_EmptyLearnerGcid(t *testing.T) {
	t.Parallel()
	sub, _ := buildPaymentsSubscriber(t)
	payload := events.PaymentsUserSubscriptionPaymentCapturedPayload{
		StripeSubscriptionID: psTestStripeID,
	}
	if err := sub.HandlePaymentCaptured(context.Background(), paymentsEnvelope(), payload); err == nil {
		t.Error("empty learner gcid must be rejected by validateBase")
	}
}
