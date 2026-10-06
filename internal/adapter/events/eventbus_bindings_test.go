// eventbus_bindings_test.go — tests for the handler adapters that bind the
// four cross-domain subscribers (enrollment, payments, kyc-fee,
// tenant-bootstrapped) to the NATS JetStream consume loop.
//
// Each adapter must decode the producer's wire format onto the subscriber's
// payload struct:
//
//	chora.delivery.enrollment.created.v1        → JSON (no Protobuf encoder
//	                                              in chora-delivery's registry)
//	chora.payments.user_subscription.*.v1       → Protobuf (envelope embedded)
//	chora.payments.identity_kyc_fee.*.v1        → Protobuf (envelope embedded)
//	chora.tenancy.tenant.bootstrapped.v1        → Protobuf (envelope embedded)
//
// The payloads below are built exactly as the producers build them
// (chora-payments outbox/payload.go marshalUserSubscription /
// marshalIdentityKycFee; chora-tenancy pg/bootstrap_outbox.go
// buildBootstrapOutboxRow) and proto.Marshal'd, so the decode path under test
// is the production wire path.
package events_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/apollo-chora/chora-common/envelope"
	"github.com/apollo-chora/chora-common/eventbus"

	commonv1 "github.com/apollo-chora/chora-contracts/gen/go/chora/common/v1"
	paymentsv1 "github.com/apollo-chora/chora-contracts/gen/go/chora/payments/v1"
	tenancyv1 "github.com/apollo-chora/chora-contracts/gen/go/chora/tenancy/v1"
	"github.com/apollo-chora/chora-identity/internal/adapter/events"
	"github.com/apollo-chora/chora-identity/internal/domain/identity"
	usersub "github.com/apollo-chora/chora-identity/internal/domain/user_subscription"
)

// bindingEnvelope builds the transport envelope the eventbus reconstructs
// from NATS headers (chora-common/eventbus envelopeFromHeaders). The
// producers stamp source_project + source_service on the publish headers,
// so the reconstructed transport envelope carries them.
func bindingEnvelope(tenant, gcid, idem string) envelope.Envelope {
	now := time.Now().UTC()
	return envelope.Envelope{
		EventID:        "01935b5a-9bcf-7000-8000-0000000000e1",
		IdempotencyKey: idem,
		TenantID:       tenant,
		GCID:           gcid,
		OccurredAt:     now,
		PublishedAt:    now,
		Traceparent:    "00-aabbccddeeff00112233445566778899-0011223344556677-01",
		SourceProject:  "chora-489812",
		SourceService:  "chora-payments",
		SchemaVersion:  1,
	}
}

// -----------------------------------------------------------------------------
// EnrollmentHandler — chora.delivery emits JSON
// -----------------------------------------------------------------------------

func TestEnrollmentHandler_DispatchesAndProjectsCourseRole(t *testing.T) {
	sub, roles, rec := buildEnrollmentSubscriber(t)
	handler := events.EnrollmentHandler(sub)

	// Exactly the JSON body chora-delivery's PublishEnrollmentCreated emits.
	body, err := json.Marshal(map[string]any{
		"enrollment_id":        "01935b5a-9bcf-7000-8000-aaaaaa000001",
		"course_id":            "01935b5a-9bcf-7000-8000-000000000099",
		"learner_gcid":         "01935b5a-9bcf-7000-8000-0000000000aa",
		"enrolled_at":          time.Now().UTC().Format(time.RFC3339Nano),
		"chora_imda_dimension": "accountability",
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	msg := eventbus.Message{
		Subject:  events.TopicEnrollmentCreated,
		Envelope: bindingEnvelope("01935b5a-9bcf-7000-8000-000000000010", "01935b5a-9bcf-7000-8000-0000000000aa", "idem-enroll-1"),
		Payload:  body,
	}
	if err := handler(context.Background(), msg); err != nil {
		t.Fatalf("handler: %v", err)
	}
	ctx := context.Background()
	got, err := roles.GetAssignment(ctx, "01935b5a-9bcf-7000-8000-0000000000aa", "01935b5a-9bcf-7000-8000-000000000099")
	if err != nil {
		t.Fatalf("expected assignment; got %v", err)
	}
	if got.Role != identity.CourseRoleLearner {
		t.Fatalf("expected learner; got %v", got.Role)
	}
	if emitted := rec.RecordedByTopic("chora.identity.role.granted.v1"); len(emitted) != 1 {
		t.Fatalf("expected 1 role.granted.v1 emit, got %d", len(emitted))
	}
}

func TestEnrollmentHandler_MalformedJSONErrors(t *testing.T) {
	sub, _, _ := buildEnrollmentSubscriber(t)
	handler := events.EnrollmentHandler(sub)
	msg := eventbus.Message{
		Subject:  events.TopicEnrollmentCreated,
		Envelope: bindingEnvelope("t-1", "g-1", "idem-1"),
		Payload:  []byte("{not-json"),
	}
	if err := handler(context.Background(), msg); err == nil {
		t.Fatal("malformed payload must error (nack)")
	}
}

func TestEnrollmentHandler_MissingTransportTenantErrors(t *testing.T) {
	// chora-delivery's JSON body carries no embedded envelope, so the
	// transport envelope is the only tenant source — an empty one must
	// fail the subscriber's validation gate.
	sub, _, _ := buildEnrollmentSubscriber(t)
	handler := events.EnrollmentHandler(sub)
	body, _ := json.Marshal(map[string]any{
		"enrollment_id": "e-1", "course_id": "c-1", "learner_gcid": "g-1",
	})
	msg := eventbus.Message{
		Subject:  events.TopicEnrollmentCreated,
		Envelope: envelope.Envelope{EventID: "e1", IdempotencyKey: "i1", Traceparent: "00-x-01"},
		Payload:  body,
	}
	if err := handler(context.Background(), msg); err == nil {
		t.Fatal("missing tenant_id must error")
	}
}

func TestEnrollmentHandler_NilSubscriberErrors(t *testing.T) {
	if err := events.EnrollmentHandler(nil)(context.Background(), eventbus.Message{Payload: []byte("{}")}); err == nil {
		t.Fatal("nil subscriber must error")
	}
}

// -----------------------------------------------------------------------------
// PaymentsHandler — chora-payments emits Protobuf
// -----------------------------------------------------------------------------

func paymentsCapturedProto(t *testing.T, idem string) []byte {
	t.Helper()
	now := time.Now().UTC()
	ev := &paymentsv1.UserSubscriptionPaymentCaptured{
		Envelope: &commonv1.EventEnvelope{
			EventId:        "01935b5a-9bcf-7000-8000-0000000000e2",
			IdempotencyKey: idem,
			TenantId:       psTestTenantID,
			Gcid:           psTestGcid,
			OccurredAt:     timestamppb.New(now),
			PublishedAt:    timestamppb.New(now),
			Traceparent:    "00-aabbccddeeff00112233445566778899-0011223344556677-01",
		},
		PurchaseId:            "p-1",
		LearnerGcid:           psTestGcid,
		PlanSku:               "subscription.companion.standard_monthly.v1",
		BillingPeriod:         "monthly",
		StripeSubscriptionId:  psTestStripeID,
		StripeInvoiceId:       "in_1",
		StripePaymentIntentId: "pi_1",
		StripeChargeId:        "ch_1",
		AmountCentsPaid:       999,
		Currency:              "USD",
		PeriodStart:           timestamppb.New(now),
		PeriodEnd:             timestamppb.New(now.Add(30 * 24 * time.Hour)),
		PaidAt:                timestamppb.New(now),
	}
	bz, err := proto.Marshal(ev)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return bz
}

func TestPaymentsHandler_PaymentCaptured_ActivatesPendingSubscription(t *testing.T) {
	sub, subs := buildPaymentsSubscriber(t)
	seedActiveSubscription(t, subs) // pending_activation with psTestStripeID
	handler := events.PaymentsHandler(sub)

	msg := eventbus.Message{
		Subject:  events.TopicPaymentsUserSubscriptionCaptured,
		Envelope: bindingEnvelope(psTestTenantID, psTestGcid, "idem-pay-1"),
		Payload:  paymentsCapturedProto(t, "idem-pay-1"),
	}
	if err := handler(context.Background(), msg); err != nil {
		t.Fatalf("handler: %v", err)
	}
	s, err := subs.GetByStripeSubscriptionID(context.Background(), psTestStripeID)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if s.Status != usersub.StatusActive {
		t.Fatalf("status = %q, want active", s.Status)
	}
}

func TestPaymentsHandler_PaymentFailed_EntersGrace(t *testing.T) {
	sub, subs := buildPaymentsSubscriber(t)
	s := seedActiveSubscription(t, subs)
	if err := s.Activate(); err != nil {
		t.Fatalf("activate: %v", err)
	}
	if err := subs.Save(context.Background(), s); err != nil {
		t.Fatalf("save: %v", err)
	}
	handler := events.PaymentsHandler(sub)

	now := time.Now().UTC()
	ev := &paymentsv1.UserSubscriptionPaymentFailed{
		Envelope: &commonv1.EventEnvelope{
			EventId:        "01935b5a-9bcf-7000-8000-0000000000e3",
			IdempotencyKey: "idem-pay-2",
			TenantId:       psTestTenantID,
			Gcid:           psTestGcid,
			OccurredAt:     timestamppb.New(now),
			PublishedAt:    timestamppb.New(now),
			Traceparent:    "00-aabbccddeeff00112233445566778899-0011223344556677-01",
		},
		PurchaseId:           "p-1",
		LearnerGcid:          psTestGcid,
		StripeSubscriptionId: psTestStripeID,
		StripeFailureCode:    "card_declined",
		FailedAt:             timestamppb.New(now),
	}
	bz, err := proto.Marshal(ev)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	msg := eventbus.Message{
		Subject:  events.TopicPaymentsUserSubscriptionFailed,
		Envelope: bindingEnvelope(psTestTenantID, psTestGcid, "idem-pay-2"),
		Payload:  bz,
	}
	if err := handler(context.Background(), msg); err != nil {
		t.Fatalf("handler: %v", err)
	}
	got, err := subs.GetByStripeSubscriptionID(context.Background(), psTestStripeID)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if got.Status != usersub.StatusGrace {
		t.Fatalf("status = %q, want grace", got.Status)
	}
}

func TestPaymentsHandler_Refunded_Cancels(t *testing.T) {
	sub, subs := buildPaymentsSubscriber(t)
	s := seedActiveSubscription(t, subs)
	if err := s.Activate(); err != nil {
		t.Fatalf("activate: %v", err)
	}
	if err := subs.Save(context.Background(), s); err != nil {
		t.Fatalf("save: %v", err)
	}
	handler := events.PaymentsHandler(sub)

	now := time.Now().UTC()
	ev := &paymentsv1.UserSubscriptionRefunded{
		Envelope: &commonv1.EventEnvelope{
			EventId:        "01935b5a-9bcf-7000-8000-0000000000e4",
			IdempotencyKey: "idem-pay-3",
			TenantId:       psTestTenantID,
			Gcid:           psTestGcid,
			OccurredAt:     timestamppb.New(now),
			PublishedAt:    timestamppb.New(now),
			Traceparent:    "00-aabbccddeeff00112233445566778899-0011223344556677-01",
		},
		PurchaseId:           "p-1",
		LearnerGcid:          psTestGcid,
		StripeSubscriptionId: psTestStripeID,
		AmountCentsRefunded:  999,
		Currency:             "USD",
		Reason:               "customer_request",
		RefundedAt:           timestamppb.New(now),
	}
	bz, err := proto.Marshal(ev)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	msg := eventbus.Message{
		Subject:  events.TopicPaymentsUserSubscriptionRefunded,
		Envelope: bindingEnvelope(psTestTenantID, psTestGcid, "idem-pay-3"),
		Payload:  bz,
	}
	if err := handler(context.Background(), msg); err != nil {
		t.Fatalf("handler: %v", err)
	}
	got, err := subs.GetByStripeSubscriptionID(context.Background(), psTestStripeID)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if got.Status != usersub.StatusCancelled {
		t.Fatalf("status = %q, want cancelled", got.Status)
	}
}

func TestPaymentsHandler_Expired_UnknownSubscriptionDropsCleanly(t *testing.T) {
	sub, _ := buildPaymentsSubscriber(t) // no seed — no local handle
	handler := events.PaymentsHandler(sub)

	now := time.Now().UTC()
	ev := &paymentsv1.UserSubscriptionExpired{
		Envelope: &commonv1.EventEnvelope{
			EventId:        "01935b5a-9bcf-7000-8000-0000000000e5",
			IdempotencyKey: "idem-pay-4",
			TenantId:       psTestTenantID,
			Gcid:           psTestGcid,
			OccurredAt:     timestamppb.New(now),
			PublishedAt:    timestamppb.New(now),
			Traceparent:    "00-aabbccddeeff00112233445566778899-0011223344556677-01",
		},
		PurchaseId:      "p-1",
		LearnerGcid:     psTestGcid,
		StripeSessionId: "cs_test_abandoned",
		ExpiredAt:       timestamppb.New(now),
	}
	bz, err := proto.Marshal(ev)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	msg := eventbus.Message{
		Subject:  events.TopicPaymentsUserSubscriptionExpired,
		Envelope: bindingEnvelope(psTestTenantID, psTestGcid, "idem-pay-4"),
		Payload:  bz,
	}
	if err := handler(context.Background(), msg); err != nil {
		t.Fatalf("unknown subscription must drop cleanly, got %v", err)
	}
}

func TestPaymentsHandler_TenantFallsBackToEmbeddedEnvelope(t *testing.T) {
	// The transport envelope carries no tenant/gcid; the Protobuf payload's
	// embedded envelope supplies them (identityEnvelopeFromMsg fallback).
	sub, subs := buildPaymentsSubscriber(t)
	seedActiveSubscription(t, subs)
	handler := events.PaymentsHandler(sub)

	msg := eventbus.Message{
		Subject: events.TopicPaymentsUserSubscriptionCaptured,
		Envelope: envelope.Envelope{
			EventID:        "01935b5a-9bcf-7000-8000-0000000000e2",
			IdempotencyKey: "idem-pay-5",
			Traceparent:    "00-aabbccddeeff00112233445566778899-0011223344556677-01",
		},
		Payload: paymentsCapturedProto(t, "idem-pay-5"),
	}
	if err := handler(context.Background(), msg); err != nil {
		t.Fatalf("handler: %v", err)
	}
	s, err := subs.GetByStripeSubscriptionID(context.Background(), psTestStripeID)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if s.Status != usersub.StatusActive {
		t.Fatalf("status = %q, want active", s.Status)
	}
}

func TestPaymentsHandler_UnknownSubjectErrors(t *testing.T) {
	sub, _ := buildPaymentsSubscriber(t)
	handler := events.PaymentsHandler(sub)
	msg := eventbus.Message{
		Subject:  "chora.payments.user_subscription.renewed.v1",
		Envelope: bindingEnvelope(psTestTenantID, psTestGcid, "idem-1"),
		Payload:  paymentsCapturedProto(t, "idem-1"),
	}
	if err := handler(context.Background(), msg); err == nil {
		t.Fatal("unknown subject must error")
	}
}

func TestPaymentsHandler_MalformedProtoErrors(t *testing.T) {
	sub, _ := buildPaymentsSubscriber(t)
	handler := events.PaymentsHandler(sub)
	msg := eventbus.Message{
		Subject:  events.TopicPaymentsUserSubscriptionCaptured,
		Envelope: bindingEnvelope(psTestTenantID, psTestGcid, "idem-1"),
		Payload:  []byte("not-a-proto"),
	}
	if err := handler(context.Background(), msg); err == nil {
		t.Fatal("malformed payload must error (nack)")
	}
}

func TestPaymentsHandler_NilSubscriberErrors(t *testing.T) {
	if err := events.PaymentsHandler(nil)(context.Background(), eventbus.Message{Payload: []byte("{}")}); err == nil {
		t.Fatal("nil subscriber must error")
	}
}

// -----------------------------------------------------------------------------
// KycFeeHandler — chora-payments emits Protobuf; only captured acts
// -----------------------------------------------------------------------------

func TestKycFeeHandler_Captured_EntersReviewQueueAndEmits(t *testing.T) {
	sub, kycRepo, rec := buildKycFeeSubscriber(t)
	seedPendingManual(t, kycRepo)
	handler := events.KycFeeHandler(sub)

	now := time.Now().UTC()
	ev := &paymentsv1.IdentityKycFeePaymentCaptured{
		Envelope: &commonv1.EventEnvelope{
			EventId:        "01935b5a-9bcf-7000-8000-0000000000e6",
			IdempotencyKey: "idem-kyc-1",
			TenantId:       "01935b5a-9bcf-7000-8000-000000000010",
			Gcid:           kycFeeGcid,
			OccurredAt:     timestamppb.New(now),
			PublishedAt:    timestamppb.New(now),
			Traceparent:    "00-aabbccddeeff00112233445566778899-0011223344556677-01",
			SourceProject:  "chora-489812",
			SourceService:  "chora-payments",
			SchemaVersion:  1,
		},
		PurchaseId:      "01970000-0000-7000-8000-000000000777",
		LearnerGcid:     kycFeeGcid,
		KycDocType:      "manual_passport",
		StripeSessionId: "cs_test_kyc",
		AmountCentsPaid: 999,
		Currency:        "USD",
		PaidAt:          timestamppb.New(now),
	}
	bz, err := proto.Marshal(ev)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	msg := eventbus.Message{
		Subject:  events.TopicPaymentsIdentityKycFeeCaptured,
		Envelope: bindingEnvelope("01935b5a-9bcf-7000-8000-000000000010", kycFeeGcid, "idem-kyc-1"),
		Payload:  bz,
	}
	if err := handler(context.Background(), msg); err != nil {
		t.Fatalf("handler: %v", err)
	}
	v, err := kycRepo.GetLatestByGcid(context.Background(), kycFeeGcid)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if v.Status != "submitted" {
		t.Fatalf("status = %q, want submitted", v.Status)
	}
	if emitted := rec.RecordedByTopic("chora.identity.kyc.submitted.v1"); len(emitted) != 1 {
		t.Fatalf("expected 1 kyc.submitted.v1 emit, got %d", len(emitted))
	}
}

func TestKycFeeHandler_Failed_Refunded_Expired_AreCleanNoOps(t *testing.T) {
	sub, kycRepo, _ := buildKycFeeSubscriber(t)
	seedPendingManual(t, kycRepo) // stays pending — no queue entry
	handler := events.KycFeeHandler(sub)

	now := time.Now().UTC()
	base := &commonv1.EventEnvelope{
		EventId:     "01935b5a-9bcf-7000-8000-0000000000e7",
		TenantId:    "01935b5a-9bcf-7000-8000-000000000010",
		Gcid:        kycFeeGcid,
		OccurredAt:  timestamppb.New(now),
		PublishedAt: timestamppb.New(now),
		Traceparent: "00-aabbccddeeff00112233445566778899-0011223344556677-01",
	}
	for _, tc := range []struct {
		subject string
		payload proto.Message
	}{
		{events.TopicPaymentsIdentityKycFeeFailed, &paymentsv1.IdentityKycFeePaymentFailed{
			Envelope: base, PurchaseId: "p-1", LearnerGcid: kycFeeGcid, FailedAt: timestamppb.New(now),
		}},
		{events.TopicPaymentsIdentityKycFeeRefunded, &paymentsv1.IdentityKycFeeRefunded{
			Envelope: base, PurchaseId: "p-1", LearnerGcid: kycFeeGcid, RefundedAt: timestamppb.New(now),
		}},
		{events.TopicPaymentsIdentityKycFeeExpired, &paymentsv1.IdentityKycFeeExpired{
			Envelope: base, PurchaseId: "p-1", LearnerGcid: kycFeeGcid, ExpiredAt: timestamppb.New(now),
		}},
	} {
		bz, err := proto.Marshal(tc.payload)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		msg := eventbus.Message{
			Subject:  tc.subject,
			Envelope: bindingEnvelope("01935b5a-9bcf-7000-8000-000000000010", kycFeeGcid, "idem-kyc-noop"),
			Payload:  bz,
		}
		if err := handler(context.Background(), msg); err != nil {
			t.Fatalf("%s: no-op subject must ack, got %v", tc.subject, err)
		}
	}
	v, err := kycRepo.GetLatestByGcid(context.Background(), kycFeeGcid)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if v.Status != "pending" {
		t.Fatalf("status = %q, want pending (no-op subjects must not act)", v.Status)
	}
}

func TestKycFeeHandler_UnknownSubjectErrors(t *testing.T) {
	sub, _, _ := buildKycFeeSubscriber(t)
	handler := events.KycFeeHandler(sub)
	msg := eventbus.Message{
		Subject:  "chora.payments.identity_kyc_fee.checkout_started.v1",
		Envelope: bindingEnvelope("t-1", kycFeeGcid, "idem-1"),
		Payload:  []byte("{}"),
	}
	if err := handler(context.Background(), msg); err == nil {
		t.Fatal("unknown subject must error")
	}
}

func TestKycFeeHandler_NilSubscriberErrors(t *testing.T) {
	if err := events.KycFeeHandler(nil)(context.Background(), eventbus.Message{Payload: []byte("{}")}); err == nil {
		t.Fatal("nil subscriber must error")
	}
}

// -----------------------------------------------------------------------------
// TenantBootstrappedHandler — chora-tenancy emits Protobuf
// -----------------------------------------------------------------------------

func TestTenantBootstrappedHandler_DispatchesAndMirrorsMembership(t *testing.T) {
	upsert := &fakeTenantMembershipUpserter{}
	sub := events.NewTenantBootstrappedSubscriber(upsert, nil)
	handler := events.TenantBootstrappedHandler(sub)

	now := time.Now().UTC()
	ev := &tenancyv1.TenantBootstrapped{
		Envelope: &commonv1.EventEnvelope{
			EventId:        "01935f12-0000-7000-8000-0000000000aa",
			IdempotencyKey: "tenant-bootstrapped:01935f12-0000-7000-8000-000000000111",
			TenantId:       "01935f12-0000-7000-8000-000000000111",
			Gcid:           "01935f12-0000-7000-8000-000000000222",
			OccurredAt:     timestamppb.New(now),
			PublishedAt:    timestamppb.New(now),
			Traceparent:    "00-aabbccddeeff00112233445566778899-0011223344556677-01",
		},
		TenantId:       "01935f12-0000-7000-8000-000000000111",
		OwnerGcid:      "01935f12-0000-7000-8000-000000000222",
		DisplayName:    "Phase 2 Sample",
		OwnerMemberId:  "01935f12-0000-7000-8000-000000000333",
		EntitlementId:  "01935f12-0000-7000-8000-000000000444",
		BootstrappedAt: timestamppb.New(now),
	}
	bz, err := proto.Marshal(ev)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	msg := eventbus.Message{
		Subject:  events.TopicTenancyTenantBootstrappedV1,
		Envelope: bindingEnvelope("01935f12-0000-7000-8000-000000000111", "01935f12-0000-7000-8000-000000000222", "tenant-bootstrapped:01935f12-0000-7000-8000-000000000111"),
		Payload:  bz,
	}
	if err := handler(context.Background(), msg); err != nil {
		t.Fatalf("handler: %v", err)
	}
	if upsert.calls != 1 {
		t.Fatalf("upsert calls = %d, want 1", upsert.calls)
	}
	if upsert.lastRole != "owner" {
		t.Fatalf("upsert role = %q, want owner", upsert.lastRole)
	}
	if upsert.lastTenant != "01935f12-0000-7000-8000-000000000111" {
		t.Fatalf("upsert tenant_id = %q", upsert.lastTenant)
	}
}

func TestTenantBootstrappedHandler_MalformedProtoErrors(t *testing.T) {
	sub := events.NewTenantBootstrappedSubscriber(&fakeTenantMembershipUpserter{}, nil)
	handler := events.TenantBootstrappedHandler(sub)
	msg := eventbus.Message{
		Subject:  events.TopicTenancyTenantBootstrappedV1,
		Envelope: bindingEnvelope("t-1", "g-1", "idem-1"),
		Payload:  []byte("not-a-proto"),
	}
	if err := handler(context.Background(), msg); err == nil {
		t.Fatal("malformed payload must error (nack)")
	}
}

func TestTenantBootstrappedHandler_NilSubscriberErrors(t *testing.T) {
	if err := events.TenantBootstrappedHandler(nil)(context.Background(), eventbus.Message{Payload: []byte("{}")}); err == nil {
		t.Fatal("nil subscriber must error")
	}
}
