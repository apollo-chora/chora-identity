// subscriber_bindings_test.go — end-to-end proof that the four
// cross-domain subscribers (enrollment, payments, kyc-fee,
// tenant-bootstrapped) are ACTIVELY CONSUMING once bound via
// bindSubscription — the exact helper main.go uses.
//
// The test reproduces the production topology against an embedded
// nats-server: a CHORA_EVENTS stream (subjects chora.>), a JetStreamBus,
// and durable consumers created by eventbus Subscribe. Events are published
// in the producers' wire formats (JSON for chora.delivery, Protobuf for
// chora-payments / chora-tenancy) and the assertions verify the domain
// effects actually land — i.e. the messages were decoded and handled, not
// merely delivered.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	natsserver "github.com/nats-io/nats-server/v2/test"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/apollo-chora/chora-common/envelope"
	"github.com/apollo-chora/chora-common/eventbus"

	commonv1 "github.com/apollo-chora/chora-contracts/gen/go/chora/common/v1"
	paymentsv1 "github.com/apollo-chora/chora-contracts/gen/go/chora/payments/v1"
	tenancyv1 "github.com/apollo-chora/chora-contracts/gen/go/chora/tenancy/v1"
	"github.com/apollo-chora/chora-identity/internal/adapter/events"
	"github.com/apollo-chora/chora-identity/internal/adapter/inmem"
	"github.com/apollo-chora/chora-identity/internal/adapter/repo"
	"github.com/apollo-chora/chora-identity/internal/domain/identity"
	"github.com/apollo-chora/chora-identity/internal/domain/kyc"
	usersub "github.com/apollo-chora/chora-identity/internal/domain/user_subscription"
)

const (
	e2eTenant  = "01935b5a-9bcf-7000-8000-000000000010"
	e2eGcid    = "01935b5a-9bcf-7000-8000-0000000000aa"
	e2eStripe  = "sub_e2e_payments_aaaa"
	e2eKycGcid = "01970000-0000-7000-8000-0000000000aa"
	e2eTrace   = "00-aabbccddeeff00112233445566778899-0011223344556677-01"
)

// fakeTenantUpserter records the mirror-row writes the tenant-bootstrapped
// subscriber performs (the production adapter upserts into
// chora_identity.tenant_memberships).
type fakeTenantUpserter struct {
	calls  int
	gcid   string
	tenant string
	role   string
}

func (f *fakeTenantUpserter) UpsertMembershipOnBootstrap(_ context.Context, gcid, tenantID, role string) error {
	f.calls++
	f.gcid = gcid
	f.tenant = tenantID
	f.role = role
	return nil
}

// e2eEnvelope builds a fully-mandated transport envelope, matching what the
// producers stamp on the publish (and what the eventbus reconstructs from
// NATS headers). The eventID must be unique per message — the eventbus
// projects it onto the Nats-Msg-Id header, so a repeated eventID is
// suppressed by the stream's duplicate window.
func e2eEnvelope(eventID, idem string) envelope.Envelope {
	now := time.Now().UTC()
	return envelope.Envelope{
		EventID:        eventID,
		IdempotencyKey: idem,
		TenantID:       e2eTenant,
		GCID:           e2eGcid,
		OccurredAt:     now,
		PublishedAt:    now,
		Traceparent:    e2eTrace,
		SourceProject:  "chora-489812",
		SourceService:  "chora-payments",
		SchemaVersion:  1,
	}
}

// waitFor polls cond until it holds or the timeout elapses.
func waitFor(t *testing.T, timeout time.Duration, cond func() bool, what string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// TestCrossDomainSubscribers_BoundAndConsuming drives the full path:
// publish → JetStream durable consumer → handler adapter → subscriber →
// domain effect, for all four previously-discarded subscribers.
func TestCrossDomainSubscribers_BoundAndConsuming(t *testing.T) {
	ctx := context.Background()

	// Embedded NATS with the production-shaped CHORA_EVENTS stream.
	opts := natsserver.DefaultTestOptions
	opts.Port = -1
	opts.JetStream = true
	opts.StoreDir = t.TempDir()
	srv := natsserver.RunServer(&opts)
	defer srv.Shutdown()

	nc, err := nats.Connect(srv.ClientURL())
	if err != nil {
		t.Fatalf("nats connect: %v", err)
	}
	defer nc.Close()
	js, err := jetstream.New(nc)
	if err != nil {
		t.Fatalf("jetstream: %v", err)
	}
	stream := fmt.Sprintf("CHORA_EVENTS_E2E_%d", time.Now().UnixNano())
	if _, err := js.CreateStream(ctx, jetstream.StreamConfig{
		Name:     stream,
		Subjects: []string{"chora.>"},
		Storage:  jetstream.FileStorage,
	}); err != nil {
		t.Fatalf("create stream: %v", err)
	}
	defer func() { _ = js.DeleteStream(context.Background(), stream) }()

	bus, err := eventbus.NewJetStream(eventbus.JetStreamConfig{URL: srv.ClientURL(), StreamName: stream})
	if err != nil {
		t.Fatalf("NewJetStream: %v", err)
	}
	defer func() { _ = bus.Close() }()

	// --- subscribers (in-memory fakes, as main.go wires in dev) -----------
	roles := inmem.NewCourseRoleRepository()
	enrollRec := events.NewRecorder()
	enrollSub := events.NewEnrollmentSubscriber(roles, events.NewEconomyPublisher(enrollRec), nil)

	subs := repo.NewInMemUserSubscriptionRepo()
	s, err := usersub.NewSubscription(usersub.NewParams{
		Gcid:                 e2eGcid,
		TenantID:             e2eTenant,
		PlanCode:             "familiar_standard",
		Tier:                 usersub.TierStandard,
		BillingPeriod:        usersub.BillingMonthly,
		ManaMonthlyUnits:     2500,
		OnboardingBonusUnits: 2500,
		StripeSubscriptionID: e2eStripe,
		PeriodStart:          time.Now().UTC().Add(-24 * time.Hour),
		PeriodEnd:            time.Now().UTC().Add(29 * 24 * time.Hour),
	})
	if err != nil {
		t.Fatalf("NewSubscription: %v", err)
	}
	if err := subs.Save(ctx, s); err != nil {
		t.Fatalf("seed subscription: %v", err)
	}
	paymentsSub := events.NewPaymentsSubscriber(subs, nil)

	kycRepo := repo.NewInMemKycRepo()
	v, err := kyc.NewVerification(kyc.NewParams{
		Gcid: e2eKycGcid, Method: kyc.MethodManualDoc, Provider: "internal_review",
	})
	if err != nil {
		t.Fatalf("NewVerification: %v", err)
	}
	if err := v.AttachPendingDocument("gs://chora-kyc-sandbox/doc-e2e"); err != nil {
		t.Fatalf("AttachPendingDocument: %v", err)
	}
	if err := kycRepo.Save(ctx, v); err != nil {
		t.Fatalf("seed verification: %v", err)
	}
	kycRec := events.NewRecorder()
	kycFeeSub := events.NewKycFeeSubscriber(kycRepo, events.NewEconomyPublisher(kycRec), nil)

	upsert := &fakeTenantUpserter{}
	tenantSub := events.NewTenantBootstrappedSubscriber(upsert, nil)

	// --- bind via the same helper main.go uses -----------------------------
	bindSubscription(ctx, bus, events.TopicEnrollmentCreated, events.EnrollmentHandler(enrollSub))
	paymentsHandler := events.PaymentsHandler(paymentsSub)
	for _, subject := range paymentsSub.SubscribedTopics() {
		bindSubscription(ctx, bus, subject, paymentsHandler)
	}
	kycFeeHandler := events.KycFeeHandler(kycFeeSub)
	for _, subject := range kycFeeSub.SubscribedTopics() {
		bindSubscription(ctx, bus, subject, kycFeeHandler)
	}
	bindSubscription(ctx, bus, events.TopicTenancyTenantBootstrappedV1, events.TenantBootstrappedHandler(tenantSub))

	// --- publish in the producers' wire formats ----------------------------
	// chora-delivery: JSON body (no Protobuf encoder for this topic).
	enrollBody, err := json.Marshal(map[string]any{
		"enrollment_id": "01935b5a-9bcf-7000-8000-aaaaaa0000e2",
		"course_id":     "01935b5a-9bcf-7000-8000-000000000099",
		"learner_gcid":  e2eGcid,
		"enrolled_at":   time.Now().UTC().Format(time.RFC3339Nano),
	})
	if err != nil {
		t.Fatalf("marshal enrollment: %v", err)
	}
	if err := bus.Publish(ctx, events.TopicEnrollmentCreated, e2eEnvelope("01935b5a-9bcf-7000-8000-0000000000ea", "idem-e2e-enroll"), enrollBody); err != nil {
		t.Fatalf("publish enrollment: %v", err)
	}

	// chora-payments: Protobuf wire bytes with embedded envelope.
	now := time.Now().UTC()
	paymentsBody, err := proto.Marshal(&paymentsv1.UserSubscriptionPaymentCaptured{
		Envelope: &commonv1.EventEnvelope{
			EventId:        "01935b5a-9bcf-7000-8000-0000000000e2",
			IdempotencyKey: "idem-e2e-pay",
			TenantId:       e2eTenant,
			Gcid:           e2eGcid,
			OccurredAt:     timestamppb.New(now),
			PublishedAt:    timestamppb.New(now),
			Traceparent:    e2eTrace,
			SourceProject:  "chora-489812",
			SourceService:  "chora-payments",
			SchemaVersion:  1,
		},
		PurchaseId:           "p-e2e-1",
		LearnerGcid:          e2eGcid,
		PlanSku:              "subscription.companion.standard_monthly.v1",
		BillingPeriod:        "monthly",
		StripeSubscriptionId: e2eStripe,
		AmountCentsPaid:      999,
		Currency:             "USD",
		PeriodStart:          timestamppb.New(now),
		PeriodEnd:            timestamppb.New(now.Add(30 * 24 * time.Hour)),
		PaidAt:               timestamppb.New(now),
	})
	if err != nil {
		t.Fatalf("marshal payments: %v", err)
	}
	if err := bus.Publish(ctx, events.TopicPaymentsUserSubscriptionCaptured, e2eEnvelope("01935b5a-9bcf-7000-8000-0000000000eb", "idem-e2e-pay"), paymentsBody); err != nil {
		t.Fatalf("publish payments: %v", err)
	}

	kycBody, err := proto.Marshal(&paymentsv1.IdentityKycFeePaymentCaptured{
		Envelope: &commonv1.EventEnvelope{
			EventId:        "01935b5a-9bcf-7000-8000-0000000000e3",
			IdempotencyKey: "idem-e2e-kyc",
			TenantId:       e2eTenant,
			Gcid:           e2eKycGcid,
			OccurredAt:     timestamppb.New(now),
			PublishedAt:    timestamppb.New(now),
			Traceparent:    e2eTrace,
			SourceProject:  "chora-489812",
			SourceService:  "chora-payments",
			SchemaVersion:  1,
		},
		PurchaseId:      "01970000-0000-7000-8000-000000000777",
		LearnerGcid:     e2eKycGcid,
		KycDocType:      "manual_passport",
		StripeSessionId: "cs_test_e2e",
		AmountCentsPaid: 999,
		Currency:        "USD",
		PaidAt:          timestamppb.New(now),
	})
	if err != nil {
		t.Fatalf("marshal kyc fee: %v", err)
	}
	if err := bus.Publish(ctx, events.TopicPaymentsIdentityKycFeeCaptured, e2eEnvelope("01935b5a-9bcf-7000-8000-0000000000ec", "idem-e2e-kyc"), kycBody); err != nil {
		t.Fatalf("publish kyc fee: %v", err)
	}

	// chora-tenancy: Protobuf wire bytes with embedded envelope.
	tenantBody, err := proto.Marshal(&tenancyv1.TenantBootstrapped{
		Envelope: &commonv1.EventEnvelope{
			EventId:        "01935f12-0000-7000-8000-0000000000aa",
			IdempotencyKey: "tenant-bootstrapped:" + e2eTenant,
			TenantId:       e2eTenant,
			Gcid:           e2eGcid,
			OccurredAt:     timestamppb.New(now),
			PublishedAt:    timestamppb.New(now),
			Traceparent:    e2eTrace,
			SourceProject:  "chora-489812",
			SourceService:  "chora-tenancy",
			SchemaVersion:  1,
		},
		TenantId:       e2eTenant,
		OwnerGcid:      e2eGcid,
		DisplayName:    "E2E Tenant",
		OwnerMemberId:  "01935f12-0000-7000-8000-000000000333",
		EntitlementId:  "01935f12-0000-7000-8000-000000000444",
		BootstrappedAt: timestamppb.New(now),
	})
	if err != nil {
		t.Fatalf("marshal tenant: %v", err)
	}
	if err := bus.Publish(ctx, events.TopicTenancyTenantBootstrappedV1, e2eEnvelope("01935b5a-9bcf-7000-8000-0000000000ed", "tenant-bootstrapped:"+e2eTenant), tenantBody); err != nil {
		t.Fatalf("publish tenant: %v", err)
	}

	// --- assert the domain effects landed ----------------------------------
	waitFor(t, 5*time.Second, func() bool {
		_, err := roles.GetAssignment(ctx, e2eGcid, "01935b5a-9bcf-7000-8000-000000000099")
		return err == nil
	}, "enrollment role assignment projection")
	if emitted := enrollRec.RecordedByTopic("chora.identity.role.granted.v1"); len(emitted) != 1 {
		t.Fatalf("expected 1 role.granted.v1 emit, got %d", len(emitted))
	}

	waitFor(t, 5*time.Second, func() bool {
		got, err := subs.GetByStripeSubscriptionID(ctx, e2eStripe)
		if err == nil && got.Status == usersub.StatusActive {
			return true
		}
		return false
	}, "payments FSM activation")
	if got, err := subs.GetByStripeSubscriptionID(ctx, e2eStripe); err == nil && got.TenantID != e2eTenant {
		t.Fatalf("subscription tenant = %q, want %q", got.TenantID, e2eTenant)
	}

	waitFor(t, 5*time.Second, func() bool {
		got, err := kycRepo.GetLatestByGcid(ctx, e2eKycGcid)
		return err == nil && got.Status == kyc.StatusSubmitted
	}, "kyc fee review-queue entry")
	if emitted := kycRec.RecordedByTopic("chora.identity.kyc.submitted.v1"); len(emitted) != 1 {
		t.Fatalf("expected 1 kyc.submitted.v1 emit, got %d", len(emitted))
	}

	waitFor(t, 5*time.Second, func() bool { return upsert.calls == 1 }, "tenant membership mirror")
	if upsert.role != string(identity.RoleOwner) {
		t.Fatalf("mirror role = %q, want owner", upsert.role)
	}
	if upsert.tenant != e2eTenant {
		t.Fatalf("mirror tenant = %q, want %q", upsert.tenant, e2eTenant)
	}
}
