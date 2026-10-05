// Tests for the KycFeeSubscriber — the chora-payments → chora-identity
// capture path that gates manual-doc KYC review-queue entry on the $9.99
// fee being captured (ADR-142 + ADR-164 Stage A.5).
package events_test

import (
	"context"
	"testing"
	"time"

	"github.com/apollo-chora/chora-common/idempotent"
	"github.com/apollo-chora/chora-identity/internal/adapter/events"
	"github.com/apollo-chora/chora-identity/internal/adapter/repo"
	"github.com/apollo-chora/chora-identity/internal/domain/kyc"
)

const kycFeeGcid = "01970000-0000-7000-8000-0000000000aa"

func buildKycFeeSubscriber(t *testing.T) (*events.KycFeeSubscriber, *repo.InMemKycRepo, *events.Recorder) {
	t.Helper()
	kycRepo := repo.NewInMemKycRepo()
	rec := events.NewRecorder()
	pub := events.NewEconomyPublisher(rec)
	sub := events.NewKycFeeSubscriber(kycRepo, pub, idempotent.NewMemoryStore())
	return sub, kycRepo, rec
}

// seedPendingManual creates a pending manual_doc verification with an
// attached document — the state the verification is in after submitManual
// has created the Checkout Session but before the fee is captured.
func seedPendingManual(t *testing.T, r *repo.InMemKycRepo) *kyc.Verification {
	t.Helper()
	v, err := kyc.NewVerification(kyc.NewParams{
		Gcid: kycFeeGcid, Method: kyc.MethodManualDoc, Provider: "internal_review",
	})
	if err != nil {
		t.Fatalf("NewVerification: %v", err)
	}
	if err := v.AttachPendingDocument("gs://chora-kyc-sandbox/doc-1"); err != nil {
		t.Fatalf("AttachPendingDocument: %v", err)
	}
	if err := r.Save(context.Background(), v); err != nil {
		t.Fatalf("seed save: %v", err)
	}
	return v
}

func capturedPayload() events.PaymentsIdentityKycFeePaymentCapturedPayload {
	return events.PaymentsIdentityKycFeePaymentCapturedPayload{
		PurchaseID:      "01970000-0000-7000-8000-000000000777",
		LearnerGcid:     kycFeeGcid,
		KycDocType:      "manual_passport",
		StripeSessionID: "cs_test_kyc",
		AmountCentsPaid: 999,
		Currency:        "USD",
		PaidAt:          time.Unix(1748000000, 0).UTC(),
	}
}

func TestKycFee_Captured_EntersReviewQueueAndEmits(t *testing.T) {
	t.Parallel()
	sub, kycRepo, rec := buildKycFeeSubscriber(t)
	seedPendingManual(t, kycRepo)

	env := events.NewEnvelope("01935b5a-9bcf-7000-8000-000000000010", kycFeeGcid, "00-aabbccddeeff00112233445566778899-0011223344556677-01", "")
	env.IdempotencyKey = "idem-kyc-1"

	if err := sub.HandlePaymentCaptured(context.Background(), env, capturedPayload()); err != nil {
		t.Fatalf("HandlePaymentCaptured: %v", err)
	}

	v, err := kycRepo.GetLatestByGcid(context.Background(), kycFeeGcid)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if v.Status != kyc.StatusSubmitted {
		t.Errorf("status = %q, want submitted (review queue entered on capture)", v.Status)
	}
	if v.FeeChargedCents != 999 {
		t.Errorf("fee_charged_cents = %d, want 999", v.FeeChargedCents)
	}
	emitted := rec.RecordedByTopic("chora.identity.kyc.submitted.v1")
	if len(emitted) != 1 {
		t.Fatalf("expected 1 kyc.submitted.v1 emit, got %d", len(emitted))
	}
}

func TestKycFee_Captured_Idempotent(t *testing.T) {
	t.Parallel()
	sub, kycRepo, rec := buildKycFeeSubscriber(t)
	seedPendingManual(t, kycRepo)
	env := events.NewEnvelope("01935b5a-9bcf-7000-8000-000000000010", kycFeeGcid, "00-aabbccddeeff00112233445566778899-0011223344556677-01", "")
	env.IdempotencyKey = "idem-kyc-dup"

	for i := 0; i < 3; i++ {
		if err := sub.HandlePaymentCaptured(context.Background(), env, capturedPayload()); err != nil {
			t.Fatalf("attempt %d: %v", i, err)
		}
	}
	// Dedupe → exactly one submitted emit despite 3 deliveries.
	if got := len(rec.RecordedByTopic("chora.identity.kyc.submitted.v1")); got != 1 {
		t.Errorf("expected 1 emit under dedupe, got %d", got)
	}
}

func TestKycFee_Captured_NoVerification_DropsCleanly(t *testing.T) {
	t.Parallel()
	sub, _, rec := buildKycFeeSubscriber(t) // no seed
	env := events.NewEnvelope("01935b5a-9bcf-7000-8000-000000000010", kycFeeGcid, "00-aabbccddeeff00112233445566778899-0011223344556677-01", "")
	if err := sub.HandlePaymentCaptured(context.Background(), env, capturedPayload()); err != nil {
		t.Fatalf("expected clean drop, got %v", err)
	}
	if got := len(rec.RecordedByTopic("chora.identity.kyc.submitted.v1")); got != 0 {
		t.Errorf("expected 0 emits, got %d", got)
	}
}

func TestKycFee_Captured_AlreadySubmitted_NoOp(t *testing.T) {
	t.Parallel()
	sub, kycRepo, rec := buildKycFeeSubscriber(t)
	v := seedPendingManual(t, kycRepo)
	// Already in the review queue (e.g., captured event re-delivered after a
	// prior dedupe window expired).
	if err := v.Submit(v.DocumentURI, 999, "USD"); err != nil {
		t.Fatalf("pre-submit: %v", err)
	}
	if err := kycRepo.Save(context.Background(), v); err != nil {
		t.Fatalf("save: %v", err)
	}
	env := events.NewEnvelope("01935b5a-9bcf-7000-8000-000000000010", kycFeeGcid, "00-aabbccddeeff00112233445566778899-0011223344556677-01", "")
	if err := sub.HandlePaymentCaptured(context.Background(), env, capturedPayload()); err != nil {
		t.Fatalf("HandlePaymentCaptured: %v", err)
	}
	if got := len(rec.RecordedByTopic("chora.identity.kyc.submitted.v1")); got != 0 {
		t.Errorf("expected no re-emit for already-submitted verification, got %d", got)
	}
}

func TestKycFee_Captured_ValidationRejectsMissingFields(t *testing.T) {
	t.Parallel()
	sub, _, _ := buildKycFeeSubscriber(t)
	env := events.NewEnvelope("", kycFeeGcid, "", "") // missing tenant
	if err := sub.HandlePaymentCaptured(context.Background(), env, capturedPayload()); err == nil {
		t.Fatalf("expected validation error for missing tenant_id")
	}
}

// --- accessor coverage: WithInboxTTL + SubscribedTopics ------------------------

func TestKycFeeSubscriber_WithInboxTTL_Fluent(t *testing.T) {
	t.Parallel()
	sub := events.NewKycFeeSubscriber(nil, nil, nil) // nil inbox → MemoryStore fallback
	if sub == nil {
		t.Fatal("NewKycFeeSubscriber must not return nil")
	}
	fluent := sub.WithInboxTTL(30 * time.Minute)
	if fluent != sub {
		t.Error("WithInboxTTL must return the same subscriber (fluent wiring)")
	}
	sub.WithInboxTTL(0) // d<=0 keeps the TTL unchanged (no-op branch)
}

func TestKycFeeSubscriber_SubscribedTopics(t *testing.T) {
	t.Parallel()
	sub := events.NewKycFeeSubscriber(nil, nil, nil)
	want := []string{
		events.TopicPaymentsIdentityKycFeeCaptured,
		events.TopicPaymentsIdentityKycFeeFailed,
		events.TopicPaymentsIdentityKycFeeRefunded,
		events.TopicPaymentsIdentityKycFeeExpired,
	}
	got := sub.SubscribedTopics()
	if len(got) != len(want) {
		t.Fatalf("got %d topics, want %d: %v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("topic[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

// TestKycFeeSubscriber_NilRepo_Errors drives the not-initialised guard.
func TestKycFeeSubscriber_NilRepo_Errors(t *testing.T) {
	t.Parallel()
	sub := events.NewKycFeeSubscriber(nil, nil, nil) // kycRepo nil, inbox → MemoryStore
	env := events.NewEnvelope("t-1", kycFeeGcid, "00-trace-01", "")
	if err := sub.HandlePaymentCaptured(context.Background(), env, capturedPayload()); err == nil {
		t.Error("nil kyc repo must error")
	}
}

// TestKycFeeSubscriber_ValidationBranches drives the remaining validate()
// error branches: empty learner gcid, AGID-shaped gcid, empty purchase_id.
func TestKycFeeSubscriber_ValidationBranches(t *testing.T) {
	t.Parallel()
	sub, _, _ := buildKycFeeSubscriber(t)
	env := events.NewEnvelope("t-1", kycFeeGcid, "00-trace-01", "")
	cases := []struct {
		name    string
		env     events.Envelope
		payload events.PaymentsIdentityKycFeePaymentCapturedPayload
	}{
		{"missing learner gcid", env, events.PaymentsIdentityKycFeePaymentCapturedPayload{PurchaseID: "p-1"}},
		{"AGID learner", env, events.PaymentsIdentityKycFeePaymentCapturedPayload{PurchaseID: "p-1", LearnerGcid: "0197a000000000000000000000000000"}},
		{"missing purchase id", env, events.PaymentsIdentityKycFeePaymentCapturedPayload{LearnerGcid: kycFeeGcid}},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			if err := sub.HandlePaymentCaptured(context.Background(), tc.env, tc.payload); err == nil {
				t.Errorf("expected validation error")
			}
		})
	}
}

// TestKycFeeSubscriber_SyntheticIdempotencyKey drives the fallback key when
// the envelope carries no idempotency_key. NOTE: the subscriber forwards the
// ORIGINAL envelope to the publisher, so a recorder-backed publisher rejects
// the idem-less envelope — the synthetic key exists for the INBOX dedupe, so
// this test wires a nil publisher and asserts the handler completes + submits.
func TestKycFeeSubscriber_SyntheticIdempotencyKey(t *testing.T) {
	t.Parallel()
	kycRepo := repo.NewInMemKycRepo()
	seedPendingManual(t, kycRepo)
	sub := events.NewKycFeeSubscriber(kycRepo, nil, idempotent.NewMemoryStore())

	env := events.NewEnvelope("01935b5a-9bcf-7000-8000-000000000010", kycFeeGcid, "00-trace-01", "")
	env.IdempotencyKey = "" // producer forgot it → synthetic key

	for i := 0; i < 2; i++ {
		if err := sub.HandlePaymentCaptured(context.Background(), env, capturedPayload()); err != nil {
			t.Fatalf("delivery %d: %v", i, err)
		}
	}
	v, err := kycRepo.GetLatestByGcid(context.Background(), kycFeeGcid)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if v.Status != kyc.StatusSubmitted {
		t.Errorf("status = %q, want submitted", v.Status)
	}
}
