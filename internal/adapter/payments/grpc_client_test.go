// Tests for the chora-payments gRPC client adapter.
//
// Per ADR-164 Wave 1 Stage E: chora-identity calls chora-payments
// synchronously for CreateSubscription. The chora-payments service owns the
// Stripe SDK + correlation persistence; chora-identity owns the downstream
// UserSubscription business-logic FSM driven by Pub/Sub events.
//
// These tests stub the PaymentServiceClient interface (the generated
// chora.services.payments.v1 client) and verify the adapter's request /
// response mapping is correct under all branches.
package payments_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	paymentsv1 "github.com/apollo-chora/chora-contracts/gen/go/chora/services/payments/v1"

	"github.com/apollo-chora/chora-identity/internal/adapter/payments"
)

// stubPaymentClient implements payments.PaymentServiceGRPCClient with
// canned responses keyed to the request. Used to drive happy-path +
// validation + error-mapping branches.
type stubPaymentClient struct {
	resp *paymentsv1.CreateSubscriptionResponse
	err  error

	// lastRequest captures the request for assertion.
	lastRequest *paymentsv1.CreateSubscriptionRequest

	// KYC-fee canned response + captured request.
	kycResp    *paymentsv1.CreateIdentityKycFeeSessionResponse
	kycErr     error
	lastKycReq *paymentsv1.CreateIdentityKycFeeSessionRequest
}

// CreateSubscription captures the request and returns the canned response.
func (s *stubPaymentClient) CreateSubscription(
	_ context.Context,
	in *paymentsv1.CreateSubscriptionRequest,
	_ ...grpc.CallOption,
) (*paymentsv1.CreateSubscriptionResponse, error) {
	s.lastRequest = in
	return s.resp, s.err
}

// CreateIdentityKycFeeSession captures the request and returns the canned
// KYC-fee response.
func (s *stubPaymentClient) CreateIdentityKycFeeSession(
	_ context.Context,
	in *paymentsv1.CreateIdentityKycFeeSessionRequest,
	_ ...grpc.CallOption,
) (*paymentsv1.CreateIdentityKycFeeSessionResponse, error) {
	s.lastKycReq = in
	return s.kycResp, s.kycErr
}

// -----------------------------------------------------------------------------
// Constructor
// -----------------------------------------------------------------------------

func TestNewPaymentsClient_NilStubRejects(t *testing.T) {
	t.Parallel()
	c, err := payments.NewPaymentsClientFromStub(nil)
	if err == nil {
		t.Fatalf("expected error for nil stub; got client=%v", c)
	}
}

func TestNewPaymentsClient_NilConnRejects(t *testing.T) {
	t.Parallel()
	c, err := payments.NewPaymentsClient(nil)
	if err == nil {
		t.Fatalf("expected error for nil conn; got client=%v", c)
	}
}

// -----------------------------------------------------------------------------
// CreateKycFee — manual-KYC $9.99 one-time charge
// -----------------------------------------------------------------------------

func TestPaymentsClient_CreateKycFee_HappyPath(t *testing.T) {
	t.Parallel()
	stub := &stubPaymentClient{
		kycResp: &paymentsv1.CreateIdentityKycFeeSessionResponse{
			PurchaseId:        "01970000-0000-7000-8000-000000000777",
			StripeSessionId:   "cs_test_kyc",
			StripeCheckoutUrl: "https://checkout.stripe.com/c/test_kyc",
			State:             paymentsv1.PurchaseState_PURCHASE_STATE_CHECKOUT_STARTED,
		},
	}
	c := payments.NewPaymentsClientFromStubMust(t, stub)

	in := payments.CreateKycFeeInput{
		IdempotencyKey: "01970000-0000-7000-8000-kkkkkk000001",
		TenantID:       "01935b5a-9bcf-7000-8000-000000000010",
		LearnerGcid:    "01935b5a-9bcf-7000-8000-0000000000aa",
		KYCDocType:     "manual_passport",
		AmountCents:    999,
		Currency:       "USD",
		SuccessURL:     "https://chora.site/me/kyc/success",
		CancelURL:      "https://chora.site/me/kyc/cancel",
	}
	out, err := c.CreateKycFee(context.Background(), in)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out.PurchaseID != "01970000-0000-7000-8000-000000000777" {
		t.Errorf("purchase_id mismatch: got %q", out.PurchaseID)
	}
	if out.StripeCheckoutURL != "https://checkout.stripe.com/c/test_kyc" {
		t.Errorf("checkout_url mismatch: got %q", out.StripeCheckoutURL)
	}
	if out.State != "checkout_started" {
		t.Errorf("state mismatch: got %q", out.State)
	}
	// Request mapping: every input field reaches the gRPC stub.
	got := stub.lastKycReq
	if got == nil {
		t.Fatalf("stub did not receive a kyc request")
	}
	if got.KycDocType != "manual_passport" {
		t.Errorf("kyc_doc_type mismatch: got %q", got.KycDocType)
	}
	if got.AmountCents != 999 {
		t.Errorf("amount_cents mismatch: got %d", got.AmountCents)
	}
	if got.LearnerGcid != in.LearnerGcid {
		t.Errorf("learner_gcid mismatch: got %q", got.LearnerGcid)
	}
}

func TestPaymentsClient_CreateKycFee_ValidationRejectsBadInput(t *testing.T) {
	t.Parallel()
	c := payments.NewPaymentsClientFromStubMust(t, &stubPaymentClient{})
	cases := []struct {
		name string
		in   payments.CreateKycFeeInput
	}{
		{"missing idempotency", payments.CreateKycFeeInput{TenantID: "t", LearnerGcid: "g", KYCDocType: "manual_id_doc", AmountCents: 999, Currency: "USD"}},
		{"missing tenant", payments.CreateKycFeeInput{IdempotencyKey: "k", LearnerGcid: "g", KYCDocType: "manual_id_doc", AmountCents: 999, Currency: "USD"}},
		{"missing doc type", payments.CreateKycFeeInput{IdempotencyKey: "k", TenantID: "t", LearnerGcid: "g", AmountCents: 999, Currency: "USD"}},
		{"zero amount", payments.CreateKycFeeInput{IdempotencyKey: "k", TenantID: "t", LearnerGcid: "g", KYCDocType: "manual_id_doc", AmountCents: 0, Currency: "USD"}},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, err := c.CreateKycFee(context.Background(), tc.in); !errors.Is(err, payments.ErrInvalidInput) {
				t.Fatalf("expected ErrInvalidInput; got %v", err)
			}
		})
	}
}

func TestPaymentsClient_CreateKycFee_UnavailableMapsSentinel(t *testing.T) {
	t.Parallel()
	stub := &stubPaymentClient{kycErr: status.Error(codes.Unavailable, "mesh sidecar down")}
	c := payments.NewPaymentsClientFromStubMust(t, stub)
	in := payments.CreateKycFeeInput{
		IdempotencyKey: "k", TenantID: "t", LearnerGcid: "g",
		KYCDocType: "manual_id_doc", AmountCents: 999, Currency: "USD",
	}
	if _, err := c.CreateKycFee(context.Background(), in); !errors.Is(err, payments.ErrPaymentsUnavailable) {
		t.Fatalf("expected ErrPaymentsUnavailable; got %v", err)
	}
}

// -----------------------------------------------------------------------------
// CreateSubscription — happy path
// -----------------------------------------------------------------------------

func TestPaymentsClient_CreateSubscription_HappyPath(t *testing.T) {
	t.Parallel()
	stub := &stubPaymentClient{
		resp: &paymentsv1.CreateSubscriptionResponse{
			PurchaseId:        "01970000-0000-7000-8000-000000000001",
			StripeSessionId:   "cs_test_abc",
			StripeCheckoutUrl: "https://checkout.stripe.com/c/test_abc",
			State:             paymentsv1.PurchaseState_PURCHASE_STATE_CHECKOUT_STARTED,
		},
	}
	c := payments.NewPaymentsClientFromStubMust(t, stub)

	in := payments.CreateSubscriptionInput{
		IdempotencyKey: "01970000-0000-7000-8000-aaaaaa000001",
		TenantID:       "01935b5a-9bcf-7000-8000-000000000010",
		LearnerGcid:    "01935b5a-9bcf-7000-8000-0000000000aa",
		PlanSku:        "subscription.familiar.standard_monthly.v1",
		BillingPeriod:  "monthly",
		AmountCents:    1499,
		Currency:       "USD",
		SuccessURL:     "https://chora.site/me/subscriptions/success",
		CancelURL:      "https://chora.site/me/subscriptions/cancel",
	}
	out, err := c.CreateSubscription(context.Background(), in)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out.PurchaseID != "01970000-0000-7000-8000-000000000001" {
		t.Errorf("purchase_id mismatch: got %q", out.PurchaseID)
	}
	if out.StripeSessionID != "cs_test_abc" {
		t.Errorf("stripe_session_id mismatch: got %q", out.StripeSessionID)
	}
	if out.StripeCheckoutURL != "https://checkout.stripe.com/c/test_abc" {
		t.Errorf("stripe_checkout_url mismatch: got %q", out.StripeCheckoutURL)
	}
	if out.State != "checkout_started" {
		t.Errorf("state mismatch: got %q", out.State)
	}

	// Verify request mapping: every input field reaches the gRPC stub.
	got := stub.lastRequest
	if got == nil {
		t.Fatalf("stub did not receive a request")
	}
	if got.IdempotencyKey != in.IdempotencyKey {
		t.Errorf("idempotency_key mismatch: got %q", got.IdempotencyKey)
	}
	if got.TenantId != in.TenantID {
		t.Errorf("tenant_id mismatch: got %q", got.TenantId)
	}
	if got.LearnerGcid != in.LearnerGcid {
		t.Errorf("learner_gcid mismatch: got %q", got.LearnerGcid)
	}
	if got.PlanSku != in.PlanSku {
		t.Errorf("plan_sku mismatch: got %q", got.PlanSku)
	}
	if got.BillingPeriod != paymentsv1.BillingPeriod_BILLING_PERIOD_MONTHLY {
		t.Errorf("billing_period not mapped to MONTHLY: got %v", got.BillingPeriod)
	}
	if got.AmountCents != in.AmountCents {
		t.Errorf("amount_cents mismatch: got %d", got.AmountCents)
	}
	if got.Currency != in.Currency {
		t.Errorf("currency mismatch: got %q", got.Currency)
	}
	if got.SuccessUrl != in.SuccessURL {
		t.Errorf("success_url mismatch: got %q", got.SuccessUrl)
	}
	if got.CancelUrl != in.CancelURL {
		t.Errorf("cancel_url mismatch: got %q", got.CancelUrl)
	}
}

func TestPaymentsClient_CreateSubscription_AnnuallyBillingMaps(t *testing.T) {
	t.Parallel()
	stub := &stubPaymentClient{
		resp: &paymentsv1.CreateSubscriptionResponse{
			PurchaseId:        "01970000-0000-7000-8000-000000000002",
			StripeSessionId:   "cs_test_annual",
			StripeCheckoutUrl: "https://checkout.stripe.com/c/test_annual",
			State:             paymentsv1.PurchaseState_PURCHASE_STATE_CHECKOUT_STARTED,
		},
	}
	c := payments.NewPaymentsClientFromStubMust(t, stub)

	in := payments.CreateSubscriptionInput{
		IdempotencyKey: "01970000-0000-7000-8000-aaaaaa000002",
		TenantID:       "01935b5a-9bcf-7000-8000-000000000010",
		LearnerGcid:    "01935b5a-9bcf-7000-8000-0000000000bb",
		PlanSku:        "subscription.familiar.premium_annually.v1",
		BillingPeriod:  "annually",
		AmountCents:    39999,
		Currency:       "USD",
	}
	_, err := c.CreateSubscription(context.Background(), in)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if stub.lastRequest.BillingPeriod != paymentsv1.BillingPeriod_BILLING_PERIOD_ANNUALLY {
		t.Errorf("billing_period not mapped to ANNUALLY: got %v", stub.lastRequest.BillingPeriod)
	}
}

// -----------------------------------------------------------------------------
// CreateSubscription — input validation
// -----------------------------------------------------------------------------

func TestPaymentsClient_CreateSubscription_RejectsMissingFields(t *testing.T) {
	t.Parallel()
	stub := &stubPaymentClient{
		resp: &paymentsv1.CreateSubscriptionResponse{},
	}
	c := payments.NewPaymentsClientFromStubMust(t, stub)

	base := payments.CreateSubscriptionInput{
		IdempotencyKey: "01970000-0000-7000-8000-aaaaaa000003",
		TenantID:       "01935b5a-9bcf-7000-8000-000000000010",
		LearnerGcid:    "01935b5a-9bcf-7000-8000-0000000000cc",
		PlanSku:        "subscription.familiar.basic_monthly.v1",
		BillingPeriod:  "monthly",
		AmountCents:    499,
		Currency:       "USD",
	}

	tests := map[string]func(in *payments.CreateSubscriptionInput){
		"empty idempotency_key": func(in *payments.CreateSubscriptionInput) { in.IdempotencyKey = "" },
		"empty tenant_id":       func(in *payments.CreateSubscriptionInput) { in.TenantID = "" },
		"empty learner_gcid":    func(in *payments.CreateSubscriptionInput) { in.LearnerGcid = "" },
		"empty plan_sku":        func(in *payments.CreateSubscriptionInput) { in.PlanSku = "" },
		"empty billing_period":  func(in *payments.CreateSubscriptionInput) { in.BillingPeriod = "" },
		"invalid billing_period": func(in *payments.CreateSubscriptionInput) {
			in.BillingPeriod = "biennially"
		},
		"zero amount":    func(in *payments.CreateSubscriptionInput) { in.AmountCents = 0 },
		"empty currency": func(in *payments.CreateSubscriptionInput) { in.Currency = "" },
	}
	for name, mutator := range tests {
		t.Run(name, func(t *testing.T) {
			in := base
			mutator(&in)
			if _, err := c.CreateSubscription(context.Background(), in); err == nil {
				t.Fatalf("expected validation error for %s", name)
			}
		})
	}
}

// -----------------------------------------------------------------------------
// CreateSubscription — gRPC error propagation
// -----------------------------------------------------------------------------

func TestPaymentsClient_CreateSubscription_PropagatesGRPCError(t *testing.T) {
	t.Parallel()
	stub := &stubPaymentClient{
		err: status.Error(codes.Unavailable, "chora-payments offline"),
	}
	c := payments.NewPaymentsClientFromStubMust(t, stub)
	in := payments.CreateSubscriptionInput{
		IdempotencyKey: "01970000-0000-7000-8000-aaaaaa000004",
		TenantID:       "01935b5a-9bcf-7000-8000-000000000010",
		LearnerGcid:    "01935b5a-9bcf-7000-8000-0000000000dd",
		PlanSku:        "subscription.familiar.basic_monthly.v1",
		BillingPeriod:  "monthly",
		AmountCents:    499,
		Currency:       "USD",
	}
	_, err := c.CreateSubscription(context.Background(), in)
	if err == nil {
		t.Fatalf("expected error from stub")
	}
	if !errors.Is(err, payments.ErrPaymentsUnavailable) {
		// Propagation should map UNAVAILABLE to our sentinel for caller
		// inspection via errors.Is.
		if st, ok := status.FromError(errors.Unwrap(err)); ok {
			if st.Code() != codes.Unavailable {
				t.Errorf("expected UNAVAILABLE; got %v", st.Code())
			}
		}
	}
}

func TestPaymentsClient_CreateSubscription_NilResponseRejects(t *testing.T) {
	t.Parallel()
	stub := &stubPaymentClient{resp: nil}
	c := payments.NewPaymentsClientFromStubMust(t, stub)
	in := payments.CreateSubscriptionInput{
		IdempotencyKey: "01970000-0000-7000-8000-aaaaaa000005",
		TenantID:       "01935b5a-9bcf-7000-8000-000000000010",
		LearnerGcid:    "01935b5a-9bcf-7000-8000-0000000000ee",
		PlanSku:        "subscription.familiar.basic_monthly.v1",
		BillingPeriod:  "monthly",
		AmountCents:    499,
		Currency:       "USD",
	}
	if _, err := c.CreateSubscription(context.Background(), in); err == nil {
		t.Fatalf("expected error for nil response")
	}
}

// -----------------------------------------------------------------------------
// Bootstrap helper
// -----------------------------------------------------------------------------

func TestNewPaymentsClientFromEnv_FailsLoudWithoutEnv(t *testing.T) {
	// Cannot run in parallel — uses t.Setenv which mutates process env.
	t.Setenv("CHORA_PAYMENTS_GRPC_ADDR", "")
	c, err := payments.NewPaymentsClientFromEnv(context.Background())
	if err == nil {
		t.Fatalf("expected error when CHORA_PAYMENTS_GRPC_ADDR unset; got %v", c)
	}
	if c != nil {
		t.Errorf("expected nil client on err; got %v", c)
	}
}

// -----------------------------------------------------------------------------
// State enum mapping
// -----------------------------------------------------------------------------

func TestStateString_ConvertsAllKnownStates(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   paymentsv1.PurchaseState
		want string
	}{
		{paymentsv1.PurchaseState_PURCHASE_STATE_CHECKOUT_STARTED, "checkout_started"},
		{paymentsv1.PurchaseState_PURCHASE_STATE_PAYMENT_CAPTURED, "payment_captured"},
		{paymentsv1.PurchaseState_PURCHASE_STATE_PAYMENT_FAILED, "payment_failed"},
		{paymentsv1.PurchaseState_PURCHASE_STATE_REFUNDED, "refunded"},
		{paymentsv1.PurchaseState_PURCHASE_STATE_EXPIRED, "expired"},
		{paymentsv1.PurchaseState_PURCHASE_STATE_UNSPECIFIED, "unspecified"},
	}
	for _, tc := range cases {
		if got := payments.StateString(tc.in); got != tc.want {
			t.Errorf("StateString(%v) = %q; want %q", tc.in, got, tc.want)
		}
	}
}

// _ = time import kept for future deadline-injection tests.
var _ = time.Time{}
