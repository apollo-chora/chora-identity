// Package payments — outbound gRPC client to chora-payments
// (chora.services.payments.v1.PaymentService).
//
// Per ADR-164 Wave 1 Stage E: chora-identity no longer holds an inline
// Stripe SDK; the Stripe-correlation half of UserSubscription lifecycle
// is owned by chora-payments. chora-identity calls chora-payments via:
//
//   - Synchronous gRPC for Create-Subscription (this file).
//   - Asynchronous Pub/Sub subscribers for payment outcomes
//     (chora.payments.user_subscription.*.v1 — see
//     ../events/payments_subscriber.go).
//
// Hexagonal note: ADAPTER. Domain code (services/.../domain/user_subscription)
// never imports this package; HTTP handlers + Pub/Sub subscribers consume
// CreateSubscriptionInput / Output values directly.
//
// Trust model: mTLS via Cloud Service Mesh. The CallerSA at the mesh
// layer is the chora-identity workload identity; chora-payments'
// AuthorizationPolicy gates access by source SA. No JWT validation here.
//
// OTLP context propagation: the unary client interceptor on the
// underlying grpc.ClientConn carries W3C traceparent into the
// chora-payments span automatically.
//
// Per `feedback_no_inline_config`: the upstream URL is sourced from env
// (CHORA_PAYMENTS_GRPC_ADDR — fail loud when unset in NewPaymentsClientFromEnv).
package payments

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	paymentsv1 "github.com/apollo-chora/chora-contracts/gen/go/chora/services/payments/v1"
)

// -----------------------------------------------------------------------------
// Errors
// -----------------------------------------------------------------------------

var (
	// ErrPaymentsUnavailable — chora-payments returned codes.Unavailable
	// (transport failure, mesh sidecar down, target service down).
	ErrPaymentsUnavailable = errors.New("payments: chora-payments unavailable")

	// ErrInvalidInput — input validation rejected before the RPC dial.
	ErrInvalidInput = errors.New("payments: invalid input")

	// ErrEmptyResponse — chora-payments returned a nil/empty response body.
	ErrEmptyResponse = errors.New("payments: empty response from chora-payments")
)

// -----------------------------------------------------------------------------
// Ports
// -----------------------------------------------------------------------------

// PaymentServiceGRPCClient is the minimal slice of the generated
// paymentsv1.PaymentServiceClient that chora-identity calls. Tests inject
// a fake; production wires the real gRPC dial against
// CHORA_PAYMENTS_GRPC_ADDR via grpc.NewClient.
type PaymentServiceGRPCClient interface {
	CreateSubscription(
		ctx context.Context,
		in *paymentsv1.CreateSubscriptionRequest,
		opts ...grpc.CallOption,
	) (*paymentsv1.CreateSubscriptionResponse, error)
	CreateIdentityKycFeeSession(
		ctx context.Context,
		in *paymentsv1.CreateIdentityKycFeeSessionRequest,
		opts ...grpc.CallOption,
	) (*paymentsv1.CreateIdentityKycFeeSessionResponse, error)
}

// -----------------------------------------------------------------------------
// Inputs / outputs (port shapes shared with subscribers)
// -----------------------------------------------------------------------------

// CreateSubscriptionInput is the canonical port input for the
// CreateSubscription RPC. Callers (chora-identity HTTP handler) build
// these values from the FE body + bearer-auth context.
type CreateSubscriptionInput struct {
	// IdempotencyKey is the originating-service idempotency key (UUIDv7).
	// chora-payments uses this to dedupe duplicate Create-Subscription
	// calls within a 24h window. Required.
	IdempotencyKey string

	// TenantID is the tenant scope (UUIDv7).
	TenantID string

	// LearnerGcid is the learner subscribing (UUIDv7, opaque).
	LearnerGcid string

	// PlanSku is the platform catalog plan code
	// (e.g., "subscription.familiar.standard_monthly.v1").
	PlanSku string

	// BillingPeriod is "monthly" or "annually".
	BillingPeriod string

	// AmountCents is the per-period charge in minor units.
	AmountCents int64

	// Currency is the ISO 4217 3-letter code.
	Currency string

	// SuccessURL + CancelURL are optional FE redirect targets after
	// Stripe Checkout. When empty, chora-payments falls back to its
	// STRIPE_DEFAULT_*_URL envs.
	SuccessURL string
	CancelURL  string
}

// CreateSubscriptionOutput is the port output. The state field is the
// canonical FSM state string (Stripe-side); for a freshly-minted
// Checkout Session this is always "checkout_started".
type CreateSubscriptionOutput struct {
	PurchaseID        string
	StripeSessionID   string
	StripeCheckoutURL string
	State             string
}

// -----------------------------------------------------------------------------
// Client
// -----------------------------------------------------------------------------

// Client is the chora-identity adapter implementing the payment-port
// shape. Wraps the generated paymentsv1.PaymentServiceClient stub.
type Client struct {
	stub PaymentServiceGRPCClient
}

// NewPaymentsClient wraps an existing grpc.ClientConn (constructed by
// the caller — typically cmd/server/main.go with mesh-internal credentials).
// Returns an error when conn is nil so boot fails loud.
func NewPaymentsClient(conn *grpc.ClientConn) (*Client, error) {
	if conn == nil {
		return nil, errors.New("payments.NewPaymentsClient: nil conn")
	}
	return &Client{stub: paymentsv1.NewPaymentServiceClient(conn)}, nil
}

// NewPaymentsClientFromStub constructs a Client from a pre-built stub.
// Used by tests with a bufconn-backed stub or an explicit fake.
func NewPaymentsClientFromStub(stub PaymentServiceGRPCClient) (*Client, error) {
	if stub == nil {
		return nil, errors.New("payments.NewPaymentsClientFromStub: nil stub")
	}
	return &Client{stub: stub}, nil
}

// NewPaymentsClientFromStubMust is the test-only constructor that fails
// the test on stub construction error.
func NewPaymentsClientFromStubMust(t *testing.T, stub PaymentServiceGRPCClient) *Client {
	t.Helper()
	c, err := NewPaymentsClientFromStub(stub)
	if err != nil {
		t.Fatalf("payments client construction failed: %v", err)
	}
	return c
}

// NewPaymentsClientFromEnv reads CHORA_PAYMENTS_GRPC_ADDR + dials.
// Fail-loud when unset per `feedback_no_inline_config` + ADR-164 §0 hard rule
// "no inline config". The caller owns the returned grpc.ClientConn lifecycle
// via the second return value.
func NewPaymentsClientFromEnv(_ context.Context) (*ClientWithConn, error) {
	addr := strings.TrimSpace(os.Getenv("CHORA_PAYMENTS_GRPC_ADDR"))
	if addr == "" {
		return nil, errors.New("payments.NewPaymentsClientFromEnv: CHORA_PAYMENTS_GRPC_ADDR not set")
	}
	conn, err := grpc.NewClient(addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return nil, fmt.Errorf("payments.NewPaymentsClientFromEnv: grpc.NewClient %s: %w", addr, err)
	}
	client, err := NewPaymentsClient(conn)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return &ClientWithConn{Client: client, conn: conn}, nil
}

// ClientWithConn pairs a Client with its underlying grpc.ClientConn so
// the caller can Close it during graceful shutdown.
type ClientWithConn struct {
	*Client
	conn *grpc.ClientConn
}

// Close drains the underlying gRPC connection.
func (c *ClientWithConn) Close() error {
	if c == nil || c.conn == nil {
		return nil
	}
	return c.conn.Close()
}

// -----------------------------------------------------------------------------
// CreateSubscription
// -----------------------------------------------------------------------------

// CreateSubscription invokes chora-payments' CreateSubscription RPC + maps
// the response to the port output shape. Validates the input first;
// returns ErrInvalidInput on missing required fields, ErrPaymentsUnavailable
// on transport failure, ErrEmptyResponse on nil response.
func (c *Client) CreateSubscription(
	ctx context.Context,
	in CreateSubscriptionInput,
) (CreateSubscriptionOutput, error) {
	var zero CreateSubscriptionOutput
	if c == nil || c.stub == nil {
		return zero, errors.New("payments: client not initialised")
	}
	if err := validateCreateSubscriptionInput(in); err != nil {
		return zero, err
	}

	billing, err := mapBillingPeriod(in.BillingPeriod)
	if err != nil {
		return zero, err
	}

	req := &paymentsv1.CreateSubscriptionRequest{
		IdempotencyKey: in.IdempotencyKey,
		TenantId:       in.TenantID,
		LearnerGcid:    in.LearnerGcid,
		PlanSku:        in.PlanSku,
		BillingPeriod:  billing,
		AmountCents:    in.AmountCents,
		Currency:       in.Currency,
		SuccessUrl:     in.SuccessURL,
		CancelUrl:      in.CancelURL,
	}
	resp, err := c.stub.CreateSubscription(ctx, req)
	if err != nil {
		if st, ok := status.FromError(err); ok && st.Code() == codes.Unavailable {
			return zero, fmt.Errorf("%w: %s", ErrPaymentsUnavailable, st.Message())
		}
		return zero, fmt.Errorf("payments: CreateSubscription rpc: %w", err)
	}
	if resp == nil {
		return zero, ErrEmptyResponse
	}
	return CreateSubscriptionOutput{
		PurchaseID:        resp.GetPurchaseId(),
		StripeSessionID:   resp.GetStripeSessionId(),
		StripeCheckoutURL: resp.GetStripeCheckoutUrl(),
		State:             StateString(resp.GetState()),
	}, nil
}

// -----------------------------------------------------------------------------
// CreateKycFee — manual-KYC $9.99 one-time charge (ADR-142 + ADR-164 A.5)
// -----------------------------------------------------------------------------

// CreateKycFeeInput is the canonical port input for the
// CreateIdentityKycFeeSession RPC. Built by the chora-identity KYC handler
// from the manual-doc submission + bearer-auth context. Per ADR-142 the
// fee is charged ONLY for manual-doc KYC; Singpass / SkillsFutures learners
// never reach this call (DefaultFeeCents == 0).
type CreateKycFeeInput struct {
	// IdempotencyKey dedupes duplicate Create-KYC-fee calls within a 24h
	// window on the chora-payments side. Required (the verification_id is
	// a natural fit — one fee per verification attempt).
	IdempotencyKey string
	TenantID       string
	LearnerGcid    string
	// KYCDocType is the canonical doc type being verified (e.g.,
	// "manual_id_doc", "manual_passport", "manual_proof_of_address").
	KYCDocType  string
	AmountCents int64
	Currency    string
	// SuccessURL + CancelURL are optional FE redirect targets. When empty,
	// chora-payments falls back to its STRIPE_DEFAULT_*_URL envs.
	SuccessURL string
	CancelURL  string
}

// CreateKycFeeOutput is the port output. For a freshly-minted Checkout
// Session State is always "checkout_started"; the verification only enters
// the review queue once chora-payments publishes payment_captured.
type CreateKycFeeOutput struct {
	PurchaseID        string
	StripeSessionID   string
	StripeCheckoutURL string
	State             string
}

// CreateKycFee invokes chora-payments' CreateIdentityKycFeeSession RPC +
// maps the response to the port output shape. Mirrors CreateSubscription:
// ErrInvalidInput on missing required fields, ErrPaymentsUnavailable on
// transport failure, ErrEmptyResponse on nil response.
func (c *Client) CreateKycFee(
	ctx context.Context,
	in CreateKycFeeInput,
) (CreateKycFeeOutput, error) {
	var zero CreateKycFeeOutput
	if c == nil || c.stub == nil {
		return zero, errors.New("payments: client not initialised")
	}
	if err := validateCreateKycFeeInput(in); err != nil {
		return zero, err
	}

	req := &paymentsv1.CreateIdentityKycFeeSessionRequest{
		IdempotencyKey: in.IdempotencyKey,
		TenantId:       in.TenantID,
		LearnerGcid:    in.LearnerGcid,
		KycDocType:     in.KYCDocType,
		AmountCents:    in.AmountCents,
		Currency:       in.Currency,
		SuccessUrl:     in.SuccessURL,
		CancelUrl:      in.CancelURL,
	}
	resp, err := c.stub.CreateIdentityKycFeeSession(ctx, req)
	if err != nil {
		if st, ok := status.FromError(err); ok && st.Code() == codes.Unavailable {
			return zero, fmt.Errorf("%w: %s", ErrPaymentsUnavailable, st.Message())
		}
		return zero, fmt.Errorf("payments: CreateIdentityKycFeeSession rpc: %w", err)
	}
	if resp == nil {
		return zero, ErrEmptyResponse
	}
	return CreateKycFeeOutput{
		PurchaseID:        resp.GetPurchaseId(),
		StripeSessionID:   resp.GetStripeSessionId(),
		StripeCheckoutURL: resp.GetStripeCheckoutUrl(),
		State:             StateString(resp.GetState()),
	}, nil
}

// validateCreateKycFeeInput rejects empty / zero required fields before the
// RPC dial — surfaces wiring bugs at the caller's stack frame.
func validateCreateKycFeeInput(in CreateKycFeeInput) error {
	if strings.TrimSpace(in.IdempotencyKey) == "" {
		return fmt.Errorf("%w: idempotency_key required", ErrInvalidInput)
	}
	if strings.TrimSpace(in.TenantID) == "" {
		return fmt.Errorf("%w: tenant_id required", ErrInvalidInput)
	}
	if strings.TrimSpace(in.LearnerGcid) == "" {
		return fmt.Errorf("%w: learner_gcid required", ErrInvalidInput)
	}
	if strings.TrimSpace(in.KYCDocType) == "" {
		return fmt.Errorf("%w: kyc_doc_type required", ErrInvalidInput)
	}
	if in.AmountCents <= 0 {
		return fmt.Errorf("%w: amount_cents must be > 0; got %d", ErrInvalidInput, in.AmountCents)
	}
	if strings.TrimSpace(in.Currency) == "" {
		return fmt.Errorf("%w: currency required", ErrInvalidInput)
	}
	return nil
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

// validateCreateSubscriptionInput rejects empty / zero required fields
// + an invalid billing_period before the RPC dial. Cheap-fast-fail per
// `feedback_no_stubs_real_wiring` — surfaces wiring bugs at the caller's
// stack frame.
func validateCreateSubscriptionInput(in CreateSubscriptionInput) error {
	if strings.TrimSpace(in.IdempotencyKey) == "" {
		return fmt.Errorf("%w: idempotency_key required", ErrInvalidInput)
	}
	if strings.TrimSpace(in.TenantID) == "" {
		return fmt.Errorf("%w: tenant_id required", ErrInvalidInput)
	}
	if strings.TrimSpace(in.LearnerGcid) == "" {
		return fmt.Errorf("%w: learner_gcid required", ErrInvalidInput)
	}
	if strings.TrimSpace(in.PlanSku) == "" {
		return fmt.Errorf("%w: plan_sku required", ErrInvalidInput)
	}
	if strings.TrimSpace(in.BillingPeriod) == "" {
		return fmt.Errorf("%w: billing_period required", ErrInvalidInput)
	}
	if in.AmountCents <= 0 {
		return fmt.Errorf("%w: amount_cents must be > 0; got %d", ErrInvalidInput, in.AmountCents)
	}
	if strings.TrimSpace(in.Currency) == "" {
		return fmt.Errorf("%w: currency required", ErrInvalidInput)
	}
	return nil
}

// mapBillingPeriod converts the port-shape string to the proto enum.
// Returns ErrInvalidInput for unknown values; rejecting at the adapter
// avoids forwarding bogus enum values to chora-payments.
func mapBillingPeriod(s string) (paymentsv1.BillingPeriod, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "monthly":
		return paymentsv1.BillingPeriod_BILLING_PERIOD_MONTHLY, nil
	case "annually":
		return paymentsv1.BillingPeriod_BILLING_PERIOD_ANNUALLY, nil
	default:
		return paymentsv1.BillingPeriod_BILLING_PERIOD_UNSPECIFIED,
			fmt.Errorf("%w: billing_period must be 'monthly' or 'annually'; got %q",
				ErrInvalidInput, s)
	}
}

// StateString converts the proto PurchaseState enum to the canonical
// lowercase string used by the chora-identity domain layer and the FE
// response shape.
func StateString(s paymentsv1.PurchaseState) string {
	switch s {
	case paymentsv1.PurchaseState_PURCHASE_STATE_CHECKOUT_STARTED:
		return "checkout_started"
	case paymentsv1.PurchaseState_PURCHASE_STATE_PAYMENT_CAPTURED:
		return "payment_captured"
	case paymentsv1.PurchaseState_PURCHASE_STATE_PAYMENT_FAILED:
		return "payment_failed"
	case paymentsv1.PurchaseState_PURCHASE_STATE_REFUNDED:
		return "refunded"
	case paymentsv1.PurchaseState_PURCHASE_STATE_EXPIRED:
		return "expired"
	default:
		return "unspecified"
	}
}
