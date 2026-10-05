// grpc_client_gap_test.go — remaining adapter branches: the success paths
// of the conn-based constructors, the env constructor's success branch, the
// ClientWithConn close lifecycle, the uninitialised-client guard, and the
// CreateKycFee error-mapping branches not covered by the main suite.
package payments_test

import (
	"context"
	"errors"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	"github.com/apollo-chora/chora-identity/internal/adapter/payments"
)

func TestNewPaymentsClient_WithRealConn(t *testing.T) {
	t.Parallel()
	// grpc.NewClient is lazy — no dial happens; the generated stub wraps the
	// conn, so the success branch is exercised without a live service.
	conn, err := grpc.NewClient("127.0.0.1:1", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("grpc.NewClient: %v", err)
	}
	defer conn.Close()
	c, err := payments.NewPaymentsClient(conn)
	if err != nil {
		t.Fatalf("NewPaymentsClient(conn): %v", err)
	}
	if c == nil {
		t.Fatal("NewPaymentsClient returned nil client")
	}
}

func TestNewPaymentsClientFromEnv_SuccessAndClose(t *testing.T) {
	t.Setenv("CHORA_PAYMENTS_GRPC_ADDR", "127.0.0.1:1")
	c, err := payments.NewPaymentsClientFromEnv(context.Background())
	if err != nil {
		t.Fatalf("NewPaymentsClientFromEnv: %v", err)
	}
	if c == nil || c.Client == nil {
		t.Fatal("NewPaymentsClientFromEnv returned nil client")
	}
	if err := c.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}

func TestClientWithConn_CloseNilSafe(t *testing.T) {
	t.Parallel()
	var c *payments.ClientWithConn
	if err := c.Close(); err != nil {
		t.Errorf("Close on nil receiver: %v", err)
	}
}

func TestClient_CreateSubscription_UninitialisedGuard(t *testing.T) {
	t.Parallel()
	var c *payments.Client
	if _, err := c.CreateSubscription(context.Background(), payments.CreateSubscriptionInput{
		IdempotencyKey: "k", TenantID: "t", LearnerGcid: "g", PlanSku: "p",
		BillingPeriod: "monthly", AmountCents: 100, Currency: "USD",
	}); err == nil {
		t.Error("CreateSubscription on nil client must error")
	}
}

func TestClient_CreateKycFee_UninitialisedGuard(t *testing.T) {
	t.Parallel()
	var c *payments.Client
	if _, err := c.CreateKycFee(context.Background(), payments.CreateKycFeeInput{
		IdempotencyKey: "k", TenantID: "t", LearnerGcid: "g", KYCDocType: "manual_id_doc",
		AmountCents: 999, Currency: "USD",
	}); err == nil {
		t.Error("CreateKycFee on nil client must error")
	}
}

func TestClient_CreateKycFee_NonUnavailableGRPCError(t *testing.T) {
	t.Parallel()
	stub := &stubPaymentClient{kycErr: status.Error(codes.Internal, "boom")}
	c := payments.NewPaymentsClientFromStubMust(t, stub)
	_, err := c.CreateKycFee(context.Background(), payments.CreateKycFeeInput{
		IdempotencyKey: "k", TenantID: "t", LearnerGcid: "g", KYCDocType: "manual_id_doc",
		AmountCents: 999, Currency: "USD",
	})
	if err == nil {
		t.Fatal("expected RPC error")
	}
	if errors.Is(err, payments.ErrPaymentsUnavailable) {
		t.Errorf("Internal code must NOT map to ErrPaymentsUnavailable: %v", err)
	}
}

func TestClient_CreateKycFee_UnavailableMapsSentinel(t *testing.T) {
	t.Parallel()
	stub := &stubPaymentClient{kycErr: status.Error(codes.Unavailable, "mesh down")}
	c := payments.NewPaymentsClientFromStubMust(t, stub)
	_, err := c.CreateKycFee(context.Background(), payments.CreateKycFeeInput{
		IdempotencyKey: "k", TenantID: "t", LearnerGcid: "g", KYCDocType: "manual_id_doc",
		AmountCents: 999, Currency: "USD",
	})
	if !errors.Is(err, payments.ErrPaymentsUnavailable) {
		t.Errorf("Unavailable must map to ErrPaymentsUnavailable; got %v", err)
	}
}

func TestClient_CreateKycFee_NilResponseRejects(t *testing.T) {
	t.Parallel()
	stub := &stubPaymentClient{}
	c := payments.NewPaymentsClientFromStubMust(t, stub)
	_, err := c.CreateKycFee(context.Background(), payments.CreateKycFeeInput{
		IdempotencyKey: "k", TenantID: "t", LearnerGcid: "g", KYCDocType: "manual_id_doc",
		AmountCents: 999, Currency: "USD",
	})
	if !errors.Is(err, payments.ErrEmptyResponse) {
		t.Errorf("nil response must map to ErrEmptyResponse; got %v", err)
	}
}

func TestClient_CreateSubscription_NonUnavailableGRPCError(t *testing.T) {
	t.Parallel()
	stub := &stubPaymentClient{err: status.Error(codes.PermissionDenied, "nope")}
	c := payments.NewPaymentsClientFromStubMust(t, stub)
	_, err := c.CreateSubscription(context.Background(), payments.CreateSubscriptionInput{
		IdempotencyKey: "k", TenantID: "t", LearnerGcid: "g", PlanSku: "p",
		BillingPeriod: "monthly", AmountCents: 100, Currency: "USD",
	})
	if err == nil {
		t.Fatal("expected RPC error")
	}
	if errors.Is(err, payments.ErrPaymentsUnavailable) {
		t.Errorf("PermissionDenied must NOT map to ErrPaymentsUnavailable: %v", err)
	}
}

func TestValidateCreateKycFeeInput_MissingCurrencyAndAmount(t *testing.T) {
	t.Parallel()
	c := payments.NewPaymentsClientFromStubMust(t, &stubPaymentClient{})
	valid := payments.CreateKycFeeInput{
		IdempotencyKey: "k", TenantID: "t", LearnerGcid: "g", KYCDocType: "manual_id_doc",
		AmountCents: 999, Currency: "USD",
	}
	noCurrency := valid
	noCurrency.Currency = ""
	if _, err := c.CreateKycFee(context.Background(), noCurrency); !errors.Is(err, payments.ErrInvalidInput) {
		t.Errorf("missing currency: err=%v, want ErrInvalidInput", err)
	}
	zeroAmount := valid
	zeroAmount.AmountCents = 0
	if _, err := c.CreateKycFee(context.Background(), zeroAmount); !errors.Is(err, payments.ErrInvalidInput) {
		t.Errorf("zero amount: err=%v, want ErrInvalidInput", err)
	}
}
