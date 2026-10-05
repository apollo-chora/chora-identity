// mana_grpc_bufconn_test.go — in-process gRPC integration test for the
// ManaProtoServer using google.golang.org/grpc/test/bufconn. Verifies
// end-to-end serialization + the proto<->wire type bridge by running a
// real *grpc.Server on a bufconn.Listener, registering the ManaService
// server, dialing it with the bufconn DialContext, and round-tripping
// the three RPC methods.
//
// This complements the direct-method-invocation tests
// (mana_proto_server_test.go) by exercising the gRPC marshalling + the
// transport layer end-to-end — the same path chora-creation's ManaClient
// will take when SVC_IDENTITY_GRPC_URL is wired in prod.
package grpcadapter_test

import (
	"context"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	identityv1 "github.com/apollo-chora/chora-contracts/gen/go/chora/services/identity/v1"

	grpcadapter "github.com/apollo-chora/chora-identity/internal/adapter/grpc"
	mana "github.com/apollo-chora/chora-identity/internal/domain/user_mana"
)

const bufconnSize = 1024 * 1024

// startBufconnManaServer spins up an in-process *grpc.Server with a real
// ManaProtoServer bound + returns the proto client + cleanup hook. This is
// the SAME wiring cmd/server/main.go will use (modulo the listener — bufconn
// vs ":8081" tcp).
func startBufconnManaServer(t *testing.T) (identityv1.ManaServiceClient, func()) {
	t.Helper()
	lis := bufconn.Listen(bufconnSize)
	srv := grpc.NewServer()
	store := mana.NewInMemoryStore()
	q := mana.NewQuoter(store)
	core := grpcadapter.NewManaServer(q, store, nil)
	identityv1.RegisterManaServiceServer(srv, grpcadapter.NewManaProtoServer(core))

	go func() {
		if err := srv.Serve(lis); err != nil {
			t.Logf("bufconn mana server stopped: %v", err)
		}
	}()

	//nolint:staticcheck // bufconn dial requires the legacy DialContext API.
	conn, err := grpc.DialContext(
		context.Background(),
		"bufconn",
		grpc.WithContextDialer(func(_ context.Context, _ string) (net.Conn, error) {
			return lis.Dial()
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("bufconn dial: %v", err)
	}
	client := identityv1.NewManaServiceClient(conn)

	cleanup := func() {
		_ = conn.Close()
		srv.GracefulStop()
		_ = lis.Close()
	}
	return client, cleanup
}

// TestBufconn_ManaService_RoundTrip exercises the full chora-creation →
// chora-identity wire path: CreditMana (subscription grant) → DeductMana
// (single-Q ai_draft action) → GetBalance. The same call sequence the
// chora-creation question_jobs_handler.createQuestionJob fans out.
func TestBufconn_ManaService_RoundTrip(t *testing.T) {
	t.Parallel()
	client, cleanup := startBufconnManaServer(t)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	gcid := "01970000-0000-7000-8000-000000001999" // canonical Phyllis fixture

	// 1. Credit 100 mana via subscription_grant.
	credResp, err := client.CreditMana(ctx, &identityv1.CreditManaRequest{
		Gcid:                 gcid,
		Source:               identityv1.ManaSource_MANA_SOURCE_SUBSCRIPTION_GRANT,
		Units:                100,
		Reason:               identityv1.ManaReasonCode_MANA_REASON_CODE_SUBSCRIPTION_GRANT,
		IdempotencyKey:       "ck-bufconn-1",
		SourceSubscriptionId: "sub-phyllis-basic",
	})
	if err != nil {
		t.Fatalf("CreditMana: %v", err)
	}
	if credResp.GetBalanceAfterUnits() != 100 {
		t.Errorf("after credit balance = %d; want 100", credResp.GetBalanceAfterUnits())
	}
	if credResp.GetEntry() == nil {
		t.Fatalf("CreditMana Entry nil")
	}
	if credResp.GetEntry().GetUnits() != 100 {
		t.Errorf("Entry.Units = %d; want 100", credResp.GetEntry().GetUnits())
	}

	// 2. Deduct 10 mana for question_authoring_ai_draft.
	dedResp, err := client.DeductMana(ctx, &identityv1.DeductManaRequest{
		Gcid:           gcid,
		ActionCode:     "question_authoring_ai_draft",
		Units:          10,
		IdempotencyKey: "01970000-0000-7000-8000-000000000001",
	})
	if err != nil {
		t.Fatalf("DeductMana: %v", err)
	}
	if !dedResp.GetSuccess() {
		t.Errorf("DeductMana success = false; want true")
	}
	if dedResp.GetBalanceAfterUnits() != 90 {
		t.Errorf("after deduct balance = %d; want 90", dedResp.GetBalanceAfterUnits())
	}

	// 3. GetBalance reports the post-debit state.
	balResp, err := client.GetBalance(ctx, &identityv1.GetBalanceRequest{Gcid: gcid})
	if err != nil {
		t.Fatalf("GetBalance: %v", err)
	}
	if balResp.GetBalanceUnits() != 90 {
		t.Errorf("GetBalance BalanceUnits = %d; want 90", balResp.GetBalanceUnits())
	}
}

// TestBufconn_ManaService_DeductMana_InsufficientBalance asserts the
// Success=false + RequiredUnits + CurrentBalanceUnits round-trip works.
// chora-creation's ManaClient renders the 402 InsufficientManaUpsell
// envelope from these fields.
func TestBufconn_ManaService_DeductMana_InsufficientBalance(t *testing.T) {
	t.Parallel()
	client, cleanup := startBufconnManaServer(t)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	gcid := "01970000-0000-7000-8000-000000000099"

	// Credit only 5 mana.
	if _, err := client.CreditMana(ctx, &identityv1.CreditManaRequest{
		Gcid:           gcid,
		Source:         identityv1.ManaSource_MANA_SOURCE_TOPUP,
		Units:          5,
		Reason:         identityv1.ManaReasonCode_MANA_REASON_CODE_TOPUP,
		IdempotencyKey: "ck-low-1",
		SourceTopupId:  "topup-1",
	}); err != nil {
		t.Fatalf("seed CreditMana: %v", err)
	}

	// Attempt 100 mana debit.
	resp, err := client.DeductMana(ctx, &identityv1.DeductManaRequest{
		Gcid:           gcid,
		ActionCode:     "question_authoring_ai_draft",
		Units:          100,
		IdempotencyKey: "dk-low-1",
	})
	if err != nil {
		t.Fatalf("DeductMana: %v", err)
	}
	if resp.GetSuccess() {
		t.Errorf("Success = true; want false on insufficient balance")
	}
	if resp.GetRequiredUnits() != 100 {
		t.Errorf("RequiredUnits = %d; want 100", resp.GetRequiredUnits())
	}
	if resp.GetCurrentBalanceUnits() != 5 {
		t.Errorf("CurrentBalanceUnits = %d; want 5", resp.GetCurrentBalanceUnits())
	}
}

// TestBufconn_ManaService_Idempotency asserts the wire-level idempotency
// guard: repeated DeductMana with the same idempotency_key MUST NOT debit
// multiple times.
func TestBufconn_ManaService_Idempotency(t *testing.T) {
	t.Parallel()
	client, cleanup := startBufconnManaServer(t)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	gcid := "01970000-0000-7000-8000-000000000033"
	if _, err := client.CreditMana(ctx, &identityv1.CreditManaRequest{
		Gcid:           gcid,
		Source:         identityv1.ManaSource_MANA_SOURCE_TOPUP,
		Units:          500,
		Reason:         identityv1.ManaReasonCode_MANA_REASON_CODE_TOPUP,
		IdempotencyKey: "ck",
		SourceTopupId:  "t-1",
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	// Three duplicate DeductMana calls on the same key — only ONE should
	// land. ManaClient retries with the same key under retry policy.
	for i := 0; i < 3; i++ {
		if _, err := client.DeductMana(ctx, &identityv1.DeductManaRequest{
			Gcid:           gcid,
			ActionCode:     "x",
			Units:          100,
			IdempotencyKey: "dk-replay",
		}); err != nil {
			t.Fatalf("DeductMana #%d: %v", i, err)
		}
	}
	bal, err := client.GetBalance(ctx, &identityv1.GetBalanceRequest{Gcid: gcid})
	if err != nil {
		t.Fatalf("GetBalance: %v", err)
	}
	if bal.GetBalanceUnits() != 400 {
		t.Errorf("replay debited multiple times; balance = %d; want 400", bal.GetBalanceUnits())
	}
}
