// exp_rule_grpc_bufconn_test.go — in-process gRPC integration test for the
// ExpRuleProtoServer using google.golang.org/grpc/test/bufconn. Verifies the
// end-to-end wire path chora-consumption's growth award path takes when it calls
// ExpRuleService.ResolveExpRule (ADR-218 D6): a real *grpc.Server on a
// bufconn.Listener, RegisterExpRuleServiceServer, dial, and round-trip the RPC.
//
// This is the SAME wiring cmd/server/main.go uses (modulo the listener — bufconn
// vs ":9090" tcp) and complements the direct-method tests by exercising the gRPC
// marshalling + transport + the InvalidArgument / Internal status mapping over the
// wire.
package grpcadapter_test

import (
	"context"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	identityv1 "github.com/apollo-chora/chora-contracts/gen/go/chora/services/identity/v1"

	grpcadapter "github.com/apollo-chora/chora-identity/internal/adapter/grpc"
	exprules "github.com/apollo-chora/chora-identity/internal/domain/exp_rules"
)

const expRuleBufconnSize = 1024 * 1024

// startBufconnExpRuleServer spins up an in-process *grpc.Server with a real
// ExpRuleProtoServer bound over the domain resolver + the supplied stub store,
// and returns the proto client + cleanup hook.
func startBufconnExpRuleServer(t *testing.T, store exprules.ExpRuleStore) (identityv1.ExpRuleServiceClient, func()) {
	t.Helper()
	lis := bufconn.Listen(expRuleBufconnSize)
	srv := grpc.NewServer()
	resolver := exprules.NewExpRuleResolver(store)
	identityv1.RegisterExpRuleServiceServer(srv, grpcadapter.NewExpRuleProtoServer(resolver))

	go func() {
		if err := srv.Serve(lis); err != nil {
			t.Logf("bufconn exp-rule server stopped: %v", err)
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
	client := identityv1.NewExpRuleServiceClient(conn)
	cleanup := func() {
		_ = conn.Close()
		srv.GracefulStop()
		_ = lis.Close()
	}
	return client, cleanup
}

// TestBufconn_ExpRuleService_ResolvesCatalogueDefault exercises the full
// chora-consumption → chora-identity wire path for a catalogue-default source (the
// behaviour-neutral parity path — migration 0029 seeds atom_session 3/30).
func TestBufconn_ExpRuleService_ResolvesCatalogueDefault(t *testing.T) {
	t.Parallel()
	store := &stubExpRuleStore{out: exprules.ResolvedExpRule{
		SourceCode: "atom_session", ExpValue: 3, DailyCap: 30, Enabled: true, Source: "catalogue",
	}}
	client, cleanup := startBufconnExpRuleServer(t, store)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := client.ResolveExpRule(ctx, &identityv1.ResolveExpRuleRequest{SourceCode: "atom_session"})
	if err != nil {
		t.Fatalf("ResolveExpRule: %v", err)
	}
	if resp.GetExpValue() != 3 || resp.GetDailyCap() != 30 {
		t.Errorf("got {%d,%d}, want {3,30}", resp.GetExpValue(), resp.GetDailyCap())
	}
	if !resp.GetEnabled() || resp.GetResolutionSource() != "catalogue" {
		t.Errorf("enabled/source = {%v,%q}, want {true,catalogue}", resp.GetEnabled(), resp.GetResolutionSource())
	}
}

// TestBufconn_ExpRuleService_UnknownSourceInvalidArgument asserts an unknown
// source is rejected as gRPC InvalidArgument over the wire — the code
// chora-consumption's growth client relies on to distinguish a caller contract
// error from a retryable server fault.
func TestBufconn_ExpRuleService_UnknownSourceInvalidArgument(t *testing.T) {
	t.Parallel()
	store := &stubExpRuleStore{err: exprules.ErrUnknownSource}
	client, cleanup := startBufconnExpRuleServer(t, store)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := client.ResolveExpRule(ctx, &identityv1.ResolveExpRuleRequest{SourceCode: "i_passed_the_real_pmp"})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("status = %v, want InvalidArgument", status.Code(err))
	}
}

// TestBufconn_ExpRuleService_DisabledIsEnabledFalse asserts a disabled source
// round-trips as a SUCCESSFUL resolution with enabled=false (the caller skips the
// award) — NOT an error.
func TestBufconn_ExpRuleService_DisabledIsEnabledFalse(t *testing.T) {
	t.Parallel()
	store := &stubExpRuleStore{out: exprules.ResolvedExpRule{
		SourceCode: "atom_authored", ExpValue: 20, DailyCap: 40, Enabled: false, Source: "tenant",
	}}
	client, cleanup := startBufconnExpRuleServer(t, store)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := client.ResolveExpRule(ctx, &identityv1.ResolveExpRuleRequest{
		SourceCode: "atom_authored", TenantId: "11111111-1111-7111-8111-111111111111",
	})
	if err != nil {
		t.Fatalf("ResolveExpRule: %v (disabled is a valid resolved state, not an error)", err)
	}
	if resp.GetEnabled() {
		t.Errorf("Enabled = true, want false")
	}
}
