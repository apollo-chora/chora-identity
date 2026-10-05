//go:build integration

// identity_integration_test.go — `//go:build integration` tagged smoke for
// chora-identity. Runs in Cloud Build stage 3 (integration-test) invoked
// via `go test -race -tags=integration ./...`.
//
// Exercises the ManaService GetBalance RPC end-to-end via bufconn plus the
// gRPC Health/Check round-trip — the same wire path chora-creation's
// ManaClient takes when SVC_IDENTITY_GRPC_URL is set, and the same Health
// probe Cloud Deploy's VERIFY Job dispatches post-DEPLOY.
//
// Mirrors the unit-level bufconn test at mana_grpc_bufconn_test.go (same
// composition, untagged) and adds Health coverage that the verify-Job
// smoke depends on. The existing internal/adapter/pg/integration_test.go
// auto-skips in CI without CHORA_TEST_DSN; this file always runs.
package grpcadapter_test

import (
	"context"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	healthgrpc "google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/test/bufconn"

	identityv1 "github.com/apollo-chora/chora-contracts/gen/go/chora/services/identity/v1"

	grpcadapter "github.com/apollo-chora/chora-identity/internal/adapter/grpc"
	mana "github.com/apollo-chora/chora-identity/internal/domain/user_mana"
)

// startIntegrationIdentityServer mirrors cmd/server/main.go's gRPC composition:
// ManaService bound + Health bound on the same *grpc.Server. The Health
// registration is the new Wave-2 #3 fix — main.go now registers
// chora.services.identity.v1.{Identity, ManaService, KycService} as SERVING.
func startIntegrationIdentityServer(t *testing.T) (*grpc.ClientConn, func()) {
	t.Helper()
	lis := bufconn.Listen(1024 * 1024)
	srv := grpc.NewServer()

	// ManaService — the canonical wire surface for chora-creation's ManaClient.
	store := mana.NewInMemoryStore()
	q := mana.NewQuoter(store)
	core := grpcadapter.NewManaServer(q, store, nil)
	identityv1.RegisterManaServiceServer(srv, grpcadapter.NewManaProtoServer(core))

	// Health — mirrors the post-Wave-2-#3 main.go registration.
	healthSrv := healthgrpc.NewServer()
	healthSrv.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)
	healthSrv.SetServingStatus("chora.services.identity.v1.ManaService", healthpb.HealthCheckResponse_SERVING)
	healthSrv.SetServingStatus("chora.services.identity.v1.Identity", healthpb.HealthCheckResponse_SERVING)
	healthSrv.SetServingStatus("chora.services.identity.v1.KycService", healthpb.HealthCheckResponse_SERVING)
	healthpb.RegisterHealthServer(srv, healthSrv)

	go func() {
		if err := srv.Serve(lis); err != nil {
			t.Logf("integration bufconn server stopped: %v", err)
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
		t.Fatalf("integration bufconn dial: %v", err)
	}
	cleanup := func() {
		_ = conn.Close()
		srv.GracefulStop()
		_ = lis.Close()
	}
	return conn, cleanup
}

// Integration smoke: gRPC Health/Check responds SERVING for the default
// surface AND for the service-scoped registrations the CSM probe-routing
// relies on. This is the verify-Job contract that runs in Cloud Deploy's
// VERIFY stage post-DEPLOY.
func TestIntegration_Identity_HealthCheck_AllSurfacesServing(t *testing.T) {
	t.Parallel()
	conn, cleanup := startIntegrationIdentityServer(t)
	defer cleanup()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client := healthpb.NewHealthClient(conn)
	cases := []struct {
		name    string
		service string
	}{
		{"default", ""},
		{"ManaService", "chora.services.identity.v1.ManaService"},
		{"Identity", "chora.services.identity.v1.Identity"},
		{"KycService", "chora.services.identity.v1.KycService"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			resp, err := client.Check(ctx, &healthpb.HealthCheckRequest{Service: tc.service})
			if err != nil {
				t.Fatalf("Health/Check(%q): %v", tc.service, err)
			}
			if resp.Status != healthpb.HealthCheckResponse_SERVING {
				t.Errorf("Health/Check(%q) = %v; want SERVING", tc.service, resp.Status)
			}
		})
	}
}

// Integration smoke: ManaService.GetBalance RPC end-to-end via bufconn.
// Verifies the full marshalling + proto<->wire bridge — same path
// chora-creation's ManaClient takes when SVC_IDENTITY_GRPC_URL is set.
func TestIntegration_Identity_ManaService_GetBalance_RoundTrip(t *testing.T) {
	t.Parallel()
	conn, cleanup := startIntegrationIdentityServer(t)
	defer cleanup()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client := identityv1.NewManaServiceClient(conn)
	const gcid = "01970000-0000-7000-9000-000000ce0001"

	// Fresh user → balance is 0 (in-memory store seeds nothing for unknown gcid).
	resp, err := client.GetBalance(ctx, &identityv1.GetBalanceRequest{Gcid: gcid})
	if err != nil {
		t.Fatalf("GetBalance: %v", err)
	}
	if got := resp.GetBalanceUnits(); got != 0 {
		t.Errorf("balance_units = %d; want 0 (fresh user)", got)
	}
	if got := resp.GetLifetimeEarned(); got != 0 {
		t.Errorf("lifetime_earned = %d; want 0 (fresh user)", got)
	}
	if got := resp.GetLifetimeSpent(); got != 0 {
		t.Errorf("lifetime_spent = %d; want 0 (fresh user)", got)
	}
}
