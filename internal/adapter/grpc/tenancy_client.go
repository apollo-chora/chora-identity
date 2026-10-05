// Package grpc — gRPC client adapters for chora-identity.
//
// This file owns the TenancyClient — the wrapper around the
// chora.services.tenancy.v1.TenancyClient stub used by the resolve_handler
// to look up tenant memberships for a freshly-validated GCID.
//
// Per ddd-enforcement HARD RULE: chora-identity MUST NOT query chora_tenancy
// directly. This client is the sole sanctioned cross-domain read path.
//
// Trust model: mTLS via Cloud Service Mesh. The CallerSA at the mesh
// layer is the chora-identity workload identity; chora-tenancy's
// AuthorizationPolicy gates access by source SA. No JWT validation here.
//
// OTLP context propagation: the unary client interceptor on the
// underlying grpc.ClientConn carries W3C traceparent into the chora-
// tenancy span automatically.
package grpcadapter

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"google.golang.org/grpc"

	tenancyv1 "github.com/apollo-chora/chora-contracts/gen/go/chora/services/tenancy/v1"

	httpadapter "github.com/apollo-chora/chora-identity/internal/adapter/http"
)

// TenancyClient is the chora-identity adapter that satisfies the
// httpadapter.TenancyClient port. Wraps the gRPC stub + translates the
// proto TenantMembership into the local httpadapter.TenantMembership.
type TenancyClient struct {
	stub tenancyv1.TenancyClient
}

// NewTenancyClient wraps an existing grpc.ClientConn (constructed by the
// caller — typically cmd/server/main.go with mesh-internal credentials).
// Returns an error when conn is nil so boot fails loud.
func NewTenancyClient(conn *grpc.ClientConn) (*TenancyClient, error) {
	if conn == nil {
		return nil, errors.New("grpc.NewTenancyClient: nil conn")
	}
	return &TenancyClient{stub: tenancyv1.NewTenancyClient(conn)}, nil
}

// NewTenancyClientFromStub constructs a TenancyClient from a pre-built
// stub. Used by tests with a bufconn-backed stub.
func NewTenancyClientFromStub(stub tenancyv1.TenancyClient) *TenancyClient {
	return &TenancyClient{stub: stub}
}

// ListMembershipsByGCID implements httpadapter.TenancyClient.
//
// Translates the proto response into the resolve-handler-native shape so
// the handler stays decoupled from chora-contracts gen stubs.
func (c *TenancyClient) ListMembershipsByGCID(ctx context.Context, gcid string) (*httpadapter.MembershipsResolution, error) {
	if strings.TrimSpace(gcid) == "" {
		return nil, errors.New("grpc.TenancyClient.ListMembershipsByGCID: empty gcid")
	}
	resp, err := c.stub.ListMembershipsByGCID(ctx, &tenancyv1.ListMembershipsByGCIDRequest{
		Gcid: gcid,
	})
	if err != nil {
		return nil, fmt.Errorf("grpc.TenancyClient.ListMembershipsByGCID: %w", err)
	}
	out := &httpadapter.MembershipsResolution{
		DefaultTenantID: resp.GetDefaultTenantId(),
	}
	for _, m := range resp.GetMemberships() {
		out.Memberships = append(out.Memberships, httpadapter.TenantMembership{
			TenantID:   m.GetTenantId(),
			TenantSlug: m.GetTenantSlug(),
			Roles:      append([]string(nil), m.GetRoles()...),
			Surfaces:   append([]string(nil), m.GetSurfaces()...),
			IsDefault:  m.GetIsDefault(),
		})
	}
	return out, nil
}

// Compile-time check.
var _ httpadapter.TenancyClient = (*TenancyClient)(nil)
