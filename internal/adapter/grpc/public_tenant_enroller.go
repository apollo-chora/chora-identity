// public_tenant_enroller.go — ADR-182 auto-enrol adapter.
//
// Implements httpadapter.PublicTenantEnroller against chora-tenancy's
// UpsertMembership RPC: at first resolve with zero memberships, the
// resolve handler enrols the GCID into the public chora-master tenant as
// learner+author. The authoritative write lands in chora_tenancy.members
// (ON CONFLICT DO NOTHING — idempotent under resolve races); the
// identity-side tenant_memberships MIRROR is upserted best-effort per
// granted role (non-fatal — the tenant.bootstrapped.v1 subscriber path
// and later resolves self-heal a missed mirror row).
//
// Tenant addressing is by slug (env PUBLIC_TENANT_SLUG, default
// "chora-master") so no tenant UUID is inlined per
// feedback_no_inline_config.
package grpcadapter

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"

	"google.golang.org/grpc"

	tenancyv1 "github.com/apollo-chora/chora-contracts/gen/go/chora/services/tenancy/v1"

	httpadapter "github.com/apollo-chora/chora-identity/internal/adapter/http"
)

// publicTenantRoles is the ADR-182 D2 default public-space grant.
var publicTenantRoles = []string{"learner", "author"}

// membershipUpsertStub is the single-RPC slice of the generated
// tenancyv1.TenancyClient this adapter needs — keeps the test fake tiny.
type membershipUpsertStub interface {
	UpsertMembership(ctx context.Context, in *tenancyv1.UpsertMembershipRequest, opts ...grpc.CallOption) (*tenancyv1.UpsertMembershipResponse, error)
}

// MirrorUpserter is the best-effort identity-mirror seam — satisfied by
// pg.MembershipBootstrapUpserter.
type MirrorUpserter interface {
	UpsertMembershipOnBootstrap(ctx context.Context, gcid, tenantID, role string) error
}

// PublicTenantEnroller satisfies httpadapter.PublicTenantEnroller.
type PublicTenantEnroller struct {
	stub   membershipUpsertStub
	slug   string
	mirror MirrorUpserter
}

// NewPublicTenantEnroller wraps an existing grpc.ClientConn (the same
// conn the TenancyClient uses). slug empty → "chora-master". mirror may
// be nil (mirror upserts skipped).
func NewPublicTenantEnroller(conn *grpc.ClientConn, slug string, mirror MirrorUpserter) (*PublicTenantEnroller, error) {
	if conn == nil {
		return nil, errors.New("grpc.NewPublicTenantEnroller: nil conn")
	}
	return NewPublicTenantEnrollerFromStub(tenancyv1.NewTenancyClient(conn), slug, mirror), nil
}

// NewPublicTenantEnrollerFromStub constructs from a pre-built stub —
// used by tests.
func NewPublicTenantEnrollerFromStub(stub membershipUpsertStub, slug string, mirror MirrorUpserter) *PublicTenantEnroller {
	slug = strings.TrimSpace(slug)
	if slug == "" {
		slug = "chora-master"
	}
	return &PublicTenantEnroller{stub: stub, slug: slug, mirror: mirror}
}

// EnsurePublicMembership implements httpadapter.PublicTenantEnroller.
func (e *PublicTenantEnroller) EnsurePublicMembership(ctx context.Context, gcid string) error {
	if strings.TrimSpace(gcid) == "" {
		return errors.New("grpc.PublicTenantEnroller.EnsurePublicMembership: empty gcid")
	}
	resp, err := e.stub.UpsertMembership(ctx, &tenancyv1.UpsertMembershipRequest{
		Gcid:       gcid,
		TenantSlug: e.slug,
		Roles:      append([]string(nil), publicTenantRoles...),
	})
	if err != nil {
		return fmt.Errorf("grpc.PublicTenantEnroller.EnsurePublicMembership: %w", err)
	}

	// Best-effort mirror upserts — one row per granted role; failures are
	// logged, never fatal (the authoritative store already has the rows).
	if e.mirror != nil {
		m := resp.GetMembership()
		for _, role := range m.GetRoles() {
			if merr := e.mirror.UpsertMembershipOnBootstrap(ctx, gcid, m.GetTenantId(), role); merr != nil {
				log.Printf("grpc.PublicTenantEnroller: mirror upsert gcid=%s role=%s (non-fatal): %v", gcid, role, merr)
			}
		}
	}
	return nil
}

// Compile-time check.
var _ httpadapter.PublicTenantEnroller = (*PublicTenantEnroller)(nil)
