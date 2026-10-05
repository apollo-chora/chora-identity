// admin_membership_upserter.go — ADR-182 authoritative add-member adapter.
//
// Implements httpadapter.AuthoritativeMembershipUpserter against
// chora-tenancy's UpsertMembership RPC, addressing the tenant by id (the
// admin handler already holds the caller's tenant id from the mesh
// header). gRPC status codes are mapped onto the httpadapter sentinels so
// the handler translates them without importing grpc/codes:
//
//	FAILED_PRECONDITION → refusalSentinel: the errdetails reason picks between
//	                      ErrUpstreamMembershipSuspended,
//	                      ErrUpstreamLastOwnerProtected and
//	                      ErrUpstreamOwnerRoleProtected (S7-B1)
//	NOT_FOUND           → httpadapter.ErrUpstreamTenantNotFound
package grpcadapter

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	tenancyv1 "github.com/apollo-chora/chora-contracts/gen/go/chora/services/tenancy/v1"

	httpadapter "github.com/apollo-chora/chora-identity/internal/adapter/http"
)

// membershipAdminStub is the slice of tenancyv1.TenancyClient the admin
// adapter needs: UpsertMembership (add/replace) + RemoveMembership (WS2b
// member-centric revoke). The real client satisfies it; the test fake adds
// RemoveMembership alongside its existing UpsertMembership.
type membershipAdminStub interface {
	UpsertMembership(ctx context.Context, in *tenancyv1.UpsertMembershipRequest, opts ...grpc.CallOption) (*tenancyv1.UpsertMembershipResponse, error)
	RemoveMembership(ctx context.Context, in *tenancyv1.RemoveMembershipRequest, opts ...grpc.CallOption) (*tenancyv1.RemoveMembershipResponse, error)
}

// refusalSentinel maps a tenancy FAILED_PRECONDITION onto the httpadapter
// sentinel the handler branches on. Three refusals now share that status code
// (suspended, last owner, owner strip), so the discriminator is the
// errdetails.ErrorInfo reason chora-tenancy attaches, not the message text.
//
// An error with no reason, or with a reason this build does not know, keeps
// the historical suspension mapping. That is deliberate: an unrecognised
// refusal must not be dressed up as an ownership problem, because "hand
// ownership over" is useless advice for a refusal that has nothing to do with
// ownership. It stays an error either way; only the label is conservative.
func refusalSentinel(err error) error {
	st, ok := status.FromError(err)
	if !ok {
		return httpadapter.ErrUpstreamMembershipSuspended
	}
	for _, d := range st.Details() {
		info, ok := d.(*errdetails.ErrorInfo)
		if !ok {
			continue
		}
		switch info.GetReason() {
		case "LAST_OWNER_PROTECTED":
			return httpadapter.ErrUpstreamLastOwnerProtected
		case "OWNER_ROLE_PROTECTED":
			return httpadapter.ErrUpstreamOwnerRoleProtected
		}
	}
	return httpadapter.ErrUpstreamMembershipSuspended
}

// AdminMembershipUpserter satisfies httpadapter.AuthoritativeMembershipUpserter.
type AdminMembershipUpserter struct {
	stub membershipAdminStub
}

// NewAdminMembershipUpserter wraps an existing grpc.ClientConn (the same
// conn the TenancyClient uses).
func NewAdminMembershipUpserter(conn *grpc.ClientConn) (*AdminMembershipUpserter, error) {
	if conn == nil {
		return nil, errors.New("grpc.NewAdminMembershipUpserter: nil conn")
	}
	return NewAdminMembershipUpserterFromStub(tenancyv1.NewTenancyClient(conn)), nil
}

// NewAdminMembershipUpserterFromStub constructs from a pre-built stub —
// used by tests.
func NewAdminMembershipUpserterFromStub(stub membershipAdminStub) *AdminMembershipUpserter {
	return &AdminMembershipUpserter{stub: stub}
}

// UpsertMembershipByTenantID implements
// httpadapter.AuthoritativeMembershipUpserter.
func (a *AdminMembershipUpserter) UpsertMembershipByTenantID(ctx context.Context, gcid, tenantID string, roles []string) (bool, error) {
	return a.callUpsert(ctx, gcid, tenantID, roles, false)
}

// ReplaceMembershipByTenantID implements
// httpadapter.AuthoritativeMembershipUpserter — calls the same UpsertMembership
// RPC with replace_existing=true so chora-tenancy soft-deletes the existing
// live role rows that are NOT in `roles` before upserting the request set.
func (a *AdminMembershipUpserter) ReplaceMembershipByTenantID(ctx context.Context, gcid, tenantID string, roles []string) (bool, error) {
	return a.callUpsert(ctx, gcid, tenantID, roles, true)
}

func (a *AdminMembershipUpserter) callUpsert(ctx context.Context, gcid, tenantID string, roles []string, replace bool) (bool, error) {
	if strings.TrimSpace(gcid) == "" {
		return false, errors.New("grpc.AdminMembershipUpserter: empty gcid")
	}
	if strings.TrimSpace(tenantID) == "" {
		return false, errors.New("grpc.AdminMembershipUpserter: empty tenant_id")
	}
	if len(roles) == 0 {
		return false, errors.New("grpc.AdminMembershipUpserter: empty roles")
	}
	resp, err := a.stub.UpsertMembership(ctx, &tenancyv1.UpsertMembershipRequest{
		Gcid:            gcid,
		TenantId:        tenantID,
		Roles:           append([]string(nil), roles...),
		ReplaceExisting: replace,
	})
	if err != nil {
		switch status.Code(err) {
		case codes.FailedPrecondition:
			return false, fmt.Errorf("%w: %v", refusalSentinel(err), err)
		case codes.NotFound:
			return false, fmt.Errorf("%w: %v", httpadapter.ErrUpstreamTenantNotFound, err)
		}
		return false, fmt.Errorf("grpc.AdminMembershipUpserter.UpsertMembership: %w", err)
	}
	return resp.GetCreated(), nil
}

// RemoveMembershipByTenantID implements
// httpadapter.AuthoritativeMembershipUpserter — calls tenancy RemoveMembership
// to SOFT-DELETE every authoritative role row for (tenant, gcid) (WS2b /
// CHO-1869). gRPC status mapping mirrors callUpsert:
//
//	FAILED_PRECONDITION → refusalSentinel (suspended / last owner / owner strip)
//	NOT_FOUND           → httpadapter.ErrUpstreamMembershipNotFound
func (a *AdminMembershipUpserter) RemoveMembershipByTenantID(ctx context.Context, gcid, tenantID string) error {
	if strings.TrimSpace(gcid) == "" {
		return errors.New("grpc.AdminMembershipUpserter: empty gcid")
	}
	if strings.TrimSpace(tenantID) == "" {
		return errors.New("grpc.AdminMembershipUpserter: empty tenant_id")
	}
	if _, err := a.stub.RemoveMembership(ctx, &tenancyv1.RemoveMembershipRequest{
		Gcid:     gcid,
		TenantId: tenantID,
	}); err != nil {
		switch status.Code(err) {
		case codes.FailedPrecondition:
			return fmt.Errorf("%w: %v", refusalSentinel(err), err)
		case codes.NotFound:
			return fmt.Errorf("%w: %v", httpadapter.ErrUpstreamMembershipNotFound, err)
		}
		return fmt.Errorf("grpc.AdminMembershipUpserter.RemoveMembership: %w", err)
	}
	return nil
}

// Compile-time check.
var _ httpadapter.AuthoritativeMembershipUpserter = (*AdminMembershipUpserter)(nil)
