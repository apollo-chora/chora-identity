// admin_membership_upserter_test.go — TDD for the ADR-182 authoritative
// add-member adapter: tenancy UpsertMembership by tenant_id with gRPC
// status-code → httpadapter sentinel mapping.
package grpcadapter

import (
	"context"
	"errors"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	tenancyv1 "github.com/apollo-chora/chora-contracts/gen/go/chora/services/tenancy/v1"

	httpadapter "github.com/apollo-chora/chora-identity/internal/adapter/http"
)

const amuTenant = "11111111-1111-7111-8111-111111111111"

func TestAdminMembershipUpserter_Happy_CreatedPassthrough(t *testing.T) {
	stub := &fakeUpsertStub{resp: &tenancyv1.UpsertMembershipResponse{Created: true}}
	a := NewAdminMembershipUpserterFromStub(stub)

	created, err := a.UpsertMembershipByTenantID(context.Background(), enrolGCID, amuTenant, []string{"instructor"})
	if err != nil {
		t.Fatalf("UpsertMembershipByTenantID: %v", err)
	}
	if !created {
		t.Error("created must pass through true")
	}
	if stub.gotReq.GetGcid() != enrolGCID || stub.gotReq.GetTenantId() != amuTenant {
		t.Errorf("req: gcid=%q tenant_id=%q", stub.gotReq.GetGcid(), stub.gotReq.GetTenantId())
	}
	if stub.gotReq.GetTenantSlug() != "" {
		t.Errorf("tenant_slug must stay empty (id addressing), got %q", stub.gotReq.GetTenantSlug())
	}
	if roles := stub.gotReq.GetRoles(); len(roles) != 1 || roles[0] != "instructor" {
		t.Errorf("roles: got %v", roles)
	}
}

func TestAdminMembershipUpserter_DuplicateNotCreated(t *testing.T) {
	stub := &fakeUpsertStub{resp: &tenancyv1.UpsertMembershipResponse{Created: false}}
	a := NewAdminMembershipUpserterFromStub(stub)
	created, err := a.UpsertMembershipByTenantID(context.Background(), enrolGCID, amuTenant, []string{"learner"})
	if err != nil || created {
		t.Fatalf("got created=%v err=%v want false,nil", created, err)
	}
}

func TestAdminMembershipUpserter_FailedPreconditionMapsToSuspended(t *testing.T) {
	stub := &fakeUpsertStub{err: status.Error(codes.FailedPrecondition, "membership suspended")}
	a := NewAdminMembershipUpserterFromStub(stub)
	_, err := a.UpsertMembershipByTenantID(context.Background(), enrolGCID, amuTenant, []string{"learner"})
	if !errors.Is(err, httpadapter.ErrUpstreamMembershipSuspended) {
		t.Fatalf("err: got %v want ErrUpstreamMembershipSuspended", err)
	}
}

func TestAdminMembershipUpserter_NotFoundMapsToTenantNotFound(t *testing.T) {
	stub := &fakeUpsertStub{err: status.Error(codes.NotFound, "tenant not found")}
	a := NewAdminMembershipUpserterFromStub(stub)
	_, err := a.UpsertMembershipByTenantID(context.Background(), enrolGCID, amuTenant, []string{"learner"})
	if !errors.Is(err, httpadapter.ErrUpstreamTenantNotFound) {
		t.Fatalf("err: got %v want ErrUpstreamTenantNotFound", err)
	}
}

func TestAdminMembershipUpserter_GenericErrorWraps(t *testing.T) {
	boom := status.Error(codes.Unavailable, "conn refused")
	stub := &fakeUpsertStub{err: boom}
	a := NewAdminMembershipUpserterFromStub(stub)
	_, err := a.UpsertMembershipByTenantID(context.Background(), enrolGCID, amuTenant, []string{"learner"})
	if err == nil || errors.Is(err, httpadapter.ErrUpstreamMembershipSuspended) || errors.Is(err, httpadapter.ErrUpstreamTenantNotFound) {
		t.Fatalf("generic error must wrap without sentinel mapping, got %v", err)
	}
}

func TestAdminMembershipUpserter_ValidatesInputs(t *testing.T) {
	a := NewAdminMembershipUpserterFromStub(&fakeUpsertStub{resp: &tenancyv1.UpsertMembershipResponse{Created: true}})
	if _, err := a.UpsertMembershipByTenantID(context.Background(), "", amuTenant, []string{"learner"}); err == nil {
		t.Error("empty gcid must error")
	}
	if _, err := a.UpsertMembershipByTenantID(context.Background(), enrolGCID, "", []string{"learner"}); err == nil {
		t.Error("empty tenant must error")
	}
	if _, err := a.UpsertMembershipByTenantID(context.Background(), enrolGCID, amuTenant, nil); err == nil {
		t.Error("empty roles must error")
	}
}

// --- RemoveMembershipByTenantID (WS2b / CHO-1869) ----------------------------

func TestAdminMembershipUpserter_Remove_Happy(t *testing.T) {
	stub := &fakeUpsertStub{removeResp: &tenancyv1.RemoveMembershipResponse{RemovedRoleCount: 3}}
	a := NewAdminMembershipUpserterFromStub(stub)
	if err := a.RemoveMembershipByTenantID(context.Background(), enrolGCID, amuTenant); err != nil {
		t.Fatalf("RemoveMembershipByTenantID: %v", err)
	}
	if stub.gotRemoveReq.GetGcid() != enrolGCID || stub.gotRemoveReq.GetTenantId() != amuTenant {
		t.Errorf("req: gcid=%q tenant_id=%q", stub.gotRemoveReq.GetGcid(), stub.gotRemoveReq.GetTenantId())
	}
	if stub.gotRemoveReq.GetTenantSlug() != "" {
		t.Errorf("tenant_slug must stay empty (id addressing), got %q", stub.gotRemoveReq.GetTenantSlug())
	}
}

func TestAdminMembershipUpserter_Remove_SuspendedMapsSentinel(t *testing.T) {
	stub := &fakeUpsertStub{removeErr: status.Error(codes.FailedPrecondition, "suspended")}
	a := NewAdminMembershipUpserterFromStub(stub)
	if err := a.RemoveMembershipByTenantID(context.Background(), enrolGCID, amuTenant); !errors.Is(err, httpadapter.ErrUpstreamMembershipSuspended) {
		t.Fatalf("err: got %v want ErrUpstreamMembershipSuspended", err)
	}
}

func TestAdminMembershipUpserter_Remove_NotFoundMapsSentinel(t *testing.T) {
	stub := &fakeUpsertStub{removeErr: status.Error(codes.NotFound, "no membership")}
	a := NewAdminMembershipUpserterFromStub(stub)
	if err := a.RemoveMembershipByTenantID(context.Background(), enrolGCID, amuTenant); !errors.Is(err, httpadapter.ErrUpstreamMembershipNotFound) {
		t.Fatalf("err: got %v want ErrUpstreamMembershipNotFound", err)
	}
}

func TestAdminMembershipUpserter_Remove_ValidatesInputs(t *testing.T) {
	a := NewAdminMembershipUpserterFromStub(&fakeUpsertStub{})
	if err := a.RemoveMembershipByTenantID(context.Background(), "", amuTenant); err == nil {
		t.Error("empty gcid must error")
	}
	if err := a.RemoveMembershipByTenantID(context.Background(), enrolGCID, ""); err == nil {
		t.Error("empty tenant must error")
	}
}

func TestAdminMembershipUpserter_Remove_GenericErrorWraps(t *testing.T) {
	boom := status.Error(codes.Unavailable, "tenancy down")
	stub := &fakeUpsertStub{removeErr: boom}
	a := NewAdminMembershipUpserterFromStub(stub)
	err := a.RemoveMembershipByTenantID(context.Background(), enrolGCID, amuTenant)
	if err == nil || errors.Is(err, httpadapter.ErrUpstreamMembershipSuspended) || errors.Is(err, httpadapter.ErrUpstreamMembershipNotFound) {
		t.Fatalf("generic remove error must wrap without sentinel mapping, got %v", err)
	}
}

// --- NewAdminMembershipUpserter + ReplaceMembershipByTenantID ----------------

func TestAdminMembershipUpserter_New_WrapsConn(t *testing.T) {
	a, err := NewAdminMembershipUpserter(bufconnConn(t))
	if err != nil {
		t.Fatalf("NewAdminMembershipUpserter(conn): %v", err)
	}
	if a == nil {
		t.Fatal("upserter must be non-nil")
	}
}

func TestAdminMembershipUpserter_New_NilConnErrors(t *testing.T) {
	if _, err := NewAdminMembershipUpserter(nil); err == nil {
		t.Fatal("nil conn must error")
	}
}

func TestAdminMembershipUpserter_Replace_SetsReplaceExisting(t *testing.T) {
	stub := &fakeUpsertStub{resp: &tenancyv1.UpsertMembershipResponse{Created: true}}
	a := NewAdminMembershipUpserterFromStub(stub)

	created, err := a.ReplaceMembershipByTenantID(context.Background(), enrolGCID, amuTenant, []string{"learner", "author"})
	if err != nil {
		t.Fatalf("ReplaceMembershipByTenantID: %v", err)
	}
	if !created {
		t.Error("created must pass through true")
	}
	if !stub.gotReq.GetReplaceExisting() {
		t.Error("replace_existing must be true for ReplaceMembershipByTenantID")
	}
	if stub.gotReq.GetGcid() != enrolGCID || stub.gotReq.GetTenantId() != amuTenant {
		t.Errorf("req: gcid=%q tenant_id=%q", stub.gotReq.GetGcid(), stub.gotReq.GetTenantId())
	}
	if roles := stub.gotReq.GetRoles(); len(roles) != 2 || roles[0] != "learner" || roles[1] != "author" {
		t.Errorf("roles: got %v want [learner author]", roles)
	}
}

func TestAdminMembershipUpserter_Replace_FailedPreconditionMaps(t *testing.T) {
	stub := &fakeUpsertStub{err: status.Error(codes.FailedPrecondition, "membership suspended")}
	a := NewAdminMembershipUpserterFromStub(stub)
	_, err := a.ReplaceMembershipByTenantID(context.Background(), enrolGCID, amuTenant, []string{"learner"})
	if !errors.Is(err, httpadapter.ErrUpstreamMembershipSuspended) {
		t.Fatalf("err: got %v want ErrUpstreamMembershipSuspended", err)
	}
}

func TestAdminMembershipUpserter_Replace_NotFoundMaps(t *testing.T) {
	stub := &fakeUpsertStub{err: status.Error(codes.NotFound, "tenant not found")}
	a := NewAdminMembershipUpserterFromStub(stub)
	_, err := a.ReplaceMembershipByTenantID(context.Background(), enrolGCID, amuTenant, []string{"learner"})
	if !errors.Is(err, httpadapter.ErrUpstreamTenantNotFound) {
		t.Fatalf("err: got %v want ErrUpstreamTenantNotFound", err)
	}
}

func TestAdminMembershipUpserter_Replace_ValidatesInputs(t *testing.T) {
	a := NewAdminMembershipUpserterFromStub(&fakeUpsertStub{resp: &tenancyv1.UpsertMembershipResponse{Created: true}})
	if _, err := a.ReplaceMembershipByTenantID(context.Background(), "", amuTenant, []string{"learner"}); err == nil {
		t.Error("empty gcid must error")
	}
	if _, err := a.ReplaceMembershipByTenantID(context.Background(), enrolGCID, "", []string{"learner"}); err == nil {
		t.Error("empty tenant must error")
	}
	if _, err := a.ReplaceMembershipByTenantID(context.Background(), enrolGCID, amuTenant, nil); err == nil {
		t.Error("empty roles must error")
	}
}
