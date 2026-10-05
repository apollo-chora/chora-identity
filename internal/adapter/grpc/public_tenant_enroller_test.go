// public_tenant_enroller_test.go — TDD for the ADR-182 auto-enrol
// adapter: tenancy UpsertMembership-backed implementation of
// httpadapter.PublicTenantEnroller, with best-effort (non-fatal)
// identity-mirror upserts.
package grpcadapter

import (
	"context"
	"errors"
	"testing"

	"google.golang.org/grpc"

	tenancyv1 "github.com/apollo-chora/chora-contracts/gen/go/chora/services/tenancy/v1"
)

type fakeUpsertStub struct {
	gotReq *tenancyv1.UpsertMembershipRequest
	resp   *tenancyv1.UpsertMembershipResponse
	err    error

	// RemoveMembership config (WS2b).
	gotRemoveReq *tenancyv1.RemoveMembershipRequest
	removeResp   *tenancyv1.RemoveMembershipResponse
	removeErr    error
}

func (f *fakeUpsertStub) UpsertMembership(_ context.Context, in *tenancyv1.UpsertMembershipRequest, _ ...grpc.CallOption) (*tenancyv1.UpsertMembershipResponse, error) {
	f.gotReq = in
	if f.err != nil {
		return nil, f.err
	}
	return f.resp, nil
}

func (f *fakeUpsertStub) RemoveMembership(_ context.Context, in *tenancyv1.RemoveMembershipRequest, _ ...grpc.CallOption) (*tenancyv1.RemoveMembershipResponse, error) {
	f.gotRemoveReq = in
	if f.removeErr != nil {
		return nil, f.removeErr
	}
	if f.removeResp != nil {
		return f.removeResp, nil
	}
	return &tenancyv1.RemoveMembershipResponse{RemovedRoleCount: 1}, nil
}

type fakeMirror struct {
	calls [][3]string // gcid, tenantID, role
	err   error
}

func (f *fakeMirror) UpsertMembershipOnBootstrap(_ context.Context, gcid, tenantID, role string) error {
	f.calls = append(f.calls, [3]string{gcid, tenantID, role})
	return f.err
}

const (
	enrolGCID       = "00000000-0000-7000-8000-000000002001"
	choraMasterID   = "00000000-0000-7000-8000-000000000001"
	choraMasterSlug = "chora-master"
)

func enrolResp() *tenancyv1.UpsertMembershipResponse {
	return &tenancyv1.UpsertMembershipResponse{
		Membership: &tenancyv1.TenantMembership{
			TenantId:   choraMasterID,
			TenantSlug: choraMasterSlug,
			Roles:      []string{"author", "learner"},
			Surfaces:   []string{"aplus", "cplus"},
			IsDefault:  true,
		},
	}
}

func TestPublicTenantEnroller_Happy_UpsertsLearnerAuthorBySlug(t *testing.T) {
	stub := &fakeUpsertStub{resp: enrolResp()}
	mirror := &fakeMirror{}
	e := NewPublicTenantEnrollerFromStub(stub, "", mirror)

	if err := e.EnsurePublicMembership(context.Background(), enrolGCID); err != nil {
		t.Fatalf("EnsurePublicMembership: %v", err)
	}
	if stub.gotReq.GetGcid() != enrolGCID {
		t.Errorf("gcid: got %q", stub.gotReq.GetGcid())
	}
	if stub.gotReq.GetTenantSlug() != choraMasterSlug {
		t.Errorf("slug must default to chora-master, got %q", stub.gotReq.GetTenantSlug())
	}
	if stub.gotReq.GetTenantId() != "" {
		t.Errorf("tenant_id must stay empty (slug addressing), got %q", stub.gotReq.GetTenantId())
	}
	roles := stub.gotReq.GetRoles()
	if len(roles) != 2 || roles[0] != "learner" || roles[1] != "author" {
		t.Errorf("roles: got %v want [learner author]", roles)
	}
}

func TestPublicTenantEnroller_MirrorsEachGrantedRole(t *testing.T) {
	stub := &fakeUpsertStub{resp: enrolResp()}
	mirror := &fakeMirror{}
	e := NewPublicTenantEnrollerFromStub(stub, choraMasterSlug, mirror)

	if err := e.EnsurePublicMembership(context.Background(), enrolGCID); err != nil {
		t.Fatalf("EnsurePublicMembership: %v", err)
	}
	if len(mirror.calls) != 2 {
		t.Fatalf("mirror calls: got %d want 2 (one per granted role)", len(mirror.calls))
	}
	for i, want := range []string{"author", "learner"} {
		c := mirror.calls[i]
		if c[0] != enrolGCID || c[1] != choraMasterID || c[2] != want {
			t.Errorf("mirror call %d: got %v want [gcid chora-master-id %s]", i, c, want)
		}
	}
}

func TestPublicTenantEnroller_MirrorErrorIsNonFatal(t *testing.T) {
	stub := &fakeUpsertStub{resp: enrolResp()}
	mirror := &fakeMirror{err: errors.New("mirror down")}
	e := NewPublicTenantEnrollerFromStub(stub, choraMasterSlug, mirror)

	if err := e.EnsurePublicMembership(context.Background(), enrolGCID); err != nil {
		t.Fatalf("mirror failure must be non-fatal, got %v", err)
	}
	if len(mirror.calls) != 2 {
		t.Fatalf("all roles must still be attempted, got %d calls", len(mirror.calls))
	}
}

func TestPublicTenantEnroller_NilMirrorOK(t *testing.T) {
	stub := &fakeUpsertStub{resp: enrolResp()}
	e := NewPublicTenantEnrollerFromStub(stub, choraMasterSlug, nil)
	if err := e.EnsurePublicMembership(context.Background(), enrolGCID); err != nil {
		t.Fatalf("nil mirror must be fine: %v", err)
	}
}

func TestPublicTenantEnroller_UpsertErrorPropagates(t *testing.T) {
	boom := errors.New("tenancy down")
	stub := &fakeUpsertStub{err: boom}
	mirror := &fakeMirror{}
	e := NewPublicTenantEnrollerFromStub(stub, choraMasterSlug, mirror)

	if err := e.EnsurePublicMembership(context.Background(), enrolGCID); !errors.Is(err, boom) {
		t.Fatalf("err: got %v want wrapped boom", err)
	}
	if len(mirror.calls) != 0 {
		t.Fatalf("mirror must not fire on upsert failure, got %v", mirror.calls)
	}
}

func TestPublicTenantEnroller_EmptyGCIDRejected(t *testing.T) {
	e := NewPublicTenantEnrollerFromStub(&fakeUpsertStub{resp: enrolResp()}, choraMasterSlug, nil)
	if err := e.EnsurePublicMembership(context.Background(), "  "); err == nil {
		t.Fatal("empty gcid must error")
	}
}

func TestPublicTenantEnroller_New_WrapsConn(t *testing.T) {
	e, err := NewPublicTenantEnroller(bufconnConn(t), "", nil)
	if err != nil {
		t.Fatalf("NewPublicTenantEnroller(conn): %v", err)
	}
	if e == nil {
		t.Fatal("enroller must be non-nil")
	}
}

func TestPublicTenantEnroller_New_NilConnErrors(t *testing.T) {
	if _, err := NewPublicTenantEnroller(nil, "", nil); err == nil {
		t.Fatal("nil conn must error")
	}
}
