// tenancy_client_test.go — coverage for the TenancyClient wrapper around
// the generated chora.services.tenancy.v1.TenancyClient stub: nil-conn
// guard, the FromStub constructor, and the proto → local
// httpadapter.MembershipsResolution translation.
package grpcadapter

import (
	"context"
	"errors"
	"net"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	tenancyv1 "github.com/apollo-chora/chora-contracts/gen/go/chora/services/tenancy/v1"
)

// fakeTenancyStub embeds the full generated TenancyClient interface and
// overrides only ListMembershipsByGCID — the single RPC TenancyClient uses.
type fakeTenancyStub struct {
	tenancyv1.TenancyClient
	gotGCID string
	resp    *tenancyv1.ListMembershipsByGCIDResponse
	err     error
}

func (f *fakeTenancyStub) ListMembershipsByGCID(_ context.Context, in *tenancyv1.ListMembershipsByGCIDRequest, _ ...grpc.CallOption) (*tenancyv1.ListMembershipsByGCIDResponse, error) {
	f.gotGCID = in.GetGcid()
	return f.resp, f.err
}

// bufconnConn spins up an in-process *grpc.ClientConn so the conn-accepting
// constructors (NewTenancyClient & friends) can be exercised without a real
// mesh. No services are registered — the constructors never invoke RPCs.
func bufconnConn(t *testing.T) *grpc.ClientConn {
	t.Helper()
	lis := bufconn.Listen(1024 * 1024)
	srv := grpc.NewServer()
	go func() {
		_ = srv.Serve(lis)
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
	t.Cleanup(func() {
		_ = conn.Close()
		srv.Stop()
		_ = lis.Close()
	})
	return conn
}

func TestTenancyClient_New_WrapsConn(t *testing.T) {
	c, err := NewTenancyClient(bufconnConn(t))
	if err != nil {
		t.Fatalf("NewTenancyClient(conn): %v", err)
	}
	if c == nil {
		t.Fatal("client must be non-nil")
	}
}

func TestTenancyClient_New_NilConnErrors(t *testing.T) {
	if _, err := NewTenancyClient(nil); err == nil {
		t.Fatal("nil conn must error")
	}
}

func TestTenancyClient_ListMemberships_MapsProtoToLocal(t *testing.T) {
	stub := &fakeTenancyStub{resp: &tenancyv1.ListMembershipsByGCIDResponse{
		DefaultTenantId: "01970000-0000-7000-8000-000000000101",
		Memberships: []*tenancyv1.TenantMembership{
			{
				TenantId:   "01970000-0000-7000-8000-000000000102",
				TenantSlug: "chora-master",
				Roles:      []string{"learner", "author"},
				Surfaces:   []string{"aplus", "cplus"},
				IsDefault:  true,
			},
			{
				TenantId:   "01970000-0000-7000-8000-000000000103",
				TenantSlug: "acme",
				Roles:      []string{"instructor"},
				Surfaces:   nil,
				IsDefault:  false,
			},
		},
	}}
	c := NewTenancyClientFromStub(stub)

	const gcid = "01970000-0000-7000-8000-00000000a001"
	out, err := c.ListMembershipsByGCID(context.Background(), gcid)
	if err != nil {
		t.Fatalf("ListMembershipsByGCID: %v", err)
	}
	if stub.gotGCID != gcid {
		t.Errorf("stub received gcid %q, want %q", stub.gotGCID, gcid)
	}
	if out.DefaultTenantID != "01970000-0000-7000-8000-000000000101" {
		t.Errorf("DefaultTenantID = %q", out.DefaultTenantID)
	}
	if len(out.Memberships) != 2 {
		t.Fatalf("wanted 2 memberships, got %d", len(out.Memberships))
	}
	first := out.Memberships[0]
	if first.TenantID != "01970000-0000-7000-8000-000000000102" ||
		first.TenantSlug != "chora-master" || !first.IsDefault {
		t.Errorf("first membership not mapped: %+v", first)
	}
	if len(first.Roles) != 2 || first.Roles[0] != "learner" || first.Roles[1] != "author" {
		t.Errorf("roles not mapped: %v", first.Roles)
	}
	if len(first.Surfaces) != 2 || first.Surfaces[0] != "aplus" {
		t.Errorf("surfaces not mapped: %v", first.Surfaces)
	}
	if len(out.Memberships[1].Roles) != 1 || out.Memberships[1].Roles[0] != "instructor" {
		t.Errorf("second membership roles: %v", out.Memberships[1].Roles)
	}
}

func TestTenancyClient_ListMemberships_CopiesRoleSlice(t *testing.T) {
	stub := &fakeTenancyStub{resp: &tenancyv1.ListMembershipsByGCIDResponse{
		Memberships: []*tenancyv1.TenantMembership{
			{TenantId: "t-1", Roles: []string{"learner"}},
		},
	}}
	c := NewTenancyClientFromStub(stub)
	out, err := c.ListMembershipsByGCID(context.Background(), "gcid-1")
	if err != nil {
		t.Fatalf("ListMembershipsByGCID: %v", err)
	}
	// Mutating the proto response afterwards must not leak into the local
	// projection (append([]string(nil), ...) copy).
	stub.resp.Memberships[0].Roles[0] = "admin"
	if got := out.Memberships[0].Roles[0]; got != "learner" {
		t.Errorf("roles slice aliased the proto response: got %q", got)
	}
}

func TestTenancyClient_ListMemberships_EmptyGCIDRejected(t *testing.T) {
	c := NewTenancyClientFromStub(&fakeTenancyStub{resp: &tenancyv1.ListMembershipsByGCIDResponse{}})
	if _, err := c.ListMembershipsByGCID(context.Background(), "   "); err == nil {
		t.Fatal("empty gcid must error")
	}
}

func TestTenancyClient_ListMemberships_StubErrorWraps(t *testing.T) {
	boom := errors.New("tenancy down")
	stub := &fakeTenancyStub{err: boom}
	c := NewTenancyClientFromStub(stub)
	if _, err := c.ListMembershipsByGCID(context.Background(), "gcid-1"); !errors.Is(err, boom) {
		t.Fatalf("err = %v, want wrapped boom", err)
	}
}
