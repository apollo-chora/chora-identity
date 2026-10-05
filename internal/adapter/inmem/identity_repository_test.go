// Package inmem_test exercises the in-memory User / Membership / Snapshot
// repository adapters.
package inmem_test

import (
	"context"
	"errors"
	"testing"

	"github.com/apollo-chora/chora-identity/internal/adapter/inmem"
	"github.com/apollo-chora/chora-identity/internal/domain/identity"
)

const (
	tenantA = "01970000-0000-7000-8000-000000000001"
	tenantB = "01970000-0000-7000-8000-000000000002"
)

func mustNewUser(t *testing.T, email string) *identity.User {
	t.Helper()
	u, err := identity.NewUser(identity.NewUserParams{
		Email: email, IdentityProvider: identity.ProviderOIDC, FederatedSubject: "sub-" + email,
	})
	if err != nil {
		t.Fatalf("NewUser unexpected: %v", err)
	}
	return u
}

// -----------------------------------------------------------------------------
// User repo
// -----------------------------------------------------------------------------

func TestUserRepo_SaveAndGet(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	r := inmem.NewUserRepository()
	u := mustNewUser(t, "alice@chora.dev")
	if err := r.Save(ctx, u); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := r.GetByGcid(ctx, u.Gcid)
	if err != nil {
		t.Fatalf("GetByGcid: %v", err)
	}
	if got.Gcid != u.Gcid {
		t.Errorf("Gcid mismatch")
	}
}

func TestUserRepo_GetMissing_ReturnsErrUserNotFound(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	r := inmem.NewUserRepository()
	_, err := r.GetByGcid(ctx, "nope")
	if !errors.Is(err, identity.ErrUserNotFound) {
		t.Errorf("err = %v; want ErrUserNotFound", err)
	}
}

// -----------------------------------------------------------------------------
// Membership repo
// -----------------------------------------------------------------------------

func TestMembershipRepo_AddAndGet(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	r := inmem.NewMembershipRepository()
	gcid := "01970000-0000-7000-9000-000000000001"
	m, _ := identity.NewTenantMembership(identity.NewMembershipParams{
		Gcid: gcid, TenantID: tenantA, Role: identity.RoleLearner,
	})
	if err := r.AddMembership(ctx, m); err != nil {
		t.Fatalf("Add: %v", err)
	}
	got, err := r.GetByID(ctx, m.MembershipID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.MembershipID != m.MembershipID {
		t.Errorf("MembershipID mismatch")
	}
}

func TestMembershipRepo_DuplicateRejected(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	r := inmem.NewMembershipRepository()
	gcid := "01970000-0000-7000-9000-000000000001"
	m1, _ := identity.NewTenantMembership(identity.NewMembershipParams{
		Gcid: gcid, TenantID: tenantA, Role: identity.RoleLearner,
	})
	if err := r.AddMembership(ctx, m1); err != nil {
		t.Fatalf("first Add: %v", err)
	}
	m2, _ := identity.NewTenantMembership(identity.NewMembershipParams{
		Gcid: gcid, TenantID: tenantA, Role: identity.RoleInstructor,
	})
	err := r.AddMembership(ctx, m2)
	if !errors.Is(err, identity.ErrMembershipExists) {
		t.Errorf("err = %v; want ErrMembershipExists", err)
	}
}

func TestMembershipRepo_AllowsDifferentTenantSameGcid(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	r := inmem.NewMembershipRepository()
	gcid := "01970000-0000-7000-9000-000000000001"
	m1, _ := identity.NewTenantMembership(identity.NewMembershipParams{
		Gcid: gcid, TenantID: tenantA, Role: identity.RoleLearner,
	})
	m2, _ := identity.NewTenantMembership(identity.NewMembershipParams{
		Gcid: gcid, TenantID: tenantB, Role: identity.RoleAdmin,
	})
	if err := r.AddMembership(ctx, m1); err != nil {
		t.Fatalf("Add tenantA: %v", err)
	}
	if err := r.AddMembership(ctx, m2); err != nil {
		t.Fatalf("Add tenantB: %v", err)
	}
}

func TestMembershipRepo_ListFilters(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	r := inmem.NewMembershipRepository()
	gcid1 := "01970000-0000-7000-9000-000000000001"
	gcid2 := "01970000-0000-7000-9000-000000000002"
	m1, _ := identity.NewTenantMembership(identity.NewMembershipParams{
		Gcid: gcid1, TenantID: tenantA, Role: identity.RoleLearner,
	})
	m2, _ := identity.NewTenantMembership(identity.NewMembershipParams{
		Gcid: gcid2, TenantID: tenantA, Role: identity.RoleAdmin,
	})
	m3, _ := identity.NewTenantMembership(identity.NewMembershipParams{
		Gcid: gcid1, TenantID: tenantB, Role: identity.RoleAuditor,
	})
	_ = r.AddMembership(ctx, m1)
	_ = r.AddMembership(ctx, m2)
	_ = r.AddMembership(ctx, m3)

	// Filter by tenant
	items, _ := r.List(ctx, identity.MembershipFilter{TenantID: tenantA})
	if len(items) != 2 {
		t.Errorf("List(tenantA) size = %d; want 2", len(items))
	}

	// Filter by gcid
	items, _ = r.List(ctx, identity.MembershipFilter{Gcid: gcid1})
	if len(items) != 2 {
		t.Errorf("List(gcid1) size = %d; want 2", len(items))
	}

	// Filter by both
	items, _ = r.List(ctx, identity.MembershipFilter{Gcid: gcid1, TenantID: tenantA})
	if len(items) != 1 {
		t.Errorf("List(both) size = %d; want 1", len(items))
	}
}

func TestMembershipRepo_UpdateRole(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	r := inmem.NewMembershipRepository()
	gcid := "01970000-0000-7000-9000-000000000001"
	m, _ := identity.NewTenantMembership(identity.NewMembershipParams{
		Gcid: gcid, TenantID: tenantA, Role: identity.RoleLearner,
	})
	_ = r.AddMembership(ctx, m)
	_ = m.ChangeRole(identity.RoleInstructor, "actor-1")
	if err := r.UpdateRole(ctx, m); err != nil {
		t.Fatalf("UpdateRole: %v", err)
	}
	got, _ := r.GetByID(ctx, m.MembershipID)
	if got.Role != identity.RoleInstructor {
		t.Errorf("Role = %q; want instructor", got.Role)
	}
	if len(got.AuditTrail) != 1 {
		t.Errorf("AuditTrail size = %d; want 1", len(got.AuditTrail))
	}
}

// -----------------------------------------------------------------------------
// Snapshot repo — append-only
// -----------------------------------------------------------------------------

func TestSnapshotRepo_AppendAndList(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	r := inmem.NewSnapshotRepository()
	gcid := "01970000-0000-7000-9000-000000000001"
	s1, _ := identity.NewPortableSnapshot(identity.NewPortableSnapshotParams{
		Gcid: gcid, Sequence: 1, PayloadHash: "h1",
	})
	s2, _ := identity.NewPortableSnapshot(identity.NewPortableSnapshotParams{
		Gcid: gcid, Sequence: 2, PayloadHash: "h2",
	})
	if err := r.Append(ctx, s1); err != nil {
		t.Fatalf("Append1: %v", err)
	}
	if err := r.Append(ctx, s2); err != nil {
		t.Fatalf("Append2: %v", err)
	}
	items, err := r.List(ctx, gcid)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(items) != 2 {
		t.Errorf("size = %d; want 2", len(items))
	}
}

func TestSnapshotRepo_AppendDuplicateSnapshotID_Rejected(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	r := inmem.NewSnapshotRepository()
	gcid := "01970000-0000-7000-9000-000000000001"
	s, _ := identity.NewPortableSnapshot(identity.NewPortableSnapshotParams{
		Gcid: gcid, Sequence: 1, PayloadHash: "h",
	})
	_ = r.Append(ctx, s)
	if err := r.Append(ctx, s); !errors.Is(err, identity.ErrSnapshotImmutable) {
		t.Errorf("re-appending same snapshot id err = %v; want ErrSnapshotImmutable", err)
	}
}

func TestSnapshotRepo_NextSequence(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	r := inmem.NewSnapshotRepository()
	gcid := "01970000-0000-7000-9000-000000000001"

	n, err := r.NextSequence(ctx, gcid)
	if err != nil {
		t.Fatalf("NextSequence: %v", err)
	}
	if n != 1 {
		t.Errorf("first NextSequence = %d; want 1", n)
	}
	s, _ := identity.NewPortableSnapshot(identity.NewPortableSnapshotParams{
		Gcid: gcid, Sequence: n, PayloadHash: "h1",
	})
	_ = r.Append(ctx, s)

	n2, _ := r.NextSequence(ctx, gcid)
	if n2 != 2 {
		t.Errorf("next NextSequence = %d; want 2", n2)
	}
}

func TestSnapshotRepo_List_FiltersByGcid(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	r := inmem.NewSnapshotRepository()
	gcid1 := "01970000-0000-7000-9000-000000000001"
	gcid2 := "01970000-0000-7000-9000-000000000002"
	s1, _ := identity.NewPortableSnapshot(identity.NewPortableSnapshotParams{Gcid: gcid1, Sequence: 1, PayloadHash: "a"})
	s2, _ := identity.NewPortableSnapshot(identity.NewPortableSnapshotParams{Gcid: gcid2, Sequence: 1, PayloadHash: "b"})
	_ = r.Append(ctx, s1)
	_ = r.Append(ctx, s2)

	items, _ := r.List(ctx, gcid1)
	if len(items) != 1 || items[0].Gcid != gcid1 {
		t.Errorf("expected exactly 1 item for gcid1, got %v", items)
	}
}
