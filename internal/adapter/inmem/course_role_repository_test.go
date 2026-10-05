// Package inmem_test exercises the in-memory CourseRoleRepository +
// SeedComicFixtures helper.
package inmem_test

import (
	"context"
	"errors"
	"testing"

	"github.com/apollo-chora/chora-identity/internal/adapter/inmem"
	"github.com/apollo-chora/chora-identity/internal/domain/identity"
)

func TestCourseRoleRepository_AssignAndGet(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	r := inmem.NewCourseRoleRepository()

	a := identity.CourseRoleAssignment{
		Gcid: "GCID-PHYLLIS", CourseID: "COURSE-1",
		TenantID: "tenant-1", Role: identity.CourseRoleInstructor,
	}
	if err := r.Assign(a); err != nil {
		t.Fatalf("Assign: %v", err)
	}

	got, err := r.GetAssignment(ctx, "gcid-phyllis", "course-1")
	if err != nil {
		t.Fatalf("GetAssignment: %v", err)
	}
	if got.Role != identity.CourseRoleInstructor {
		t.Errorf("Role = %q; want instructor", got.Role)
	}
	if got.TenantID != "tenant-1" {
		t.Errorf("TenantID = %q", got.TenantID)
	}
}

func TestCourseRoleRepository_KeysAreCaseInsensitive(t *testing.T) {
	t.Parallel()
	r := inmem.NewCourseRoleRepository()
	err := r.Assign(identity.CourseRoleAssignment{
		Gcid: "GCID", CourseID: "Course", Role: identity.CourseRoleLearner,
	})
	if err != nil {
		t.Fatalf("Assign: %v", err)
	}
	// Mixed-case lookup resolves via the lowercase key().
	got, err := r.GetAssignment(context.Background(), "gcid", "course")
	if err != nil {
		t.Fatalf("GetAssignment: %v", err)
	}
	if got.Role != identity.CourseRoleLearner {
		t.Errorf("Role = %q; want learner", got.Role)
	}
}

func TestCourseRoleRepository_GetAssignment_NotFound(t *testing.T) {
	t.Parallel()
	r := inmem.NewCourseRoleRepository()
	ctx := context.Background()
	if _, err := r.GetAssignment(ctx, "gcid-x", "course-x"); !errors.Is(err, identity.ErrCourseRoleNotFound) {
		t.Errorf("err = %v; want ErrCourseRoleNotFound", err)
	}
}

func TestCourseRoleRepository_AssignValidation(t *testing.T) {
	t.Parallel()
	r := inmem.NewCourseRoleRepository()

	cases := []struct {
		name string
		a    identity.CourseRoleAssignment
	}{
		{"empty gcid", identity.CourseRoleAssignment{CourseID: "c-1", Role: identity.CourseRoleLearner}},
		{"blank gcid", identity.CourseRoleAssignment{Gcid: "  ", CourseID: "c-1", Role: identity.CourseRoleLearner}},
		{"empty course", identity.CourseRoleAssignment{Gcid: "g-1", Role: identity.CourseRoleLearner}},
		{"invalid role", identity.CourseRoleAssignment{Gcid: "g-1", CourseID: "c-1", Role: identity.CourseRole("wizard")}},
		{"role none", identity.CourseRoleAssignment{Gcid: "g-1", CourseID: "c-1", Role: identity.CourseRoleNone}},
	}
	for _, tc := range cases {
		if err := r.Assign(tc.a); err == nil {
			t.Errorf("[%s] expected error, got nil", tc.name)
		}
	}
}

func TestCourseRoleRepository_Upsert_InsertThenOverwrite(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	r := inmem.NewCourseRoleRepository()

	inserted, err := r.Upsert(ctx, identity.CourseRoleAssignment{
		Gcid: "g-1", CourseID: "c-1", TenantID: "t-1", Role: identity.CourseRoleLearner,
	})
	if err != nil {
		t.Fatalf("first Upsert: %v", err)
	}
	if !inserted {
		t.Errorf("first Upsert inserted=false; want true")
	}

	// Same (gcid, course_id) key — new role overwrites, reports replace.
	inserted, err = r.Upsert(ctx, identity.CourseRoleAssignment{
		Gcid: "g-1", CourseID: "c-1", TenantID: "t-1", Role: identity.CourseRoleInstructor,
	})
	if err != nil {
		t.Fatalf("second Upsert: %v", err)
	}
	if inserted {
		t.Errorf("second Upsert inserted=true; want false (overwrite)")
	}
	got, _ := r.GetAssignment(ctx, "g-1", "c-1")
	if got.Role != identity.CourseRoleInstructor {
		t.Errorf("Role after overwrite = %q; want instructor", got.Role)
	}
}

func TestCourseRoleRepository_Upsert_Validation(t *testing.T) {
	t.Parallel()
	r := inmem.NewCourseRoleRepository()
	ctx := context.Background()

	cases := []identity.CourseRoleAssignment{
		{CourseID: "c-1", Role: identity.CourseRoleLearner},                // missing gcid
		{Gcid: "g-1", Role: identity.CourseRoleLearner},                    // missing course
		{Gcid: "g-1", CourseID: "c-1", Role: identity.CourseRoleNone},      // role none
		{Gcid: "g-1", CourseID: "c-1", Role: identity.CourseRole("bogus")}, // invalid role
	}
	for i, a := range cases {
		if _, err := r.Upsert(ctx, a); err == nil {
			t.Errorf("case %d: expected error, got nil", i)
		}
	}
}

func TestCourseRoleRepository_SeedComicFixtures(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	users := inmem.NewUserRepository()
	roles := inmem.NewCourseRoleRepository()

	if err := inmem.SeedComicFixtures(users, roles); err != nil {
		t.Fatalf("SeedComicFixtures: %v", err)
	}

	// Both users pre-minted with fixed Comic GCIDs.
	for _, gcid := range []string{inmem.ComicGcidPhyllis, inmem.ComicGcidChen} {
		u, err := users.GetByGcid(ctx, gcid)
		if err != nil {
			t.Fatalf("GetByGcid(%s): %v", gcid, err)
		}
		if u.Status != identity.UserStatusActive {
			t.Errorf("user %s status = %q; want active", gcid, u.Status)
		}
	}

	// The three per-course role assignments.
	phyllisCSPO, err := roles.GetAssignment(ctx, inmem.ComicGcidPhyllis, inmem.ComicCourseCSPO)
	if err != nil {
		t.Fatalf("phyllis/CSPO: %v", err)
	}
	if phyllisCSPO.Role != identity.CourseRoleInstructor {
		t.Errorf("phyllis on CSPO = %q; want instructor", phyllisCSPO.Role)
	}

	phyllisCSM, err := roles.GetAssignment(ctx, inmem.ComicGcidPhyllis, inmem.ComicCourseCSM)
	if err != nil {
		t.Fatalf("phyllis/CSM: %v", err)
	}
	if phyllisCSM.Role != identity.CourseRoleLearner {
		t.Errorf("phyllis on CSM = %q; want learner", phyllisCSM.Role)
	}

	chenCSM, err := roles.GetAssignment(ctx, inmem.ComicGcidChen, inmem.ComicCourseCSM)
	if err != nil {
		t.Fatalf("chen/CSM: %v", err)
	}
	if chenCSM.Role != identity.CourseRoleInstructor {
		t.Errorf("chen on CSM = %q; want instructor", chenCSM.Role)
	}
	if chenCSM.TenantID != inmem.ComicTenantMightyMS {
		t.Errorf("chen tenant = %q; want %q", chenCSM.TenantID, inmem.ComicTenantMightyMS)
	}
}
