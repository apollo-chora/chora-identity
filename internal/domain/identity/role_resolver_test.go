// Package identity_test exercises the per-course role resolver per Comic
// Ch4 P8 "I Am Two People" → "One Identity to Rule Them All".
//
// Invariant: SAME GCID + DIFFERENT course context = DIFFERENT role, but ONE
// identity. Per CLAUDE.md §1 §3 + ddd-enforcement aggregate invariant #10:
// agents (AGID) cannot hold a role on a course; only GCIDs can.
//
// TDD RED: tests assume RoleResolver does NOT yet exist when authored.
package identity_test

import (
	"context"
	"errors"
	"sort"
	"testing"

	"github.com/apollo-chora/chora-identity/internal/domain/identity"
)

const (
	phyllisGcid    = "01935b5a-9bcf-7000-8000-000000000001"
	chenGcid       = "01935b5a-9bcf-7000-8000-000000000002"
	courseCSPO     = "01935b5a-9bcf-7000-8000-000000000099"
	courseCSM      = "01935b5a-9bcf-7000-8000-000000000098"
	courseUnknown  = "01935b5a-9bcf-7000-8000-0000000000aa"
	tenantMightyMS = "01935b5a-9bcf-7000-8000-000000000010"
)

// stubAssignmentRepo is a dependency-free in-test fake for CourseRoleRepository.
// We deliberately NOT import the inmem adapter package here — domain tests must
// stay infra-free per hexagonal rules.
type stubAssignmentRepo struct {
	data []identity.CourseRoleAssignment
}

func (s *stubAssignmentRepo) GetAssignment(_ context.Context, gcid, courseID string) (*identity.CourseRoleAssignment, error) {
	for i := range s.data {
		a := s.data[i]
		if a.Gcid == gcid && a.CourseID == courseID {
			return &a, nil
		}
	}
	return nil, identity.ErrCourseRoleNotFound
}

// -----------------------------------------------------------------------------
// Comic Ch4 P8 invariant — same GCID, different courses, different roles.
// -----------------------------------------------------------------------------

func TestResolveCourseRole_SameGcid_TwoCourses_TwoRoles(t *testing.T) {
	t.Parallel()
	repo := &stubAssignmentRepo{data: []identity.CourseRoleAssignment{
		{Gcid: phyllisGcid, CourseID: courseCSPO, TenantID: tenantMightyMS, Role: identity.CourseRoleInstructor},
		{Gcid: phyllisGcid, CourseID: courseCSM, TenantID: tenantMightyMS, Role: identity.CourseRoleLearner},
	}}
	resolver := identity.NewRoleResolver(repo)

	ctxA, err := resolver.ResolveCourseRole(context.Background(), phyllisGcid, courseCSPO)
	if err != nil {
		t.Fatalf("courseA resolve unexpected: %v", err)
	}
	ctxB, err := resolver.ResolveCourseRole(context.Background(), phyllisGcid, courseCSM)
	if err != nil {
		t.Fatalf("courseB resolve unexpected: %v", err)
	}

	// Same identity (Comic Ch4 P8 invariant).
	if ctxA.Gcid != ctxB.Gcid {
		t.Errorf("comic invariant violated: ctxA.Gcid=%q ctxB.Gcid=%q must be equal",
			ctxA.Gcid, ctxB.Gcid)
	}
	if ctxA.Gcid != phyllisGcid {
		t.Errorf("ctxA.Gcid=%q want %q", ctxA.Gcid, phyllisGcid)
	}

	// Different roles per course.
	if ctxA.Role != identity.CourseRoleInstructor {
		t.Errorf("courseA role=%q want instructor", ctxA.Role)
	}
	if ctxB.Role != identity.CourseRoleLearner {
		t.Errorf("courseB role=%q want learner", ctxB.Role)
	}
}

func TestResolveCourseRole_NoAssignment_ReturnsRoleNoneEmptyPermissions(t *testing.T) {
	t.Parallel()
	repo := &stubAssignmentRepo{data: nil}
	resolver := identity.NewRoleResolver(repo)

	ctx, err := resolver.ResolveCourseRole(context.Background(), phyllisGcid, courseUnknown)
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if ctx.Role != identity.CourseRoleNone {
		t.Errorf("Role=%q; want none", ctx.Role)
	}
	if len(ctx.Permissions) != 0 {
		t.Errorf("Permissions size=%d; want 0", len(ctx.Permissions))
	}
	if ctx.Gcid != phyllisGcid {
		t.Errorf("Gcid=%q; want %q", ctx.Gcid, phyllisGcid)
	}
	// course_id echoed back even if unknown
	if ctx.CourseID != courseUnknown {
		t.Errorf("CourseID=%q; want %q", ctx.CourseID, courseUnknown)
	}
}

func TestResolveCourseRole_LearnerOnCourseB_GetsLearnerPermissions(t *testing.T) {
	t.Parallel()
	repo := &stubAssignmentRepo{data: []identity.CourseRoleAssignment{
		{Gcid: phyllisGcid, CourseID: courseCSM, TenantID: tenantMightyMS, Role: identity.CourseRoleLearner},
	}}
	resolver := identity.NewRoleResolver(repo)

	ctx, err := resolver.ResolveCourseRole(context.Background(), phyllisGcid, courseCSM)
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if ctx.Role != identity.CourseRoleLearner {
		t.Errorf("Role=%q; want learner", ctx.Role)
	}
	got := sortedPerms(ctx.Permissions)
	want := sortedPerms([]identity.CoursePermission{
		identity.PermissionRead,
		identity.PermissionSubmit,
	})
	if !equalSlices(got, want) {
		t.Errorf("learner perms=%v want %v", got, want)
	}
}

func TestResolveCourseRole_InstructorOnCourseA_GetsAuthorGradePublishModerate(t *testing.T) {
	t.Parallel()
	repo := &stubAssignmentRepo{data: []identity.CourseRoleAssignment{
		{Gcid: phyllisGcid, CourseID: courseCSPO, TenantID: tenantMightyMS, Role: identity.CourseRoleInstructor},
	}}
	resolver := identity.NewRoleResolver(repo)

	ctx, err := resolver.ResolveCourseRole(context.Background(), phyllisGcid, courseCSPO)
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if ctx.Role != identity.CourseRoleInstructor {
		t.Errorf("Role=%q; want instructor", ctx.Role)
	}
	got := sortedPerms(ctx.Permissions)
	want := sortedPerms([]identity.CoursePermission{
		identity.PermissionAuthor,
		identity.PermissionGrade,
		identity.PermissionPublish,
		identity.PermissionModerate,
	})
	if !equalSlices(got, want) {
		t.Errorf("instructor perms=%v want %v", got, want)
	}
}

// -----------------------------------------------------------------------------
// Permissions enum exhaustively asserted per role (table-driven).
// -----------------------------------------------------------------------------

func TestPermissionsForRole_TableDriven(t *testing.T) {
	t.Parallel()
	cases := []struct {
		role identity.CourseRole
		want []identity.CoursePermission
	}{
		{
			role: identity.CourseRoleInstructor,
			want: []identity.CoursePermission{
				identity.PermissionAuthor,
				identity.PermissionGrade,
				identity.PermissionPublish,
				identity.PermissionModerate,
			},
		},
		{
			role: identity.CourseRoleLearner,
			want: []identity.CoursePermission{
				identity.PermissionRead,
				identity.PermissionSubmit,
			},
		},
		{
			role: identity.CourseRoleTenantAdmin,
			want: []identity.CoursePermission{
				identity.PermissionRead,
				identity.PermissionAdminister,
				identity.PermissionModerate,
			},
		},
		{
			role: identity.CourseRoleSuperAdmin,
			want: []identity.CoursePermission{
				identity.PermissionRead,
				identity.PermissionAuthor,
				identity.PermissionGrade,
				identity.PermissionPublish,
				identity.PermissionModerate,
				identity.PermissionAdminister,
			},
		},
		{
			role: identity.CourseRoleAuditor,
			want: []identity.CoursePermission{
				identity.PermissionRead,
				identity.PermissionAudit,
			},
		},
		{
			role: identity.CourseRoleNone,
			want: []identity.CoursePermission{},
		},
	}
	for _, c := range cases {
		c := c
		t.Run(string(c.role), func(t *testing.T) {
			t.Parallel()
			got := sortedPerms(identity.PermissionsForRole(c.role))
			want := sortedPerms(c.want)
			if !equalSlices(got, want) {
				t.Errorf("PermissionsForRole(%q)=%v want %v", c.role, got, want)
			}
		})
	}
}

func TestCourseRole_Valid_AcceptsAllExceptUnknown(t *testing.T) {
	t.Parallel()
	for _, r := range []identity.CourseRole{
		identity.CourseRoleInstructor,
		identity.CourseRoleLearner,
		identity.CourseRoleTenantAdmin,
		identity.CourseRoleSuperAdmin,
		identity.CourseRoleAuditor,
		identity.CourseRoleNone,
	} {
		if !r.Valid() {
			t.Errorf("CourseRole(%q).Valid()=false; want true", r)
		}
	}
	if identity.CourseRole("godmode").Valid() {
		t.Errorf("CourseRole(godmode).Valid()=true; want false")
	}
}

// -----------------------------------------------------------------------------
// Validation edges.
// -----------------------------------------------------------------------------

func TestResolveCourseRole_RejectsInvalidUUIDCourseID(t *testing.T) {
	t.Parallel()
	repo := &stubAssignmentRepo{data: nil}
	resolver := identity.NewRoleResolver(repo)
	_, err := resolver.ResolveCourseRole(context.Background(), phyllisGcid, "not-a-uuid")
	if err == nil {
		t.Fatalf("expected error for invalid course_id; got nil")
	}
	if !errors.Is(err, identity.ErrInvalidCourseID) {
		t.Errorf("err=%v; want errors.Is(_, ErrInvalidCourseID)", err)
	}
}

func TestResolveCourseRole_RejectsEmptyGcid(t *testing.T) {
	t.Parallel()
	repo := &stubAssignmentRepo{data: nil}
	resolver := identity.NewRoleResolver(repo)
	_, err := resolver.ResolveCourseRole(context.Background(), "", courseCSPO)
	if err == nil {
		t.Fatalf("expected error for empty gcid; got nil")
	}
	if !errors.Is(err, identity.ErrInvalidGCID) {
		t.Errorf("err=%v; want errors.Is(_, ErrInvalidGCID)", err)
	}
}

func TestResolveCourseRole_RejectsAGIDInGcidPosition(t *testing.T) {
	t.Parallel()
	// Per ddd-enforcement aggregate invariant #10: agents cannot hold roles.
	agid := "0197A000-0000-7000-9000-000000000001"
	repo := &stubAssignmentRepo{data: nil}
	resolver := identity.NewRoleResolver(repo)
	_, err := resolver.ResolveCourseRole(context.Background(), agid, courseCSPO)
	if err == nil {
		t.Fatalf("expected error rejecting AGID; got nil")
	}
	if !errors.Is(err, identity.ErrInvalidGCID) {
		t.Errorf("err=%v; want errors.Is(_, ErrInvalidGCID)", err)
	}
}

// -----------------------------------------------------------------------------
// helpers
// -----------------------------------------------------------------------------

func sortedPerms(in []identity.CoursePermission) []identity.CoursePermission {
	out := append([]identity.CoursePermission(nil), in...)
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func equalSlices[T comparable](a, b []T) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
