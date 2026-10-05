// Per-course role resolver per Comic Ch4 P8 "I Am Two People" → "One Identity
// to Rule Them All": SAME GCID + DIFFERENT course context = DIFFERENT role,
// but ONE identity.
//
// This is a domain primitive — no infrastructure imports. It depends only on
// the CourseRoleRepository port (declared below) which adapters implement.
//
// Per ddd-enforcement aggregate invariant #10 (CLAUDE.md §1 §3): an AGID
// (agent identity) MUST NOT hold a per-course role. The resolver rejects AGID
// shapes via IsAGID at the boundary.
package identity

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
)

// -----------------------------------------------------------------------------
// CourseRole enum — distinct from TenantMembership Role because per-course
// roles include super_admin / tenant_admin scope variants and an explicit
// `none` sentinel for "no assignment on this course".
// -----------------------------------------------------------------------------

type CourseRole string

const (
	CourseRoleInstructor  CourseRole = "instructor"
	CourseRoleLearner     CourseRole = "learner"
	CourseRoleTenantAdmin CourseRole = "tenant_admin"
	CourseRoleSuperAdmin  CourseRole = "super_admin"
	CourseRoleAuditor     CourseRole = "auditor"
	CourseRoleNone        CourseRole = "none"
)

// Valid reports whether r is one of the six known course roles.
func (r CourseRole) Valid() bool {
	switch r {
	case CourseRoleInstructor, CourseRoleLearner, CourseRoleTenantAdmin,
		CourseRoleSuperAdmin, CourseRoleAuditor, CourseRoleNone:
		return true
	}
	return false
}

// -----------------------------------------------------------------------------
// CoursePermission enum — hardcoded mapping for MVP per spec.
// -----------------------------------------------------------------------------

type CoursePermission string

const (
	PermissionRead       CoursePermission = "read"
	PermissionSubmit     CoursePermission = "submit"
	PermissionAuthor     CoursePermission = "author"
	PermissionGrade      CoursePermission = "grade"
	PermissionPublish    CoursePermission = "publish"
	PermissionModerate   CoursePermission = "moderate"
	PermissionAdminister CoursePermission = "administer"
	PermissionAudit      CoursePermission = "audit"
)

// PermissionsForRole returns the canonical (sorted-deterministic) permission
// set for a given course role. Returns an empty (non-nil) slice for
// CourseRoleNone or any unrecognised role — callers can rely on a non-nil
// slice for clean JSON marshalling as `[]`.
func PermissionsForRole(r CourseRole) []CoursePermission {
	switch r {
	case CourseRoleInstructor:
		return []CoursePermission{
			PermissionAuthor, PermissionGrade, PermissionPublish, PermissionModerate,
		}
	case CourseRoleLearner:
		return []CoursePermission{PermissionRead, PermissionSubmit}
	case CourseRoleTenantAdmin:
		return []CoursePermission{PermissionRead, PermissionAdminister, PermissionModerate}
	case CourseRoleSuperAdmin:
		return []CoursePermission{
			PermissionRead, PermissionAuthor, PermissionGrade,
			PermissionPublish, PermissionModerate, PermissionAdminister,
		}
	case CourseRoleAuditor:
		return []CoursePermission{PermissionRead, PermissionAudit}
	case CourseRoleNone:
		return []CoursePermission{}
	}
	return []CoursePermission{}
}

// -----------------------------------------------------------------------------
// CourseRoleAssignment — entity representing the (gcid, course_id) → role
// triple, stamped with the tenant_id to which the course belongs. The course
// itself is owned by Content Delivery (chora_delivery DB); per ddd-enforcement
// HARD RULE we don't query that DB. The Identity DB stores a denormalised
// projection refreshed via Pub/Sub (chora.delivery.course.published.v1 +
// chora.delivery.enrolment.granted.v1; deferred to Tier 2).
// -----------------------------------------------------------------------------

type CourseRoleAssignment struct {
	Gcid     string     `json:"gcid"`
	CourseID string     `json:"course_id"`
	TenantID string     `json:"tenant_id"`
	Role     CourseRole `json:"role"`
}

// -----------------------------------------------------------------------------
// CourseRoleRepository — port owned by the domain. Adapters (inmem; later
// pgx against chora_identity) implement it.
// -----------------------------------------------------------------------------

// ErrCourseRoleNotFound is returned by GetAssignment when no assignment
// exists for (gcid, course_id). The resolver translates this to
// CourseRoleNone — the absence of a role is itself a domain-meaningful answer
// per Comic Ch4 P8.
var (
	ErrCourseRoleNotFound = errors.New("course role assignment not found")
	ErrInvalidGCID        = errors.New("invalid gcid")
	ErrInvalidCourseID    = errors.New("invalid course_id")
)

// CourseRoleRepository is the persistence port for CourseRoleAssignment.
type CourseRoleRepository interface {
	// GetAssignment returns the assignment for (gcid, course_id) or
	// ErrCourseRoleNotFound if absent.
	GetAssignment(ctx context.Context, gcid, courseID string) (*CourseRoleAssignment, error)
}

// CourseRoleWriter extends CourseRoleRepository with the upsert path used by
// the enrolment subscriber. Adapters that implement projection writes
// (in-memory + pgx) must satisfy this interface.
type CourseRoleWriter interface {
	CourseRoleRepository
	// Upsert inserts or replaces the assignment. Returns true when a NEW row
	// was inserted (driver for at-most-once event emission), false when an
	// existing row was overwritten.
	Upsert(ctx context.Context, a CourseRoleAssignment) (inserted bool, err error)
}

// -----------------------------------------------------------------------------
// CourseRoleContext — value object returned by the resolver to handlers.
// The handler serialises it as the GET /me/roles response body.
// -----------------------------------------------------------------------------

type CourseRoleContext struct {
	Gcid        string             `json:"gcid"`
	CourseID    string             `json:"course_id"`
	TenantID    string             `json:"tenant_id"`
	Role        CourseRole         `json:"role"`
	Permissions []CoursePermission `json:"permissions"`
}

// -----------------------------------------------------------------------------
// RoleResolver — pure domain service.
// -----------------------------------------------------------------------------

// RoleResolver answers "what role does GCID X have on course Y?" given a
// CourseRoleRepository. The resolver is stateless and can be safely shared
// across goroutines.
type RoleResolver struct {
	repo CourseRoleRepository
}

// NewRoleResolver wires a resolver to a repository port.
func NewRoleResolver(repo CourseRoleRepository) *RoleResolver {
	return &RoleResolver{repo: repo}
}

// ResolveCourseRole returns the (role, tenant, permissions) context for the
// given GCID + course pair. Per Comic Ch4 P8 invariant: SAME gcid value is
// always echoed back verbatim, even when the user has no role on the course
// (Role=CourseRoleNone).
//
// Returns:
//   - ErrInvalidGCID  if gcid is empty or AGID-shaped.
//   - ErrInvalidCourseID if course_id is not a valid UUID string.
//   - any repository error wrapped via fmt.Errorf
//
// On ErrCourseRoleNotFound from the repo, returns a context with
// Role=CourseRoleNone and Permissions=[]. The TenantID is left empty in that
// case because we don't know the tenant without an assignment row; downstream
// callers can fill it from the request context if needed.
func (r *RoleResolver) ResolveCourseRole(
	ctx context.Context,
	gcid, courseID string,
) (*CourseRoleContext, error) {
	gcid = strings.TrimSpace(gcid)
	if gcid == "" {
		return nil, fmt.Errorf("%w: empty", ErrInvalidGCID)
	}
	if IsAGID(gcid) {
		return nil, fmt.Errorf("%w: AGID cannot hold a course role", ErrInvalidGCID)
	}
	courseID = strings.TrimSpace(courseID)
	if courseID == "" {
		return nil, fmt.Errorf("%w: empty", ErrInvalidCourseID)
	}
	if _, err := uuid.Parse(courseID); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidCourseID, err)
	}

	out := &CourseRoleContext{
		Gcid:     gcid,
		CourseID: courseID,
	}

	a, err := r.repo.GetAssignment(ctx, gcid, courseID)
	if err != nil {
		if errors.Is(err, ErrCourseRoleNotFound) {
			out.Role = CourseRoleNone
			out.Permissions = PermissionsForRole(CourseRoleNone)
			return out, nil
		}
		return nil, fmt.Errorf("get assignment: %w", err)
	}

	out.TenantID = a.TenantID
	out.Role = a.Role
	out.Permissions = PermissionsForRole(a.Role)
	return out, nil
}
