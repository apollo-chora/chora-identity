// TenantMembership — the GCID ↔ TenantID role join with append-only role audit.
//
// Per ddd-enforcement aggregate invariant #10 (CLAUDE.md §1 §3): an AGID
// (agent identity) MUST NOT hold a TenantMembership. The constructor enforces
// this invariant; duplicate (gcid, tenant_id) pairs are rejected at the
// repository layer.
package identity

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// -----------------------------------------------------------------------------
// Role enum — tenant-scoped membership roles backed by the PG ENUM
// `membership_role` (migration 0001_initial.sql line 41). Lowercase form is
// the on-disk + on-wire shape for tenant_memberships rows.
//
// These 4 values are stored against a (gcid, tenant_id) join row. The
// CANONICAL ROLES list below extends with JWT-only roles (OWNER /
// SUPPORT_AGENT / TRAINING_ADMIN / TENANT_ADMIN / PLATFORM_OPERATOR) that
// are asserted via the chora-session JWT `roles` claim + propagated on
// `x-mesh-user-roles` headers but are NOT represented in the PG ENUM.
// See ADR-141 (canonical uppercase form) + ADR-165 (PLATFORM_OPERATOR
// cross-tenant role + RLS bypass policy).
// -----------------------------------------------------------------------------

type Role string

const (
	RoleLearner Role = "learner"
	// RoleAuthor — ADR-182: A+ Creator mode authoring; default
	// public-space role alongside learner (migration 0020_author_role).
	RoleAuthor     Role = "author"
	RoleInstructor Role = "instructor"
	RoleAdmin      Role = "admin"
	RoleAuditor    Role = "auditor"
	// RoleOwner is the tenant owner (UX refactor R21, migration
	// 0041_owner_role). It IS a stored membership_role: the mirror row for a
	// bootstrapped tenant now carries it instead of being downgraded to
	// `admin`, which is what finally lets the H+ roster show who owns the
	// organisation. It is deliberately NOT grantable: ownership is written
	// only by tenant bootstrap and moved only by the S7 handover, so it is
	// absent from Grantable() and present in Stored(). Never add it to
	// Grantable(): the pending-invite path gates on that predicate alone.
	RoleOwner Role = "owner"
)

// Grantable reports whether an admin API may hand this role out. It is the
// five-role set, and `owner` is not in it (see RoleOwner). This predicate
// gates every grant path in the service: the admin add-member and role-change
// handlers, the CSV import, the membership repository writes and the
// pending-invite constructor. Widening it grants ownership through all five.
func (r Role) Grantable() bool {
	switch r {
	case RoleLearner, RoleAuthor, RoleInstructor, RoleAdmin, RoleAuditor:
		return true
	}
	return false
}

// Stored reports whether r is a value the membership_role ENUM can hold: the
// grantable set plus `owner`. Use it when reading a role BACK from the
// database, where an owner row is legitimate and Grantable would wrongly
// discard it. PLATFORM_OPERATOR and the other JWT-extension roles are in
// neither set: they hold no tenant_memberships row at all (ADR-165).
func (r Role) Stored() bool {
	return r == RoleOwner || r.Grantable()
}

// -----------------------------------------------------------------------------
// Canonical JWT-stamped role tokens — UPPERCASE form per ADR-141.
//
// These cover the FULL role vocabulary asserted on chora-session JWTs and
// propagated via `x-mesh-user-roles`. Of the 11 canonical roles below, the
// first 10 are tenant-scoped (the CALLER must hold a `tenant_memberships`
// row in the active tenant for these to be honoured downstream) and the
// 11th — PLATFORM_OPERATOR — is the SOLE cross-tenant role per ADR-165,
// intentionally with NO tenant_memberships representation. PLATFORM_OPERATOR
// is the only principal authorised to invoke `WithRLSBypass(ctx)` on
// chora-payments to render the H+ tx-history cross-tenant operator view.
//
// NB — not every canonical role is a stored lowercase membership_role: AUTHOR
// (ADR-182) widened the ENUM because it is a default public-space role, but
// SUPPORT_AGENT / TRAINING_ADMIN / TENANT_ADMIN / PLATFORM_OPERATOR / PROCTOR
// are JWT-extension roles (asserted via the JWT + x-mesh-user-roles, NOT in
// the membership_role ENUM). PROCTOR (ADR-191) is additionally add-on-gated
// (`exam_administration`) and bound per-sitting via ExamInvigilator.
//
// New roles MUST be added BOTH here AND in a chora-identity migration that
// seeds `role_catalog` (single-row idempotent INSERT … ON CONFLICT DO
// NOTHING — the 0014/0020/0035 template) so the catalogue + the Go enum stay
// in lockstep.
// -----------------------------------------------------------------------------

type CanonicalRole string

const (
	CanonicalRoleLearner          CanonicalRole = "LEARNER"
	CanonicalRoleAuthor           CanonicalRole = "AUTHOR" // ADR-182 — A+ Creator authoring (0020_author_role)
	CanonicalRoleInstructor       CanonicalRole = "INSTRUCTOR"
	CanonicalRoleAdmin            CanonicalRole = "ADMIN"
	CanonicalRoleAuditor          CanonicalRole = "AUDITOR"
	CanonicalRoleOwner            CanonicalRole = "OWNER"
	CanonicalRoleSupportAgent     CanonicalRole = "SUPPORT_AGENT"
	CanonicalRoleTrainingAdmin    CanonicalRole = "TRAINING_ADMIN"
	CanonicalRoleTenantAdmin      CanonicalRole = "TENANT_ADMIN"
	CanonicalRoleProctor          CanonicalRole = "PROCTOR"           // ADR-191 — exam invigilation logistics; content-embargoed (0035_proctor_role)
	CanonicalRolePlatformOperator CanonicalRole = "PLATFORM_OPERATOR" // ADR-165 — cross-tenant only
)

// CanonicalRoles is the authoritative list of accepted JWT role tokens.
// Order is deliberate: tenant-scoped roles first; cross-tenant LAST so the
// boundary is visually obvious in test fixtures + error messages.
var CanonicalRoles = []CanonicalRole{
	CanonicalRoleLearner,
	CanonicalRoleAuthor,
	CanonicalRoleInstructor,
	CanonicalRoleAdmin,
	CanonicalRoleAuditor,
	CanonicalRoleOwner,
	CanonicalRoleSupportAgent,
	CanonicalRoleTrainingAdmin,
	CanonicalRoleTenantAdmin,
	CanonicalRoleProctor,
	CanonicalRolePlatformOperator,
}

// Valid reports whether r is one of the known canonical role tokens.
func (r CanonicalRole) Valid() bool {
	for _, known := range CanonicalRoles {
		if known == r {
			return true
		}
	}
	return false
}

// IsTenantScoped reports whether this role is scoped to the active tenant.
// All 10 tenant-scoped roles return true (a caller acts WITHIN a tenant);
// only PLATFORM_OPERATOR returns false — it is asserted ONLY via the JWT,
// has no membership row, and is the sole cross-tenant role (ADR-165, and
// reaffirmed for the PROCTOR add in ADR-191 D1).
func (r CanonicalRole) IsTenantScoped() bool {
	return r != CanonicalRolePlatformOperator
}

// -----------------------------------------------------------------------------
// MembershipStatus
// -----------------------------------------------------------------------------

type MembershipStatus string

const (
	MembershipStatusActive   MembershipStatus = "active"
	MembershipStatusInactive MembershipStatus = "inactive"
)

// -----------------------------------------------------------------------------
// RoleAuditEntry — append-only entry for every role transition.
// -----------------------------------------------------------------------------

type RoleAuditEntry struct {
	PriorRole     Role      `json:"prior_role"`
	NewRole       Role      `json:"new_role"`
	ChangedByGcid string    `json:"changed_by_gcid"`
	ChangedAt     time.Time `json:"changed_at"`
}

// -----------------------------------------------------------------------------
// TenantMembership
// -----------------------------------------------------------------------------

type TenantMembership struct {
	MembershipID string           `json:"membership_id"`
	Gcid         string           `json:"gcid"`
	TenantID     string           `json:"tenant_id"`
	Role         Role             `json:"role"`
	Status       MembershipStatus `json:"status"`
	CreatedAt    time.Time        `json:"created_at"`
	UpdatedAt    time.Time        `json:"updated_at"`
	AuditTrail   []RoleAuditEntry `json:"audit_trail"`
}

// NewMembershipParams is the constructor input for NewTenantMembership.
type NewMembershipParams struct {
	Gcid     string
	TenantID string
	Role     Role
}

// NewTenantMembership constructs a fresh TenantMembership. Refuses AGID-shaped
// identifiers per ddd-enforcement aggregate invariant #10.
func NewTenantMembership(p NewMembershipParams) (*TenantMembership, error) {
	gcid := strings.TrimSpace(p.Gcid)
	if gcid == "" {
		return nil, errors.New("gcid is required")
	}
	if IsAGID(gcid) {
		return nil, errors.New("AGID cannot hold TenantMembership (agents are not learners)")
	}
	tenant := strings.TrimSpace(p.TenantID)
	if tenant == "" {
		return nil, errors.New("tenant_id is required")
	}
	if !p.Role.Grantable() {
		return nil, fmt.Errorf("invalid role: %q", string(p.Role))
	}

	id, err := uuid.NewV7()
	if err != nil {
		return nil, fmt.Errorf("uuidv7: %w", err)
	}
	now := time.Now().UTC()
	return &TenantMembership{
		MembershipID: id.String(),
		Gcid:         gcid,
		TenantID:     tenant,
		Role:         p.Role,
		Status:       MembershipStatusActive,
		CreatedAt:    now,
		UpdatedAt:    now,
		AuditTrail:   []RoleAuditEntry{},
	}, nil
}

// ChangeRole transitions the membership to a new role and appends an audit
// entry. No-op when the new role equals the current role. The actor (changedBy)
// is recorded as the gcid of the user performing the action.
func (m *TenantMembership) ChangeRole(newRole Role, changedByGcid string) error {
	if !newRole.Grantable() {
		return fmt.Errorf("invalid role: %q", string(newRole))
	}
	if newRole == m.Role {
		return nil // idempotent: no audit entry for same-role change
	}
	now := time.Now().UTC()
	entry := RoleAuditEntry{
		PriorRole:     m.Role,
		NewRole:       newRole,
		ChangedByGcid: changedByGcid,
		ChangedAt:     now,
	}
	m.AuditTrail = append(m.AuditTrail, entry)
	m.Role = newRole
	m.UpdatedAt = now
	return nil
}

// Deactivate sets Status to inactive (e.g., upon account suspension).
func (m *TenantMembership) Deactivate() {
	if m.Status == MembershipStatusInactive {
		return
	}
	m.Status = MembershipStatusInactive
	m.UpdatedAt = time.Now().UTC()
}
