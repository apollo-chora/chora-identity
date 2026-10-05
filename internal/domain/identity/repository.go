// Repository ports — persistence interfaces owned by the domain.
//
// Adapters (in-memory, Cloud SQL via pgx, etc.) implement these interfaces;
// the domain MUST NOT import any adapter package.
package identity

import (
	"context"
	"errors"
)

// Sentinels — exported so handlers can errors.Is() against them.
var (
	ErrUserNotFound       = errors.New("user not found")
	ErrMembershipNotFound = errors.New("membership not found")
	ErrMembershipExists   = errors.New("membership already exists for (gcid, tenant_id)")
	ErrSnapshotImmutable  = errors.New("portable snapshots are append-only")

	// ErrOwnerRoleProtected: a role edit would deactivate a live `owner`
	// mirror row (S7-B1 guard D2). Fires whether or not a co-owner remains:
	// `owner` is absent from Role.Grantable(), so nothing can put it back.
	ErrOwnerRoleProtected = errors.New("cannot strip the owner role")

	// ErrLastOwnerProtected: a member revoke would take away the tenant's
	// last live `owner` mirror row (S7-B1 guard D1), leaving the organisation
	// with nobody who owns it. Hand ownership over first.
	ErrLastOwnerProtected = errors.New("cannot remove the tenant's last owner")
)

// UserRepository — User persistence port.
type UserRepository interface {
	Save(ctx context.Context, u *User) error
	GetByGcid(ctx context.Context, gcid string) (*User, error)
}

// UIPreferencesRepository — GCID-scoped UI-preference persistence port
// (users.ui_preferences JSONB, migration 0034). Identity-scoped (no tenant
// axis) — the adapter filters by gcid = the authenticated caller, never the
// request body. Not an RLS-bypass surface (users has no RLS policy).
type UIPreferencesRepository interface {
	// GetUIPreferences returns the caller's UI preferences. A never-set store
	// yields a zero-value UIPreferences (DashboardLayout nil), NOT an error;
	// ErrUserNotFound only when no live user carries the GCID.
	GetUIPreferences(ctx context.Context, gcid string) (*UIPreferences, error)
	// UpsertDashboardLayout replaces the dashboard_layout key of the caller's
	// ui_preferences JSONB (other keys preserved). ErrUserNotFound when no live
	// user carries the GCID. The caller validates the layout first
	// (ValidateDashboardOrder) — the adapter persists what it is given.
	UpsertDashboardLayout(ctx context.Context, gcid string, layout DashboardLayout) error
	// UpsertHomeLayout replaces the home_layout key of the caller's
	// ui_preferences JSONB (other keys preserved, incl dashboard_layout) -
	// ADR-240 D2. ErrUserNotFound when no live user carries the GCID. The caller
	// validates STRUCTURE first (ValidateHomePins) - the adapter persists what it
	// is given, verbatim (the pin objects' position fields are opaque, D10/D11).
	UpsertHomeLayout(ctx context.Context, gcid string, layout HomeLayout) error
}

// MembershipRepository — TenantMembership persistence port.
//
// AddMembership enforces the (gcid, tenant_id) uniqueness invariant in the
// adapter (returns ErrMembershipExists for duplicates).
type MembershipRepository interface {
	AddMembership(ctx context.Context, m *TenantMembership) error
	GetByID(ctx context.Context, membershipID string) (*TenantMembership, error)
	List(ctx context.Context, filter MembershipFilter) ([]*TenantMembership, error)
	UpdateRole(ctx context.Context, m *TenantMembership) error
}

// MembershipFilter — query parameters for List.
type MembershipFilter struct {
	TenantID string
	Gcid     string
}

// SnapshotRepository — PortableSnapshot persistence port. Append-only:
// no Update / Delete methods are exposed.
type SnapshotRepository interface {
	Append(ctx context.Context, s *PortableSnapshot) error
	List(ctx context.Context, gcid string) ([]*PortableSnapshot, error)
	NextSequence(ctx context.Context, gcid string) (int, error)
}
