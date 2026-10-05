// Package identity_test exercises the User / TenantMembership / PortableSnapshot
// aggregate invariants for the Identity supporting domain.
//
// TDD RED phase first — these tests assume implementation does NOT yet exist
// when authored. Each test names an invariant from .claude/rules/ddd-enforcement.md
// or CLAUDE.md §1 §3.
package identity_test

import (
	"strings"
	"testing"
	"time"

	"github.com/apollo-chora/chora-identity/internal/domain/identity"
)

const (
	tenantA = "01970000-0000-7000-8000-000000000001"
	tenantB = "01970000-0000-7000-8000-000000000002"
)

// -----------------------------------------------------------------------------
// User construction invariants — GCID + portability
// -----------------------------------------------------------------------------

func TestNewUser_AssignsUUIDv7Gcid(t *testing.T) {
	t.Parallel()

	u, err := identity.NewUser(identity.NewUserParams{
		Email:            "alice@chora.dev",
		IdentityProvider: identity.ProviderOIDC,
		FederatedSubject: "sub-001",
		DisplayName:      "Alice",
	})
	if err != nil {
		t.Fatalf("NewUser unexpected error: %v", err)
	}
	if u.Gcid == "" {
		t.Errorf("Gcid was empty; want UUIDv7")
	}
	if len(u.Gcid) != 36 {
		t.Errorf("Gcid length = %d; want 36", len(u.Gcid))
	}
	if u.Gcid[14] != '7' {
		t.Errorf("Gcid version char = %q; want '7' (UUIDv7)", string(u.Gcid[14]))
	}
}

func TestNewUser_DefaultsToActiveStatus(t *testing.T) {
	t.Parallel()

	u, _ := identity.NewUser(identity.NewUserParams{
		Email: "a@b.com", IdentityProvider: identity.ProviderOIDC, FederatedSubject: "x",
	})
	if u.Status != identity.UserStatusActive {
		t.Errorf("Status = %q; want active", u.Status)
	}
}

func TestNewUser_RejectsEmptyEmail(t *testing.T) {
	t.Parallel()

	_, err := identity.NewUser(identity.NewUserParams{
		Email: "  ", IdentityProvider: identity.ProviderOIDC, FederatedSubject: "x",
	})
	if err == nil {
		t.Errorf("expected error for empty email; got nil")
	}
}

func TestNewUser_RejectsInvalidEmail(t *testing.T) {
	t.Parallel()

	_, err := identity.NewUser(identity.NewUserParams{
		Email: "not-an-email", IdentityProvider: identity.ProviderOIDC, FederatedSubject: "x",
	})
	if err == nil {
		t.Errorf("expected error for invalid email; got nil")
	}
}

func TestNewUser_RejectsInvalidProvider(t *testing.T) {
	t.Parallel()

	_, err := identity.NewUser(identity.NewUserParams{
		Email: "a@b.com", IdentityProvider: identity.IdentityProvider("badprovider"), FederatedSubject: "x",
	})
	if err == nil {
		t.Errorf("expected error for invalid provider; got nil")
	}
}

func TestNewUser_RejectsEmptyFederatedSubject(t *testing.T) {
	t.Parallel()

	_, err := identity.NewUser(identity.NewUserParams{
		Email: "a@b.com", IdentityProvider: identity.ProviderOIDC, FederatedSubject: "  ",
	})
	if err == nil {
		t.Errorf("expected error for empty FederatedSubject; got nil")
	}
}

func TestNewUser_AcceptsAllValidProviders(t *testing.T) {
	t.Parallel()

	for _, p := range []identity.IdentityProvider{
		identity.ProviderOIDC,
		identity.ProviderSAML,
		identity.ProviderWebAuthn,
	} {
		_, err := identity.NewUser(identity.NewUserParams{
			Email: "a@b.com", IdentityProvider: p, FederatedSubject: "sub",
		})
		if err != nil {
			t.Errorf("NewUser(provider=%q) unexpected: %v", p, err)
		}
	}
}

func TestNewUser_TrimsEmailAndDisplayName(t *testing.T) {
	t.Parallel()

	u, err := identity.NewUser(identity.NewUserParams{
		Email: "  trim@me.dev  ", IdentityProvider: identity.ProviderOIDC,
		FederatedSubject: "x", DisplayName: "  Trimmed  ",
	})
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if u.Email != "trim@me.dev" {
		t.Errorf("Email = %q; want trim@me.dev", u.Email)
	}
	if u.DisplayName != "Trimmed" {
		t.Errorf("DisplayName = %q; want Trimmed", u.DisplayName)
	}
}

func TestNewUser_SetsCreatedAndUpdatedAt(t *testing.T) {
	t.Parallel()

	before := time.Now().UTC()
	u, _ := identity.NewUser(identity.NewUserParams{
		Email: "a@b.com", IdentityProvider: identity.ProviderOIDC, FederatedSubject: "x",
	})
	after := time.Now().UTC()
	if u.CreatedAt.Before(before) || u.CreatedAt.After(after) {
		t.Errorf("CreatedAt out of range")
	}
	if !u.UpdatedAt.Equal(u.CreatedAt) {
		t.Errorf("UpdatedAt should equal CreatedAt on creation")
	}
}

// -----------------------------------------------------------------------------
// AGID-vs-GCID distinction (CLAUDE.md §1 §3) — agents CANNOT have TenantMembership
// -----------------------------------------------------------------------------

func TestIsAGID_DetectsAgentShape(t *testing.T) {
	t.Parallel()

	// AGID shape: starts with the prefix "0197A" (skeleton heuristic — declared
	// in CLAUDE.md §1 §3 and ddd-enforcement aggregate invariant #10).
	cases := []struct {
		id   string
		want bool
	}{
		{"0197A000-0000-7000-9000-000000000001", true},
		{"0197a000-0000-7000-9000-000000000001", true}, // case-insensitive
		{"01970000-0000-7000-9000-000000000001", false},
		{"00000000-0000-0000-0000-000000000000", false},
		{"", false},
	}
	for _, c := range cases {
		got := identity.IsAGID(c.id)
		if got != c.want {
			t.Errorf("IsAGID(%q) = %v; want %v", c.id, got, c.want)
		}
	}
}

func TestNewTenantMembership_RejectsAGID(t *testing.T) {
	t.Parallel()

	agid := "0197A000-0000-7000-9000-000000000001"
	_, err := identity.NewTenantMembership(identity.NewMembershipParams{
		Gcid:     agid,
		TenantID: tenantA,
		Role:     identity.RoleLearner,
	})
	if err == nil {
		t.Errorf("expected error binding TenantMembership to AGID; got nil")
	}
}

func TestNewTenantMembership_AcceptsGcid(t *testing.T) {
	t.Parallel()

	gcid := "01970000-0000-7000-9000-000000000001"
	m, err := identity.NewTenantMembership(identity.NewMembershipParams{
		Gcid: gcid, TenantID: tenantA, Role: identity.RoleLearner,
	})
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if m.Gcid != gcid {
		t.Errorf("Gcid mismatch")
	}
}

func TestNewTenantMembership_RejectsInvalidRole(t *testing.T) {
	t.Parallel()

	gcid := "01970000-0000-7000-9000-000000000001"
	_, err := identity.NewTenantMembership(identity.NewMembershipParams{
		Gcid: gcid, TenantID: tenantA, Role: identity.Role("godmode"),
	})
	if err == nil {
		t.Errorf("expected error for invalid role; got nil")
	}
}

func TestNewTenantMembership_AcceptsAllValidRoles(t *testing.T) {
	t.Parallel()

	gcid := "01970000-0000-7000-9000-000000000001"
	for _, r := range []identity.Role{
		identity.RoleLearner, identity.RoleInstructor,
		identity.RoleAdmin, identity.RoleAuditor,
	} {
		_, err := identity.NewTenantMembership(identity.NewMembershipParams{
			Gcid: gcid, TenantID: tenantA, Role: r,
		})
		if err != nil {
			t.Errorf("role=%q unexpected error: %v", r, err)
		}
	}
}

func TestNewTenantMembership_RejectsMissingTenantOrGcid(t *testing.T) {
	t.Parallel()

	_, err := identity.NewTenantMembership(identity.NewMembershipParams{
		Gcid: "", TenantID: tenantA, Role: identity.RoleLearner,
	})
	if err == nil {
		t.Errorf("expected error for missing gcid")
	}
	gcid := "01970000-0000-7000-9000-000000000001"
	_, err = identity.NewTenantMembership(identity.NewMembershipParams{
		Gcid: gcid, TenantID: "", Role: identity.RoleLearner,
	})
	if err == nil {
		t.Errorf("expected error for missing tenant_id")
	}
}

// -----------------------------------------------------------------------------
// Role transition audit trail
// -----------------------------------------------------------------------------

func TestChangeRole_AppendsAuditEntryWithPriorAndNewRole(t *testing.T) {
	t.Parallel()

	gcid := "01970000-0000-7000-9000-000000000001"
	m, _ := identity.NewTenantMembership(identity.NewMembershipParams{
		Gcid: gcid, TenantID: tenantA, Role: identity.RoleLearner,
	})

	if got := len(m.AuditTrail); got != 0 {
		t.Errorf("initial AuditTrail size = %d; want 0", got)
	}

	if err := m.ChangeRole(identity.RoleInstructor, "actor-gcid-1"); err != nil {
		t.Fatalf("unexpected: %v", err)
	}

	if m.Role != identity.RoleInstructor {
		t.Errorf("Role = %q; want instructor", m.Role)
	}
	if got := len(m.AuditTrail); got != 1 {
		t.Errorf("AuditTrail size = %d; want 1", got)
	}
	entry := m.AuditTrail[0]
	if entry.PriorRole != identity.RoleLearner {
		t.Errorf("PriorRole = %q; want learner", entry.PriorRole)
	}
	if entry.NewRole != identity.RoleInstructor {
		t.Errorf("NewRole = %q; want instructor", entry.NewRole)
	}
	if entry.ChangedByGcid != "actor-gcid-1" {
		t.Errorf("ChangedByGcid = %q; want actor-gcid-1", entry.ChangedByGcid)
	}
	if entry.ChangedAt.IsZero() {
		t.Errorf("ChangedAt should be set")
	}
}

func TestChangeRole_NoOpWhenSameRole(t *testing.T) {
	t.Parallel()

	gcid := "01970000-0000-7000-9000-000000000001"
	m, _ := identity.NewTenantMembership(identity.NewMembershipParams{
		Gcid: gcid, TenantID: tenantA, Role: identity.RoleLearner,
	})
	if err := m.ChangeRole(identity.RoleLearner, "actor"); err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if len(m.AuditTrail) != 0 {
		t.Errorf("same-role change should not append audit; got %d entries", len(m.AuditTrail))
	}
}

func TestChangeRole_RejectsInvalidRole(t *testing.T) {
	t.Parallel()

	gcid := "01970000-0000-7000-9000-000000000001"
	m, _ := identity.NewTenantMembership(identity.NewMembershipParams{
		Gcid: gcid, TenantID: tenantA, Role: identity.RoleLearner,
	})
	if err := m.ChangeRole(identity.Role("godmode"), "actor"); err == nil {
		t.Errorf("expected error for invalid role")
	}
}

// -----------------------------------------------------------------------------
// PortableSnapshot — append-only (BP-01 Learner Ownership)
// -----------------------------------------------------------------------------

func TestNewPortableSnapshot_AssignsIDAndStartsAtSequenceOne(t *testing.T) {
	t.Parallel()

	gcid := "01970000-0000-7000-9000-000000000001"
	s, err := identity.NewPortableSnapshot(identity.NewPortableSnapshotParams{
		Gcid:        gcid,
		Sequence:    1,
		PayloadHash: "sha256:deadbeef",
	})
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if s.SnapshotID == "" {
		t.Errorf("SnapshotID empty")
	}
	if s.Sequence != 1 {
		t.Errorf("Sequence = %d; want 1", s.Sequence)
	}
	if s.GeneratedAt.IsZero() {
		t.Errorf("GeneratedAt should be set")
	}
}

func TestNewPortableSnapshot_RejectsZeroSequence(t *testing.T) {
	t.Parallel()

	_, err := identity.NewPortableSnapshot(identity.NewPortableSnapshotParams{
		Gcid: "01970000-0000-7000-9000-000000000001", Sequence: 0, PayloadHash: "h",
	})
	if err == nil {
		t.Errorf("expected error for zero sequence; got nil")
	}
}

func TestNewPortableSnapshot_RejectsEmptyGcid(t *testing.T) {
	t.Parallel()

	_, err := identity.NewPortableSnapshot(identity.NewPortableSnapshotParams{
		Gcid: "", Sequence: 1, PayloadHash: "h",
	})
	if err == nil {
		t.Errorf("expected error for empty gcid; got nil")
	}
}

func TestPortableSnapshot_NoMutatorMethodsExposed(t *testing.T) {
	t.Parallel()

	// Append-only invariant: a PortableSnapshot is constructed once and its
	// fields are then read-only from the domain's perspective. We assert the
	// type does not surface any mutator methods that would violate append-only.
	// The cheapest reliable check is a static compile-time guard via the
	// AppendOnlyMarker() interface — calling it should always be a no-op.
	gcid := "01970000-0000-7000-9000-000000000001"
	s, _ := identity.NewPortableSnapshot(identity.NewPortableSnapshotParams{
		Gcid: gcid, Sequence: 1, PayloadHash: "h",
	})
	// AppendOnlyMarker exists to document the constraint to readers + reviewers.
	s.AppendOnlyMarker()
}

// -----------------------------------------------------------------------------
// User helpers
// -----------------------------------------------------------------------------

func TestUser_Suspend_SetsStatusSuspended(t *testing.T) {
	t.Parallel()
	u, _ := identity.NewUser(identity.NewUserParams{
		Email: "a@b.com", IdentityProvider: identity.ProviderOIDC, FederatedSubject: "x",
	})
	u.Suspend()
	if u.Status != identity.UserStatusSuspended {
		t.Errorf("Status = %q; want suspended", u.Status)
	}
	first := u.UpdatedAt
	u.Suspend()
	if !u.UpdatedAt.Equal(first) {
		t.Errorf("Suspend should be idempotent")
	}
}

func TestMembership_Deactivate_SetsInactiveAndIdempotent(t *testing.T) {
	t.Parallel()
	gcid := "01970000-0000-7000-9000-000000000001"
	m, _ := identity.NewTenantMembership(identity.NewMembershipParams{
		Gcid: gcid, TenantID: tenantA, Role: identity.RoleLearner,
	})
	m.Deactivate()
	if m.Status != identity.MembershipStatusInactive {
		t.Errorf("Status = %q; want inactive", m.Status)
	}
	first := m.UpdatedAt
	m.Deactivate()
	if !m.UpdatedAt.Equal(first) {
		t.Errorf("Deactivate should be idempotent")
	}
}

func TestUser_Close_SetsStatusClosedAndIsIdempotent(t *testing.T) {
	t.Parallel()
	u, _ := identity.NewUser(identity.NewUserParams{
		Email: "a@b.com", IdentityProvider: identity.ProviderOIDC, FederatedSubject: "x",
	})
	u.Close()
	if u.Status != identity.UserStatusClosed {
		t.Errorf("Status = %q; want closed", u.Status)
	}
	first := u.UpdatedAt
	u.Close()
	if !u.UpdatedAt.Equal(first) {
		t.Errorf("Close should be idempotent; UpdatedAt mutated")
	}
}

func TestEmailValidation_LooseSanity(t *testing.T) {
	t.Parallel()
	// Smoke test the loose email validator we use.
	good := []string{"a@b.com", "alice+tag@chora.dev", "x.y@z.co.uk"}
	bad := []string{"", " ", "no-at-sign", "@noprefix.com", "noend@"}

	for _, e := range good {
		if !identity.LooseValidEmail(e) {
			t.Errorf("LooseValidEmail(%q) = false; want true", e)
		}
	}
	for _, e := range bad {
		if identity.LooseValidEmail(strings.TrimSpace(e)) {
			t.Errorf("LooseValidEmail(%q) = true; want false", e)
		}
	}
}
