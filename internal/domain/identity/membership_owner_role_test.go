// membership_owner_role_test.go: S7-B3, `owner` becomes a real stored
// membership_role, WITHOUT becoming grantable (UX refactor R21).
//
// Migration 0041 adds 'owner' to the chora_identity.membership_role ENUM so
// the H+ roster can finally show who owns the organisation, instead of the
// mirror deliberately downgrading the owner to `admin`
// (tenant_bootstrapped_subscriber.go). That widening creates a hazard: three
// call sites gate a role purely on the old Role.Valid(), and one of them is
// the pending-invite path. If `owner` had simply been added to Valid(), an
// invite could grant ownership, which no API is allowed to do
// (first-launch spec 13.1: "owner cannot be granted through any API").
//
// So the vocabulary splits in two, and the names say which is which:
//
//	Grantable()  the five roles an admin API may hand out. Owner is NOT one.
//	             This is the old Valid(), renamed, with its set byte-for-byte
//	             unchanged.
//	Stored()     every value the ENUM can hold, which now includes owner.
//	             Used when reading a role BACK from the database.
//
// The tests below are the fence: they fail the moment someone widens
// Grantable() or lets owner reach a grant path.
package identity

import (
	"testing"
	"time"
)

func TestRole_GrantableSetIsExactlyTheFiveAdminGrantableRoles(t *testing.T) {
	t.Parallel()
	grantable := []Role{RoleLearner, RoleAuthor, RoleInstructor, RoleAdmin, RoleAuditor}
	for _, r := range grantable {
		if !r.Grantable() {
			t.Errorf("Grantable(%q) = false, want true", string(r))
		}
	}
	notGrantable := []Role{RoleOwner, "platform_operator", "support_agent", "", "OWNER", "nonsense"}
	for _, r := range notGrantable {
		if r.Grantable() {
			t.Errorf("Grantable(%q) = true, want false", string(r))
		}
	}
}

func TestRole_StoredIncludesOwnerButGrantableDoesNot(t *testing.T) {
	t.Parallel()
	if !RoleOwner.Stored() {
		t.Errorf("Stored(%q) = false; owner IS a membership_role value after migration 0041", string(RoleOwner))
	}
	if RoleOwner.Grantable() {
		t.Fatalf("owner must never be grantable: it is written only by tenant bootstrap " +
			"and moved only by the S7 handover")
	}
	// Every grantable role is also storable; the split widens, never narrows.
	for _, r := range []Role{RoleLearner, RoleAuthor, RoleInstructor, RoleAdmin, RoleAuditor} {
		if !r.Stored() {
			t.Errorf("Stored(%q) = false, want true", string(r))
		}
	}
	if Role("platform_operator").Stored() {
		t.Errorf("PLATFORM_OPERATOR is JWT-only (ADR-165) and holds no membership row")
	}
}

// The invariant the rename exists to protect. NewPendingInvite gates its role
// list on the grantable set alone, so a widened predicate here would make
// "invite somebody as owner" succeed.
func TestNewPendingInvite_RefusesOwner(t *testing.T) {
	t.Parallel()
	for _, roles := range [][]Role{
		{RoleOwner},
		{RoleAdmin, RoleOwner},
		{RoleOwner, RoleLearner},
	} {
		if _, err := NewPendingInvite(NewPendingInviteParams{
			TenantID:      "01970000-0000-7000-8000-000000000010",
			Email:         "nominee@example.com",
			Roles:         roles,
			InvitedByGcid: "01970000-0000-7000-8000-000000000020",
			TTL:           24 * time.Hour,
		}); err == nil {
			t.Errorf("NewPendingInvite(roles=%v) = nil error; an invite must never grant ownership", roles)
		}
	}
}

// A membership aggregate cannot be constructed as an owner either: the mirror
// row for an owner is written by the bootstrap subscriber's raw-string upsert,
// not through this constructor, and keeping the constructor closed means no
// admin flow can mint one by accident.
func TestNewTenantMembership_RefusesOwner(t *testing.T) {
	t.Parallel()
	if _, err := NewTenantMembership(NewMembershipParams{
		Gcid:     "01970000-0000-7000-8000-000000000030",
		TenantID: "01970000-0000-7000-8000-000000000010",
		Role:     RoleOwner,
	}); err == nil {
		t.Fatalf("NewTenantMembership(role=owner) = nil error, want a refusal")
	}
}

func TestTenantMembership_ChangeRoleRefusesOwner(t *testing.T) {
	t.Parallel()
	m, err := NewTenantMembership(NewMembershipParams{
		Gcid:     "01970000-0000-7000-8000-000000000030",
		TenantID: "01970000-0000-7000-8000-000000000010",
		Role:     RoleAdmin,
	})
	if err != nil {
		t.Fatalf("NewTenantMembership: %v", err)
	}
	if err := m.ChangeRole(RoleOwner, "01970000-0000-7000-8000-000000000020"); err == nil {
		t.Fatalf("ChangeRole(owner) = nil error; ownership is not a role change")
	}
	if m.Role != RoleAdmin {
		t.Errorf("Role = %q, want the membership left untouched by a refused change", string(m.Role))
	}
}
