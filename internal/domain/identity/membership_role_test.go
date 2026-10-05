package identity_test

import (
	"testing"

	"github.com/apollo-chora/chora-identity/internal/domain/identity"
)

// ADR-191 — PROCTOR canonical role lockstep.
//
// PROCTOR is a tenant-scoped, add-on-gated, JWT-extension canonical role
// (mirrors the ADR-182 AUTHOR lockstep). It MUST be registered in
// CanonicalRoles, validate, and be tenant-scoped — only PLATFORM_OPERATOR is
// cross-tenant per docs/architecture.md §3.5 #12.
func TestCanonicalRoleProctor_RegisteredAndTenantScoped(t *testing.T) {
	if got := string(identity.CanonicalRoleProctor); got != "PROCTOR" {
		t.Errorf("token = %q; want PROCTOR (single uppercase token per ADR-141)", got)
	}
	if !identity.CanonicalRoleProctor.Valid() {
		t.Fatalf("CanonicalRoleProctor.Valid() = false; want true")
	}

	found := false
	for _, r := range identity.CanonicalRoles {
		if r == identity.CanonicalRoleProctor {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("CanonicalRoleProctor is not in CanonicalRoles — lockstep broken (ADR-191 D1)")
	}

	if !identity.CanonicalRoleProctor.IsTenantScoped() {
		t.Errorf("IsTenantScoped(PROCTOR) = false; want true — PROCTOR is tenant-scoped, " +
			"only PLATFORM_OPERATOR is cross-tenant (ADR-191 D1, Alternative B rejected)")
	}
}

// ADR-191 D1 / Alternative D — PROCTOR is a JWT-extension role, NOT a stored
// lowercase membership_role. It is bound per-sitting via ExamInvigilator, so it
// must be rejected by BOTH membership predicates (no ENUM widening, no grant).
// This assertion used to read Role.Valid(), which migration 0041 split into
// Grantable (the five admin-grantable roles) and Stored (those plus owner).
func TestProctor_IsNotAStoredMembershipRole(t *testing.T) {
	for _, token := range []string{"proctor", "PROCTOR"} {
		if identity.Role(token).Stored() {
			t.Errorf(`Role(%q).Stored() = true; want false, PROCTOR is JWT-extension, not membership_role`, token)
		}
		if identity.Role(token).Grantable() {
			t.Errorf(`Role(%q).Grantable() = true; want false`, token)
		}
	}
}

// Exactly one canonical role remains cross-tenant (PLATFORM_OPERATOR) after the
// PROCTOR add — guards the §3.5 #12 invariant that adding PROCTOR does not
// create a second cross-tenant role.
func TestCanonicalRoles_ExactlyOneCrossTenant(t *testing.T) {
	crossTenant := 0
	for _, r := range identity.CanonicalRoles {
		if !r.IsTenantScoped() {
			crossTenant++
		}
	}
	if crossTenant != 1 {
		t.Errorf("cross-tenant canonical roles = %d; want exactly 1 (PLATFORM_OPERATOR)", crossTenant)
	}
}
