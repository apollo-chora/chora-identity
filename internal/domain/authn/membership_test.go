package authn_test

import (
	"testing"
	"time"

	"github.com/apollo-chora/chora-identity/internal/domain/authn"
)

func TestNormalizeUsername(t *testing.T) {
	cases := map[string]string{
		"  Admin  ": "admin",
		"ADMIN":     "admin",
		"aDmIn":     "admin",
		"":          "",
	}
	for in, want := range cases {
		if got := authn.NormalizeUsername(in); got != want {
			t.Errorf("NormalizeUsername(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestGroupByTenant(t *testing.T) {
	now := time.Now()
	m := []authn.Membership{
		{TenantID: "t-b", Role: "admin", CreatedAt: now},
		{TenantID: "t-a", Role: "learner", CreatedAt: now},
		{TenantID: "t-a", Role: "author", CreatedAt: now},
	}
	groups := authn.GroupByTenant(m)
	if len(groups) != 2 {
		t.Fatalf("groups = %d, want 2", len(groups))
	}
	if groups[0].TenantID != "t-b" || len(groups[0].Roles) != 1 || groups[0].Roles[0] != "admin" {
		t.Errorf("groups[0] = %+v", groups[0])
	}
	if groups[1].TenantID != "t-a" {
		t.Errorf("groups[1].TenantID = %q", groups[1].TenantID)
	}
	// Roles are sorted deterministically.
	if len(groups[1].Roles) != 2 || groups[1].Roles[0] != "author" || groups[1].Roles[1] != "learner" {
		t.Errorf("groups[1].Roles = %v, want [author learner]", groups[1].Roles)
	}
}

func TestResolveActiveTenant_ZeroMemberships(t *testing.T) {
	tid, roles := authn.ResolveActiveTenant(nil, nil)
	if tid != "" || roles != nil {
		t.Errorf("zero memberships: got (%q,%v), want empty", tid, roles)
	}
}

func TestResolveActiveTenant_SingleTenant(t *testing.T) {
	now := time.Now()
	m := []authn.Membership{{TenantID: "t-1", Role: "learner", CreatedAt: now}}
	tid, roles := authn.ResolveActiveTenant(m, authn.GroupByTenant(m))
	if tid != "t-1" {
		t.Errorf("active tenant = %q, want t-1", tid)
	}
	if len(roles) != 1 || roles[0] != "learner" {
		t.Errorf("roles = %v", roles)
	}
}

func TestResolveActiveTenant_MultipleTenantsPicksOldest(t *testing.T) {
	now := time.Now()
	m := []authn.Membership{
		{TenantID: "t-new", Role: "admin", CreatedAt: now},
		{TenantID: "t-old", Role: "learner", CreatedAt: now.Add(-24 * time.Hour)},
		{TenantID: "t-old", Role: "author", CreatedAt: now.Add(-24 * time.Hour)},
	}
	tid, roles := authn.ResolveActiveTenant(m, authn.GroupByTenant(m))
	if tid != "t-old" {
		t.Fatalf("active tenant = %q, want t-old (oldest membership)", tid)
	}
	if len(roles) != 2 || roles[0] != "author" || roles[1] != "learner" {
		t.Errorf("roles = %v, want [author learner]", roles)
	}
}

func TestResolveActiveTenant_TieBreakByTenantID(t *testing.T) {
	at := time.Now()
	m := []authn.Membership{
		{TenantID: "t-b", Role: "admin", CreatedAt: at},
		{TenantID: "t-a", Role: "admin", CreatedAt: at},
	}
	tid, _ := authn.ResolveActiveTenant(m, authn.GroupByTenant(m))
	if tid != "t-a" {
		t.Errorf("tie-break tenant = %q, want t-a (ascending tenant_id)", tid)
	}
}
