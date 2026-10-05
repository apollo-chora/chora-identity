// membership_mirror_owner_guard_test.go: S7-B1 on the MIRROR side.
//
// chora_tenancy.members is authoritative for ownership and carries its own
// last-owner and owner-strip guards. chora_identity.tenant_memberships is the
// projection the H+ Members roster actually reads, and it needs guards of its
// own for two separate reasons:
//
//  1. PATCH /api/v1/admin/tenant-members/{gcid}/role reaches the MIRROR FIRST
//     and only then makes a best-effort ADDITIVE call to the authoritative
//     store. So the tenancy guard never sees it. Before migration 0041 that
//     did not matter, because the mirror said `admin` for the owner anyway;
//     the moment the mirror carries `owner`, this endpoint becomes a fresh way
//     to make ownership invisible again. This guard is created by that change
//     and ships with it.
//  2. The handler falls back to a mirror-only path when no tenancy client is
//     wired (dev). There the mirror guard is the only guard there is.
//
// Same asymmetry as the authoritative side, for the same reasons: a role edit
// must never drop an owner row, and a whole-member revoke is refused only when
// it would leave the tenant with no owner at all.
package pg

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/apollo-chora/chora-identity/internal/domain/identity"
)

// maOtherGcid is a second member of maTenant, so "last owner" and "co-owner"
// are distinguishable.
const maOtherGcid = "00000000-0000-7000-8000-000000002999"

// ownerCounts builds the guard's QueryRow response: (target_owns, live_owners).
func ownerCounts(targetOwns, liveOwners int) Row {
	return &stubMemberSearchRow{vals: []any{targetOwns, liveOwners}}
}

// ownerGuardSQL finds the guard statement among the captured queries.
func ownerGuardSQL(t *testing.T, queries []capturedQuery) string {
	t.Helper()
	for _, q := range queries {
		if strings.Contains(q.SQL, "'owner'::membership_role") {
			return q.SQL
		}
	}
	t.Fatalf("no owner-guard query issued; queries=%v", queries)
	return ""
}

// assertNoDeactivation fails when any statement would flip a row inactive.
func assertNoDeactivation(t *testing.T, queries []capturedQuery) {
	t.Helper()
	for _, q := range queries {
		if strings.Contains(q.SQL, "'inactive'::membership_status") {
			t.Errorf("the guard must refuse BEFORE any deactivation; ran:\n%s", q.SQL)
		}
	}
}

// -----------------------------------------------------------------------------
// ChangeRole, the H+ inline role select. Mirror-first, so this is the only
// guard on that endpoint.
// -----------------------------------------------------------------------------

func TestMembershipAdmin_ChangeRole_RefusesToStripOwner(t *testing.T) {
	tx := &stubTx{queryRowFn: rowQueue(
		&stubMemberSearchRow{vals: []any{1}}, // existence gate: a live row
		ownerCounts(1, 1),                    // the target owns this tenant
	)}
	repo := NewMembershipAdminRepository(&stubTxQuerier{tx: tx})

	err := repo.ChangeRole(context.Background(), maGcid, maTenant, identity.RoleInstructor)
	if !errors.Is(err, identity.ErrOwnerRoleProtected) {
		t.Fatalf("err = %v, want ErrOwnerRoleProtected", err)
	}
	assertNoDeactivation(t, tx.queries)
}

func TestMembershipAdmin_ChangeRole_RefusesEvenWhenAnotherOwnerExists(t *testing.T) {
	tx := &stubTx{queryRowFn: rowQueue(
		&stubMemberSearchRow{vals: []any{1}},
		ownerCounts(1, 2), // co-owner present; the individual still loses it
	)}
	repo := NewMembershipAdminRepository(&stubTxQuerier{tx: tx})

	if err := repo.ChangeRole(context.Background(), maGcid, maTenant, identity.RoleAdmin); !errors.Is(err, identity.ErrOwnerRoleProtected) {
		t.Fatalf("err = %v, want ErrOwnerRoleProtected", err)
	}
}

func TestMembershipAdmin_ChangeRole_AllowsNonOwner(t *testing.T) {
	tx := &stubTx{queryRowFn: rowQueue(
		&stubMemberSearchRow{vals: []any{1}},
		ownerCounts(0, 1), // somebody else owns this tenant
	)}
	repo := NewMembershipAdminRepository(&stubTxQuerier{tx: tx})

	if err := repo.ChangeRole(context.Background(), maGcid, maTenant, identity.RoleInstructor); err != nil {
		t.Fatalf("ChangeRole: %v", err)
	}
	guard := ownerGuardSQL(t, tx.queries)
	if !strings.Contains(guard, "'active'::membership_status") {
		t.Errorf("the mirror guard must count ACTIVE owner rows; got:\n%s", guard)
	}
	if !strings.Contains(guard, "FOR UPDATE") {
		t.Errorf("the mirror guard should lock the owner rows it asserts on; got:\n%s", guard)
	}
}

// -----------------------------------------------------------------------------
// SetRoles, the H+ multi-role checkbox editor.
// -----------------------------------------------------------------------------

func TestMembershipAdmin_SetRoles_RefusesToStripOwner(t *testing.T) {
	tx := &stubTx{queryRowFn: rowQueue(
		&stubMemberSearchRow{vals: []any{1}},
		ownerCounts(1, 1),
	)}
	repo := NewMembershipAdminRepository(&stubTxQuerier{tx: tx})

	err := repo.SetRoles(context.Background(), maGcid, maTenant,
		[]identity.Role{identity.RoleAdmin, identity.RoleInstructor})
	if !errors.Is(err, identity.ErrOwnerRoleProtected) {
		t.Fatalf("err = %v, want ErrOwnerRoleProtected", err)
	}
	assertNoDeactivation(t, tx.queries)
}

func TestMembershipAdmin_SetRoles_AllowsWhenOwnerIsKept(t *testing.T) {
	// Defensive, exactly as on the authoritative side: the predicate fires on
	// a STRIP, not on the presence of an owner. No caller can send `owner`
	// today because Role.Grantable() rejects it upstream.
	tx := &stubTx{queryRowFn: rowQueue(
		&stubMemberSearchRow{vals: []any{1}},
		ownerCounts(1, 1),
	)}
	repo := NewMembershipAdminRepository(&stubTxQuerier{tx: tx})

	if err := repo.SetRoles(context.Background(), maGcid, maTenant,
		[]identity.Role{identity.RoleOwner, identity.RoleAdmin}); err != nil {
		t.Fatalf("SetRoles: %v", err)
	}
}

func TestMembershipAdmin_SetRoles_AllowsNonOwner(t *testing.T) {
	tx := &stubTx{queryRowFn: rowQueue(
		&stubMemberSearchRow{vals: []any{1}},
		ownerCounts(0, 1),
	)}
	repo := NewMembershipAdminRepository(&stubTxQuerier{tx: tx})

	if err := repo.SetRoles(context.Background(), maGcid, maTenant,
		[]identity.Role{identity.RoleAdmin}); err != nil {
		t.Fatalf("SetRoles: %v", err)
	}
}

// -----------------------------------------------------------------------------
// RemoveMember, last-owner semantics mirroring the authoritative guard.
// -----------------------------------------------------------------------------

func TestMembershipAdmin_RemoveMember_RefusesLastOwner(t *testing.T) {
	tx := &stubTx{queryRowFn: rowQueue(
		&stubMemberSearchRow{vals: []any{1}}, // active-row gate
		ownerCounts(1, 1),                    // the target is the only owner
	)}
	repo := NewMembershipAdminRepository(&stubTxQuerier{tx: tx})

	err := repo.RemoveMember(context.Background(), maGcid, maTenant)
	if !errors.Is(err, identity.ErrLastOwnerProtected) {
		t.Fatalf("err = %v, want ErrLastOwnerProtected", err)
	}
	assertNoDeactivation(t, tx.queries)
}

func TestMembershipAdmin_RemoveMember_AllowsCoOwner(t *testing.T) {
	tx := &stubTx{queryRowFn: rowQueue(
		&stubMemberSearchRow{vals: []any{1}},
		ownerCounts(1, 2), // the tenant keeps an owner
	)}
	repo := NewMembershipAdminRepository(&stubTxQuerier{tx: tx})

	if err := repo.RemoveMember(context.Background(), maGcid, maTenant); err != nil {
		t.Fatalf("RemoveMember: %v", err)
	}
}

func TestMembershipAdmin_RemoveMember_AllowsNonOwner(t *testing.T) {
	tx := &stubTx{queryRowFn: rowQueue(
		&stubMemberSearchRow{vals: []any{1}},
		ownerCounts(0, 1),
	)}
	repo := NewMembershipAdminRepository(&stubTxQuerier{tx: tx})

	if err := repo.RemoveMember(context.Background(), maGcid, maTenant); err != nil {
		t.Fatalf("RemoveMember: %v", err)
	}
}

// A guard whose own read fails must fail the write, not wave it through. The
// stub returns ErrNoRows once the scripted queue is exhausted, which is what a
// guard reading nothing looks like.
func TestMembershipAdmin_OwnerGuard_FailsLoudWhenItCannotRead(t *testing.T) {
	for _, tc := range []struct {
		name string
		call func(*MembershipAdminRepository) error
	}{
		{"ChangeRole", func(r *MembershipAdminRepository) error {
			return r.ChangeRole(context.Background(), maGcid, maTenant, identity.RoleAdmin)
		}},
		{"SetRoles", func(r *MembershipAdminRepository) error {
			return r.SetRoles(context.Background(), maGcid, maTenant, []identity.Role{identity.RoleAdmin})
		}},
		{"RemoveMember", func(r *MembershipAdminRepository) error {
			return r.RemoveMember(context.Background(), maGcid, maTenant)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tx := &stubTx{queryRowFn: rowQueue(
				&stubMemberSearchRow{vals: []any{1}},                      // gate passes
				&stubMemberSearchRow{err: errors.New("owner guard boom")}, // guard read fails
			)}
			err := tc.call(NewMembershipAdminRepository(&stubTxQuerier{tx: tx}))
			if err == nil || !strings.Contains(err.Error(), "owner guard") {
				t.Fatalf("err = %v, want one naming the owner guard", err)
			}
			assertNoDeactivation(t, tx.queries)
		})
	}
}
