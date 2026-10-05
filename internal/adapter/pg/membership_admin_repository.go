// membership_admin_repository.go — pgx-backed tenant-membership writes for
// the L1 Tenant lane (CHO-1707): add-member-by-email + tenant-scoped role
// change, keyed by (gcid, tenant_id).
//
// SQL contract (multi-role mirror — migration 0020 UNIQUE(gcid,
// tenant_id, role) per ADR-182):
//
//	AddMembership:
//	  INSERT INTO tenant_memberships (gcid, tenant_id, role, status)
//	  VALUES (...) ON CONFLICT (gcid, tenant_id, role) DO NOTHING
//	  RETURNING membership_id
//	  → no row returned = duplicate role → identity.ErrMembershipExists
//	    (a DIFFERENT role for the same (gcid, tenant) inserts fine)
//
//	ChangeRole (set-replace — a single-role UPDATE breaks under
//	multi-role: it would collide with an existing target-role row):
//	  1. SELECT 1 ... WHERE status = 'active' LIMIT 1
//	     → no row = absent (or cross-tenant — RLS hides it anyway)
//	       → identity.ErrMembershipNotFound
//	  2. UPDATE ... SET status = 'inactive' WHERE role <> $3 AND status = 'active'
//	  3. INSERT ... ON CONFLICT (gcid, tenant_id, role)
//	     DO UPDATE SET status = 'active'
//
// RLS contract: tenant_memberships carries the tenant_isolation policy and
// chora_identity_app_rw is NOBYPASSRLS in production, so BOTH statements
// MUST run inside RunInTenantTx with SET LOCAL chora.tenant_id matching the
// row being written (the MembershipBootstrapUpserter precedent).
package pg

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/apollo-chora/chora-identity/internal/domain/identity"
)

// MembershipAdminRepository satisfies the http adapter's
// AdminMembershipWriter port.
type MembershipAdminRepository struct {
	tx TxQuerier
}

// NewMembershipAdminRepository wraps a TxQuerier. *PgxPoolQuerier satisfies
// TxQuerier — that's the production wiring. Panics on nil so wiring bugs
// fail loud at boot.
func NewMembershipAdminRepository(tx TxQuerier) *MembershipAdminRepository {
	if tx == nil {
		panic("pg.NewMembershipAdminRepository: nil TxQuerier")
	}
	return &MembershipAdminRepository{tx: tx}
}

func validateMembershipArgs(gcid, tenantID string, role identity.Role) error {
	if gcid == "" {
		return errors.New("pg.MembershipAdmin: empty gcid")
	}
	if tenantID == "" {
		return errors.New("pg.MembershipAdmin: empty tenant_id")
	}
	if !role.Grantable() {
		return fmt.Errorf("pg.MembershipAdmin: invalid membership role %q", role)
	}
	return nil
}

// ownerMirrorGuard reads how many ACTIVE `owner` rows this tenant has and
// whether the target GCID holds one, locking those rows for the rest of the
// transaction (S7-B1). Call it inside RunInTenantTx: the tenant_isolation
// policy scopes it to the tenant whose GUC is set.
//
// The authoritative record of ownership is chora_tenancy.members, which runs
// the same two guards with its own lock. This one exists because the H+ inline
// role select reaches the mirror FIRST (PATCH /tenant-members/{gcid}/role does
// a mirror set-replace, then a best-effort ADDITIVE authoritative call), so the
// tenancy guard never sees that request, and because the handler falls back to
// a mirror-only path when no tenancy client is wired.
//
// A read failure is returned, never swallowed: a guard that reads nothing and
// shrugs would report "no owners" and wave the destructive write straight
// through, which is worse than having no guard at all.
func ownerMirrorGuard(ctx context.Context, tx Tx, gcid, tenantID string) (targetOwns bool, liveOwners int, err error) {
	const q = `
        SELECT
            count(*) FILTER (WHERE o.gcid = $1::uuid) AS target_owns,
            count(*)                                  AS live_owners
        FROM (
            SELECT gcid
            FROM   tenant_memberships
            WHERE  tenant_id = $2::uuid
              AND  role = 'owner'::membership_role
              AND  status = 'active'::membership_status
            FOR UPDATE
        ) AS o
    `
	var owns int
	if err := tx.QueryRow(ctx, q, gcid, tenantID).Scan(&owns, &liveOwners); err != nil {
		return false, 0, fmt.Errorf("pg.MembershipAdmin owner guard: %w", err)
	}
	return owns > 0, liveOwners, nil
}

// refuseOwnerStrip is the shared D2 check for the two role-edit paths: a role
// edit must never drop a live owner row. `roles` is the post-edit role set.
func refuseOwnerStrip(ctx context.Context, tx Tx, gcid, tenantID string, roles []string) error {
	for _, r := range roles {
		if r == string(identity.RoleOwner) {
			return nil // ownership is kept, so nothing is being stripped
		}
	}
	owns, _, err := ownerMirrorGuard(ctx, tx, gcid, tenantID)
	if err != nil {
		return err
	}
	if owns {
		return identity.ErrOwnerRoleProtected
	}
	return nil
}

// AddMembership inserts an active membership row; duplicate
// (gcid, tenant, role) maps to identity.ErrMembershipExists.
func (r *MembershipAdminRepository) AddMembership(ctx context.Context, gcid, tenantID string, role identity.Role) error {
	if err := validateMembershipArgs(gcid, tenantID, role); err != nil {
		return err
	}
	return r.tx.RunInTenantTx(ctx, tenantID, func(ctx context.Context, tx Tx) error {
		insert := `
            INSERT INTO tenant_memberships (gcid, tenant_id, role, status)
            VALUES ($1::uuid, $2::uuid, $3::membership_role, 'active'::membership_status)
            ON CONFLICT (gcid, tenant_id, role) DO NOTHING
            RETURNING membership_id
        `
		var membershipID string
		row := tx.QueryRow(ctx, insert, gcid, tenantID, string(role))
		if err := row.Scan(&membershipID); err != nil {
			if errors.Is(err, ErrNoRows) {
				return identity.ErrMembershipExists
			}
			return fmt.Errorf("pg.MembershipAdmin.AddMembership: %w", err)
		}
		return nil
	})
}

// ChangeRole replaces the active role SET for (gcid, tenant) with exactly
// {role} — set-replace, not a single-row UPDATE, because the multi-role
// mirror can hold several active rows and the target role may already
// exist as its own row. No active rows — including a cross-tenant gcid
// the RLS policy hides — maps to identity.ErrMembershipNotFound.
func (r *MembershipAdminRepository) ChangeRole(ctx context.Context, gcid, tenantID string, role identity.Role) error {
	if err := validateMembershipArgs(gcid, tenantID, role); err != nil {
		return err
	}
	return r.tx.RunInTenantTx(ctx, tenantID, func(ctx context.Context, tx Tx) error {
		gate := `
            SELECT 1
            FROM tenant_memberships
            WHERE gcid = $1::uuid AND tenant_id = $2::uuid AND status = 'active'::membership_status
            LIMIT 1
        `
		var one int
		if err := tx.QueryRow(ctx, gate, gcid, tenantID).Scan(&one); err != nil {
			if errors.Is(err, ErrNoRows) {
				return identity.ErrMembershipNotFound
			}
			return fmt.Errorf("pg.MembershipAdmin.ChangeRole gate: %w", err)
		}

		// Owner guard (S7-B1 defect D2). The deactivate below drops every
		// active row whose role is not the target, and the target can never be
		// `owner` because validateMembershipArgs gates on Role.Grantable().
		// So without this, one inline role-select change hides the owner of
		// the organisation from every screen that reads the mirror.
		if err := refuseOwnerStrip(ctx, tx, gcid, tenantID, []string{string(role)}); err != nil {
			return err
		}

		deactivate := `
            UPDATE tenant_memberships
            SET status = 'inactive'::membership_status, updated_at = now()
            WHERE gcid = $1::uuid AND tenant_id = $2::uuid
              AND role <> $3::membership_role
              AND status = 'active'::membership_status
        `
		if err := tx.Exec(ctx, deactivate, gcid, tenantID, string(role)); err != nil {
			return fmt.Errorf("pg.MembershipAdmin.ChangeRole deactivate: %w", err)
		}

		upsert := `
            INSERT INTO tenant_memberships (gcid, tenant_id, role, status)
            VALUES ($1::uuid, $2::uuid, $3::membership_role, 'active'::membership_status)
            ON CONFLICT (gcid, tenant_id, role) DO UPDATE
            SET status = 'active'::membership_status, updated_at = now()
        `
		if err := tx.Exec(ctx, upsert, gcid, tenantID, string(role)); err != nil {
			return fmt.Errorf("pg.MembershipAdmin.ChangeRole upsert: %w", err)
		}
		return nil
	})
}

// SetRoles is the REPLACE flavour of ChangeRole (CHO-1809 follow-up for
// the H+ Members page multi-role editor). Deactivates every existing
// active row for (gcid, tenant_id) whose role is NOT in `roles`, then
// upserts the rows that ARE in `roles` (mirroring ChangeRole's upsert).
// Returns identity.ErrMembershipNotFound when no live (active) row
// exists for (gcid, tenant_id).
func (r *MembershipAdminRepository) SetRoles(ctx context.Context, gcid, tenantID string, roles []identity.Role) error {
	if err := validateGcidTenant(gcid, tenantID); err != nil {
		return err
	}
	if len(roles) == 0 {
		return errors.New("pg.MembershipAdmin.SetRoles: at least one role required")
	}
	// Stringify + de-dup once.
	rawRoles := make([]string, 0, len(roles))
	seen := make(map[string]bool, len(roles))
	for _, role := range roles {
		s := string(role)
		if seen[s] {
			continue
		}
		seen[s] = true
		rawRoles = append(rawRoles, s)
	}
	return r.tx.RunInTenantTx(ctx, tenantID, func(ctx context.Context, tx Tx) error {
		// Membership existence gate (any non-deleted row is enough; the
		// admin can replace roles even on a fully-inactive but extant
		// membership — that's how a paused-and-re-enabled user lands).
		gate := `
            SELECT 1
            FROM tenant_memberships
            WHERE gcid = $1::uuid AND tenant_id = $2::uuid
            LIMIT 1
        `
		var one int
		if err := tx.QueryRow(ctx, gate, gcid, tenantID).Scan(&one); err != nil {
			if errors.Is(err, ErrNoRows) {
				return identity.ErrMembershipNotFound
			}
			return fmt.Errorf("pg.MembershipAdmin.SetRoles gate: %w", err)
		}

		// Owner guard (S7-B1 defect D2), same rule as ChangeRole: the
		// deactivate below drops every active row outside the new set, and
		// `owner` can never be in that set through an admin API.
		if err := refuseOwnerStrip(ctx, tx, gcid, tenantID, rawRoles); err != nil {
			return err
		}

		// Deactivate every active row whose role is NOT in the new set.
		deactivate := `
            UPDATE tenant_memberships
            SET status = 'inactive'::membership_status, updated_at = now()
            WHERE gcid = $1::uuid AND tenant_id = $2::uuid
              AND role::text <> ALL ($3::text[])
              AND status = 'active'::membership_status
        `
		if err := tx.Exec(ctx, deactivate, gcid, tenantID, rawRoles); err != nil {
			return fmt.Errorf("pg.MembershipAdmin.SetRoles deactivate: %w", err)
		}

		// Upsert each kept role — reuses ChangeRole's per-role pattern so
		// `inactive` rows for the role-being-restored flip back to active.
		upsert := `
            INSERT INTO tenant_memberships (gcid, tenant_id, role, status)
            VALUES ($1::uuid, $2::uuid, $3::membership_role, 'active'::membership_status)
            ON CONFLICT (gcid, tenant_id, role) DO UPDATE
            SET status = 'active'::membership_status, updated_at = now()
        `
		for _, role := range rawRoles {
			if err := tx.Exec(ctx, upsert, gcid, tenantID, role); err != nil {
				return fmt.Errorf("pg.MembershipAdmin.SetRoles upsert role %q: %w", role, err)
			}
		}
		return nil
	})
}

// GrantMembership upserts the full `roles` set ACTIVE for (gcid, tenant) in a
// single RLS tx and returns a representative active membership_id (the first
// role's row). Additive + idempotent: a role already active is a no-op, an
// inactive role is reactivated, a new role is inserted (ON CONFLICT DO UPDATE
// always RETURNs the id). ADR-194 D1 / WS2 (CHO-1872) — the operator
// cross-tenant grant. Runs inside RunInTenantTx(tenantID): every written row's
// tenant_id equals the chora.tenant_id GUC, so the tenant_isolation policy
// passes (RLS-enforced, NOT a bypass).
func (r *MembershipAdminRepository) GrantMembership(ctx context.Context, gcid, tenantID string, roles []identity.Role) (string, error) {
	if err := validateGcidTenant(gcid, tenantID); err != nil {
		return "", err
	}
	if len(roles) == 0 {
		return "", errors.New("pg.MembershipAdmin.GrantMembership: at least one role required")
	}
	for _, role := range roles {
		if !role.Grantable() {
			return "", fmt.Errorf("pg.MembershipAdmin.GrantMembership: invalid membership role %q", role)
		}
	}
	var membershipID string
	err := r.tx.RunInTenantTx(ctx, tenantID, func(ctx context.Context, tx Tx) error {
		upsert := `
            INSERT INTO tenant_memberships (gcid, tenant_id, role, status)
            VALUES ($1::uuid, $2::uuid, $3::membership_role, 'active'::membership_status)
            ON CONFLICT (gcid, tenant_id, role) DO UPDATE
            SET status = 'active'::membership_status, updated_at = now()
            RETURNING membership_id
        `
		for _, role := range roles {
			var id string
			if err := tx.QueryRow(ctx, upsert, gcid, tenantID, string(role)).Scan(&id); err != nil {
				return fmt.Errorf("pg.MembershipAdmin.GrantMembership role %q: %w", role, err)
			}
			if membershipID == "" {
				membershipID = id
			}
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	return membershipID, nil
}

// RemoveMember (WS2b / CHO-1869) deactivates EVERY active mirror row for
// (gcid, tenant_id) — the member-centric revoke. Soft-delete only (status →
// inactive; NEVER hard-deletes — the row persists for audit + closure). Runs
// inside RunInTenantTx(tenantID) so RLS scopes the write to the caller's
// tenant. Returns identity.ErrMembershipNotFound when no active row exists.
func (r *MembershipAdminRepository) RemoveMember(ctx context.Context, gcid, tenantID string) error {
	if err := validateGcidTenant(gcid, tenantID); err != nil {
		return err
	}
	return r.tx.RunInTenantTx(ctx, tenantID, func(ctx context.Context, tx Tx) error {
		// Gate: at least one ACTIVE row must exist for (gcid, tenant) — else
		// there is nothing to remove (mirrors SetRoles' gate pattern, but
		// scoped to active so a re-remove of an already-removed member 404s).
		const gate = `
            SELECT 1
            FROM tenant_memberships
            WHERE gcid = $1::uuid AND tenant_id = $2::uuid
              AND status = 'active'::membership_status
            LIMIT 1
        `
		var one int
		if err := tx.QueryRow(ctx, gate, gcid, tenantID).Scan(&one); err != nil {
			if errors.Is(err, ErrNoRows) {
				return identity.ErrMembershipNotFound
			}
			return fmt.Errorf("pg.MembershipAdmin.RemoveMember gate: %w", err)
		}

		// Last-owner guard (S7-B1 defect D1). The deactivate below has no
		// role filter, so it takes the owner row with everything else. Refuse
		// only when this GCID holds the tenant's last active owner row: the
		// invariant is that no organisation is left unowned, not that an owner
		// row is untouchable.
		owns, liveOwners, err := ownerMirrorGuard(ctx, tx, gcid, tenantID)
		if err != nil {
			return err
		}
		if owns && liveOwners == 1 {
			return identity.ErrLastOwnerProtected
		}

		// Soft-delete: deactivate EVERY active role row (status → inactive).
		const deactivate = `
            UPDATE tenant_memberships
            SET status = 'inactive'::membership_status, updated_at = now()
            WHERE gcid = $1::uuid AND tenant_id = $2::uuid
              AND status = 'active'::membership_status
        `
		if err := tx.Exec(ctx, deactivate, gcid, tenantID); err != nil {
			return fmt.Errorf("pg.MembershipAdmin.RemoveMember: %w", err)
		}
		return nil
	})
}

// validateGcidTenant — moved out so SetRoles + future replace ops share it.
func validateGcidTenant(gcid, tenantID string) error {
	if strings.TrimSpace(gcid) == "" || strings.TrimSpace(tenantID) == "" {
		return errors.New("pg.MembershipAdmin: gcid and tenantID required")
	}
	return nil
}
