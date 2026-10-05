// pending_invite_repository.go — pgx-backed pending_invites store (WS3 /
// CHO-1873, ADR-194 D2). Admin CRUD is tenant-scoped (RunInTenantTx); the
// cross-tenant email match goes through the SECURITY DEFINER function (which
// ignores RLS), wrapped in a placeholder tx scope.
package pg

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/apollo-chora/chora-identity/internal/domain/identity"
)

// crossTenantMatcherScope is the placeholder tenant the SECURITY DEFINER
// matcher runs under. The function runs as its owner with `row_security = off`,
// so it returns invites across ALL tenants regardless of the chora.tenant_id
// GUC — the scope is required only by the RunInTenantTx surface, never honoured
// by the function. chora-master always exists (ADR-182 D1), so it is a safe,
// always-valid placeholder UUID.
const crossTenantMatcherScope = "00000000-0000-7000-8000-000000000001"

// PendingInviteRepository implements the pending-invite persistence ports.
type PendingInviteRepository struct {
	tx TxQuerier
}

// NewPendingInviteRepository wraps a TxQuerier. Panics on nil so wiring bugs
// fail loud at boot.
func NewPendingInviteRepository(tx TxQuerier) *PendingInviteRepository {
	if tx == nil {
		panic("pg.NewPendingInviteRepository: nil TxQuerier")
	}
	return &PendingInviteRepository{tx: tx}
}

// Insert persists a fresh pending invite (RunInTenantTx). A partial-unique
// violation (a live pending invite already exists for the tenant+email) maps to
// identity.ErrPendingInviteExists.
func (r *PendingInviteRepository) Insert(ctx context.Context, pi *identity.PendingInvite) error {
	if pi == nil {
		return errors.New("pg.PendingInvite.Insert: nil invite")
	}
	return r.tx.RunInTenantTx(ctx, pi.TenantID, func(ctx context.Context, tx Tx) error {
		const q = `
            INSERT INTO pending_invites
                (invite_id, tenant_id, email, roles, invited_by_gcid, token, status, expires_at, created_at, updated_at)
            VALUES ($1::uuid, $2::uuid, $3, $4::text[], $5::uuid, $6::uuid, $7::pending_invite_status, $8, $9, $10)
        `
		if err := tx.Exec(ctx, q, pi.InviteID, pi.TenantID, pi.Email, pi.RoleStrings(),
			pi.InvitedByGcid, pi.Token, string(pi.Status), pi.ExpiresAt, pi.CreatedAt, pi.UpdatedAt); err != nil {
			if isUniqueViolation(err) {
				return identity.ErrPendingInviteExists
			}
			return fmt.Errorf("pg.PendingInvite.Insert: %w", err)
		}
		return nil
	})
}

// ListByTenant returns the LIVE (pending) invites for a tenant (RunInTenantTx),
// most-recent first.
func (r *PendingInviteRepository) ListByTenant(ctx context.Context, tenantID string) ([]identity.PendingInvite, error) {
	var out []identity.PendingInvite
	err := r.tx.RunInTenantTx(ctx, tenantID, func(ctx context.Context, tx Tx) error {
		const q = `
            SELECT invite_id, email, roles, invited_by_gcid, token, status,
                   expires_at, accepted_at, accepted_gcid, created_at, updated_at
            FROM pending_invites
            WHERE tenant_id = $1::uuid AND status = 'pending'::pending_invite_status
            ORDER BY created_at DESC
        `
		rows, err := tx.Query(ctx, q, tenantID)
		if err != nil {
			return fmt.Errorf("pg.PendingInvite.ListByTenant: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var (
				pi           identity.PendingInvite
				roles        []string
				status       string
				acceptedAt   *time.Time
				acceptedGcid *string
			)
			if err := rows.Scan(&pi.InviteID, &pi.Email, &roles, &pi.InvitedByGcid, &pi.Token,
				&status, &pi.ExpiresAt, &acceptedAt, &acceptedGcid, &pi.CreatedAt, &pi.UpdatedAt); err != nil {
				return fmt.Errorf("pg.PendingInvite.ListByTenant scan: %w", err)
			}
			pi.TenantID = tenantID
			pi.Status = identity.PendingInviteStatus(status)
			pi.Roles = toDomainRoles(roles)
			pi.AcceptedAt = acceptedAt
			if acceptedGcid != nil {
				pi.AcceptedGcid = *acceptedGcid
			}
			out = append(out, pi)
		}
		return rows.Err()
	})
	return out, err
}

// Revoke soft-cancels a pending invite (RunInTenantTx). A non-pending /
// missing / cross-tenant invite maps to identity.ErrPendingInviteNotFound.
func (r *PendingInviteRepository) Revoke(ctx context.Context, tenantID, inviteID string) error {
	return r.tx.RunInTenantTx(ctx, tenantID, func(ctx context.Context, tx Tx) error {
		const q = `
            UPDATE pending_invites
            SET status = 'revoked'::pending_invite_status, updated_at = now()
            WHERE invite_id = $1::uuid AND tenant_id = $2::uuid AND status = 'pending'::pending_invite_status
            RETURNING invite_id
        `
		var id string
		if err := tx.QueryRow(ctx, q, inviteID, tenantID).Scan(&id); err != nil {
			if errors.Is(err, ErrNoRows) {
				return identity.ErrPendingInviteNotFound
			}
			return fmt.Errorf("pg.PendingInvite.Revoke: %w", err)
		}
		return nil
	})
}

// MatchByEmail returns the LIVE pending invites for an email across ALL tenants
// via the SECURITY DEFINER matcher (resolve-time cold-invite apply).
func (r *PendingInviteRepository) MatchByEmail(ctx context.Context, email string) ([]identity.PendingInviteMatch, error) {
	var out []identity.PendingInviteMatch
	err := r.tx.RunInTenantTx(ctx, crossTenantMatcherScope, func(ctx context.Context, tx Tx) error {
		const q = `SELECT invite_id, tenant_id, roles, expires_at FROM match_pending_invites_by_email($1)`
		rows, err := tx.Query(ctx, q, identity.NormalizeEmail(email))
		if err != nil {
			return fmt.Errorf("pg.PendingInvite.MatchByEmail: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var m identity.PendingInviteMatch
			if err := rows.Scan(&m.InviteID, &m.TenantID, &m.Roles, &m.ExpiresAt); err != nil {
				return fmt.Errorf("pg.PendingInvite.MatchByEmail scan: %w", err)
			}
			out = append(out, m)
		}
		return rows.Err()
	})
	return out, err
}

// MarkAccepted transitions a pending invite to accepted (RunInTenantTx),
// stamping the accepting gcid. Idempotent: a no-longer-pending invite (already
// accepted / gone) returns nil so a resolve retry is byte-safe.
func (r *PendingInviteRepository) MarkAccepted(ctx context.Context, tenantID, inviteID, gcid string) error {
	return r.tx.RunInTenantTx(ctx, tenantID, func(ctx context.Context, tx Tx) error {
		const q = `
            UPDATE pending_invites
            SET status = 'accepted'::pending_invite_status, accepted_gcid = $3::uuid,
                accepted_at = now(), updated_at = now()
            WHERE invite_id = $1::uuid AND tenant_id = $2::uuid AND status = 'pending'::pending_invite_status
            RETURNING invite_id
        `
		var id string
		if err := tx.QueryRow(ctx, q, inviteID, tenantID, gcid).Scan(&id); err != nil {
			if errors.Is(err, ErrNoRows) {
				return nil // idempotent — already accepted or revoked/expired
			}
			return fmt.Errorf("pg.PendingInvite.MarkAccepted: %w", err)
		}
		return nil
	})
}

// isUniqueViolation reports whether err is a Postgres unique-violation (23505).
// pgx wraps pgconn.PgError whose Error() string carries "SQLSTATE 23505".
func isUniqueViolation(err error) bool {
	return err != nil && strings.Contains(err.Error(), "23505")
}

func toDomainRoles(raw []string) []identity.Role {
	out := make([]identity.Role, 0, len(raw))
	for _, s := range raw {
		out = append(out, identity.Role(s))
	}
	return out
}
