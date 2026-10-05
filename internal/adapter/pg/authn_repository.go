// authn_repository.go — pgx-backed repository for the local username/password
// authentication domain (authn.CredentialsRepository + authn.MembershipRepository).
//
// Schema:
//
//	local_credentials (gcid PK, username, username_norm UNIQUE, password_hash)
//	  — migration 0042; identity-scoped, no RLS (like `users`).
//
//	identity_active_memberships_for_gcid(uuid)
//	  — migration 0042 SECURITY DEFINER helper; returns the GCID's ACTIVE
//	    tenant_memberships rows across tenants. Required because
//	    tenant_memberships carries the tenant_isolation RLS policy and the
//	    runtime role is NOBYPASSRLS, so a plain cross-tenant SELECT returns
//	    nothing at login time.
package pg

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/apollo-chora/chora-identity/internal/domain/authn"
)

// AuthnRepository satisfies authn.CredentialsRepository and
// authn.MembershipRepository.
type AuthnRepository struct {
	q Querier
}

// NewAuthnRepository wraps a Querier (production: *PgxPoolQuerier). Panics on
// nil so wiring bugs fail loud at boot.
func NewAuthnRepository(q Querier) *AuthnRepository {
	if q == nil {
		panic("pg.NewAuthnRepository: nil Querier")
	}
	return &AuthnRepository{q: q}
}

// GetByUsernameNorm implements authn.CredentialsRepository.
func (r *AuthnRepository) GetByUsernameNorm(ctx context.Context, usernameNorm string) (*authn.Credentials, error) {
	const query = `
        SELECT gcid::text, username, username_norm, password_hash, created_at, updated_at
        FROM   local_credentials
        WHERE  username_norm = $1`
	var c authn.Credentials
	err := r.q.QueryRow(ctx, query, usernameNorm).Scan(
		&c.Gcid, &c.Username, &c.UsernameNorm, &c.PasswordHash, &c.CreatedAt, &c.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, ErrNoRows) {
			return nil, authn.ErrCredentialsNotFound
		}
		return nil, fmt.Errorf("pg.AuthnRepository.GetByUsernameNorm: %w", err)
	}
	return &c, nil
}

// Upsert implements authn.CredentialsRepository. Keyed on gcid; the unique
// username_norm constraint is the global uniqueness guard.
func (r *AuthnRepository) Upsert(ctx context.Context, c *authn.Credentials) error {
	if c == nil {
		return errors.New("pg.AuthnRepository.Upsert: nil credentials")
	}
	const query = `
        INSERT INTO local_credentials (gcid, username, username_norm, password_hash)
        VALUES ($1, $2, $3, $4)
        ON CONFLICT (gcid) DO UPDATE
        SET username      = EXCLUDED.username,
            username_norm = EXCLUDED.username_norm,
            password_hash = EXCLUDED.password_hash,
            updated_at    = now()`
	if err := r.q.Exec(ctx, query, c.Gcid, c.Username, c.UsernameNorm, c.PasswordHash); err != nil {
		return fmt.Errorf("pg.AuthnRepository.Upsert: %w", err)
	}
	return nil
}

// ListActiveByGCID implements authn.MembershipRepository via the SECURITY
// DEFINER helper, aggregated into a single JSONB row so the read fits the
// minimal Querier surface.
func (r *AuthnRepository) ListActiveByGCID(ctx context.Context, gcid string) ([]authn.Membership, error) {
	const query = `
        SELECT coalesce(
            jsonb_agg(
                jsonb_build_object(
                    'tenant_id', tenant_id,
                    'role',      role,
                    'created_at', created_at
                )
                ORDER BY created_at, tenant_id, role
            ),
            '[]'::jsonb
        )
        FROM identity_active_memberships_for_gcid($1::uuid)`
	var raw []byte
	if err := r.q.QueryRow(ctx, query, gcid).Scan(&raw); err != nil {
		return nil, fmt.Errorf("pg.AuthnRepository.ListActiveByGCID: %w", err)
	}
	var rows []struct {
		TenantID  string    `json:"tenant_id"`
		Role      string    `json:"role"`
		CreatedAt time.Time `json:"created_at"`
	}
	if err := json.Unmarshal(raw, &rows); err != nil {
		return nil, fmt.Errorf("pg.AuthnRepository.ListActiveByGCID: decode: %w", err)
	}
	out := make([]authn.Membership, 0, len(rows))
	for _, row := range rows {
		out = append(out, authn.Membership{
			TenantID:  row.TenantID,
			Role:      row.Role,
			CreatedAt: row.CreatedAt,
		})
	}
	return out, nil
}

// compile-time: the repo satisfies both authn ports.
var (
	_ authn.CredentialsRepository = (*AuthnRepository)(nil)
	_ authn.MembershipRepository  = (*AuthnRepository)(nil)
)
