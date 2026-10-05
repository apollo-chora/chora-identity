// tenant_idp_provider_repository.go — pgx-backed implementation of
// tenant_idp_provider.Repository (Setup Wizard Phase C, CHO-1682).
//
// Schema reference : services/chora-identity/migrations/0018_tenant_idp_providers.up.sql
// Domain port      : services/chora-identity/internal/domain/tenant_idp_provider
//
// RLS discipline   : tenant_idp_providers carries `idp_tenant_isolation`
//
//	keyed on chora.tenant_id. ALL methods on this
//	repository wrap their SQL in RunInTenantTx so the
//	SET LOCAL chora.tenant_id GUC is applied inside the
//	same transaction (PgBouncer transaction-pooling
//	safe). A bare pool query against this table from
//	the chora_identity_app_rw role would silently
//	return 0 rows — this is the canonical defence.
//
// Soft delete      : queries default to `WHERE deleted_at IS NULL`.
//
//	SoftDelete is the only mutator that sets the column.
//
// Idempotent upsert: ON CONFLICT on the partial unique index
//
//	`uq_tenant_idp_providers_tenant_type_active`
//	(tenant_id, provider_type) WHERE deleted_at IS NULL.
//	The domain Service supplies the ID — for net-new rows
//	the supplied UUIDv7 lands; for existing-row upserts
//	the conflict path UPDATEs the row and Postgres returns
//	the existing primary key via RETURNING.
package pg

import (
	"context"
	"errors"
	"fmt"
	"time"

	tip "github.com/apollo-chora/chora-identity/internal/domain/tenant_idp_provider"
)

// TenantIdpProviderRepository is the pgx-backed implementation of
// tenant_idp_provider.Repository.
type TenantIdpProviderRepository struct {
	tx TxQuerier
}

// NewTenantIdpProviderRepository wraps a TxQuerier (production:
// *PgxPoolQuerier).
func NewTenantIdpProviderRepository(tx TxQuerier) *TenantIdpProviderRepository {
	return &TenantIdpProviderRepository{tx: tx}
}

// Compile-time check.
var _ tip.Repository = (*TenantIdpProviderRepository)(nil)

const tenantIdpProviderColumns = `id, tenant_id, provider_type, client_id, client_secret_name,
    discovery_url, singpass_enabled, created_at, updated_at, deleted_at`

// Upsert idempotently writes (or replaces) the active row for
// (tenant_id, provider_type). The ID supplied on `p` is used for net-new
// rows; for existing rows the conflict path UPDATEs in place and the
// caller-visible aggregate is mutated to reflect the persisted ID.
func (r *TenantIdpProviderRepository) Upsert(ctx context.Context, p *tip.TenantIdpProvider) error {
	if p == nil {
		return errors.New("pg.TenantIdpProviderRepository.Upsert: nil aggregate")
	}
	return r.tx.RunInTenantTx(ctx, p.TenantID, func(ctx context.Context, tx Tx) error {
		// nullables — empty strings on the aggregate become NULL in pg so
		// the chk_provider_validity constraint reads them correctly.
		var (
			clientID         any = nullIfEmpty(p.ClientID)
			clientSecretName any = nullIfEmpty(p.ClientSecretName)
			discoveryURL     any = nullIfEmpty(p.DiscoveryURL)
		)

		const sql = `
INSERT INTO tenant_idp_providers
    (id, tenant_id, provider_type, client_id, client_secret_name,
     discovery_url, singpass_enabled, created_at, updated_at)
VALUES
    ($1, $2, $3, $4, $5, $6, $7, $8, $9)
ON CONFLICT (tenant_id, provider_type) WHERE deleted_at IS NULL DO UPDATE
SET
    client_id          = EXCLUDED.client_id,
    client_secret_name = EXCLUDED.client_secret_name,
    discovery_url      = EXCLUDED.discovery_url,
    singpass_enabled   = EXCLUDED.singpass_enabled,
    updated_at         = EXCLUDED.updated_at
RETURNING id, created_at, updated_at`

		row := tx.QueryRow(ctx, sql,
			p.ID, p.TenantID, string(p.ProviderType),
			clientID, clientSecretName, discoveryURL,
			p.SingpassEnabled, p.CreatedAt, p.UpdatedAt,
		)
		var (
			gotID        string
			gotCreatedAt time.Time
			gotUpdatedAt time.Time
		)
		if err := row.Scan(&gotID, &gotCreatedAt, &gotUpdatedAt); err != nil {
			return fmt.Errorf("pg.TenantIdpProviderRepository.Upsert: %w", err)
		}
		// Reflect persisted state back to the caller (matters for the
		// existing-row conflict path where the ID was the previously-stored
		// value, not the freshly-minted UUIDv7).
		p.ID = gotID
		p.CreatedAt = gotCreatedAt
		p.UpdatedAt = gotUpdatedAt
		return nil
	})
}

// Get returns the active row for (tenant_id, provider_type) or
// tip.ErrNotFound when absent / soft-deleted.
func (r *TenantIdpProviderRepository) Get(ctx context.Context, tenantID string, pt tip.ProviderType) (*tip.TenantIdpProvider, error) {
	var out *tip.TenantIdpProvider
	err := r.tx.RunInTenantTx(ctx, tenantID, func(ctx context.Context, tx Tx) error {
		const sql = `
SELECT ` + tenantIdpProviderColumns + `
FROM   tenant_idp_providers
WHERE  tenant_id = $1
  AND  provider_type = $2
  AND  deleted_at IS NULL`
		row := tx.QueryRow(ctx, sql, tenantID, string(pt))
		var p tip.TenantIdpProvider
		var (
			clientID         *string
			clientSecretName *string
			discoveryURL     *string
			ptStr            string
			deletedAt        *time.Time
		)
		if err := row.Scan(
			&p.ID, &p.TenantID, &ptStr, &clientID, &clientSecretName,
			&discoveryURL, &p.SingpassEnabled, &p.CreatedAt, &p.UpdatedAt, &deletedAt,
		); err != nil {
			if errors.Is(err, ErrNoRows) {
				return tip.ErrNotFound
			}
			return fmt.Errorf("pg.TenantIdpProviderRepository.Get: %w", err)
		}
		p.ProviderType = tip.ProviderType(ptStr)
		p.ClientID = derefString(clientID)
		p.ClientSecretName = derefString(clientSecretName)
		p.DiscoveryURL = derefString(discoveryURL)
		p.DeletedAt = deletedAt
		out = &p
		return nil
	})
	if err != nil {
		if errors.Is(err, tip.ErrNotFound) {
			return nil, err
		}
		return nil, err
	}
	return out, nil
}

// ListByTenant returns all ACTIVE rows for the tenant. Order is by
// created_at ascending so callers can render the wizard timeline.
func (r *TenantIdpProviderRepository) ListByTenant(ctx context.Context, tenantID string) ([]tip.TenantIdpProvider, error) {
	var out []tip.TenantIdpProvider
	err := r.tx.RunInTenantTx(ctx, tenantID, func(ctx context.Context, tx Tx) error {
		const sql = `
SELECT ` + tenantIdpProviderColumns + `
FROM   tenant_idp_providers
WHERE  tenant_id = $1
  AND  deleted_at IS NULL
ORDER BY created_at ASC`
		rows, err := tx.Query(ctx, sql, tenantID)
		if err != nil {
			return fmt.Errorf("pg.TenantIdpProviderRepository.ListByTenant: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var p tip.TenantIdpProvider
			var (
				clientID         *string
				clientSecretName *string
				discoveryURL     *string
				ptStr            string
				deletedAt        *time.Time
			)
			if err := rows.Scan(
				&p.ID, &p.TenantID, &ptStr, &clientID, &clientSecretName,
				&discoveryURL, &p.SingpassEnabled, &p.CreatedAt, &p.UpdatedAt, &deletedAt,
			); err != nil {
				return fmt.Errorf("pg.TenantIdpProviderRepository.ListByTenant: scan: %w", err)
			}
			p.ProviderType = tip.ProviderType(ptStr)
			p.ClientID = derefString(clientID)
			p.ClientSecretName = derefString(clientSecretName)
			p.DiscoveryURL = derefString(discoveryURL)
			p.DeletedAt = deletedAt
			out = append(out, p)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// SoftDelete marks the active row for (tenant_id, provider_type) as
// deleted (`deleted_at = now`). Idempotent — calling on an already-
// deleted row is a no-op; the row never returns to active state.
func (r *TenantIdpProviderRepository) SoftDelete(ctx context.Context, tenantID string, pt tip.ProviderType, now time.Time) error {
	return r.tx.RunInTenantTx(ctx, tenantID, func(ctx context.Context, tx Tx) error {
		const sql = `
UPDATE tenant_idp_providers
   SET deleted_at = $3,
       updated_at = $3
 WHERE tenant_id = $1
   AND provider_type = $2
   AND deleted_at IS NULL`
		if err := tx.Exec(ctx, sql, tenantID, string(pt), now); err != nil {
			return fmt.Errorf("pg.TenantIdpProviderRepository.SoftDelete: %w", err)
		}
		return nil
	})
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func derefString(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}
