// tenant_member_search.go — pgx-backed implementation of
// identity.TenantMemberSearchRepo (operationId `searchTenantMembers`,
// contract `chora-contracts/openapi/identity-admin.yaml`).
//
// SQL contract (B6.1 — assessment cohort picker, 2026-05-16):
//
//	SELECT u.gcid, u.email, u.display_name, tm.role::text, u.updated_at
//	FROM tenant_memberships tm
//	JOIN users u USING (gcid)
//	LEFT JOIN closure_sagas cs
//	    ON cs.gcid = u.gcid
//	    AND cs.state IN ('suspended','pseudonymized','cold_archived','crypto_shredded')
//	    AND cs.cancelled_at IS NULL
//	WHERE tm.status = 'active'
//	  AND u.deleted_at IS NULL
//	  AND cs.saga_id IS NULL              -- excludes accounts in non-active closure states
//	  AND ($1::text IS NULL OR
//	       LOWER(u.email) LIKE $1 OR
//	       LOWER(u.display_name) LIKE $1)
//	  AND ($2::text IS NULL OR tm.role::text = $2)
//	ORDER BY u.updated_at DESC NULLS LAST, u.display_name ASC
//	LIMIT $3 OFFSET $4
//
// RLS contract: tenant_memberships carries the `tenant_isolation` RLS policy
// (migration 0001_initial.sql); the wrapping RunInTenantTx applies
// SET LOCAL chora.tenant_id BEFORE this SELECT so only the caller's tenant's
// rows surface. closure_sagas + course_role_assignments are also RLS-scoped
// on the same tenant_id GUC so the LEFT JOIN's filter still scopes correctly.
//
// Limit-plus-one pattern: the adapter requests PageSize+1 rows so it can
// detect "has more" without an extra COUNT query (the contract `total` field
// is intentionally omitted for very-large-tenant performance). When the
// query returns PageSize+1 rows the (last) row is trimmed and HasMore=true;
// NextOffset = caller.Offset + PageSize so the next page advances correctly.
//
// Roles array: post-CHO-1817 (migration 0022), tenant_memberships keys on
// (gcid, tenant_id, role) so a single (gcid, tenant) pair may carry multiple
// active role rows. The SELECT aggregates them per gcid via array_agg into a
// single TenantMemberSummary so the roster never emits duplicate rows for a
// multi-role member.
package pg

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/apollo-chora/chora-identity/internal/domain/identity"
)

// TenantMemberSearchRepository is the pgx-backed implementation of
// identity.TenantMemberSearchRepo.
type TenantMemberSearchRepository struct {
	tx TxQuerier
}

// NewTenantMemberSearchRepository wraps a TxQuerier. *PgxPoolQuerier satisfies
// TxQuerier — that's the production wiring (every SELECT runs inside a
// SET LOCAL chora.tenant_id transaction).
func NewTenantMemberSearchRepository(tx TxQuerier) *TenantMemberSearchRepository {
	return &TenantMemberSearchRepository{tx: tx}
}

// canonical column list for the SELECT — comment-locked to the test's expected
// shape so refactors fail loudly. The role column is an aggregated text[]
// (sorted, distinct) so multi-role memberships collapse to one roster row.
const tenantMemberSearchColumns = `u.gcid, u.email, u.display_name, array_agg(DISTINCT tm.role::text ORDER BY tm.role::text) AS roles, u.updated_at`

// Search implements identity.TenantMemberSearchRepo.
//
// Failure modes:
//   - Empty TenantID                  → error (defence in depth; the handler
//     already validates, but the adapter is
//     an independent boundary).
//   - PageSize == 0                   → defaults to 20 (mirrors handler default).
//   - RunInTenantTx error             → wrapped + returned.
//   - SQL error / scan error          → wrapped + returned.
func (r *TenantMemberSearchRepository) Search(ctx context.Context, q identity.TenantMemberSearchQuery) (identity.TenantMemberSearchResult, error) {
	if strings.TrimSpace(q.TenantID) == "" {
		return identity.TenantMemberSearchResult{}, errors.New("pg.TenantMemberSearchRepository: tenant_id required")
	}
	pageSize := q.PageSize
	if pageSize <= 0 {
		pageSize = 20
	}

	// LIKE pattern: `nil` arg when q is empty so the SQL `$1 IS NULL` branch
	// short-circuits to "return all" (RLS-scoped). When non-empty, wrap in
	// %...% and lowercase for the case-insensitive LIKE.
	var likeArg any // string OR nil
	if strings.TrimSpace(q.Q) != "" {
		like := "%" + strings.ToLower(strings.TrimSpace(q.Q)) + "%"
		likeArg = like
	}

	var roleArg any // string OR nil
	if strings.TrimSpace(q.Role) != "" {
		roleArg = strings.ToLower(strings.TrimSpace(q.Role))
	}

	// The role-filter ($2) is applied to the unaggregated row before GROUP BY
	// so the picker still narrows to "members who hold THIS role" — the
	// returned roles[] for those members still aggregates ALL their active
	// roles (the filter is a membership predicate, not an output projection).
	const sql = `
        SELECT ` + tenantMemberSearchColumns + `
        FROM tenant_memberships tm
        JOIN users u USING (gcid)
        LEFT JOIN closure_sagas cs
            ON cs.gcid = u.gcid
            AND cs.state IN ('suspended','pseudonymized','cold_archived','crypto_shredded')
            AND cs.cancelled_at IS NULL
        WHERE tm.status = 'active'
          AND u.deleted_at IS NULL
          AND cs.saga_id IS NULL
          AND ($1::text IS NULL OR
               LOWER(u.email) LIKE $1 OR
               LOWER(u.display_name) LIKE $1)
          AND ($2::text IS NULL OR EXISTS (
              SELECT 1 FROM tenant_memberships tm2
              WHERE tm2.gcid = u.gcid AND tm2.tenant_id = tm.tenant_id
                AND tm2.role::text = $2
                AND tm2.status = 'active'
          ))
        GROUP BY u.gcid, u.email, u.display_name, u.updated_at
        ORDER BY u.updated_at DESC NULLS LAST, u.display_name ASC
        LIMIT $3 OFFSET $4
    `

	// LIMIT pageSize+1 for has-more detection; this is the canonical pattern
	// across Chora repos (chora-creation searchQuestions, chora-consumption
	// daily-dose roster, etc.).
	limit := pageSize + 1

	items := make([]identity.TenantMemberSummary, 0, limit)
	err := r.tx.RunInTenantTx(ctx, q.TenantID, func(ctx context.Context, tx Tx) error {
		rows, err := tx.Query(ctx, sql, likeArg, roleArg, limit, q.Offset)
		if err != nil {
			return fmt.Errorf("pg.TenantMemberSearchRepository.Search: query: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var (
				gcid        string
				email       *string
				displayName *string
				rolesLower  []string
				updatedAt   *time.Time
			)
			if err := rows.Scan(&gcid, &email, &displayName, &rolesLower, &updatedAt); err != nil {
				return fmt.Errorf("pg.TenantMemberSearchRepository.Search: scan: %w", err)
			}
			rolesUpper := make([]string, 0, len(rolesLower))
			for _, r := range rolesLower {
				rolesUpper = append(rolesUpper, strings.ToUpper(r))
			}
			summary := identity.TenantMemberSummary{
				GCID:         gcid,
				Email:        email,
				DisplayName:  displayName,
				Roles:        rolesUpper,
				LastActiveAt: updatedAt, // proxy via users.updated_at until denormalised
			}
			items = append(items, summary)
		}
		if err := rows.Err(); err != nil {
			return fmt.Errorf("pg.TenantMemberSearchRepository.Search: rows.Err: %w", err)
		}
		return nil
	})
	if err != nil {
		return identity.TenantMemberSearchResult{}, err
	}

	// Trim the +1 sentinel + signal HasMore. NextOffset advances by the
	// requested page size (the FE base64-encodes it into next_page_token).
	hasMore := len(items) > pageSize
	if hasMore {
		items = items[:pageSize]
	}
	nextOffset := 0
	if hasMore {
		nextOffset = q.Offset + pageSize
	}

	return identity.TenantMemberSearchResult{
		Items:      items,
		HasMore:    hasMore,
		NextOffset: nextOffset,
	}, nil
}

// Compile-time check.
var _ identity.TenantMemberSearchRepo = (*TenantMemberSearchRepository)(nil)
