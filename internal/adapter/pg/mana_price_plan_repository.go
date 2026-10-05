// mana_price_plan_repository.go — pgx-backed implementation of the configurable
// mana price-plan rules layer port (user_mana.PricePlanStore, ADR-178 /
// CHO-1661).
//
// Resolves (action_code, tenant, tier) → {units, refundable, per_item,
// meter_home, source} via the §1.4 precedence ladder in ONE indexed query,
// falling through to the UNCHANGED mana_action_pricing catalogue floor when no
// plan rule matches:
//
//	(1)  tenant override, tier-specific
//	(1b) tenant override, tier-agnostic (NULL tier)
//	(2)  platform default, tier-specific
//	(2b) platform default, tier-agnostic (NULL tier)
//	(3)  mana_action_pricing fallback  (catalogue floor — preserved)
//
// RLS: mana_price_plan + mana_price_rule carry the tenant axis (migration
// 0017). The precedence query runs inside RunInTenantTx so `SET LOCAL
// chora.tenant_id` scopes tenant override rows under PgBouncer transaction-
// pooling; the platform `default` plan is world-readable (policy allows
// scope='platform'), so a tenant always resolves against it as fallback. The
// catalogue floor (mana_action_pricing) has NO RLS (global config), so it is
// read in the same tx without a tenant scope concern.
//
// Cross-DB queries forbidden — all three tables + the catalogue live in
// chora_identity.
package pg

import (
	"context"
	"errors"
	"fmt"
	"strings"

	mana "github.com/apollo-chora/chora-identity/internal/domain/user_mana"
)

// ManaPricePlanStore is the pgx-backed user_mana.PricePlanStore. It wraps a
// TxQuerier (production: *PgxPoolQuerier) so the precedence + catalogue queries
// run in a single tenant-scoped transaction.
type ManaPricePlanStore struct {
	txr TxQuerier
}

// NewManaPricePlanStore wraps a TxQuerier (production: *PgxPoolQuerier).
func NewManaPricePlanStore(txr TxQuerier) *ManaPricePlanStore {
	return &ManaPricePlanStore{txr: txr}
}

// Compile-time check.
var _ mana.PricePlanStore = (*ManaPricePlanStore)(nil)

// resolvePrecedenceSQL implements the §1.4 ladder. Params: $1=action_code,
// $2=tenant_id, $3=tier. The `def` CTE supplies the action semantics flags +
// the tier_aware gate (tier rules are ignored when the action is not
// tier-aware). The rank CASE encodes precedence (lower wins). `pr.tier = $3`
// never matches a NULL-tier row (NULL comparison ⇒ NULL ⇒ not selected), so the
// tier-specific rungs only match real tier rules and NULL rows fall to the
// tier-agnostic rungs.
const resolvePrecedenceSQL = `
WITH def AS (
  SELECT refundable, per_item, meter_home, tier_aware
    FROM mana_action_def
   WHERE action_code = $1 AND deprecated_at IS NULL
),
candidate AS (
  SELECT pr.mana_cost,
         pr.tier,
         CASE WHEN pp.scope = 'tenant' THEN 'tenant_override' ELSE 'plan_default' END AS src,
         (CASE WHEN pp.scope = 'tenant'   AND pr.tier = $3       THEN 1
               WHEN pp.scope = 'tenant'   AND pr.tier IS NULL    THEN 2
               WHEN pp.scope = 'platform' AND pr.tier = $3       THEN 3
               WHEN pp.scope = 'platform' AND pr.tier IS NULL    THEN 4 END) AS rank
    FROM mana_price_rule pr
    JOIN mana_price_plan pp ON pp.plan_id = pr.plan_id AND pp.status = 'active'
   WHERE pr.action_code = $1
     AND ( (SELECT tier_aware FROM def) = true OR pr.tier IS NULL )
     AND ( pp.scope = 'platform' OR pp.tenant_id = NULLIF($2, '')::uuid )
)
SELECT c.mana_cost,
       c.src,
       COALESCE(c.tier, '') AS tier,
       COALESCE((SELECT refundable FROM def), false)      AS refundable,
       COALESCE((SELECT per_item   FROM def), false)      AS per_item,
       COALESCE((SELECT meter_home FROM def), 'gateway')  AS meter_home
  FROM candidate c
 WHERE c.rank IS NOT NULL
 ORDER BY c.rank ASC
 LIMIT 1`

// catalogueFallbackSQL is the UNCHANGED flat lookup (mirrors
// ManaPricingStore.CostForAction) — the bottom-of-precedence floor.
const catalogueFallbackSQL = `
SELECT mana_cost
  FROM mana_action_pricing
 WHERE action_code = $1
   AND deprecated_at IS NULL
   AND effective_from <= now()
 ORDER BY effective_from DESC
 LIMIT 1`

// ResolvePrice runs the precedence ladder + catalogue fallback in one
// tenant-scoped transaction. Returns mana.ErrUnknownActionCode when the code is
// absent from BOTH the active plans and the catalogue.
func (s *ManaPricePlanStore) ResolvePrice(ctx context.Context, in mana.ResolveInput) (mana.Resolved, error) {
	code := strings.TrimSpace(in.ActionCode)
	if code == "" {
		return mana.Resolved{}, fmt.Errorf("%w: empty action_code", mana.ErrUnknownActionCode)
	}
	if s.txr == nil {
		return mana.Resolved{}, errors.New("pg.ManaPricePlanStore: nil TxQuerier")
	}

	var out mana.Resolved
	var resolved bool

	// Empty tenant resolves against platform default + catalogue only — RLS for
	// the tenant axis is a no-op (no tenant rows match scope='platform'). We
	// still open a tenant-scoped tx with the validated tenant id; empty tenant
	// uses the zero-uuid sentinel so SET LOCAL is well-formed and the
	// scope='platform' branch is the only one that can match.
	tenant := strings.TrimSpace(in.TenantID)
	if tenant == "" {
		tenant = zeroUUID
	}

	err := s.txr.RunInTenantTx(ctx, tenant, func(ctx context.Context, tx Tx) error {
		// (1)–(2b) — precedence over active plans.
		row := tx.QueryRow(ctx, resolvePrecedenceSQL, code, in.TenantID, in.Tier)
		var (
			cost      int64
			src       string
			tier      string
			refund    bool
			perItem   bool
			meterHome string
		)
		switch err := row.Scan(&cost, &src, &tier, &refund, &perItem, &meterHome); {
		case err == nil:
			out = mana.Resolved{
				Units: cost, Source: src, Tier: tier,
				Refundable: refund, PerItem: perItem, MeterHome: meterHome,
			}
			resolved = true
			return nil
		case errors.Is(err, ErrNoRows):
			// fall through to catalogue
		default:
			return fmt.Errorf("pg.ManaPricePlanStore.ResolvePrice(%q): precedence: %w", code, err)
		}

		// (3) — catalogue floor (UNCHANGED behaviour; no action-def flags).
		var catCost int64
		switch err := tx.QueryRow(ctx, catalogueFallbackSQL, code).Scan(&catCost); {
		case err == nil:
			out = mana.Resolved{Units: catCost, Source: "catalogue_fallback"}
			resolved = true
			return nil
		case errors.Is(err, ErrNoRows):
			return nil // total miss → ErrUnknownActionCode below
		default:
			return fmt.Errorf("pg.ManaPricePlanStore.ResolvePrice(%q): catalogue: %w", code, err)
		}
	})
	if err != nil {
		return mana.Resolved{}, err
	}
	if !resolved {
		return mana.Resolved{}, fmt.Errorf("%w: %q", mana.ErrUnknownActionCode, code)
	}
	return out, nil
}

// zeroUUID is the all-zero UUID sentinel used to scope a tenant-agnostic
// resolution tx. No tenant plan carries this id, so only scope='platform'
// rows (+ the catalogue) can match.
const zeroUUID = "00000000-0000-0000-0000-000000000000"
