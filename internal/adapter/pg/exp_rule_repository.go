// exp_rule_repository.go — pgx-backed implementation of the configurable
// familiar-EXP rules layer port (exp_rules.ExpRuleStore, ADR-201 §5 / WS4).
//
// Resolves (source_code, tenant) → {exp_value, daily_cap, eligibility, enabled,
// source} via the precedence ladder in ONE indexed query, falling through to
// the exp_source_def catalogue default when no plan rule matches:
//
//	(1) tenant override (active tenant plan)   → Source=tenant
//	(2) platform plan   (active platform plan) → Source=plan
//	(3) exp_source_def catalogue default       → Source=catalogue
//
// Behaviour-neutral on rollout: with NO plan rows, resolution falls straight to
// exp_source_def (the ADR-203 §12 seed defaults).
//
// INVARIANT (ADR-203 L16): the EXP source is ALWAYS a verified event and is
// non-configurable. The precedence query gates plan rules behind a live
// exp_source_def row (the `src` CTE) and the catalogue floor is exp_source_def
// itself, so a source absent from (or deprecated in) exp_source_def resolves to
// ErrUnknownSource — overrides can only adjust KNOWN verified sources. The
// exp_rule.source_code FK to exp_source_def enforces the same at write time.
//
// RLS: exp_rule_plan + exp_rule carry the tenant axis (migration 0027). The
// precedence query runs inside RunInTenantTx so `SET LOCAL chora.tenant_id`
// scopes tenant-override rows under PgBouncer transaction-pooling; the platform
// plan is world-readable (policy allows scope='platform'), so a tenant always
// resolves against it as fallback. exp_source_def has NO RLS (global catalogue),
// so it is read in the same tx without a tenant-scope concern.
//
// Cross-DB queries forbidden — all three tables live in chora_identity. Mirrors
// ManaPricePlanStore (ADR-178 / CHO-1661).
package pg

import (
	"context"
	"errors"
	"fmt"
	"strings"

	exprules "github.com/apollo-chora/chora-identity/internal/domain/exp_rules"
)

// ExpRuleStore is the pgx-backed exp_rules.ExpRuleStore. It wraps a TxQuerier
// (production: *PgxPoolQuerier) so the precedence + catalogue queries run in a
// single tenant-scoped transaction.
type ExpRuleStore struct {
	txr TxQuerier
}

// NewExpRuleStore wraps a TxQuerier (production: *PgxPoolQuerier).
func NewExpRuleStore(txr TxQuerier) *ExpRuleStore {
	return &ExpRuleStore{txr: txr}
}

// Compile-time check.
var _ exprules.ExpRuleStore = (*ExpRuleStore)(nil)

// resolveExpPrecedenceSQL implements the plan precedence ladder. Params:
// $1=source_code, $2=tenant_id. The `src` CTE anchors resolution on a LIVE
// exp_source_def row (encoding the ADR-203 L16 invariant: only known verified
// sources resolve). The rank CASE encodes precedence (lower wins): a tenant-
// scope plan rule (1) beats the platform-scope plan rule (2). `$2` is
// NULLIF-safe so the placeholder ” / unset tenant GUC reset value yields NULL
// (no tenant row matches) instead of a 22P02 cast error (per migration 0019).
const resolveExpPrecedenceSQL = `
WITH src AS (
  SELECT 1 FROM exp_source_def
   WHERE source_code = $1 AND deprecated_at IS NULL
),
candidate AS (
  SELECT er.exp_value,
         er.daily_cap,
         er.eligibility,
         er.enabled,
         CASE WHEN erp.scope = 'tenant' THEN 'tenant' ELSE 'plan' END AS src,
         (CASE WHEN erp.scope = 'tenant'   THEN 1
               WHEN erp.scope = 'platform' THEN 2 END) AS rank
    FROM exp_rule er
    JOIN exp_rule_plan erp ON erp.plan_id = er.plan_id AND erp.status = 'active'
   WHERE er.source_code = $1
     AND EXISTS (SELECT 1 FROM src)
     AND ( erp.scope = 'platform' OR erp.tenant_id = NULLIF($2, '')::uuid )
)
SELECT c.exp_value, c.daily_cap, c.eligibility, c.enabled, c.src
  FROM candidate c
 WHERE c.rank IS NOT NULL
 ORDER BY c.rank ASC
 LIMIT 1`

// expCatalogueFallbackSQL is the exp_source_def catalogue floor — the
// bottom-of-precedence default (Source=catalogue, eligibility always-empty).
const expCatalogueFallbackSQL = `
SELECT default_exp_value, default_daily_cap, enabled
  FROM exp_source_def
 WHERE source_code = $1
   AND deprecated_at IS NULL
 LIMIT 1`

// ResolveExpRule runs the precedence ladder + catalogue fallback in one
// tenant-scoped transaction. Returns exprules.ErrUnknownSource when the source
// is absent from exp_source_def (so no plan rule could exist for it either).
func (s *ExpRuleStore) ResolveExpRule(ctx context.Context, in exprules.ExpResolveInput) (exprules.ResolvedExpRule, error) {
	code := strings.TrimSpace(in.SourceCode)
	if code == "" {
		return exprules.ResolvedExpRule{}, fmt.Errorf("%w: empty source_code", exprules.ErrUnknownSource)
	}
	if s.txr == nil {
		return exprules.ResolvedExpRule{}, errors.New("pg.ExpRuleStore: nil TxQuerier")
	}

	var out exprules.ResolvedExpRule
	var resolved bool

	// Empty tenant resolves against the platform plan + catalogue only — RLS for
	// the tenant axis is a no-op (no tenant rows match scope='platform'). We
	// still open a tenant-scoped tx with the zero-uuid sentinel so SET LOCAL is
	// well-formed and only scope='platform' rows can match. The query still
	// receives the original (possibly empty) tenant id as $2 (NULLIF-guarded).
	tenant := strings.TrimSpace(in.TenantID)
	if tenant == "" {
		tenant = zeroUUID
	}

	err := s.txr.RunInTenantTx(ctx, tenant, func(ctx context.Context, tx Tx) error {
		// (1)–(2) — precedence over active plans (gated on a live catalogue source).
		row := tx.QueryRow(ctx, resolveExpPrecedenceSQL, code, in.TenantID)
		var (
			val      int64
			dailyCap int32
			elig     string
			enabled  bool
			source   string
		)
		switch err := row.Scan(&val, &dailyCap, &elig, &enabled, &source); {
		case err == nil:
			out = exprules.ResolvedExpRule{
				SourceCode: code, ExpValue: val, DailyCap: dailyCap,
				Eligibility: elig, Enabled: enabled, Source: source,
			}
			resolved = true
			return nil
		case errors.Is(err, ErrNoRows):
			// fall through to catalogue
		default:
			return fmt.Errorf("pg.ExpRuleStore.ResolveExpRule(%q): precedence: %w", code, err)
		}

		// (3) — exp_source_def catalogue floor (eligibility always-empty default).
		var (
			catVal     int64
			catCap     int32
			catEnabled bool
		)
		switch err := tx.QueryRow(ctx, expCatalogueFallbackSQL, code).Scan(&catVal, &catCap, &catEnabled); {
		case err == nil:
			out = exprules.ResolvedExpRule{
				SourceCode: code, ExpValue: catVal, DailyCap: catCap,
				Eligibility: "", Enabled: catEnabled, Source: "catalogue",
			}
			resolved = true
			return nil
		case errors.Is(err, ErrNoRows):
			return nil // total miss → ErrUnknownSource below
		default:
			return fmt.Errorf("pg.ExpRuleStore.ResolveExpRule(%q): catalogue: %w", code, err)
		}
	})
	if err != nil {
		return exprules.ResolvedExpRule{}, err
	}
	if !resolved {
		return exprules.ResolvedExpRule{}, fmt.Errorf("%w: %q", exprules.ErrUnknownSource, code)
	}
	return out, nil
}
