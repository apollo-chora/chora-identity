// mana_pricing_repository.go — pgx-backed implementation of user_mana.Pricer
// (WS-1 umbrella metering, ADR-142 §4).
//
// Resolves an action_code to its active catalogue cost from mana_action_pricing
// (seeded by migrations 0002/0009/0010). The Quoter consults this only on a
// catalogue-priced debit (DeductMana with Units==0 — the chora-model-gateway
// metering seam); explicit Units>0 debits never reach here.
//
// RLS axis: NONE. mana_action_pricing is global config (NOT tenant/user-scoped
// — migrations 0002/0003 add no policy for it), so a plain pooled query is
// correct. Unlike the user_mana wallet repos there is no RunInUserTx wrapping.
package pg

import (
	"context"
	"errors"
	"fmt"
	"strings"

	mana "github.com/apollo-chora/chora-identity/internal/domain/user_mana"
)

// rowQuerier is the minimal non-transactional single-row query surface the
// pricing lookup needs. *PgxPoolQuerier satisfies it.
type rowQuerier interface {
	QueryRow(ctx context.Context, sql string, args ...any) Row
}

// ManaPricingStore is the pgx-backed user_mana.Pricer.
type ManaPricingStore struct {
	q rowQuerier
}

// NewManaPricingStore wraps a rowQuerier (production: *PgxPoolQuerier).
func NewManaPricingStore(q rowQuerier) *ManaPricingStore {
	return &ManaPricingStore{q: q}
}

// Compile-time check.
var _ mana.Pricer = (*ManaPricingStore)(nil)

// CostForAction returns the active mana cost for actionCode, or
// mana.ErrUnknownActionCode when no active catalogue row exists.
//
// "Active" = deprecated_at IS NULL AND effective_from <= now(); the most
// recent effective_from wins, supporting priced rollouts per the table's
// (action_code, effective_from) PK. A returned cost of 0 is a valid free
// action (e.g. summon_familiar), not an error.
func (s *ManaPricingStore) CostForAction(ctx context.Context, actionCode string) (int64, error) {
	code := strings.TrimSpace(actionCode)
	if code == "" {
		return 0, fmt.Errorf("%w: empty action_code", mana.ErrUnknownActionCode)
	}
	var cost int64
	err := s.q.QueryRow(ctx, `
		SELECT mana_cost
		  FROM mana_action_pricing
		 WHERE action_code = $1
		   AND deprecated_at IS NULL
		   AND effective_from <= now()
		 ORDER BY effective_from DESC
		 LIMIT 1`, code).Scan(&cost)
	if err != nil {
		if errors.Is(err, ErrNoRows) {
			return 0, fmt.Errorf("%w: %q", mana.ErrUnknownActionCode, code)
		}
		return 0, fmt.Errorf("pg.ManaPricingStore.CostForAction(%q): %w", code, err)
	}
	return cost, nil
}
