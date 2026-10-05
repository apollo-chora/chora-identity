// pricer.go — the pricing-catalogue resolution port for the WS-1 umbrella
// metering seam (ADR-142 §4).
//
// Background: every LLM call drains one per-GCID mana wallet. The metering
// chokepoint (chora-model-gateway) charges by `action_code` and does NOT know
// the price — it calls ManaService.DeductMana(action_code, units=0). The
// Quoter consults a Pricer to resolve units==0 against the seeded
// mana_action_pricing catalogue (migrations 0002/0009/0010). An explicit
// Units>0 debit (legacy ad-hoc debit sites + tests) bypasses the Pricer.
package user_mana

import (
	"context"
	"errors"
)

// ErrUnknownActionCode is returned by a Pricer when an action_code has no
// active row in the pricing catalogue (absent or deprecated). The gRPC adapter
// maps it to codes.InvalidArgument so a caller learns the code is unpriced
// rather than being silently charged zero.
var ErrUnknownActionCode = errors.New("user_mana: unknown action_code")

// IsUnknownActionCode reports whether err wraps ErrUnknownActionCode.
func IsUnknownActionCode(err error) bool { return errors.Is(err, ErrUnknownActionCode) }

// Pricer resolves the mana cost of an action_code from the pricing catalogue
// (mana_action_pricing). The Quoter consults it ONLY on a catalogue-priced
// debit — DeductMana with Units==0 — so the umbrella metering seam can charge
// by action_code without embedding prices in code (config lives in the table,
// editable via admin tooling per ADR-142). An explicit Units>0 debit bypasses
// the Pricer entirely.
//
// CostForAction returns the active cost (>= 0) for actionCode, or
// ErrUnknownActionCode when no active catalogue row exists. A cost of 0 is a
// valid "free action" (e.g. summon_familiar, daily_dose_deterministic) and is
// NOT an error — the Quoter treats it as a no-op debit (no ledger row).
type Pricer interface {
	CostForAction(ctx context.Context, actionCode string) (int64, error)
}

// PriceResolver is the richer pricing port (ADR-178 / CHO-1661 — the
// configurable price-plan rules layer, FU-4(b) qgen cutover). Unlike
// Pricer.CostForAction (tenant/tier-agnostic, units only) it resolves the full
// Resolved value — units + refundable + per_item + price_source — for a
// (action_code, tenant, tier, context) key, so a units==0 debit:
//
//   - honours TENANT OVERRIDES (the flat Pricer shim dropped tenant_id, so an
//     H+ price-plan override was silently ignored on the metering path); and
//   - returns the metadata the meter home needs to wire refund-on-failure
//     (refundable) or multiply per-item batch pricing (per_item × item_count).
//
// *PricePlanResolver satisfies it via its Resolve method. When a PriceResolver
// is wired (WithPriceResolver) it SUPERSEDES the flat Pricer for the units==0
// path; the Pricer remains the fallback for callers / tests that only wire
// WithPricer.
type PriceResolver interface {
	Resolve(ctx context.Context, in ResolveInput) (Resolved, error)
}
