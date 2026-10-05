// price_plan_resolver.go — the configurable mana price-plan rules layer
// (ADR-178 / CHO-1661). Supersedes the flat `action_code → units` Pricer with
// a rules layer resolving (action_code, tenant, tier) → {units, refundable,
// per_item, meter_home, source} via a documented precedence ladder.
//
// Precedence (ADR-178 §1.4 — resolved in the SQL adapter, Appendix A.2):
//
//	resolve(action_code, tenant_id, tier) :=
//	  COALESCE(
//	    tenant_active_plan_rule(action_code, tier),    -- (1)  tenant override
//	    tenant_active_plan_rule(action_code, NULL),    -- (1b) tenant override, tier-agnostic
//	    platform_default_plan_rule(action_code, tier), -- (2)  plan default
//	    platform_default_plan_rule(action_code, NULL), -- (2b) plan default, tier-agnostic
//	    flat_catalogue(action_code)                    -- (3)  mana_action_pricing fallback
//	  )
//
// The legacy flat catalogue (`mana_action_pricing`) is preserved as the
// bottom-of-precedence fallback, so current callers (gateway / creation /
// consumption) are byte-compatible until they opt in to the richer fields.
//
// This file is the PURE domain resolver — it holds no SQL. The precedence query
// lives in the pg adapter behind the PricePlanStore port. The per-item (× N)
// multiply stays caller-side (matches chora-creation today); the resolver
// returns the per-unit cost + the per_item flag.
package user_mana

import (
	"context"
	"fmt"
	"strings"
)

// Resolved is the output of price resolution — the richer replacement for the
// bare int64 cost the legacy Pricer returned.
type Resolved struct {
	// Units is the resolved per-unit cost (BEFORE any per-item multiply).
	Units int64
	// Refundable echoes mana_action_def.refundable — advisory; the caller (the
	// meter home) decides whether to wire debit-then-refund-on-failure. The
	// resolver never issues refunds (ADR-178 §A3).
	Refundable bool
	// PerItem echoes mana_action_def.per_item — when true the caller multiplies
	// Units by the item count (× N batch pricing). See EffectiveTotal.
	PerItem bool
	// MeterHome echoes mana_action_def.meter_home ('gateway'|'creation'|
	// 'consumption') — who is allowed to debit this action (the FU-4 lever).
	MeterHome string
	// Source records which precedence rung resolved the price:
	// 'tenant_override' | 'plan_default' | 'catalogue_fallback'. Audit/obs.
	Source string
	// Tier echoes the resolved tier ('' when tier-agnostic) — the BACKLOG
	// high/low LLM-tier axis (ADR-178 §5).
	Tier string
}

// EffectiveTotal returns the charge for itemCount items. For a per-item action
// it is Units × max(1, itemCount); for an upfront action the count is ignored
// (returns Units). Centralising the multiply in the caller preserves the proven
// chora-creation flow + the DeductMana(units=0) "server resolves per-unit cost;
// caller already knows N" semantics (ADR-178 §2.2).
func (r Resolved) EffectiveTotal(itemCount int64) int64 {
	if !r.PerItem {
		return r.Units
	}
	if itemCount < 1 {
		itemCount = 1
	}
	return r.Units * itemCount
}

// ResolveInput is the resolution key. ActionCode is required; TenantID/Tier/
// Context are optional and forward-compatible.
type ResolveInput struct {
	// ActionCode is the canonical action being priced. Required.
	ActionCode string
	// TenantID scopes the resolution to a tenant's active override plan.
	// "" ⇒ platform default + catalogue only (today's tenant-agnostic path).
	TenantID string
	// Tier is the optional LLM-tier selector ('low'|'high'). "" ⇒ tier-agnostic
	// (today's behaviour for every action). BACKLOG selection axis (ADR-178 §5).
	Tier string
	// Context is a small typed forward-compat map (e.g. {"item_count":"7"});
	// never required to resolve a price. Advisory passthrough today.
	Context map[string]string
}

// PricePlanStore is the adapter port (pg). Its ResolvePrice runs the §1.4
// precedence ladder as ONE indexed query and returns the cheapest-precedence
// row already chosen by SQL, plus the action-def flags. ErrUnknownActionCode
// on a total miss (no plan rule AND no catalogue row).
type PricePlanStore interface {
	ResolvePrice(ctx context.Context, in ResolveInput) (Resolved, error)
}

// PricePlanResolver is the pure domain service over a PricePlanStore. It
// validates the input, delegates precedence to the store, and guards the
// non-negative-cost invariant. It satisfies the legacy Pricer port via the
// CostForAction shim, so the Quoter consumes it unchanged.
type PricePlanResolver struct {
	store PricePlanStore
}

// NewPricePlanResolver wires the resolver to a PricePlanStore (production:
// the pg adapter implementing the §1.4 precedence query).
func NewPricePlanResolver(store PricePlanStore) *PricePlanResolver {
	return &PricePlanResolver{store: store}
}

// Resolve runs price resolution. Returns ErrUnknownActionCode for an empty or
// unpriced code, and a hard error for a (corrupt) negative cost.
func (r *PricePlanResolver) Resolve(ctx context.Context, in ResolveInput) (Resolved, error) {
	code := strings.TrimSpace(in.ActionCode)
	if code == "" {
		return Resolved{}, fmt.Errorf("%w: empty action_code", ErrUnknownActionCode)
	}
	if r.store == nil {
		return Resolved{}, fmt.Errorf("user_mana: PricePlanResolver has no store configured (action_code=%q)", code)
	}
	in.ActionCode = code
	got, err := r.store.ResolvePrice(ctx, in)
	if err != nil {
		return Resolved{}, err // ErrUnknownActionCode bubbles through
	}
	if got.Units < 0 {
		return Resolved{}, fmt.Errorf("user_mana: negative resolved cost for %q (%d)", code, got.Units)
	}
	return got, nil
}

// CostForAction is the backward-compat shim over the legacy Pricer port —
// tenant/tier-agnostic, returns just Units. So PricePlanResolver is a drop-in
// for ManaPricingStore: nothing that depends on the old port breaks (ADR-178
// §2.2). An explicit Units>0 debit still bypasses pricing entirely upstream.
func (r *PricePlanResolver) CostForAction(ctx context.Context, actionCode string) (int64, error) {
	res, err := r.Resolve(ctx, ResolveInput{ActionCode: actionCode})
	if err != nil {
		return 0, err
	}
	return res.Units, nil
}

// Compile-time check: PricePlanResolver is a drop-in Pricer.
var _ Pricer = (*PricePlanResolver)(nil)
