// Package exp_rules is the configurable per-source familiar-EXP rules layer
// (ADR-201 §5 / WS4 of the Familiar Holistic Redesign). It is the third
// instance of the one resolver pattern proven by ADR-178's PricePlanResolver
// (mana) and ADR-197's PromptResolver (prompts): a DB-backed, precedence-
// resolved, versioned, RLS-scoped, behaviour-neutral-on-rollout config layer
// that lets a super-admin tune economy values without a code deploy.
//
// ExpRuleResolver resolves (source_code, tenant, plan) → {exp_value, daily_cap,
// eligibility, enabled, source} via a documented precedence ladder:
//
//	resolve(source_code, tenant_id) :=
//	  COALESCE(
//	    tenant_active_plan_rule(source_code),    -- (1) tenant override  → Source=tenant
//	    platform_active_plan_rule(source_code),  -- (2) platform plan    → Source=plan
//	    exp_source_def(source_code)              -- (3) catalogue default → Source=catalogue
//	  )
//
// Behaviour-neutral on rollout: with NO plan rows, Resolve returns the
// exp_source_def catalogue default (ADR-203 §12 seed values), so the EXP economy
// behaves exactly as its defaults until a tenant/platform plan overrides a row.
//
// INVARIANT (ADR-203 L16 — verified-EXP anti-gaming): the EXP source is ALWAYS a
// Chora-verified system event and is NON-CONFIGURABLE. The editor (and this
// resolver) tunes value / cap / eligibility / enabled — it can NEVER add a
// self-declare source. A source_code absent from exp_source_def (the catalogue
// of verified sources) resolves to ErrUnknownSource; overrides can only adjust
// KNOWN verified sources (the exp_rule.source_code FK to exp_source_def enforces
// this at write time, the catalogue floor enforces it at read time).
//
// This file is the PURE domain resolver — it holds no SQL. The precedence query
// lives in the pg adapter behind the ExpRuleStore port (mirrors PricePlanResolver
// / ManaPricePlanStore). Cross-DB queries forbidden — every table lives in
// chora_identity.
package exp_rules

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// ErrUnknownSource is returned when a source_code has no row in exp_source_def
// (absent or deprecated). The EXP source is non-configurable (ADR-203 L16): an
// unknown source is rejected rather than silently awarded zero or minted as a
// new source. The gRPC/HTTP adapter maps it to InvalidArgument.
var ErrUnknownSource = errors.New("exp_rules: unknown source_code")

// IsUnknownSource reports whether err wraps ErrUnknownSource.
func IsUnknownSource(err error) bool { return errors.Is(err, ErrUnknownSource) }

// ResolvedExpRule is the output of EXP-rule resolution — the value + caps +
// eligibility + enabled state the EXP write path (chora_consumption
// familiar_growth_events admission, ADR-203 §6) applies for one occurrence of a
// verified source.
type ResolvedExpRule struct {
	// SourceCode echoes the resolved verified-event source.
	SourceCode string
	// ExpValue is the resolved EXP award (>= 0) for ONE occurrence of the source.
	ExpValue int64
	// DailyCap is the maximum EXP this source may award per calendar day; 0 =
	// uncapped. The anti-farm lever (ADR-203 §12) — the caller (ledger admission)
	// enforces the daily ceiling.
	DailyCap int32
	// Eligibility is an advisory constraint the caller applies — "" = always
	// eligible; a non-empty hint (e.g. a growth_stage / goal-scope) narrows when
	// the award applies. Only plan rules carry one; the catalogue default is "".
	Eligibility string
	// Enabled reports whether the source currently awards EXP. A disabled source
	// resolves SUCCESSFULLY with Enabled=false (the caller skips the award) — it
	// is NOT an error (the §12 "enabled" editor knob).
	Enabled bool
	// Source records which precedence rung resolved the rule:
	// "tenant" | "plan" | "catalogue". Audit / observability.
	Source string
}

// ExpResolveInput is the resolution key. SourceCode is required; TenantID/Plan/
// Context are optional and forward-compatible.
type ExpResolveInput struct {
	// SourceCode is the canonical verified-event source being valued. Required.
	SourceCode string
	// TenantID scopes resolution to a tenant's active override plan.
	// "" ⇒ platform plan + catalogue only (today's tenant-agnostic path).
	TenantID string
	// Plan is a reserved forward-compat selector — the named-plan axis,
	// mirroring the position of ADR-178's Tier sub-axis in PricePlanResolver.
	// The current resolution is single-axis by tenant scope (tenant > platform
	// plan > catalogue), so Plan is advisory passthrough today and is never
	// required to resolve a rule.
	Plan string
	// Context is a small typed forward-compat map (e.g. {"growth_stage":"4"});
	// never required to resolve a rule. Advisory passthrough today.
	Context map[string]string
}

// ExpRuleStore is the adapter port (pg). ResolveExpRule runs the precedence
// ladder (tenant override → platform plan → exp_source_def catalogue) and
// returns the winning rung already chosen by SQL. ErrUnknownSource on a total
// miss (the source is absent from exp_source_def, so no plan rule could exist
// for it either).
type ExpRuleStore interface {
	ResolveExpRule(ctx context.Context, in ExpResolveInput) (ResolvedExpRule, error)
}

// ExpRuleResolver is the pure domain service over an ExpRuleStore. It validates
// the input, delegates precedence to the store, and guards the non-negative
// value/cap invariants. Mirrors PricePlanResolver (ADR-178).
type ExpRuleResolver struct {
	store ExpRuleStore
}

// NewExpRuleResolver wires the resolver to an ExpRuleStore (production: the pg
// adapter implementing the precedence query).
func NewExpRuleResolver(store ExpRuleStore) *ExpRuleResolver {
	return &ExpRuleResolver{store: store}
}

// Resolve runs EXP-rule resolution. Returns ErrUnknownSource for an empty or
// unknown source_code, and a hard error for a (corrupt) negative value/cap. A
// disabled source is a successful resolution (Enabled=false), NOT an error.
func (r *ExpRuleResolver) Resolve(ctx context.Context, in ExpResolveInput) (ResolvedExpRule, error) {
	code := strings.TrimSpace(in.SourceCode)
	if code == "" {
		return ResolvedExpRule{}, fmt.Errorf("%w: empty source_code", ErrUnknownSource)
	}
	if r.store == nil {
		return ResolvedExpRule{}, fmt.Errorf("exp_rules: ExpRuleResolver has no store configured (source_code=%q)", code)
	}
	in.SourceCode = code
	got, err := r.store.ResolveExpRule(ctx, in)
	if err != nil {
		return ResolvedExpRule{}, err // ErrUnknownSource bubbles through
	}
	if got.ExpValue < 0 {
		return ResolvedExpRule{}, fmt.Errorf("exp_rules: negative resolved EXP for %q (%d)", code, got.ExpValue)
	}
	if got.DailyCap < 0 {
		return ResolvedExpRule{}, fmt.Errorf("exp_rules: negative resolved daily_cap for %q (%d)", code, got.DailyCap)
	}
	return got, nil
}
