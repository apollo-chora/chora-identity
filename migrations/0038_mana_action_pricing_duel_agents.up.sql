-- =============================================================================
-- chora-identity : 0038_mana_action_pricing_duel_agents.up.sql
--
-- ADR             : ADR-177 (gateway is the SOLE meter)
--                   ADR-169 (GKE web-mode ADK agents)
--                   ADR-231 (GroundedSearch — single controlled web egress)
-- Domain          : Identity (supporting)  /  Database : chora_identity
-- Date            : 2026-07-19
--
-- Purpose:
--   Register the mana pricing for the two new duel agent crews:
--
--     profile_conjurer           -> 5   cheap extraction (bio→tags+proficiency)
--     duel_atom_smith            -> 20  MCQ selection/generation (authoring band)
--     duel_atom_smith_web_research -> 50 grounded web egress (mirrors weakness_analysis)
--
--   All three are NON-refundable (the agents run synchronously inside the
--   caller's request; a failure propagates as an error, not a refund —
--   the fail-loud contract).
--
--   The duel_atom_smith_web_research row is REQUIRED for the web_research
--   tool to function: without it the GroundedSearch RPC rejects with
--   "un-priced egress is not permitted" and the tool degrades to
--   agent-knowledge-only. The row is what makes web research live.
--
--   Registered in all THREE layers (same shape as 0028):
--     1. mana_action_pricing  — flat catalogue floor
--     2. mana_action_def      — action registry (refundable / per_item / meter_home)
--     3. mana_price_rule      — platform `default` plan rule
--
--   Purely ADDITIVE + idempotent + changes NO existing action_code or price
--   (every statement is INSERT ... ON CONFLICT DO NOTHING). HARD RULE:
--   cross-database queries forbidden; all objects are local to chora_identity.
--   Do NOT apply manually — migrations auto-apply at deploy.
--
--   NOTE: category + meter_home use 'consumption' — the CHECK constraints on
--   mana_action_def allow only (authoring/familiar/consumption/grading/free)
--   for category and (gateway/creation/consumption) for meter_home. 'sharing'
--   is NOT a valid enum value in either column. The debit site is
--   chora-sharing's processMatch / profile conjurer generate, but the meter_home
--   enum predates the sharing domain — 'consumption' is the closest fit
--   (learner-facing AI consumption during duels).
-- =============================================================================

BEGIN;

-- 1. Flat catalogue floor (mana_action_pricing) — PK (action_code, effective_from).
INSERT INTO mana_action_pricing (action_code, mana_cost, description) VALUES
    ('profile_conjurer', 5,
        'Duel agent: profile conjurer extraction (bio→tags+proficiency). CHEAP tier bounded-label task. Non-refundable (synchronous fail-loud). Tenant-overridable via the price-plan layer.'),
    ('duel_atom_smith', 20,
        'Duel agent: MCQ atom selection + generation for duel rounds. Authoring band (mirrors study_aid_generate). Non-refundable (synchronous fail-loud). Tenant-overridable via the price-plan layer.'),
    ('duel_atom_smith_web_research', 50,
        'Duel agent: grounded web egress via GroundedSearch RPC (ADR-231). REQUIRED — without this row the web_research tool degrades to agent-knowledge-only. Non-refundable. Tenant-overridable via the price-plan layer.')
ON CONFLICT (action_code, effective_from) DO NOTHING;

-- 2. Action registry (mana_action_def) — refundable FALSE (synchronous fail-loud;
--    the caller's processMatch restores searchers to the pool on error, not a
--    refund), per_item FALSE (one debit per agent call).
--    category + meter_home = 'consumption' (valid enum values — 'sharing' is
--    not in either CHECK constraint).
INSERT INTO mana_action_def (action_code, display_name, category, refundable, per_item, meter_home, tier_aware) VALUES
    ('profile_conjurer',              'Duel: Profile Conjurer',       'consumption', FALSE, FALSE, 'consumption', FALSE),
    ('duel_atom_smith',              'Duel: Atom Smith',             'consumption', FALSE, FALSE, 'consumption', FALSE),
    ('duel_atom_smith_web_research', 'Duel: Atom Smith Web Research','consumption', FALSE, FALSE, 'consumption', FALSE)
ON CONFLICT (action_code) DO NOTHING;

-- 3. Platform `default` plan rule (mana_price_rule), NULL tier. The catalogue-
--    fallback resolution path carries no def flags, so a platform default rule is
--    what makes resolution return the def flags for these codes — the same
--    end-state migration 0017 back-filled for the 0009 codes. A tenant override
--    (a tenant-scoped active plan rule) wins over this default.
INSERT INTO mana_price_rule (plan_id, action_code, tier, mana_cost, note)
SELECT dp.plan_id, r.action_code, NULL, r.mana_cost, r.note
  FROM (
      SELECT plan_id FROM mana_price_plan
       WHERE plan_code = 'default' AND scope = 'platform' AND status = 'active'
       LIMIT 1
  ) dp
  CROSS JOIN (
      SELECT 'profile_conjurer' AS action_code, 5 AS mana_cost,
             'Duel profile conjurer extraction (bio→tags+proficiency)' AS note
      UNION ALL
      SELECT 'duel_atom_smith' AS action_code, 20 AS mana_cost,
             'Duel atom smith MCQ selection + generation' AS note
      UNION ALL
      SELECT 'duel_atom_smith_web_research' AS action_code, 50 AS mana_cost,
             'Duel atom smith grounded web egress (GroundedSearch RPC)' AS note
  ) r
ON CONFLICT (plan_id, action_code, tier) DO NOTHING;

COMMIT;

-- VERIFICATION (run after apply):
--   SELECT action_code, mana_cost FROM mana_action_pricing
--    WHERE action_code IN ('profile_conjurer','duel_atom_smith','duel_atom_smith_web_research')
--      AND deprecated_at IS NULL ORDER BY action_code;
--   -- => duel_atom_smith | 20 ; duel_atom_smith_web_research | 50 ; profile_conjurer | 5
--
--   SELECT r.action_code, r.mana_cost FROM mana_price_rule r
--     JOIN mana_price_plan pp ON pp.plan_id = r.plan_id
--    WHERE pp.scope='platform' AND pp.status='active'
--      AND r.action_code IN ('profile_conjurer','duel_atom_smith','duel_atom_smith_web_research')
--    ORDER BY r.action_code;
--   -- => duel_atom_smith | 20 ; duel_atom_smith_web_research | 50 ; profile_conjurer | 5
