-- =============================================================================
-- chora-identity : 0033_mana_action_pricing_proofing_test.up.sql
--
-- Jira            : CHO-2040 (Virgin Proofing Test composed runner)
-- Rulings         : R8-6 (composed goal-driven runner) + spec
--                   docs/VIRGIN-PROOFING-TEST-SKILL-SPEC-2026-07-04.md §1/§3
--                   (price_key = proofing_test_gen)
-- ADR             : ADR-142 §4 (action-cost map) · ADR-178 (price-plan layer)
--                   · ADR-205 D6 precedent (reserve→settle/refund, migration 0028)
-- Domain          : Identity (supporting)  /  Database : chora_identity
-- Date            : 2026-07-04
--
-- Purpose:
--   Register the learner-triggered Proofing Test generation action code. The
--   chora-consumption runner RESERVES this at the request door
--   (DeductMana units=0 → the resolver prices it, tenant overrides win) and
--   REFUNDS it (CreditMana against the reservation handle) when the outbox
--   publish fails or the qgen batch is REFUSED — so the reserve is never
--   stranded (the still-unseeded weakness_analysis debt this spec warns about
--   is NOT repeated here).
--
--     proofing_test_gen -> 25   one mixed MCQ+OE proofing-test batch
--                               (ai_assist authoring tier; the qgen crew runs
--                               ONE set-native generate + compose pass)
--
--   Registered in all THREE layers, mirroring 0028, so the code behaves
--   identically to its siblings end-to-end AND is TENANT-OVERRIDABLE:
--     1. mana_action_pricing — flat catalogue floor
--     2. mana_action_def     — action registry (refundable / meter_home)
--     3. mana_price_rule     — platform `default` plan rule (carries the def
--                              flags through resolution)
--
--   Purely ADDITIVE + idempotent (INSERT ... ON CONFLICT DO NOTHING). HARD
--   RULE: cross-database queries forbidden; all objects local to
--   chora_identity. GRANTs delegated to 9999_grant_app_roles.sql. Do NOT
--   apply manually — migrations auto-apply at deploy.
-- =============================================================================

BEGIN;

-- 1. Flat catalogue floor (mana_action_pricing) — PK (action_code, effective_from).
INSERT INTO mana_action_pricing (action_code, mana_cost, description) VALUES
    ('proofing_test_gen', 25,
        'Virgin Proofing Test: one learner-triggered mixed MCQ+OE test-set generation targeting the goal''s ticked growth edges (CHO-2040). Reserved at the consumption request door; refunded on publish failure or qgen refusal. Tenant-overridable via the price-plan layer.')
ON CONFLICT (action_code, effective_from) DO NOTHING;

-- 2. Action registry (mana_action_def) — refundable TRUE (the consumption
--    terminal subscriber refunds on refusal), per_item FALSE (one upfront
--    reserve per proofing test), meter_home 'consumption' (the request door
--    debits). Required so a tenant override rule (FK on mana_action_def) can
--    be authored.
INSERT INTO mana_action_def (action_code, display_name, category, refundable, per_item, meter_home, tier_aware) VALUES
    ('proofing_test_gen', 'Familiar: Virgin Proofing Test', 'consumption', TRUE, FALSE, 'consumption', FALSE)
ON CONFLICT (action_code) DO NOTHING;

-- 3. Platform `default` plan rule (mana_price_rule), NULL tier — makes
--    resolution return the def flags (the catalogue fallback path carries no
--    flags); a tenant-scoped active plan rule wins over this default.
INSERT INTO mana_price_rule (plan_id, action_code, tier, mana_cost, note)
SELECT dp.plan_id, 'proofing_test_gen', NULL, 25,
       'Virgin Proofing Test generation, reserved at the consumption request door'
  FROM (
      SELECT plan_id FROM mana_price_plan
       WHERE plan_code = 'default' AND scope = 'platform' AND status = 'active'
       LIMIT 1
  ) dp
ON CONFLICT (plan_id, action_code, tier) DO NOTHING;

COMMIT;

-- VERIFICATION (run after apply):
--   SELECT action_code, mana_cost FROM mana_action_pricing
--    WHERE action_code = 'proofing_test_gen' AND deprecated_at IS NULL;
--   -- => proofing_test_gen | 25
--
--   SELECT r.action_code, r.mana_cost FROM mana_price_rule r
--     JOIN mana_price_plan pp ON pp.plan_id = r.plan_id
--    WHERE pp.scope='platform' AND pp.status='active'
--      AND r.action_code = 'proofing_test_gen';
--   -- => proofing_test_gen | 25
-- =============================================================================
