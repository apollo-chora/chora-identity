-- =============================================================================
-- chora-identity : 0028_mana_action_pricing_weakness_growth_edge.up.sql
--
-- Jira            : CHO-1956 (WS-4 economy) / Epic CHO-1952 Growth-Edge graduation
-- ADR             : ADR-205 (Growth-Edge analyser graduation) §D6 economy
--                   ADR-178 (configurable mana price-plan rules layer, H+)
-- Domain          : Identity (supporting)  /  Database : chora_identity
-- Date            : 2026-06-29
--
-- Purpose:
--   Register the Growth-Edge PREMIUM mana pricing model. The upload-driven
--   weakness flow (chora-consumption upload door) RESERVES mana on accept and
--   the ai-kernel weakness-analyser crew SETTLES it on success / REFUNDS it on
--   any fail-loud node (ADR-205 D6). The auto-derived path (graded-assessment /
--   Ebbinghaus edges) stays FREE and sets no reservation — it never debits any
--   of these codes. Three new action codes:
--
--     weakness_analysis        -> 50   one premium multimodal weakness analysis
--     study_aid_generate       -> 20   an advice / glossary / cheat-sheet output
--     practice_test_generate   -> 30   a generated practice-test output
--
--   All three are consumption-metered (meter_home='consumption' — the upload
--   door in chora-consumption is the debit site) and REFUNDABLE (the crew owns
--   the refund on every fail-loud / BLOCK node, so the reserve is never
--   stranded). Prices are platform defaults; a tenant overrides them via the
--   ADR-178 price-plan layer. weakness_analysis (50) mirrors the heavy
--   question_generation tier; the lighter text outputs sit in the authoring
--   band (20 / 30).
--
--   Registered in all THREE layers so the codes behave identically to their
--   siblings end-to-end AND are TENANT-OVERRIDABLE (a tenant override rule
--   FK-references mana_action_def, so the def row is required for overridability):
--     1. mana_action_pricing  — flat catalogue floor (bottom-of-precedence
--                               fallback; same shape as 0009/0023/0024)
--     2. mana_action_def      — action registry (refundable / per_item / meter_home)
--     3. mana_price_rule      — platform `default` plan rule so resolution returns
--                               the def flags (the catalogue fallback path carries
--                               no flags) — the same end-state migration 0017
--                               back-filled for the 0009 codes.
--
--   Purely ADDITIVE + idempotent + changes NO existing action_code or price
--   (every statement is INSERT ... ON CONFLICT DO NOTHING). HARD RULE:
--   cross-database queries forbidden; all objects are local to chora_identity.
--   Do NOT apply manually — migrations auto-apply at deploy.
-- =============================================================================

BEGIN;

-- 1. Flat catalogue floor (mana_action_pricing) — PK (action_code, effective_from).
INSERT INTO mana_action_pricing (action_code, mana_cost, description) VALUES
    ('weakness_analysis', 50,
        'Growth-Edge premium: one multimodal weakness analysis reserved at the upload door (ADR-205 D6). The crew settles on success / refunds on fail. Auto-derived edges (graded-assessment / Ebbinghaus) never debit this. Refundable, tenant-overridable via the price-plan layer.'),
    ('study_aid_generate', 20,
        'Growth-Edge premium output: an advice / glossary / cheat-sheet study aid generated for a surfaced weak concept. Refundable on failure, tenant-overridable via the price-plan layer.'),
    ('practice_test_generate', 30,
        'Growth-Edge premium output: a generated practice test for a surfaced weak concept. Refundable on failure, tenant-overridable via the price-plan layer.')
ON CONFLICT (action_code, effective_from) DO NOTHING;

-- 2. Action registry (mana_action_def) — refundable TRUE (the crew refunds on
--    any fail-loud node), per_item FALSE (one upfront reserve per upload / output),
--    meter_home 'consumption' (the chora-consumption upload door debits). Required
--    so a tenant override rule (which FK-references this table) can be authored,
--    i.e. so the codes are tenant-overridable through the price-plan layer.
INSERT INTO mana_action_def (action_code, display_name, category, refundable, per_item, meter_home, tier_aware) VALUES
    ('weakness_analysis',      'Growth-Edge: Weakness Analysis', 'consumption', TRUE, FALSE, 'consumption', FALSE),
    ('study_aid_generate',     'Growth-Edge: Study Aid',         'consumption', TRUE, FALSE, 'consumption', FALSE),
    ('practice_test_generate', 'Growth-Edge: Practice Test',     'consumption', TRUE, FALSE, 'consumption', FALSE)
ON CONFLICT (action_code) DO NOTHING;

-- 3. Platform `default` plan rule (mana_price_rule), NULL tier. The catalogue-
--    fallback resolution path carries no def flags, so a platform default rule is
--    what makes resolution return refundable for these codes — the same end-state
--    migration 0017 back-filled for the 0009 codes. A tenant override (a
--    tenant-scoped active plan rule) wins over this default.
INSERT INTO mana_price_rule (plan_id, action_code, tier, mana_cost, note)
SELECT dp.plan_id, r.action_code, NULL, r.mana_cost, r.note
  FROM (
      SELECT plan_id FROM mana_price_plan
       WHERE plan_code = 'default' AND scope = 'platform' AND status = 'active'
       LIMIT 1
  ) dp
  CROSS JOIN (
      SELECT 'weakness_analysis' AS action_code, 50 AS mana_cost,
             'Growth-Edge premium weakness analysis, reserved at the upload door' AS note
      UNION ALL
      SELECT 'study_aid_generate' AS action_code, 20 AS mana_cost,
             'Growth-Edge premium study-aid output' AS note
      UNION ALL
      SELECT 'practice_test_generate' AS action_code, 30 AS mana_cost,
             'Growth-Edge premium practice-test output' AS note
  ) r
ON CONFLICT (plan_id, action_code, tier) DO NOTHING;

COMMIT;

-- VERIFICATION (run after apply):
--   SELECT action_code, mana_cost FROM mana_action_pricing
--    WHERE action_code IN ('weakness_analysis','study_aid_generate','practice_test_generate')
--      AND deprecated_at IS NULL ORDER BY action_code;
--   -- => practice_test_generate | 30 ; study_aid_generate | 20 ; weakness_analysis | 50
--
--   SELECT r.action_code, r.mana_cost FROM mana_price_rule r
--     JOIN mana_price_plan pp ON pp.plan_id = r.plan_id
--    WHERE pp.scope='platform' AND pp.status='active'
--      AND r.action_code IN ('weakness_analysis','study_aid_generate','practice_test_generate')
--    ORDER BY r.action_code;
--   -- => practice_test_generate | 30 ; study_aid_generate | 20 ; weakness_analysis | 50
