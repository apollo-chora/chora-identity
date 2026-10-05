-- =============================================================================
-- chora-identity : 0024_mana_action_pricing_question_generate.up.sql
--
-- Jira            : CHO unified-authoring per-question re-pricing (U2)
-- ADR             : ADR-178 — configurable mana price-plan rules layer (H+)
-- Domain          : Identity (supporting)  /  Database : chora_identity
-- Date            : 2026-06-22
--
-- Purpose:
--   Register the per-question authoring mana pricing model for the upcoming
--   UNIFIED authoring flow. The unified flow charges ONE debit per ACCEPTED
--   AI-generated question; manual-authored questions are NOT charged. Two new
--   action codes, priced off a base B = 10:
--
--     question_authoring_generate        -> B  = 10  (a pure-text AI question)
--     question_authoring_generate_image  -> 2B = 20  (an AI question carrying
--                                                      any image: a stem image
--                                                      and/or an answer image is
--                                                      still 20, never 30)
--
--   These MIRROR the column conventions of the existing question_authoring_*
--   siblings (migrations 0009/0017): category authoring, refundable on failure,
--   per_item semantics (debited per accepted question -> the caller multiplies
--   by the accepted count, exactly like question_authoring_batch_per_item),
--   meter_home creation.
--
--   Registered in all three layers so the codes behave identically to their
--   siblings end-to-end AND are TENANT-OVERRIDABLE via the ADR-178 price-plan
--   layer (a tenant override rule FK-references mana_action_def, so the def row
--   is required for overridability):
--     1. mana_action_pricing  — flat catalogue floor (bottom-of-precedence
--                               fallback; same shape as 0009/0023)
--     2. mana_action_def      — action registry (refundable/per_item/meter_home)
--     3. mana_price_rule      — platform `default` plan rule at B / 2B so
--                               resolution returns the def flags (the catalogue
--                               fallback path carries no flags) — the same
--                               end-state migration 0017 back-filled for 0009.
--
--   Purely ADDITIVE + idempotent + changes NO existing action_code or price
--   (every statement is INSERT ... ON CONFLICT DO NOTHING). HARD RULE:
--   cross-database queries forbidden; all objects are local to chora_identity.
--   Do NOT apply manually — migrations auto-apply at deploy.
-- =============================================================================

BEGIN;

-- 1. Flat catalogue floor (mana_action_pricing) — PK (action_code, effective_from).
INSERT INTO mana_action_pricing (action_code, mana_cost, description) VALUES
    ('question_authoring_generate', 10,
        'Unified authoring: one debit per ACCEPTED AI-generated pure-text question, base price B. Manual questions are not charged. Refundable on failure, per accepted item, tenant-overridable via the price-plan layer.'),
    ('question_authoring_generate_image', 20,
        'Unified authoring: one debit per ACCEPTED AI-generated question carrying any image, at 2xB. A question with both a stem image and an answer image is still 20, not 30.')
ON CONFLICT (action_code, effective_from) DO NOTHING;

-- 2. Action registry (mana_action_def) — semantics flags mirrored from the
--    question_authoring_* siblings (migration 0017 seed): refundable TRUE,
--    per_item TRUE, meter_home creation. Required so a tenant override rule
--    (which FK-references this table) can be authored, i.e. so the codes are
--    tenant-overridable through the price-plan layer.
INSERT INTO mana_action_def (action_code, display_name, category, refundable, per_item, meter_home, tier_aware) VALUES
    ('question_authoring_generate',       'Question Authoring: Generate',       'authoring', TRUE, TRUE, 'creation', FALSE),
    ('question_authoring_generate_image', 'Question Authoring: Generate Image', 'authoring', TRUE, TRUE, 'creation', FALSE)
ON CONFLICT (action_code) DO NOTHING;

-- 3. Platform `default` plan rule (mana_price_rule) at B / 2B, NULL tier. The
--    catalogue-fallback resolution path carries no def flags, so a platform
--    default rule is what makes resolution return refundable/per_item for these
--    codes — the same end-state migration 0017 back-filled for the 0009 codes.
--    A tenant override (a tenant-scoped active plan rule) wins over this default.
INSERT INTO mana_price_rule (plan_id, action_code, tier, mana_cost, note)
SELECT dp.plan_id, r.action_code, NULL, r.mana_cost, r.note
  FROM (
      SELECT plan_id FROM mana_price_plan
       WHERE plan_code = 'default' AND scope = 'platform' AND status = 'active'
       LIMIT 1
  ) dp
  CROSS JOIN (
      SELECT 'question_authoring_generate' AS action_code, 10 AS mana_cost,
             'unified authoring per accepted text question, base B' AS note
      UNION ALL
      SELECT 'question_authoring_generate_image' AS action_code, 20 AS mana_cost,
             'unified authoring per accepted question with any image, 2xB' AS note
  ) r
ON CONFLICT (plan_id, action_code, tier) DO NOTHING;

COMMIT;

-- VERIFICATION (run after apply):
--   SELECT action_code, mana_cost FROM mana_action_pricing
--    WHERE action_code IN ('question_authoring_generate','question_authoring_generate_image')
--      AND deprecated_at IS NULL ORDER BY action_code;
--   -- => question_authoring_generate | 10 ; question_authoring_generate_image | 20
--
--   SELECT r.action_code, r.mana_cost FROM mana_price_rule r
--     JOIN mana_price_plan pp ON pp.plan_id = r.plan_id
--    WHERE pp.scope='platform' AND pp.status='active'
--      AND r.action_code IN ('question_authoring_generate','question_authoring_generate_image')
--    ORDER BY r.action_code;
--   -- => question_authoring_generate | 10 ; question_authoring_generate_image | 20
