-- =============================================================================
-- chora-identity : 0039_companion_action_pricing_twins.up.sql
--
-- ADR             : ADR-254 D7 (action-code cut, R5 full depth, R17) via the
--                   Learning Companion refactor (master plan W3 window)
-- Domain          : Identity (supporting)  /  Database : chora_identity
-- Date            : 2026-08-23 (W3)
-- Companion       : chora-model-gateway FailClosedPrefix ["companion_chat"]
--                   (261b3cb08), chora-consumption cost_map.go (W4), the chat
--                   agent's resolver (WP-A, same hour)
--
-- Purpose:
--   ADD a `companion_*` twin of EVERY active `*familiar*` mana action code
--   BESIDE the old row (nothing is renamed in place, nothing is retired here):
--   the gateway image that ships in this window meters companion_chat_turn_*
--   fail-closed and the chat agent switches its codes in the same hour, while
--   consumption keeps debiting the familiar_* codes until its W4 cut. Both
--   catalogues must resolve meanwhile. The familiar_* rows are retired
--   (deprecated_at) at the END of W4 by a later migration; ledger and BigQuery
--   history keep the old codes forever (ADR-254 D7).
--
--   Name rule (ADR-254 D9): replace 'familiar' -> 'companion' in the code, with
--   ONE exception: familiar_skill_fog_scout -> companion_skill_kg_explore
--   (the fog skill is the Knowledge Graph Explorer, R23). Covers
--   summon_familiar, familiar_chat, familiar_chat_turn_{basic,standard,premium},
--   the 26 familiar_skill_*, familiar_ceremony_edge_scout(_first),
--   familiar_ritual_run and any other familiar code present at apply time,
--   with the SAME price, description (Familiar -> Companion), def flags and
--   price-plan rules (every plan, every tier) as the twin it copies.
--
--   Three catalogue surfaces, in FK order:
--     1. mana_action_pricing   (the catalogue price; PK (action_code, effective_from))
--     2. mana_action_def       (the rules-layer registry; category CHECK widened
--                               to admit 'companion' beside 'familiar')
--     3. mana_price_rule       (per-plan rules; FK -> mana_action_def)
--
--   Idempotent (ON CONFLICT DO NOTHING everywhere; re-runnable). ADDITIVE only.
-- =============================================================================

BEGIN;

-- -----------------------------------------------------------------------------
-- 0. Widen the category CHECK on mana_action_def so 'companion' is a legal
--    category beside 'familiar' (the old rows keep 'familiar' until retired).
--    The constraint was created unnamed in 0017; find it by definition.
-- -----------------------------------------------------------------------------
DO $$
DECLARE
    cname text;
BEGIN
    SELECT conname INTO cname
      FROM pg_constraint
     WHERE conrelid = 'mana_action_def'::regclass
       AND contype = 'c'
       AND pg_get_constraintdef(oid) ILIKE '%category%';
    IF cname IS NOT NULL THEN
        EXECUTE format('ALTER TABLE mana_action_def DROP CONSTRAINT %I', cname);
    END IF;
    ALTER TABLE mana_action_def
        ADD CONSTRAINT mana_action_def_category_check
        CHECK (category IN ('authoring','familiar','companion','consumption','grading','free'));
END$$;

-- -----------------------------------------------------------------------------
-- 1. mana_action_pricing: one companion twin per ACTIVE familiar code (latest
--    effective_from wins), same price.
-- -----------------------------------------------------------------------------
INSERT INTO mana_action_pricing (action_code, mana_cost, description)
SELECT CASE WHEN p.action_code = 'familiar_skill_fog_scout'
            THEN 'companion_skill_kg_explore'
            ELSE replace(p.action_code, 'familiar', 'companion') END,
       p.mana_cost,
       replace(replace(COALESCE(p.description, ''), 'Familiar', 'Companion'), 'familiar', 'companion')
  FROM (
      SELECT DISTINCT ON (action_code) action_code, mana_cost, description
        FROM mana_action_pricing
       WHERE action_code LIKE '%familiar%'
         AND deprecated_at IS NULL
         AND effective_from <= now()
       ORDER BY action_code, effective_from DESC
  ) p
 WHERE NOT EXISTS (
      SELECT 1 FROM mana_action_pricing c
       WHERE c.action_code = CASE WHEN p.action_code = 'familiar_skill_fog_scout'
                                  THEN 'companion_skill_kg_explore'
                                  ELSE replace(p.action_code, 'familiar', 'companion') END
         AND c.deprecated_at IS NULL
 )
ON CONFLICT (action_code, effective_from) DO NOTHING;

-- -----------------------------------------------------------------------------
-- 2. mana_action_def: one companion twin per familiar def, same flags,
--    category familiar -> companion.
-- -----------------------------------------------------------------------------
INSERT INTO mana_action_def (action_code, display_name, category, refundable, per_item, meter_home, tier_aware)
SELECT CASE WHEN d.action_code = 'familiar_skill_fog_scout'
            THEN 'companion_skill_kg_explore'
            ELSE replace(d.action_code, 'familiar', 'companion') END,
       replace(replace(d.display_name, 'Familiar', 'Companion'), 'familiar', 'companion'),
       CASE WHEN d.category = 'familiar' THEN 'companion' ELSE d.category END,
       d.refundable, d.per_item, d.meter_home, d.tier_aware
  FROM mana_action_def d
 WHERE d.action_code LIKE '%familiar%'
   AND d.deprecated_at IS NULL
ON CONFLICT (action_code) DO NOTHING;

-- -----------------------------------------------------------------------------
-- 3. mana_price_rule: for EVERY plan (platform default + tenant plans) and
--    every tier, a companion twin of each familiar rule with the same price.
-- -----------------------------------------------------------------------------
INSERT INTO mana_price_rule (plan_id, action_code, tier, mana_cost, note)
SELECT r.plan_id,
       CASE WHEN r.action_code = 'familiar_skill_fog_scout'
            THEN 'companion_skill_kg_explore'
            ELSE replace(r.action_code, 'familiar', 'companion') END,
       r.tier, r.mana_cost,
       'companion twin of ' || r.action_code || ' (0039, ADR-254 D7 action-code cut)'
  FROM mana_price_rule r
 WHERE r.action_code LIKE '%familiar%'
   AND EXISTS (
       SELECT 1 FROM mana_action_def d
        WHERE d.action_code = CASE WHEN r.action_code = 'familiar_skill_fog_scout'
                                   THEN 'companion_skill_kg_explore'
                                   ELSE replace(r.action_code, 'familiar', 'companion') END
   )
ON CONFLICT (plan_id, action_code, tier) DO NOTHING;

-- -----------------------------------------------------------------------------
-- 4. Any active familiar catalogue price that has NO def yet (0031/0032/0038
--    rows added after 0017's seed) still gets a companion price above; give the
--    default platform plan a NULL-tier rule for every companion code that has a
--    def but no rule, mirroring 0017 step 5, so resolution never falls through
--    to a missing rule.
-- -----------------------------------------------------------------------------
INSERT INTO mana_price_rule (plan_id, action_code, tier, mana_cost, note)
SELECT dp.plan_id, p.action_code, NULL, p.mana_cost,
       'companion catalogue back-fill (0039)'
  FROM (
      SELECT plan_id FROM mana_price_plan
       WHERE plan_code = 'default' AND scope = 'platform' AND status = 'active'
       LIMIT 1
  ) dp
  CROSS JOIN (
      SELECT DISTINCT ON (action_code) action_code, mana_cost
        FROM mana_action_pricing
       WHERE action_code LIKE 'companion%'
         AND deprecated_at IS NULL
         AND effective_from <= now()
         AND action_code IN (SELECT action_code FROM mana_action_def)
       ORDER BY action_code, effective_from DESC
  ) p
ON CONFLICT (plan_id, action_code, tier) DO NOTHING;

COMMIT;

-- VERIFICATION (run after apply):
--   SELECT count(*) FROM mana_action_pricing WHERE action_code LIKE 'companion%' AND deprecated_at IS NULL;
--   -- => the number of distinct active familiar codes (~33)
--   SELECT action_code, mana_cost FROM mana_action_pricing WHERE action_code IN
--     ('companion_chat_turn_basic','companion_chat_turn_standard','companion_chat_turn_premium','companion_skill_kg_explore');
--   -- => 5 / 15 / 30 / 20
--   SELECT count(*) FROM mana_action_def WHERE category = 'companion';
-- =============================================================================
