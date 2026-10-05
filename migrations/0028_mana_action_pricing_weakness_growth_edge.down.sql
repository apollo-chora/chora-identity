-- =============================================================================
-- chora-identity : 0028_mana_action_pricing_weakness_growth_edge.down.sql
--
-- Reverse of 0028_mana_action_pricing_weakness_growth_edge.up.sql — removes ONLY
-- the three new Growth-Edge action codes across the three layers they were
-- registered in. Idempotent (DELETE of absent rows is a no-op).
--
-- FK ORDER: mana_price_rule.action_code REFERENCES mana_action_def(action_code),
-- so the price rules must be deleted BEFORE the action_def rows.
--
-- This removes the platform-default rules AND any tenant override rules built on
-- these codes (scoped by action_code) — the correct rollback for the whole
-- feature. mana_action_pricing has no soft-delete column (config/seed table),
-- so the catalogue rows are hard-removed (mirrors the 0024 sibling down file).
-- =============================================================================

BEGIN;

-- 1. Price rules first (FK child of mana_action_def) — platform default + any
--    tenant overrides on these three codes.
DELETE FROM mana_price_rule
 WHERE action_code IN ('weakness_analysis', 'study_aid_generate', 'practice_test_generate');

-- 2. Action registry rows.
DELETE FROM mana_action_def
 WHERE action_code IN ('weakness_analysis', 'study_aid_generate', 'practice_test_generate');

-- 3. Flat catalogue rows.
DELETE FROM mana_action_pricing
 WHERE action_code IN ('weakness_analysis', 'study_aid_generate', 'practice_test_generate');

COMMIT;
