-- =============================================================================
-- chora-identity : 0017_mana_price_plan_rules_layer.down.sql
--
-- Reverts 0017_mana_price_plan_rules_layer.up.sql.
--
-- Drops ONLY the three new tables (mana_price_rule → mana_price_plan →
-- mana_action_def, child-first for the FK + plan-CASCADE). mana_action_pricing
-- is NEVER modified by the up-migration, so it is untouched here → rollback is
-- total and price-safe (Down_migration_drops_new_tables_only).
-- =============================================================================

BEGIN;

DROP TABLE IF EXISTS mana_price_rule;
DROP TABLE IF EXISTS mana_price_plan;
DROP TABLE IF EXISTS mana_action_def;

COMMIT;
