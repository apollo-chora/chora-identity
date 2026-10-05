-- =============================================================================
-- chora-identity : 0027_familiar_exp_rules_layer.down.sql
--
-- Reverts 0027_familiar_exp_rules_layer.up.sql.
--
-- Drops ONLY the three new tables, child-first for the FK chain:
--   exp_rule (FK → exp_rule_plan + exp_source_def)  →  exp_rule_plan  →
--   exp_source_def. No other table is touched, so rollback is total and
--   EXP-economy-safe. Idempotent (DROP TABLE IF EXISTS).
-- =============================================================================

BEGIN;

DROP TABLE IF EXISTS exp_rule;
DROP TABLE IF EXISTS exp_rule_plan;
DROP TABLE IF EXISTS exp_source_def;

COMMIT;
