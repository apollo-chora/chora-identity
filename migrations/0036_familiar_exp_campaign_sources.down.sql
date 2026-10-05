-- =============================================================================
-- chora-identity : 0036_familiar_exp_campaign_sources.down.sql
--
-- Reverts 0036: removes exactly the four WS-C5 campaign conquest EXP source
-- rows (ADR-227 D10, CHO-2084). No other catalogue row is touched — 0036 is
-- purely additive, so the down is a pure delete of its own seeds. Idempotent
-- (DELETE of absent rows is a no-op). exp_source_def is global config
-- catalogue (no RLS, no learner data) — the soft-delete rule governs domain
-- rows, not a migration reverting its own seed.
-- =============================================================================

BEGIN;

DELETE FROM exp_source_def
 WHERE source_code IN (
   'campaign_rung_cleared',
   'campaign_rung_refreshed',
   'campaign_node_won',
   'campaign_goal_sealed'
 );

COMMIT;
