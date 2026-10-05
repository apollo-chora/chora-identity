-- =============================================================================
-- chora-identity : 0032_mana_action_pricing_ceremony_edge_scout.down.sql
--
-- Reverts 0032_mana_action_pricing_ceremony_edge_scout.up.sql — removes ONLY
-- the two ceremony edge-scout action codes from the flat mana_action_pricing
-- catalogue floor. Idempotent (DELETE ... WHERE action_code IN (...)); the
-- hard DELETE is the migration-down carve-out (ddd-enforcement §Soft Deletes
-- Exceptions), exactly mirroring 0031's down. Touches no other code.
-- =============================================================================

BEGIN;

DELETE FROM mana_action_pricing
 WHERE action_code IN (
   'familiar_ceremony_edge_scout',
   'familiar_ceremony_edge_scout_first'
 );

COMMIT;
