-- =============================================================================
-- chora-identity : 0023_mana_action_pricing_image_regen.down.sql
--
-- Reverse of 0023_mana_action_pricing_image_regen.up.sql — removes ONLY the
-- one action_code this migration seeded. Idempotent.
-- =============================================================================

BEGIN;

DELETE FROM mana_action_pricing
 WHERE action_code = 'question_authoring_image_regen';

COMMIT;
