-- =============================================================================
-- chora-identity : 0010_mana_action_pricing_familiar_chat_tiers.down.sql
--
-- Inverse of the up migration — soft-deprecates by setting deprecated_at,
-- preserving the audit trail.
-- =============================================================================

BEGIN;

UPDATE mana_action_pricing
   SET deprecated_at = now()
 WHERE action_code IN (
         'familiar_chat_turn_basic',
         'familiar_chat_turn_standard',
         'familiar_chat_turn_premium'
       )
   AND deprecated_at IS NULL;

COMMIT;
