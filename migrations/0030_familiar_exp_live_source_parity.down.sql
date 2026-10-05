-- =============================================================================
-- chora-identity : 0030_familiar_exp_live_source_parity.down.sql
--
-- Reverts 0030_familiar_exp_live_source_parity.up.sql — restores the exp_source_def
-- catalogue to its migration-0027 (ADR-203 §12) state:
--   (a) DELETE the 10 inserted live-token rows.
--   (b) restore atom_authored to the aspirational 30/150.
--   (c) clear the deprecation on the 7 superseded ADR-203 rows.
-- Idempotent (DELETE / a fixed-value SET / SET NULL). atom_authored is NEVER
-- deleted — it pre-dates 0029 and is only re-pointed.
-- =============================================================================

BEGIN;

-- (a) remove the 10 inserted live-token rows (NOT atom_authored).
DELETE FROM exp_source_def
 WHERE source_code IN (
   'atom_session', 'ebbinghaus_review', 'hex_expand', 'conv_turn', 'daily_dose_open',
   'social_share', 'social_reaction', 'junction_accepted', 'admin_grant', 'hatch_roll'
 );

-- (b) restore atom_authored to the ADR-203 §12 aspirational 30/150 default.
UPDATE exp_source_def
   SET default_exp_value = 30,
       default_daily_cap = 150,
       updated_at        = now()
 WHERE source_code = 'atom_authored';

-- (c) clear the deprecation on the 7 superseded rows (re-enable in the catalogue).
UPDATE exp_source_def
   SET deprecated_at = NULL, updated_at = now()
 WHERE source_code = 'atom_correct';
UPDATE exp_source_def
   SET deprecated_at = NULL, updated_at = now()
 WHERE source_code = 'atom_attempt';
UPDATE exp_source_def
   SET deprecated_at = NULL, updated_at = now()
 WHERE source_code = 'on_time_review';
UPDATE exp_source_def
   SET deprecated_at = NULL, updated_at = now()
 WHERE source_code = 'chat_turn';
UPDATE exp_source_def
   SET deprecated_at = NULL, updated_at = now()
 WHERE source_code = 'kg_hexagon_expanded';
UPDATE exp_source_def
   SET deprecated_at = NULL, updated_at = now()
 WHERE source_code = 'daily_dose_completed';
UPDATE exp_source_def
   SET deprecated_at = NULL, updated_at = now()
 WHERE source_code = 'post_shared';

COMMIT;
