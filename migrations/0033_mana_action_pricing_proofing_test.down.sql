-- =============================================================================
-- chora-identity : 0033_mana_action_pricing_proofing_test.down.sql
--
-- Reverse of 0033_mana_action_pricing_proofing_test.up.sql — SOFT-deprecates
-- the proofing_test_gen action code (deliberately NOT the hard-DELETE shape
-- the older 0028/0031 down files used):
--
--   * mana_action_pricing + mana_action_def both carry `deprecated_at`, and
--     EVERY resolver read filters `deprecated_at IS NULL`
--     (mana_pricing_repository.go:59, mana_price_plan_repository.go:63/96) —
--     stamping it removes the code from resolution completely.
--   * mana_price_rule has no soft column; its platform-default row becomes
--     unreachable once the def is deprecated (resolution requires the live
--     def row), so it is left in place as an inert audit record. Re-applying
--     the up is still idempotent (ON CONFLICT DO NOTHING) and re-activation
--     is `UPDATE ... SET deprecated_at = NULL`.
--
-- Idempotent: re-running re-stamps deprecated_at only where still NULL.
-- =============================================================================

BEGIN;

UPDATE mana_action_pricing
   SET deprecated_at = now()
 WHERE action_code = 'proofing_test_gen'
   AND deprecated_at IS NULL;

UPDATE mana_action_def
   SET deprecated_at = now(),
       updated_at    = now()
 WHERE action_code = 'proofing_test_gen'
   AND deprecated_at IS NULL;

COMMIT;
