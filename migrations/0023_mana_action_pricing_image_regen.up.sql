-- =============================================================================
-- chora-identity : 0023_mana_action_pricing_image_regen.up.sql
--
-- Jira            : CHO-1822 (review-stage image regenerate) / CHO-1825
-- Domain          : Identity (supporting)  /  Database : chora_identity
-- Date            : 2026-06-22
--
-- Purpose:
--   The review-stage image-regenerate flow (chora-creation
--   POST /api/atoms/{id}/question-jobs/{job_id}/regenerate-image) debits mana
--   under action_code `question_authoring_image_regen` BEFORE dispatching the
--   re-render. That action_code was never registered in the pricing catalogue,
--   so DeductMana failed loud (InvalidArgument: unknown action_code) and the
--   regenerate 5xx'd. This registers it in the flat catalogue (mana_action_
--   pricing) alongside its question_authoring_* siblings (migration 0009).
--
--   Price = 0 (FREE). A regenerate is a re-roll of an image the author already
--   paid for at batch/single generation time; charging again for a review
--   refinement would surprise-bill. This matches the current free-by-default
--   authoring direction (migration 0018, ADR-178). A tenant can meter it later
--   via a price-plan override (the resolver checks tenant > plan > this flat
--   catalogue), or this default cost can be raised in a follow-up migration.
--
--   Purely ADDITIVE + idempotent — ON CONFLICT (action_code, effective_from)
--   DO NOTHING. HARD RULE: cross-database queries forbidden; local to
--   chora_identity.
-- =============================================================================

BEGIN;

INSERT INTO mana_action_pricing (action_code, mana_cost, description) VALUES
    ('question_authoring_image_regen', 0,
        'Re-render a review-stage question/answer illustration (CHO-1822). Free by default — the image was already paid for at generation time; tenant-overridable via the price-plan layer.')
ON CONFLICT (action_code, effective_from) DO NOTHING;

COMMIT;

-- VERIFICATION (run after apply):
--   SELECT action_code, mana_cost FROM mana_action_pricing
--    WHERE action_code = 'question_authoring_image_regen' AND deprecated_at IS NULL;
--   -- => question_authoring_image_regen | 0
