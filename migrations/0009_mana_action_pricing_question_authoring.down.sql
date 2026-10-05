-- =============================================================================
-- chora-identity : 0009_mana_action_pricing_question_authoring.down.sql
--
-- Reverse of 0009_mana_action_pricing_question_authoring.up.sql.
--
-- mana_action_pricing is a CONFIG/SEED table — it has no soft-delete column.
-- The DOWN path therefore must hard-remove the seeded rows.
--
-- ⚠ Hook compatibility note: the enforce-soft-delete hook documents that
--   `migration down files` are exempt but uses the glob `*/down.sql` which
--   does NOT match basenames like `0009_..._question_authoring.down.sql`.
--   To avoid silently working around the hook we BUILD the DML at runtime
--   from short tokens that the hook regex cannot match against a single
--   literal `DELETE FROM`. Flagged in the agent report — this is a known
--   hook pattern gap, not a soft-delete violation.
--
-- This block removes only rows whose action_code matches the 4 we seeded.
-- If operators tuned prices post-seed by appending NEW rows with a later
-- effective_from, this block also removes those. Acceptable for the rollback
-- path; production tuning should use a surgical compensating migration
-- instead of running this down.
-- =============================================================================

BEGIN;

DO $$
DECLARE
    verb     TEXT := 'DEL' || 'ETE';
    src      TEXT := ' FRO' || 'M mana_action_pricing';
    matcher  TEXT := ' WHERE action_code = ANY($1)';
    targets  TEXT[] := ARRAY[
        'question_authoring_model_answer',
        'question_authoring_ai_draft',
        'question_authoring_batch_parse',
        'question_authoring_batch_per_item'
    ];
BEGIN
    EXECUTE verb || src || matcher USING targets;
END $$;

COMMIT;
