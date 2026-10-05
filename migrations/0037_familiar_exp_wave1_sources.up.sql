-- =============================================================================
-- chora-identity : 0037_familiar_exp_wave1_sources.up.sql
--
-- ADR             : ADR-228 D4 Wave 1 — "the power of a little bit": verified
--                   events that flow through the platform unrewarded start
--                   feeding the Familiar, resolver-priced + daily-capped.
-- Related         : ADR-201 §5 (ExpRuleResolver) · ADR-203 L16 (verified-EXP,
--                   flat pricing — no difficulty/LLM scaling) · ADR-218 D6
--                   (one EXP economy, parity contract) · ADR-227 (anti-farming
--                   doctrine: caps + calendar time, never content judgment).
-- Jira            : CHO-2090 (F-I3 — Wire XP Wave 1 sources)
-- Domain          : Identity (supporting)  /  Database : chora_identity
-- Parity mirror   : chora-consumption internal/domain/growth/curve.go +
--                   exp_rules_test.go identityParitySeed (Wave-1 block)
-- Date            : 2026-07-10
--
-- Purpose:
--   Register the three NEW Wave-1 EXP sources in the exp_source_def catalogue
--   (migration 0027 schema) so the live ExpRuleResolver prices them:
--
--     weakness_grown     B  10 / 30   a Growth Edge recovered
--                                     (chora.consumption.weakness.grown.v1)
--     submission_graded  A  30 / 60   an R+ assessment submission graded
--                                     (chora.delivery.submission.graded.v1,
--                                     binary proto; flat regardless of score)
--     module_completed   B  15 / 45   a W7 StudentModuleProgress module
--                                     completed
--                                     (chora.delivery.module_progress.completed.v1)
--
--   Follows the 0030 seed idiom: the live-token INSERTs ride with the
--   dedup-deprecation of the ADR-203 §12 aspirational rows each token
--   supersedes, keeping ONE live registry row per real source:
--
--     weakness_recovered (B 100/0) → weakness_grown     (live 10/30)
--     assessment_passed  (A 200/0) → submission_graded  (live 30/60)
--
--   assessment_attempted stays untouched — it describes the SUBMITTED
--   moment, not the graded one, and is not superseded by a Wave-1 token.
--   The aspirational uncapped values were never wired; the live economy
--   prices Wave-1 against the shipped vocabulary (campaign_node_won 25/75,
--   campaign_goal_sealed 120/120) — a deprecated source resolves to
--   ErrUnknownSource; nothing feeds these today, so no live award changes.
--
--   PARITY CONTRACT (ADR-218 D6): the three value/cap pairs above mirror
--   chora-consumption growth/curve.go; consumption pins the same literals in
--   exp_rules_test.go, identity pins them in
--   familiar_exp_wave1_sources_migration_test.go. Do NOT change one side
--   alone.
--
--   INVARIANT (ADR-203 L16 — verified-EXP anti-gaming): every source is a
--   Chora-verified system event with FLAT per-event pricing; this migration
--   only registers / retires catalogue rows — it can never mint a
--   self-declare source or a difficulty-scaled value.
--
--   HARD INVARIANT: idempotent + revertable. ON CONFLICT DO NOTHING +
--   COALESCE for re-apply safety. GRANTs are delegated to
--   9999_grant_app_roles.sql.
-- =============================================================================

BEGIN;

-- -----------------------------------------------------------------------------
-- (a) 3 NEW Wave-1 live-token sources (source_code, display_name, tier,
--     default_exp_value, default_daily_cap, enabled). Idempotent.
-- -----------------------------------------------------------------------------
INSERT INTO exp_source_def
    (source_code, display_name, tier, default_exp_value, default_daily_cap, enabled)
VALUES
    ('weakness_grown',    'Growth Edge recovered (live token)',              'B', 10, 30, TRUE),
    ('submission_graded', 'Assessment submission graded (live token, flat)', 'A', 30, 60, TRUE),
    ('module_completed',  'Course module completed (live token)',            'B', 15, 45, TRUE)
ON CONFLICT (source_code) DO NOTHING;

-- -----------------------------------------------------------------------------
-- (b) Deprecate the 2 ADR-203 rows superseded by a Wave-1 live token — one
--     registry row per real source (0030(c) idiom). Idempotent:
--     deprecated_at = COALESCE(deprecated_at, now()).
-- -----------------------------------------------------------------------------
UPDATE exp_source_def
   SET deprecated_at = COALESCE(deprecated_at, now()), updated_at = now()
 WHERE source_code = 'weakness_recovered'; -- superseded by weakness_grown (live)
UPDATE exp_source_def
   SET deprecated_at = COALESCE(deprecated_at, now()), updated_at = now()
 WHERE source_code = 'assessment_passed';  -- superseded by submission_graded (live, flat)

COMMIT;

-- =============================================================================
-- VERIFICATION (run manually after apply):
--
--   -- 3 new Wave-1 tokens present with live values
--   SELECT source_code, tier, default_exp_value, default_daily_cap, enabled
--     FROM exp_source_def
--    WHERE source_code IN ('weakness_grown','submission_graded','module_completed')
--    ORDER BY source_code;
--          -- => module_completed B 15 45 t | submission_graded A 30 60 t
--          --    | weakness_grown B 10 30 t
--
--   -- the 2 superseded rows are deprecated (resolve to ErrUnknownSource)
--   SELECT source_code, deprecated_at IS NOT NULL AS deprecated
--     FROM exp_source_def
--    WHERE source_code IN ('weakness_recovered','assessment_passed');
-- =============================================================================
