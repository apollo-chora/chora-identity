-- =============================================================================
-- chora-identity : 0037_familiar_exp_wave1_sources.down.sql
--
-- Reverts the ADR-228 D4 Wave-1 EXP seed (CHO-2090):
--   (a) DELETE the 3 Wave-1 live-token rows this migration inserted;
--   (b) clear deprecated_at on the 2 aspirational rows it deprecated
--       (weakness_recovered, assessment_passed) — restoring the pre-0037
--       catalogue exactly. No pre-0037 source is deleted.
-- =============================================================================

BEGIN;

DELETE FROM exp_source_def
 WHERE source_code IN ('weakness_grown', 'submission_graded', 'module_completed');

UPDATE exp_source_def
   SET deprecated_at = NULL, updated_at = now()
 WHERE source_code = 'weakness_recovered';
UPDATE exp_source_def
   SET deprecated_at = NULL, updated_at = now()
 WHERE source_code = 'assessment_passed';

COMMIT;
