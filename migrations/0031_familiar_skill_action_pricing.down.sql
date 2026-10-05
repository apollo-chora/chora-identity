-- =============================================================================
-- chora-identity : 0031_familiar_skill_action_pricing.down.sql
--
-- Reverts 0031_familiar_skill_action_pricing.up.sql — removes ONLY the 26 Familiar
-- Skill / Ritual action codes from the flat mana_action_pricing catalogue floor.
-- Idempotent (DELETE ... WHERE action_code IN (...)). Touches no other code.
-- =============================================================================

BEGIN;

DELETE FROM mana_action_pricing
 WHERE action_code IN (
   'familiar_skill_explain_anew',
   'familiar_skill_quiz_me',
   'familiar_skill_quiz_me_gen',
   'familiar_skill_worked_example',
   'familiar_skill_socratic_drill',
   'familiar_skill_flashcard_forge',
   'familiar_skill_step_checker',
   'familiar_skill_polyglot',
   'familiar_skill_map_sight',
   'familiar_skill_weakness_sight',
   'familiar_skill_progress_mirror',
   'familiar_skill_recap_scribe',
   'familiar_skill_photo_sight',
   'familiar_skill_reminder_bell',
   'familiar_skill_path_weaver',
   'familiar_skill_fog_scout',
   'familiar_skill_goal_scribe',
   'familiar_skill_atom_forge',
   'familiar_skill_study_calendar',
   'familiar_skill_web_research',
   'familiar_skill_source_reader',
   'familiar_skill_fact_check',
   'familiar_skill_duel_second',
   'familiar_skill_dawn_briefing',
   'familiar_skill_watchful_eye',
   'familiar_ritual_run'
 );

COMMIT;
