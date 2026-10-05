-- =============================================================================
-- chora-identity : 0031_familiar_skill_action_pricing.up.sql
--
-- ADR             : ADR-218 / ADR-219 — Familiar Growth & Grimoire: per-Skill
--                   catalogue + Ritual composition. §7 pricing table.
-- Spec            : docs/FAMILIAR-SKILL-SPECS-2026-07-03.md §7
-- Jira            : CHO-2012 (P0 — Familiar Growth & Grimoire CR)
-- Domain          : Identity (supporting)  /  Database : chora_identity
-- Date            : 2026-07-03
--
-- Purpose:
--   Seed the flat mana_action_pricing catalogue floor for the 26 Familiar Skill /
--   Ritual action codes (25 familiar_skill_* + familiar_ritual_run). These are the
--   platform default per-use mana costs a Familiar Skill charges the learner.
--   Every code is editor-tunable via the ADR-178 PricePlanResolver later (a tenant
--   override / platform plan rule wins over this floor); 0030 registers only the
--   flat catalogue floor — the same single-table shape as 0010's chat tiers.
--
--   Free (0)  : quiz_me (retrieval) · map_sight · progress_mirror · reminder_bell ·
--               study_calendar
--   5–10      : recap_scribe 5 · explain_anew 10 · worked_example 10 · polyglot 10 ·
--               goal_scribe 10 · duel_second 10 · watchful_eye 10/run
--   15–25     : socratic_drill 15 · weakness_sight 15 · step_checker 15 ·
--               dawn_briefing 15/run · fog_scout 20 · quiz_me_gen 25 ·
--               flashcard_forge 25 · path_weaver 25
--   40–80     : source_reader 40 · fact_check 40 · photo_sight 60 · web_research 80
--   200       : atom_forge 200
--
--   Ritual runs use action_code familiar_ritual_run at units = published_price_units
--   (composed ONCE at publish from the revision's steps: base 20 + each premium
--   step's uplift), shown up-front in the Grimoire, then flat per run. The 20 seeded
--   here is the base-only floor; a published Ritual charges its own composed price.
--
--   Purely ADDITIVE + idempotent — one INSERT ... ON CONFLICT
--   (action_code, effective_from) DO NOTHING (see 0002 §240 PK shape + 0010). No
--   existing action_code is touched. HARD RULE: cross-database queries forbidden;
--   all objects local to chora_identity. GRANTs delegated to 9999_grant_app_roles.sql.
--   Do NOT apply manually — migrations auto-apply at deploy.
-- =============================================================================

BEGIN;

INSERT INTO mana_action_pricing (action_code, mana_cost, description) VALUES
    ('familiar_skill_explain_anew',    10,
        'Skill "Explain Anew": re-explain a concept a different way at the learner''s request.'),
    ('familiar_skill_quiz_me',          0,
        'Skill "Quiz Me" (retrieval practice): a free quiz drawn from the learner''s existing atoms — no generation cost.'),
    ('familiar_skill_quiz_me_gen',     25,
        'Skill "Quiz Me" (generate): a freshly generated quiz for the learner''s current concept.'),
    ('familiar_skill_worked_example',  10,
        'Skill "Worked Example": a fully worked step-by-step example of the concept.'),
    ('familiar_skill_socratic_drill',  15,
        'Skill "Socratic Drill": a guided Socratic questioning drill toward a concept.'),
    ('familiar_skill_flashcard_forge', 25,
        'Skill "Flashcard Forge": forge a spaced-repetition flashcard deck for a concept.'),
    ('familiar_skill_step_checker',    15,
        'Skill "Step Checker": check the learner''s working one step at a time.'),
    ('familiar_skill_polyglot',        10,
        'Skill "Polyglot": re-explain or render the concept in another language.'),
    ('familiar_skill_map_sight',        0,
        'Skill "Map Sight" (free Sight): reveal the learner''s knowledge-map view.'),
    ('familiar_skill_weakness_sight',  15,
        'Skill "Weakness Sight": surface the learner''s current weak concepts.'),
    ('familiar_skill_progress_mirror',  0,
        'Skill "Progress Mirror" (free): mirror the learner''s mastery and momentum.'),
    ('familiar_skill_recap_scribe',     5,
        'Skill "Recap Scribe": scribe a concise recap of the study session.'),
    ('familiar_skill_photo_sight',     60,
        'Skill "Photo Sight": multimodal analysis of a photographed page or problem.'),
    ('familiar_skill_reminder_bell',    0,
        'Skill "Reminder Bell" (free): ring a study reminder for the learner.'),
    ('familiar_skill_path_weaver',     25,
        'Skill "Path Weaver": weave a personalised learning path.'),
    ('familiar_skill_fog_scout',       20,
        'Skill "Fog Scout": scout the discovery-graph fog for adjacent concepts.'),
    ('familiar_skill_goal_scribe',     10,
        'Skill "Goal Scribe": scribe a new learning goal for the learner.'),
    ('familiar_skill_atom_forge',     200,
        'Skill "Atom Forge": forge a brand-new learning atom (the heaviest Skill).'),
    ('familiar_skill_study_calendar',   0,
        'Skill "Study Calendar" (free): plan the learner''s study calendar.'),
    ('familiar_skill_web_research',    80,
        'Skill "Web Research": external web research (network egress).'),
    ('familiar_skill_source_reader',   40,
        'Skill "Source Reader": read and ingest an external source document.'),
    ('familiar_skill_fact_check',      40,
        'Skill "Fact Check": fact-check a claim against external sources.'),
    ('familiar_skill_duel_second',     10,
        'Skill "Duel Second": act as the learner''s second in a knowledge duel.'),
    ('familiar_skill_dawn_briefing',   15,
        'Skill "Dawn Briefing": a daily dawn briefing, charged per run.'),
    ('familiar_skill_watchful_eye',    10,
        'Skill "Watchful Eye": a watchful-eye study monitor, charged per run.'),
    ('familiar_ritual_run',            20,
        'Ritual run base floor. Actual Ritual runs charge published_price_units composed once at publish from the revision''s steps (base 20 + each premium step''s uplift, ADR-218 §7). This 20 is the base-only floor.')
ON CONFLICT (action_code, effective_from) DO NOTHING;

COMMIT;

-- =============================================================================
-- VERIFICATION (run manually after apply):
--   SELECT action_code, mana_cost FROM mana_action_pricing
--    WHERE action_code LIKE 'familiar_skill_%' OR action_code = 'familiar_ritual_run'
--    ORDER BY mana_cost, action_code;                     -- => 26 rows
-- =============================================================================
