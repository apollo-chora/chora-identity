-- =============================================================================
-- chora-identity : 0009_mana_action_pricing_question_authoring.up.sql
--
-- CR              : Question Authoring (MCQ + Open-Ended)
-- Design doc      : docs/m14/cr-question-authoring-design-2026-05-15.md §3.2
-- Plan            : ~/.claude/plans/golden-hopping-owl.md (D1 — per-user mana)
-- Domain          : Identity (supporting)
-- Database        : chora_identity
-- Author          : agent — P0+P1 question-authoring contracts/migrations
-- Date            : 2026-05-15
-- Architecture    : Architecture Review locked 2026-05-07
--
-- Purpose:
--   Seeds 4 new mana_action_pricing rows for the Question Authoring CR.
--   Per D1 the debit is on per-user Familiar mana (NOT TenantManaPool); the
--   action codes are looked up by chora-creation via the
--   ManaService.DeductMana gRPC (see design §3.3).
--
--   Mana costs per the design doc proposal:
--     - question_authoring_model_answer   →  5  mana
--     - question_authoring_ai_draft       → 10  mana
--     - question_authoring_batch_parse    → 50  mana
--     - question_authoring_batch_per_item →  5  mana
--
--   Idempotent — ON CONFLICT (action_code, effective_from) DO NOTHING.
--   See services/chora-identity/migrations/0002_user_economy.sql §240 for the
--   PK shape.
-- =============================================================================

BEGIN;

INSERT INTO mana_action_pricing (action_code, mana_cost, description) VALUES
    ('question_authoring_model_answer',    5,
        'AI-generate a model answer (MCQ explainers OR OE reference) for an existing manual question'),
    ('question_authoring_ai_draft',       10,
        'AI-draft a complete new question (MCQ stem+options+explainers OR OE stem+rubric+model) from prompt'),
    ('question_authoring_batch_parse',    50,
        'Parse + ingest a source material upload via chora-doc-parser (T1 multimodal call)'),
    ('question_authoring_batch_per_item',  5,
        'Per-accepted-candidate generation cost in a batch job (debited at qgen_delivery time)')
ON CONFLICT (action_code, effective_from) DO NOTHING;

COMMIT;
