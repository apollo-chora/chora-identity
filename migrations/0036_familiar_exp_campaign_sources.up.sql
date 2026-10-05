-- =============================================================================
-- chora-identity : 0036_familiar_exp_campaign_sources.up.sql
--
-- ADR             : ADR-227 D10 — Familiar Campaign fog-of-war KG conquest:
--                   XP verified-events-only, resolver-priced, daily-capped,
--                   content-blind (+ Verification addendum #6: goal routing).
-- Related         : ADR-201 §5 (ExpRuleResolver) · ADR-203 L16 (verified-EXP)
--                   · ADR-218 D6 (one EXP economy, parity contract) ·
--                   ADR-228 D4 (XP wave table cross-reference).
-- Jira            : CHO-2084 (WS-C5 — campaign XP rules + caps)
-- Domain          : Identity (supporting)  /  Database : chora_identity
-- Parity mirror   : chora-consumption internal/domain/growth/curve.go +
--                   exp_rules_test.go identityParitySeed (campaign block)
-- Date            : 2026-07-09
--
-- Purpose:
--   Register the four NEW campaign conquest EXP sources in the exp_source_def
--   catalogue (migration 0027 schema) so the live ExpRuleResolver prices them:
--
--     campaign_rung_cleared    B   8 / 32   ladder rung first-clear (small, flat)
--     campaign_rung_refreshed  C   3 / 12   refresher re-clear (reduced, D10)
--     campaign_node_won        B  25 / 75   6/6 rungs — the win moment (≤3/day)
--     campaign_goal_sealed     S 120 / 120  verified frontier-clear seal (tier-S)
--
--   The seal's additional "~1/week" spacing (D10) is a code semantic in
--   consumption's campaign XP subscriber — exp_source_def carries daily caps
--   only, so the catalogue pins daily cap = value (max one seal award/day)
--   and the subscriber enforces the 7-day window per familiar.
--
--   PARITY CONTRACT (ADR-218 D6): the four value/cap pairs above mirror
--   chora-consumption growth/curve.go; consumption pins the same literals in
--   exp_rules_test.go, identity pins them in
--   familiar_exp_campaign_sources_migration_test.go. Do NOT change one side
--   alone.
--
--   INVARIANT (ADR-203 L16 — verified-EXP anti-gaming): every source is a
--   Chora-verified system event (the domain-emitted campaign.* topics; the
--   learner's bare PersonalCompletedAt never awards). This migration only
--   registers catalogue rows — it can never mint a self-declare source.
--
--   Purely additive: 4 INSERTs, no UPDATE, no deprecation.
--
--   HARD INVARIANT: idempotent + revertable. ON CONFLICT DO NOTHING for
--   re-apply safety. GRANTs are delegated to 9999_grant_app_roles.sql.
-- =============================================================================

BEGIN;

INSERT INTO exp_source_def
    (source_code, display_name, tier, default_exp_value, default_daily_cap, enabled)
VALUES
    ('campaign_rung_cleared',   'Campaign ladder rung first-clear',              'B', 8,   32,  TRUE),
    ('campaign_rung_refreshed', 'Campaign rung refresher re-clear (reduced)',    'C', 3,   12,  TRUE),
    ('campaign_node_won',       'Campaign node won — 6/6 rungs',                 'B', 25,  75,  TRUE),
    ('campaign_goal_sealed',    'Campaign goal sealed — verified frontier-clear','S', 120, 120, TRUE)
ON CONFLICT (source_code) DO NOTHING;

COMMIT;
