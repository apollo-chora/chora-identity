-- =============================================================================
-- chora-identity : 0032_mana_action_pricing_ceremony_edge_scout.up.sql
--
-- Story           : CHO-2040 — ceremony edge-scout runner (CR §8 R7-3) +
--                   owner ruling R8-1 (2026-07-04): first run per goal FREE,
--                   re-runs 25.
-- Domain          : Identity (supporting)  /  Database : chora_identity
-- Date            : 2026-07-04
--
-- Purpose:
--   Seed the flat mana_action_pricing catalogue floor for the TWO ceremony
--   edge-scout action codes (same single-table shape as 0010's chat tiers +
--   0031's familiar_skill_* floor):
--
--     familiar_ceremony_edge_scout        25  — a RE-RUN of the ceremony
--         growth-edge scout for a goal (one crawl + one fenced extraction
--         turn; the runner stamps the code, the model-gateway is the sole
--         debiter per ADR-177).
--     familiar_ceremony_edge_scout_first   0  — the FIRST run per (tenant,
--         goal, learner), owner-ruled FREE (R8-1). Zero-cost rows are an
--         established shape here (quiz_me / map_sight / progress_mirror … =
--         0; the schema CHECK is mana_cost >= 0): the turn is still stamped
--         + metered at the gateway (IMDA D3 — never an un-metered LLM turn),
--         it just debits 0. Scoping lives consumption-side in the
--         ceremony_edge_scout_runs ledger (chora_consumption migration 0067)
--         — chora_identity prices codes, it does not track runs.
--
--   This closes the ⚠ flagged in 51c40bbf2 (propose runner shipped with the
--   consumption-side provisional 25 but NO authoritative identity seed).
--   Both codes are editor-tunable via the ADR-178 PricePlanResolver later (a
--   tenant override / platform plan rule wins over this floor).
--
--   Purely ADDITIVE + idempotent — one INSERT ... ON CONFLICT
--   (action_code, effective_from) DO NOTHING (see 0002 §222 PK shape + 0010 +
--   0031). No existing action_code is touched. HARD RULE: cross-database
--   queries forbidden; all objects local to chora_identity. GRANTs delegated
--   to 9999_grant_app_roles.sql. Do NOT apply manually — migrations
--   auto-apply at deploy.
-- =============================================================================

BEGIN;

INSERT INTO mana_action_pricing (action_code, mana_cost, description) VALUES
    ('familiar_ceremony_edge_scout',       25,
        'Ceremony edge-scout RE-RUN: the Familiar re-crawls past learning signals and proposes growth edges at the goal binding ceremony (one extraction turn).'),
    ('familiar_ceremony_edge_scout_first',  0,
        'Ceremony edge-scout FIRST run per goal: owner-ruled free (R8-1, 2026-07-04). Metered at the gateway, debits 0; first-run scoping lives in chora_consumption.ceremony_edge_scout_runs.')
ON CONFLICT (action_code, effective_from) DO NOTHING;

COMMIT;

-- =============================================================================
-- VERIFICATION (run manually after apply):
--   SELECT action_code, mana_cost FROM mana_action_pricing
--    WHERE action_code LIKE 'familiar_ceremony_edge_scout%'
--    ORDER BY action_code;                              -- => 2 rows (25, 0)
-- =============================================================================
