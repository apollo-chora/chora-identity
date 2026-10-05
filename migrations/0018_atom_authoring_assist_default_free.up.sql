-- =============================================================================
-- chora-identity : 0018_atom_authoring_assist_default_free.up.sql
--
-- ADR             : ADR-178 — Configurable mana price-plan rules layer (H+)
-- Jira            : CHO-1661 (FU-4b — meter the qgen crew authoring path)
-- Domain          : Identity (supporting)  /  Database : chora_identity
-- Date            : 2026-06-06
--
-- Purpose:
--   FU-4(b) meters the single-mode AI Assist qgen crew (POST /api/atoms/ai-assist)
--   via the price-plan layer, debiting the `atom_authoring_assist` action with
--   Units==0 (server-resolved). This migration registers a PLATFORM-DEFAULT rule
--   of 0 mana (FREE) for that action so the crew is free by default — a tenant
--   admin turns metering on by overriding the price (e.g. connectivity test at
--   1 mana), and "revert to free" = remove the tenant override (falls back to
--   this default-0 rule).
--
--   atom_authoring_assist is already registered in mana_action_def (migration
--   0017 seed; category=authoring, meter_home gateway — informational, the debit
--   is issued by chora-creation). This migration only adds the price rule.
--
--   Purely ADDITIVE + idempotent + price-neutral (0 = the current free state).
--
--   HARD RULE: cross-database queries forbidden. Local to chora_identity.
--   Apply manually with the `…-migrate` (owner) role — auto-apply is broken
--   (CHO-1663). Record in chora_runner_schema_migrations after applying.
-- =============================================================================

BEGIN;

-- Ensure the action def exists (idempotent — already seeded in 0017).
INSERT INTO mana_action_def (action_code, display_name, category, refundable, per_item, meter_home, tier_aware)
VALUES ('atom_authoring_assist', 'Atom Authoring Assist', 'authoring', TRUE, FALSE, 'gateway', FALSE)
ON CONFLICT (action_code) DO NOTHING;

-- Platform-default-plan rule: atom_authoring_assist = 0 (FREE by default).
-- Resolution precedence makes a tenant override win over this; with no override
-- the crew resolves to 0 = a no-op debit (free).
INSERT INTO mana_price_rule (plan_id, action_code, tier, mana_cost, note)
SELECT dp.plan_id, 'atom_authoring_assist', NULL, 0,
       'FU-4b crew authoring default — free; tenant override turns metering on'
  FROM (
      SELECT plan_id FROM mana_price_plan
       WHERE plan_code = 'default' AND scope = 'platform' AND status = 'active'
       LIMIT 1
  ) dp
ON CONFLICT (plan_id, action_code, tier) DO NOTHING;

COMMIT;

-- VERIFICATION (run after apply):
--   SELECT r.action_code, r.mana_cost FROM mana_price_rule r
--     JOIN mana_price_plan pp ON pp.plan_id = r.plan_id
--    WHERE pp.scope='platform' AND pp.status='active'
--      AND r.action_code='atom_authoring_assist';
--   -- => atom_authoring_assist | 0
