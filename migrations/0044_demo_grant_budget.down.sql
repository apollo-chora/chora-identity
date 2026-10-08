-- =============================================================================
-- chora-identity : 0044_demo_grant_budget.down.sql
--
-- Best-effort reverse of 0044. DESTRUCTIVE — never run on a fresh database (the
-- migration runner skips *.down.sql; this file is for a deliberate manual
-- rollback of the demo-grant budget axis).
--
-- What it reverses:
--   1. the budget counters are dropped (their contents are demo accounting, and
--      the ledger keeps the authoritative record of every grant);
--   2. the helper is dropped outright rather than restored to its 0043 shape:
--      it exists only for the demo-grant budget axis, and leaving a SECURITY
--      DEFINER function behind after the feature is rolled back would be an
--      unjustified privilege (same reasoning as 0043_mana_reason_demo_grant.down);
--   3. the narrow owner role, its ledger policy and its grants go with it.
--
-- PostgreSQL cannot remove an ENUM value, so 'demo_grant' STAYS on mana_reason
-- (harmless, additive metadata — see 0043's down file).
--
-- Cross-DB queries forbidden — chora-identity touches only chora_identity.
-- =============================================================================

BEGIN;

DROP TABLE IF EXISTS demo_grant_budget;

DROP POLICY IF EXISTS demo_grant_budget_read ON public.mana_ledger;

DROP FUNCTION IF EXISTS public.mana_demo_grant_total_units();

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'chora_identity_demo_budget') THEN
        EXECUTE 'REVOKE ALL ON public.mana_ledger FROM chora_identity_demo_budget';
        EXECUTE 'REVOKE ALL ON SCHEMA public FROM chora_identity_demo_budget';
        EXECUTE 'DROP ROLE chora_identity_demo_budget';
    END IF;
END $$;

COMMIT;
