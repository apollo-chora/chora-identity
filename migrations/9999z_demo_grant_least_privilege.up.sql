-- =============================================================================
-- chora-identity : 9999z_demo_grant_least_privilege.up.sql
--
-- Domain        : Identity (supporting/platform)
-- Database      : chora_identity
-- Author        : agent A-Demo-Mana-Grant (demo-mode mana top-up, round-3 fixes)
-- Date          : 2026-10-09
--
-- WHY THIS FILE EXISTS (and why it sorts after 9999)
--   `9999_grant_app_roles.sql` hands out blanket privileges to the two runtime
--   roles — `GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO app_rw, app_ro`
--   plus `ALTER DEFAULT PRIVILEGES ... GRANT EXECUTE ON FUNCTIONS TO app_rw,
--   app_ro` and `... GRANT SELECT ON TABLES TO app_ro`. It is the LAST file in
--   lex order, so on a fresh database it re-grants exactly the two privileges
--   migration 0044 removed for the demo-grant axis:
--
--     * EXECUTE on public.mana_demo_grant_total_units() to the READ-ONLY role.
--       That function is SECURITY DEFINER and reads across GCIDs by design; a
--       read-only reporting role has no business holding it.
--     * SELECT on public.demo_grant_budget to the read-only role (via the
--       default privileges for tables created by chora_identity_migrate).
--
--   0044 cannot fix that on a fresh install (it runs first) and 9999 cannot be
--   edited (it is already applied on live databases, and the migration runner
--   rejects a modified file by SHA-256). So the least-privilege posture is
--   re-asserted here, AFTER the blanket grant: the end state is identical
--   whether or not 0044 ran before 9999, on a fresh database and on an
--   already-migrated one.
--
--   The `9999z` prefix keeps this file after 9999_grant_app_roles.sql under
--   every collation (the 0013z_drop_stray_role_catalog precedent). Any future
--   blanket-grant migration must sort before it, or repeat this revoke.
--
-- Idempotent: REVOKE/GRANT are idempotent, and every statement is guarded on
-- the object/role existing — a rolled-back demo axis (0044 down) or a database
-- without the app roles is a NOTICE, not a failed chain.
--
-- HARD RULE: cross-database queries forbidden. This touches only chora_identity.
-- =============================================================================

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'chora_identity_app_ro') THEN
        IF to_regprocedure('public.mana_demo_grant_total_units()') IS NOT NULL THEN
            EXECUTE 'REVOKE EXECUTE ON FUNCTION public.mana_demo_grant_total_units() FROM chora_identity_app_ro';
        END IF;
        IF to_regclass('public.demo_grant_budget') IS NOT NULL THEN
            EXECUTE 'REVOKE ALL ON public.demo_grant_budget FROM chora_identity_app_ro';
        END IF;
    END IF;

    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'chora_identity_app_rw') THEN
        IF to_regprocedure('public.mana_demo_grant_total_units()') IS NOT NULL THEN
            EXECUTE 'GRANT EXECUTE ON FUNCTION public.mana_demo_grant_total_units() TO chora_identity_app_rw';
        END IF;
        IF to_regclass('public.demo_grant_budget') IS NOT NULL THEN
            EXECUTE 'GRANT SELECT, INSERT, UPDATE ON public.demo_grant_budget TO chora_identity_app_rw';
        END IF;
    END IF;
END $$;

-- =============================================================================
-- VERIFICATION (run manually after apply, with the migrate DSN):
--   SELECT has_function_privilege('chora_identity_app_ro',
--            'public.mana_demo_grant_total_units()', 'EXECUTE');   -- expect: f
--   SELECT has_function_privilege('chora_identity_app_rw',
--            'public.mana_demo_grant_total_units()', 'EXECUTE');   -- expect: t
--   SELECT has_table_privilege('chora_identity_app_ro',
--            'public.demo_grant_budget', 'SELECT');                -- expect: f
-- =============================================================================
