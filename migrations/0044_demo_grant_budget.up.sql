-- =============================================================================
-- chora-identity : 0044_demo_grant_budget.up.sql
--
-- Domain        : Identity (supporting/platform)
-- Database      : chora_identity
-- Author        : agent A-Demo-Mana-Grant (demo-mode mana top-up, round-3 fixes)
-- Date          : 2026-10-09
--
-- Purpose:
--   Two ADDITIVE effects, both for the demo mana grant:
--
--     1. `demo_grant_budget` — the RESERVED/CONSUMED counters the demo-grant
--        endpoint charges INSIDE the transaction that credits the wallet:
--        key `global` is the platform-wide budget, key `gcid:<uuid>` is one
--        account's allowance. A counter is used instead of aggregating
--        `mana_ledger` because the check has to be serialized against
--        concurrent credits, and `sum(units) WHERE reason = 'demo_grant'` is
--        neither bounded nor lockable. Both rows are locked
--        `SELECT ... FOR UPDATE` before the check and charged after the ledger
--        row is written, so a rejected grant can never consume budget and a
--        concurrent pair can never overshoot.
--
--        The seed grant (cmd/seed, one-time account provisioning) deliberately
--        does NOT touch these rows: seeding a demo account must not eat the
--        interactive budget the demo button draws from. This is why the two
--        uses of `demo_grant` do not collide even though they share the reason.
--
--     2. Reconciliation of the counters with the demo_grant rows that PREDATE
--        this migration (see 1b below): on a live database upgraded in place,
--        every interactive demo_grant row is charged and every seed row is
--        not, so the counters end up consistent with the ledger.
--
--     3. The hardened `mana_demo_grant_total_units()` helper. Migration 0043
--        created it with `SET search_path = public, pg_temp`, an unqualified
--        body, the default (migration-role) owner and EXECUTE for the
--        read-only `chora_identity_app_ro` role. 0043 is already applied on
--        live databases and the migration runner refuses a modified file
--        (SHA-256 in `schema_migrations`), so the tightening happens HERE with
--        `CREATE OR REPLACE` — the same end state on a fresh database and on an
--        already-migrated one:
--
--          * body fully schema-qualified (public.mana_ledger, public.mana_reason)
--            with `search_path = pg_catalog, pg_temp`, so no caller-controlled
--            search_path can redirect the read;
--          * owned by a dedicated NOLOGIN role `chora_identity_demo_budget`
--            (NOSUPERUSER, NOCREATEDB, NOCREATEROLE, NOBYPASSRLS) instead of the
--            migration role. The narrow owner is NOT the table owner, so RLS
--            still applies to it and its elevated view is exactly the
--            role-targeted `demo_grant_budget_read` policy below — the
--            demo_grant rows and nothing else;
--          * EXECUTE for `chora_identity_app_rw` only: revoked from PUBLIC and
--            from the read-only `chora_identity_app_ro`.
--
--   Idempotent: CREATE TABLE IF NOT EXISTS / ON CONFLICT DO UPDATE (the
--   reconciliation re-asserts counters == interactive ledger rows) /
--   CREATE OR REPLACE FUNCTION / role-existence guards. 9999_grant_app_roles.sql
--   re-grants EXECUTE on every function in schema public to app_rw AND app_ro
--   and runs LAST in lex order, so the app_ro revoke is re-asserted by
--   9999z_demo_grant_least_privilege.up.sql.
--
-- HARD RULE: cross-database queries forbidden. This touches only chora_identity.
-- =============================================================================

BEGIN;

-- -----------------------------------------------------------------------------
-- 1. Demo-grant budget counters.
--
-- No RLS: this table holds no user data (a platform counter and one counter per
-- account that claimed demo grants), and the credit transaction touches both
-- rows inside the caller's RLS-scoped transaction — an RLS policy here would
-- make the global row unreadable and the whole budget unenforceable.
-- -----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS demo_grant_budget (
    budget_key      TEXT        PRIMARY KEY,
    consumed_units  BIGINT      NOT NULL DEFAULT 0,
    consumed_grants BIGINT      NOT NULL DEFAULT 0,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT demo_grant_budget_units_non_negative  CHECK (consumed_units >= 0),
    CONSTRAINT demo_grant_budget_grants_non_negative CHECK (consumed_grants >= 0)
);

COMMENT ON TABLE demo_grant_budget IS
    'Reserved/consumed counters for the INTERACTIVE demo mana grant (POST /api/v1/me/mana/demo-grant). budget_key=''global'' is the platform-wide budget; budget_key=''gcid:<uuid>'' is one account''s allowance. The one-time seed grant (cmd/seed) does not touch these rows.';

COMMENT ON COLUMN demo_grant_budget.consumed_units IS
    'Demo-grant units already committed. Never reset downwards; a grant is charged only after its ledger row is written, in the same transaction.';

-- The platform-wide row always exists, so the credit path only ever locks it.
--
-- -----------------------------------------------------------------------------
-- 1b. Reconcile the counters with the demo_grant rows that PREDATE this
--     migration.
--
-- 0044 is applied on live databases that may ALREADY carry demo_grant ledger
-- rows: the one-time seed grant (cmd/seed) and — if the endpoint was enabled
-- between 0043 and 0044 — interactive grants. Seed rows are excluded by
-- design (the seed must never eat the interactive budget — see the note on
-- demo_grant_budget above); every other demo_grant row is an interactive
-- grant and MUST be charged, otherwise this migration would silently reset
-- the budget to 0 and hand already-granted mana back to every caller.
--
-- ON CONFLICT DO UPDATE, not DO NOTHING: the ledger is the only source of
-- truth for what has been granted, so re-asserting the invariant
-- (counters == interactive ledger rows) on re-run is the correct behaviour.
-- -----------------------------------------------------------------------------

WITH interactive AS (
    SELECT l.gcid, sum(l.units)::bigint AS units, count(*) AS grants
      FROM public.mana_ledger AS l
     WHERE l.reason = 'demo_grant'::public.mana_reason
       AND l.idempotency_key NOT LIKE 'demo-seed:v1:%'
     GROUP BY l.gcid
),
reconciled AS (
    SELECT 'gcid:'::text || i.gcid::text AS budget_key, i.units, i.grants
      FROM interactive AS i
    UNION ALL
    SELECT 'global'::text, COALESCE(sum(i.units), 0), COALESCE(sum(i.grants), 0)
      FROM interactive AS i
)
INSERT INTO demo_grant_budget (budget_key, consumed_units, consumed_grants)
SELECT r.budget_key, r.units, r.grants
  FROM reconciled AS r
ON CONFLICT (budget_key) DO UPDATE SET
    consumed_units  = EXCLUDED.consumed_units,
    consumed_grants = EXCLUDED.consumed_grants,
    updated_at      = now();

-- Runtime privileges: the app role must read, create (lazily, for a first-time
-- GCID) and charge both rows. Nothing else may touch them.
GRANT SELECT, INSERT, UPDATE ON demo_grant_budget TO chora_identity_app_rw;
REVOKE ALL ON demo_grant_budget FROM PUBLIC;
REVOKE ALL ON demo_grant_budget FROM chora_identity_app_ro;

-- -----------------------------------------------------------------------------
-- 2. Narrow owner for the cross-GCID demo-grant read.
--
-- Creating the role needs CREATEROLE on the executing role. Where that is
-- unavailable (a constrained production migrate role) the creation fails SOFT
-- with a NOTICE rather than halting the whole migration chain for a demo-mode
-- hardening — the 0025_app_rw_nobypassrls precedent.
-- -----------------------------------------------------------------------------

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'chora_identity_demo_budget') THEN
        BEGIN
            CREATE ROLE chora_identity_demo_budget
                NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
        EXCEPTION WHEN insufficient_privilege THEN
            RAISE NOTICE 'chora-identity 0044: no CREATEROLE — chora_identity_demo_budget not created; the helper keeps its previous owner';
        END;
    END IF;
END $$;

-- The narrow owner's entire access: USAGE on the schema, SELECT on the ledger
-- table, and a role-targeted policy that limits what that SELECT can see to the
-- demo_grant rows. Permissive policies OR together, so this widens visibility
-- for that one role only — every other role keeps the user_isolation scope.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'chora_identity_demo_budget') THEN
        EXECUTE 'GRANT USAGE ON SCHEMA public TO chora_identity_demo_budget';
        EXECUTE 'GRANT SELECT ON public.mana_ledger TO chora_identity_demo_budget';
        IF NOT EXISTS (
            SELECT 1 FROM pg_policies
             WHERE schemaname = 'public'
               AND tablename  = 'mana_ledger'
               AND policyname = 'demo_grant_budget_read'
        ) THEN
            EXECUTE $policy$
                CREATE POLICY demo_grant_budget_read ON public.mana_ledger
                    FOR SELECT TO chora_identity_demo_budget
                    USING (reason = 'demo_grant'::public.mana_reason)
            $policy$;
        END IF;
    END IF;
END $$;

-- -----------------------------------------------------------------------------
-- 3. The helper, tightened. `pg_catalog, pg_temp` — NOT public — plus a fully
--    schema-qualified body: nothing a caller can set can change what this reads.
-- -----------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION public.mana_demo_grant_total_units()
RETURNS bigint
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
    SELECT COALESCE(sum(l.units), 0)::bigint
      FROM public.mana_ledger AS l
     WHERE l.reason = 'demo_grant'::public.mana_reason;
$$;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'chora_identity_demo_budget') THEN
        EXECUTE 'ALTER FUNCTION public.mana_demo_grant_total_units() OWNER TO chora_identity_demo_budget';
    END IF;
END $$;

REVOKE ALL ON FUNCTION public.mana_demo_grant_total_units() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.mana_demo_grant_total_units() FROM chora_identity_app_ro;
GRANT EXECUTE ON FUNCTION public.mana_demo_grant_total_units() TO chora_identity_app_rw;

COMMIT;

-- =============================================================================
-- VERIFICATION (run manually after apply, with the migrate DSN):
--   SELECT * FROM demo_grant_budget;                       -- the 'global' row + one row per GCID with pre-0044 INTERACTIVE grants; seed-only GCIDs have no row
--   SELECT mana_demo_grant_total_units();                  -- the demo_grant total (seed rows included)
--   \df+ public.mana_demo_grant_total_units                 -- owner + ACL
--   SELECT proconfig FROM pg_proc WHERE proname = 'mana_demo_grant_total_units';
--   -- expect: {search_path=pg_catalog, pg_temp}
-- =============================================================================
