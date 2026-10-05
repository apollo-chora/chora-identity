-- =============================================================================
-- chora-identity : 0025_app_rw_nobypassrls.up.sql
--
-- ADR-194 D1 / WS2 (CHO-1872) — make the RLS-ENFORCED invariant EXPLICIT for
-- `chora_identity_app_rw`, mirroring chora-tenancy migration 0013.
--
-- WHY
--   ADR-194 D1 (operator cross-tenant membership grant) relies on the
--   `tenant_memberships` `tenant_isolation` policy (0001_initial.sql:116,
--   `FOR ALL USING (tenant_id = current_setting('chora.tenant_id', true)::uuid)`)
--   to make the operator grant RLS-COMPLIANT: the grant runs inside
--   `RunInTenantTx(body.tenant_id)`, so the written row's tenant_id equals the
--   GUC and the policy's WITH CHECK passes — cross-tenant AUTHORIZATION, never
--   an RLS bypass. That property holds ONLY if `chora_identity_app_rw` does not
--   carry the `BYPASSRLS` role attribute.
--
--   `app_rw` is NOBYPASSRLS by DEFAULT (it is not a table owner and holds no
--   BYPASSRLS grant — `9999_grant_app_roles.sql` documents the invariant), so
--   this migration is DEFENSE-IN-DEPTH, not a functional prerequisite. It
--   pins the invariant in version control so a future out-of-band
--   `ALTER ROLE ... BYPASSRLS` (the chora-tenancy 0013 incident) cannot
--   silently re-open a cross-tenant hole undetected.
--
-- FAIL-SOFT ON PRIVILEGE (migration-runner-failfast lesson)
--   `ALTER ROLE ... NOBYPASSRLS` needs CREATEROLE on the executing role. The
--   13-DB ordered runner halts the WHOLE remaining chain on the first hard
--   error, so a privilege error here would strand every downstream DB. Because
--   the target posture is ALREADY the default, we fail SOFT: catch
--   insufficient_privilege and emit a NOTICE instead of erroring. The security
--   property is unchanged (still NOBYPASSRLS by default); we only forgo the
--   explicit pin in environments whose migrate role cannot ALTER ROLE.
--
-- IDEMPOTENT — ALTER ROLE ... NOBYPASSRLS is a no-op when the role already
-- lacks BYPASSRLS. Safe to re-run under the runner dedup table.
--
-- HARD RULE: cross-database queries forbidden. This touches only the
-- chora_identity-local `chora_identity_app_rw` role.
-- =============================================================================

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'chora_identity_app_rw') THEN
    ALTER ROLE chora_identity_app_rw NOBYPASSRLS;
    RAISE NOTICE 'chora_identity_app_rw set NOBYPASSRLS (ADR-194 D1 defense-in-depth)';
  ELSE
    RAISE NOTICE 'chora_identity_app_rw absent — skipping NOBYPASSRLS (dev/local)';
  END IF;
EXCEPTION WHEN insufficient_privilege THEN
  RAISE NOTICE 'insufficient privilege to ALTER ROLE chora_identity_app_rw NOBYPASSRLS — skipping (default posture is already NOBYPASSRLS)';
END $$;

-- =============================================================================
-- VERIFICATION (run manually after apply, with the migrate DSN):
--   SELECT rolname, rolbypassrls FROM pg_roles WHERE rolname = 'chora_identity_app_rw';
--   -- expect: rolbypassrls = f
-- =============================================================================
