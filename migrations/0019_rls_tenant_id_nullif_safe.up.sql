-- =============================================================================
-- chora-identity : 0019_rls_tenant_id_nullif_safe.up.sql
--
-- ADR             : ADR-178 / CHO-1661 (FU-4b) — fixes a latent RLS bug exposed
--                   by the units==0 resolve-then-debit price-plan path.
-- Domain          : Identity (supporting)  /  Database : chora_identity
-- Date            : 2026-06-06
--
-- Bug:
--   `chora.tenant_id` is a Postgres PLACEHOLDER GUC (dotted custom param with no
--   defined default). After a `SET LOCAL chora.tenant_id = '<uuid>'` transaction
--   commits, the GUC reverts to the placeholder RESET VALUE — the EMPTY STRING
--   '' (NOT NULL) — on that pooled connection. A later transaction that does NOT
--   set chora.tenant_id (e.g. the per-user mana debit, which sets only
--   chora.user_gcid via RunInUserTx) then inherits chora.tenant_id = '' on the
--   reused connection. The 0003 tenant_isolation policies cast it UNCONDITIONALLY
--   — `current_setting('chora.tenant_id', true)::uuid` — so ''::uuid raises
--   22P02 (invalid input syntax for type uuid: "").
--
--   This was dormant until FU-4b: the units==0 price-plan resolution runs
--   RunInTenantTx (setting chora.tenant_id) immediately BEFORE the debit's
--   ListAllocations, polluting the connection's GUC to '' for the debit. An
--   explicit Units>0 debit never runs RunInTenantTx, so it never triggered this.
--
-- Fix:
--   Make the two tenant-casting RLS policies NULLIF-safe so the placeholder ''
--   reset value resolves to NULL (no rows match — falls back to personal
--   balance / no cross-tenant leak) instead of 22P02-ing:
--     current_setting('chora.tenant_id', true)::uuid
--       → NULLIF(current_setting('chora.tenant_id', true), '')::uuid
--
--   Tables: mana_subsidy_allocations.tenant_isolation, user_subscriptions.tenant_isolation
--   (both from 0003_user_economy_rls.sql). The user_isolation policies (keyed on
--   chora.user_gcid) are unchanged. Behaviour-preserving for a correctly-scoped
--   tenant; only changes the empty/unset case from "error" to "no tenant rows".
--
--   Apply manually with the `…-migrate` (owner) role (auto-apply broken, CHO-1663).
-- =============================================================================

BEGIN;

-- mana_subsidy_allocations — FOR ALL USING (tenant scope)
DROP POLICY IF EXISTS tenant_isolation ON mana_subsidy_allocations;
CREATE POLICY tenant_isolation ON mana_subsidy_allocations
    FOR ALL USING (tenant_id = NULLIF(current_setting('chora.tenant_id', true), '')::uuid);

-- user_subscriptions — preserve the exact 0003 shape (tenant_id IS NULL OR
-- tenant matches); only make the tenant cast NULLIF-safe.
DROP POLICY IF EXISTS tenant_isolation ON user_subscriptions;
CREATE POLICY tenant_isolation ON user_subscriptions
    FOR ALL USING (
        tenant_id IS NULL
        OR tenant_id = NULLIF(current_setting('chora.tenant_id', true), '')::uuid
    );

COMMIT;

-- VERIFICATION (after apply): a units==0 priced debit that runs price resolution
-- before the wallet debit no longer 22P02s on ListAllocations; the policy yields
-- NULL (no allocation rows) when chora.tenant_id is '' / unset.
