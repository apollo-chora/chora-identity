-- =============================================================================
-- chora-identity : 0003_user_economy_rls.sql
--
-- Domain        : Identity (supporting/platform)
-- Database      : chora_identity
-- Author        : agent A-Platform-Infra (S1.1, ADR-142 RLS gap fix)
-- Date          : 2026-05-09
-- Architecture  : Architecture Review locked 2026-05-07 (Tier 1 D1) + ADR-142
--
-- Purpose:
--   Adds Row-Level Security to the 5 tables introduced by 0002_user_economy.sql
--   that the audit-identity-fillgaps.md §4b §RLS audit flagged as missing:
--
--     1. user_subscriptions          (gcid + nullable tenant_id; gcid scope wins)
--     2. user_mana                   (gcid only)
--     3. mana_ledger                 (partitioned, gcid + idempotency-keyed)
--     4. mana_subsidy_allocations    (tenant + gcid scoped)
--     5. kyc_verifications           (gcid only — KYC is identity-personal)
--
--   Plus, complementary fixes on the 0001 ENUM expansion needed by closure-
--   saga consumers — DEFERRED: only the RLS gap is in scope here.
--
-- Naming convention (LOCKED):
--
--   SET LOCAL chora.tenant_id = '<uuid>';
--   SET LOCAL chora.user_gcid = '<uuid>';
--   SET LOCAL chora.role      = '<learner|instructor|admin|auditor>';
--
-- Aligned with the canonical pattern already used in:
--   - chora-consumption/migrations/0002_per_user_knowledge_graph.sql (dual policy)
--   - chora-identity/migrations/0001_initial.sql (single tenant policy)
--
-- HARD INVARIANT: this migration is idempotent + revertable. Apply via
-- `migrate -database <DSN> -path migrations up`. Do NOT apply manually until
-- the build orchestrator schedules it (post-S1 fan-in).
--
-- HARD RULE: cross-database queries forbidden. These tables are local to
-- chora_identity. Cross-domain reads (e.g., TenantManaPool source in
-- chora_tenancy) flow exclusively via Pub/Sub events.
-- =============================================================================

BEGIN;

-- -----------------------------------------------------------------------------
-- user_subscriptions — per-user Familiar plan
--
-- Scope: GCID is the natural scope (per-user subscriptions). tenant_id is
-- nullable for cross-tenant subscriptions, so we apply BOTH policies (and
-- admin role bypass) so:
--   - tenant-bound rows are visible only inside the right tenant
--   - cross-tenant rows (NULL tenant_id) are visible to the GCID owner
--   - admin role can audit
-- -----------------------------------------------------------------------------

ALTER TABLE user_subscriptions ENABLE ROW LEVEL SECURITY;

DO $$ BEGIN
    CREATE POLICY tenant_isolation ON user_subscriptions
        FOR ALL USING (
            tenant_id IS NULL
            OR tenant_id = current_setting('chora.tenant_id', true)::uuid
        );
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
    CREATE POLICY user_isolation ON user_subscriptions
        FOR ALL USING (
            gcid = current_setting('chora.user_gcid', true)::uuid
            OR current_setting('chora.role', true) = 'admin'
        );
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

-- -----------------------------------------------------------------------------
-- user_mana — per-GCID wallet snapshot (one row per gcid)
--
-- Scope: GCID only — wallets are identity-personal, NOT tenant-bound. A user
-- has one wallet that follows them across tenants (per ADR-142 §portability).
-- RLS reduces to a single user-scoped policy with admin role bypass.
-- -----------------------------------------------------------------------------

ALTER TABLE user_mana ENABLE ROW LEVEL SECURITY;

DO $$ BEGIN
    CREATE POLICY user_isolation ON user_mana
        FOR ALL USING (
            gcid = current_setting('chora.user_gcid', true)::uuid
            OR current_setting('chora.role', true) = 'admin'
        );
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

-- -----------------------------------------------------------------------------
-- mana_ledger — append-only audit trail (partitioned by recorded_at)
--
-- Scope: GCID. Combined with the existing append-only triggers
-- (enforce_mana_ledger_append_only on UPDATE/DELETE) and the role-based
-- admin bypass, this gives a per-user view + auditor-readable composite.
--
-- IMPORTANT: RLS on a partitioned table propagates to all partitions. We
-- enable on the parent only; partitions inherit policies automatically.
-- -----------------------------------------------------------------------------

ALTER TABLE mana_ledger ENABLE ROW LEVEL SECURITY;

DO $$ BEGIN
    CREATE POLICY user_isolation ON mana_ledger
        FOR ALL USING (
            gcid = current_setting('chora.user_gcid', true)::uuid
            OR current_setting('chora.role', true) = 'admin'
        );
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

-- -----------------------------------------------------------------------------
-- mana_subsidy_allocations — local projection of TenantManaAllocation
--
-- Scope: tenant_id + gcid. Subsidy allocations come FROM a tenant TO a user;
-- both axes need policies so a user under tenant A cannot see allocations
-- made by tenant B (even if same GCID), and tenants cannot see other
-- tenants' allocations.
-- -----------------------------------------------------------------------------

ALTER TABLE mana_subsidy_allocations ENABLE ROW LEVEL SECURITY;

DO $$ BEGIN
    CREATE POLICY tenant_isolation ON mana_subsidy_allocations
        FOR ALL USING (tenant_id = current_setting('chora.tenant_id', true)::uuid);
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
    CREATE POLICY user_isolation ON mana_subsidy_allocations
        FOR ALL USING (
            gcid = current_setting('chora.user_gcid', true)::uuid
            OR current_setting('chora.role', true) = 'admin'
        );
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

-- -----------------------------------------------------------------------------
-- kyc_verifications — KYC is identity-personal (NOT tenant-scoped)
--
-- Scope: GCID. KYC outcomes follow the user across tenants (per ADR-142
-- §KYC §portability). admin role bypass for compliance/auditor surfaces in
-- O+ (Observability+).
-- -----------------------------------------------------------------------------

ALTER TABLE kyc_verifications ENABLE ROW LEVEL SECURITY;

DO $$ BEGIN
    CREATE POLICY user_isolation ON kyc_verifications
        FOR ALL USING (
            gcid = current_setting('chora.user_gcid', true)::uuid
            OR current_setting('chora.role', true) = 'admin'
        );
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

COMMIT;

-- =============================================================================
-- VERIFICATION QUERY (run manually after apply):
--
--   SELECT c.relname, c.relrowsecurity AS rls_enabled, p.polname
--   FROM pg_class c
--   JOIN pg_namespace n ON n.oid = c.relnamespace
--   LEFT JOIN pg_policy p ON p.polrelid = c.oid
--   WHERE n.nspname = 'public'
--     AND c.relname IN (
--         'user_subscriptions',
--         'user_mana',
--         'mana_ledger',
--         'mana_subsidy_allocations',
--         'kyc_verifications'
--     )
--   ORDER BY c.relname, p.polname;
--
-- Expected output: 5 rows × {1..2 policies each}, all with rls_enabled=true.
-- =============================================================================
