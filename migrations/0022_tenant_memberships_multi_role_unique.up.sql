-- =============================================================================
-- chora-identity : 0022_tenant_memberships_multi_role_unique.up.sql
--
-- Domain        : Identity (tenant membership mirror)
-- Database      : chora_identity
-- Contract      : services/chora-identity/internal/adapter/pg/membership_admin_repository.go
--                 (`MembershipAdminRepository.ChangeRole`)
-- Story         : sibling of CHO-1809 — multi-role memberships in the chora_identity
--                 mirror: widen unique constraint from (gcid, tenant_id) to
--                 (gcid, tenant_id, role) so a single (gcid, tenant) pair can
--                 hold >=1 role row (e.g. LEARNER + INSTRUCTOR).
-- Date          : 2026-06-21 (idempotency rewrite 2026-06-22)
--
-- Purpose:
--   `MembershipAdminRepository.ChangeRole` issues an upsert with
--   `ON CONFLICT (gcid, tenant_id, role)`, which requires a non-partial unique
--   index OR constraint on EXACTLY (gcid, tenant_id, role).
--
-- IDEMPOTENCY REWRITE (2026-06-22):
--   The original migration did a bare `DROP CONSTRAINT
--   tenant_memberships_gcid_tenant_id_key` + `ADD CONSTRAINT ...`. On the live
--   chora_identity DB that legacy (gcid, tenant_id) constraint NEVER existed
--   (the table already enforces (gcid, tenant_id, role) uniqueness via the
--   UNIQUE INDEX `uq_tenant_memberships_gcid_tenant_role`). The bare DROP threw
--   `constraint ... does not exist` — a hard error (NOT "does not exist,
--   skipping") that FATAL'd the migrations runner at the FIRST service
--   (chora-identity), stranding every downstream service's migrations across
--   all 12 DBs (root cause of CHO-1819's missing chora_creation migration
--   0018). This rewrite is fully idempotent + reality-aligned:
--     1. Drop the legacy narrow (gcid, tenant_id) uniqueness in EITHER form
--        (constraint or standalone index) with IF EXISTS — no-op when absent.
--     2. Ensure (gcid, tenant_id, role) uniqueness via CREATE UNIQUE INDEX
--        IF NOT EXISTS, matching the name the live schema already uses. A unique
--        index satisfies `ON CONFLICT (gcid, tenant_id, role)` identically to a
--        constraint. No-op on the live DB; converges any drifted env that lacks
--        it. (dup_rows verified 0 on the live DB before this lands.)
--
-- Compatibility notes:
--   - Existing rows trivially satisfy the (gcid, tenant_id, role) uniqueness
--     (it is strictly weaker than the legacy (gcid, tenant_id) form).
--   - Soft delete equivalent: the table uses `status='inactive'`; ChangeRole
--     deactivates the prior role row + upserts the new one in one transaction.
-- =============================================================================

BEGIN;

-- 1. Drop the legacy narrow (gcid, tenant_id) uniqueness if present, in either
--    form. IF EXISTS makes both a no-op when the object is absent (the live
--    chora_identity case) so the runner never sees a hard error.
ALTER TABLE tenant_memberships DROP CONSTRAINT IF EXISTS tenant_memberships_gcid_tenant_id_key;
DROP INDEX IF EXISTS tenant_memberships_gcid_tenant_id_key;

-- 2. Ensure the (gcid, tenant_id, role) uniqueness the ChangeRole upsert needs.
--    CREATE UNIQUE INDEX IF NOT EXISTS is fully idempotent; the name matches the
--    index already present on the live DB, so this is a no-op there and a
--    convergence step on any env missing it.
CREATE UNIQUE INDEX IF NOT EXISTS uq_tenant_memberships_gcid_tenant_role
  ON tenant_memberships (gcid, tenant_id, role);

COMMIT;
