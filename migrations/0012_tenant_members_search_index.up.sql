-- =============================================================================
-- chora-identity : 0012_tenant_members_search_index.up.sql
--
-- Domain        : Identity (supporting/platform)
-- Database      : chora_identity
-- Contract      : chora-contracts/openapi/identity-admin.yaml::searchTenantMembers
-- Operation     : GET /api/v1/admin/tenant-members?q=...&role=...
-- Date          : 2026-05-16 (B6.1 — assessment cohort `invited_gcids[]` picker)
--
-- Adds indexes to support the case-insensitive substring search performed by
-- the `searchTenantMembers` operation. The query (per
-- internal/adapter/pg/tenant_member_search.go) joins
--   tenant_memberships tm  (RLS — current_setting('chora.tenant_id'))
--   JOIN users u USING (gcid)
--   LEFT JOIN closure_sagas cs ON cs.gcid = u.gcid AND cs.state IN (...)
-- and filters by LOWER(u.email) LIKE '%q%' OR LOWER(u.display_name) LIKE '%q%'
-- with ORDER BY u.updated_at DESC NULLS LAST, u.display_name ASC.
--
-- The `idx_users_email` UNIQUE INDEX from 0001_initial.sql already covers
-- `lower(email)` for equality; we additionally provide a btree on
-- `lower(display_name)` and a btree on `updated_at DESC` so the sort step
-- can stream sorted rows without a sort-on-the-fly under tablet-load demo
-- traffic.
--
-- Substring (`LIKE '%...%'`) cannot use a plain btree — at the tens-of-
-- thousands-of-users-per-tenant scale we will add `pg_trgm` GIN indexes
-- (operator class `gin_trgm_ops` on lower(email) + lower(display_name)).
-- For the M13 demo (4-5 seeded users per tenant) the planner falls back to
-- a seq scan over the RLS-filtered set which is well below the 6s gateway
-- timeout. M14.x scale path is tracked separately.
--
-- Cross-DB queries forbidden — chora-identity reads only chora_identity.
-- =============================================================================

BEGIN;

-- Sort-key index: ORDER BY u.updated_at DESC NULLS LAST is the canonical
-- "most recently active first" sort. The contract field on TenantMemberSummary
-- is `last_active_at`; until we add a denormalised `users.last_active_at`
-- column (M14.x — backfill via Pub/Sub from /me + session events), we proxy
-- it via `users.updated_at` which is bumped on every MarkKycVerified +
-- Suspend + Close + UPSERT (see user_repository.go::Save). For the picker UX
-- this is good enough — the contract field is documented as best-effort.
CREATE INDEX IF NOT EXISTS idx_users_updated_at_desc
    ON users (updated_at DESC NULLS LAST)
    WHERE deleted_at IS NULL;

-- Display-name lookup: btree on lower(display_name) for the picker chip-search
-- (typed >= 3 chars). Substring matches still seq-scan but display_name= prefix
-- equality leverages this index when the FE switches to leading-anchor search.
CREATE INDEX IF NOT EXISTS idx_users_display_name_lower
    ON users (lower(display_name))
    WHERE deleted_at IS NULL AND display_name <> '';

COMMIT;
