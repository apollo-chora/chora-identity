-- =============================================================================
-- chora-identity : 0012_tenant_members_search_index.down.sql
--
-- Rolls back 0012_tenant_members_search_index.up.sql. The DROP INDEX
-- commands are idempotent (IF EXISTS) so re-running is safe.
-- =============================================================================

BEGIN;

DROP INDEX IF EXISTS idx_users_display_name_lower;
DROP INDEX IF EXISTS idx_users_updated_at_desc;

COMMIT;
