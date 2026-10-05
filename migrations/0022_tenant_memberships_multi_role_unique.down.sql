-- =============================================================================
-- chora-identity : 0022_tenant_memberships_multi_role_unique.down.sql
--
-- Inverse of 0022_tenant_memberships_multi_role_unique.up.sql — restore the
-- narrower (gcid, tenant_id) constraint. Will FAIL if any (gcid, tenant_id)
-- pair currently holds more than one row (multi-role memberships must be
-- collapsed to a single row before rolling back).
-- =============================================================================

BEGIN;

ALTER TABLE tenant_memberships
  DROP CONSTRAINT tenant_memberships_gcid_tenant_id_role_key;

ALTER TABLE tenant_memberships
  ADD CONSTRAINT tenant_memberships_gcid_tenant_id_key
  UNIQUE (gcid, tenant_id);

COMMIT;
