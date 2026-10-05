-- =============================================================================
-- chora-identity : 0020_author_role.down.sql
--
-- Best-effort reverse of 0020. PostgreSQL cannot remove an enum value:
-- 'author' stays on membership_role (harmless — rows referencing it are
-- soft-disabled below via status). The single-role UNIQUE restore is only
-- possible when no live multi-role rows exist.
-- =============================================================================

UPDATE tenant_memberships
SET    status = 'inactive', updated_at = now()
WHERE  role = 'author';

-- role_catalog is append-only by design; mark the note rather than drop.
UPDATE role_catalog
SET    notes = notes || ' [ROLLED BACK by 0020.down — do not assert on JWTs]'
WHERE  canonical_label = 'AUTHOR';

DROP INDEX IF EXISTS uq_tenant_memberships_gcid_tenant_role;
-- Best-effort: fails when live multi-role rows exist.
ALTER TABLE tenant_memberships ADD CONSTRAINT tenant_memberships_gcid_tenant_id_key UNIQUE (gcid, tenant_id);
