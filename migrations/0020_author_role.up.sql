-- =============================================================================
-- chora-identity : 0020_author_role.up.sql
--
-- ADR-182 — `author` becomes a real tenant-scoped membership role.
--
-- 1. membership_role ENUM gains 'author' (mirrors chora-tenancy migration
--    0021's tenant_member_role change — the two enums stay in lockstep).
-- 2. tenant_memberships UNIQUE(gcid, tenant_id) → UNIQUE(gcid, tenant_id,
--    role): the mirror must hold the same multi-role rows the authoritative
--    chora_tenancy.members table now holds (learner+author in chora-master
--    per ADR-182 D2).
-- 3. role_catalog gains 'AUTHOR' (per the 0014 lockstep rule: new roles
--    land BOTH in domain/identity/membership.go AND role_catalog).
-- =============================================================================

ALTER TYPE membership_role ADD VALUE IF NOT EXISTS 'author';

ALTER TABLE tenant_memberships DROP CONSTRAINT IF EXISTS tenant_memberships_gcid_tenant_id_key;
CREATE UNIQUE INDEX IF NOT EXISTS uq_tenant_memberships_gcid_tenant_role
    ON tenant_memberships (gcid, tenant_id, role);

INSERT INTO role_catalog (canonical_label, is_tenant_scoped, seeded_in, notes) VALUES
    ('AUTHOR', TRUE, '0020_author_role',
     'ADR-182 — atom authoring role (A+ Creator mode). membership_role.author; surfaces map author → [aplus]. Default public-space role alongside LEARNER.')
ON CONFLICT (canonical_label) DO NOTHING;
