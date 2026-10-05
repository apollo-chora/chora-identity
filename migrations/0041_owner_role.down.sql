-- =============================================================================
-- chora-identity : 0041_owner_role.down.sql
--
-- Best-effort reverse of 0041, and deliberately less than a full reverse.
--
-- PostgreSQL cannot remove an ENUM value, so 'owner' stays on membership_role.
-- That is harmless: an unused value costs nothing.
--
-- What this down migration must NOT do, and the 0020 precedent is exactly the
-- wrong model here. 0020.down could deactivate `author` rows because AUTHOR is
-- re-grantable through the admin API, so the rollback was recoverable. Owner
-- is not: no API can grant it back. Deactivating owner rows on a rollback
-- would leave tenants with nobody owning them and no way to fix it, which is
-- the very defect class S7-B1 exists to close. So tenant_memberships is left
-- alone, and a rolled-back deployment simply has owner rows it renders as
-- unknown rather than owner rows it destroyed.
--
-- role_catalog is append-only by design (the 0020/0035 down precedent): mark
-- the note rather than DELETE the row, so a historically issued OWNER token
-- stays traceable in the registry instead of silently vanishing. The row is
-- restored to its 0014 wording plus the rollback marker.
-- =============================================================================

UPDATE role_catalog
SET    seeded_in = 'jwt_extension',
       notes     = 'Tenant owner. JWT-stamped; not in PG ENUM. [ROLLED BACK by 0041.down, the membership_role value survives because PostgreSQL cannot remove one; treat a stored owner row as unrecognised, do not delete it]'
WHERE  canonical_label = 'OWNER';
