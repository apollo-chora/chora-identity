-- =============================================================================
-- chora-identity : 0041_owner_role.up.sql
--
-- UX refactor R21, first-launch spec 13.3.3 option (a), work item S7-B3:
-- `owner` becomes a real value of the chora_identity.membership_role ENUM so
-- that ownership stops being invisible.
--
-- What was wrong. Ownership is one row in chora_tenancy.members with
-- role='owner', written only by tenant bootstrap. The identity-side MIRROR
-- table, which is what the H+ Members roster actually reads, could not
-- represent it: membership_role held only (learner, instructor, admin,
-- auditor) from 0001 plus `author` from 0020. So the bootstrap subscriber
-- deliberately wrote the owner's mirror row as `admin`, and every human-facing
-- screen showed the owner as an ordinary admin. The JWT knew better all along,
-- because its roles come from the authoritative tenancy store, which is how
-- the platform could enforce ownership that nobody could see.
--
-- Two differences from the 0020_author_role template this otherwise follows:
--
--   1. role_catalog is UPDATED, not INSERTed. Migration 0014 already seeded
--      ('OWNER', TRUE, 'jwt_extension', 'Tenant owner. JWT-stamped; not in PG
--      ENUM.'). An INSERT ... ON CONFLICT DO NOTHING would be swallowed and
--      leave the registry asserting "not in PG ENUM" one statement after that
--      stopped being true. The 0014-lockstep rule is about keeping the
--      catalogue and domain/identity/membership.go in step, and here that
--      means correcting the row.
--   2. No UNIQUE-index change. 0020 needed one because AUTHOR made the mirror
--      multi-role; uq_tenant_memberships_gcid_tenant_role has covered
--      (gcid, tenant_id, role) ever since and an owner row fits it unchanged.
--
-- What this migration deliberately does NOT do: it moves no data. No
-- tenant_memberships row is written here, so no account gains ownership by
-- being migrated. Existing bootstrapped tenants keep the `admin` mirror row
-- they were given; the subscriber writes `owner` from now on, and reconciling
-- the historical rows is a backfill decision for the S7 handover work, not a
-- silent side effect of widening a vocabulary.
--
-- Grantability is unchanged and must stay unchanged: `owner` is absent from
-- Role.Grantable() in domain/identity/membership.go, from upsertableRoles in
-- chora-tenancy's UpsertMembership RPC, and from the CSV import's accepted
-- set. Being storable is not being grantable.
--
-- ALTER TYPE ... ADD VALUE runs inside a transaction on PostgreSQL 12+ as long
-- as the new value is not USED in the same transaction. The role_catalog
-- UPDATE below writes only text, never the enum, so this file is safe to apply
-- as one transaction.
-- =============================================================================

ALTER TYPE membership_role ADD VALUE IF NOT EXISTS 'owner';

UPDATE role_catalog
SET    seeded_in = '0041_owner_role',
       notes     = 'Tenant owner. Stored membership_role since 0041 (UX refactor R21) so the H+ roster can show who owns the organisation; the identity mirror no longer downgrades the owner to admin. Authoritative record stays chora_tenancy.members. NOT grantable by any API: written only by tenant bootstrap, moved only by the S7 two-party handover or the platform-operator override. Also JWT-stamped, as before.'
WHERE  canonical_label = 'OWNER';
