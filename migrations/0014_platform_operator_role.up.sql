-- =============================================================================
-- chora-identity : 0014_platform_operator_role.up.sql
--
-- Domain        : Identity (supporting/platform)
-- Database      : chora_identity
-- Contract      : chora-contracts/openapi/identity-admin.yaml + payments-admin.yaml
-- Architecture  : docs/architecture/adrs/adr-165-platform-operator-role-rls-bypass.md
--                 (PROPOSED 2026-05-26)
-- Author        : A5 (H+ tx-history wave — identity catalogue + architecture docs)
-- Date          : 2026-05-26
--
-- Purpose:
--   Coin a NEW canonical role `PLATFORM_OPERATOR` (uppercase per ADR-141
--   reconciliation) that is the SOLE permitted RLS-bypass principal for
--   cross-tenant operator views. The first consumer is chora-payments
--   `GET /api/v1/admin/purchases` (H+ tenant-admin Transaction History,
--   commit `8bb1b49b`) under listAdminPurchases — PLATFORM_OPERATOR sees
--   every tenant's rows in a single page; tenant-scoped callers
--   (TENANT_ADMIN / OWNER / AUDITOR) continue to see only their own.
--
-- Why this is a catalogue concern (and not just an OpenAPI enum value):
--   The 8 pre-existing canonical roles (LEARNER / INSTRUCTOR / ADMIN /
--   AUDITOR / OWNER / SUPPORT_AGENT / TRAINING_ADMIN / TENANT_ADMIN) are
--   all tenant-scoped. PLATFORM_OPERATOR is the FIRST cross-tenant role
--   in the platform — it does NOT bind to a TenantMembership row. Per
--   ddd-enforcement aggregate invariant #10, AGIDs cannot hold
--   TenantMembership; PLATFORM_OPERATOR sits in the same "no-tenant"
--   bucket from the chora_identity schema perspective and is NOT
--   represented in the `membership_role` PG ENUM. The PG ENUM stays
--   tenant-scoped; PLATFORM_OPERATOR membership is asserted in the JWT
--   `roles` claim and propagated via the `x-mesh-user-roles` header.
--
-- This migration is therefore an INTENTIONALLY EMPTY catalogue-evolution
-- marker: it (a) documents that PLATFORM_OPERATOR was coined on this
-- date, (b) reserves the migration slot so the down.sql can roll back
-- the conceptual change if ADR-165 escalates to REJECTED, and (c) adds
-- a CHECK that any future attempt to widen the `membership_role` PG ENUM
-- with `platform_operator` is loud (the lowercase variant is deliberately
-- never added — cross-tenant principals do not belong in a tenant-scoped
-- membership row).
--
-- Why no ALTER TYPE membership_role ADD VALUE:
--   `membership_role` is the PG ENUM backing `tenant_memberships.role`
--   (0001_initial.sql line 41). Adding `platform_operator` there would
--   imply a PLATFORM_OPERATOR is bound to a specific tenant — which is
--   exactly the opposite of the role's purpose. ADR-165 §"Decision" D3
--   covers this in detail.
--
-- Cross-DB queries forbidden — chora-identity reads only chora_identity.
-- =============================================================================

BEGIN;

-- -----------------------------------------------------------------------------
-- Catalogue marker — a domain-scoped registry of canonical role tokens that
-- chora-identity acknowledges. Sourced from the PG ENUM `membership_role`
-- (lowercase, 4 values) PLUS the 5 extended canonical-uppercase roles
-- stamped onto JWTs via the mint pipeline (OWNER / SUPPORT_AGENT /
-- TRAINING_ADMIN / TENANT_ADMIN / PLATFORM_OPERATOR — added by this
-- migration). All 9 roles are asserted on `x-mesh-user-roles` headers
-- and validated by the admin handlers.
--
-- Idempotent — INSERT ... ON CONFLICT DO NOTHING per the resilience rule
-- (feedback_resilience_priority).
-- -----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS role_catalog (
    role_id          UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    canonical_label  TEXT         NOT NULL UNIQUE,
    is_tenant_scoped BOOLEAN      NOT NULL,
    seeded_in        TEXT         NOT NULL,
    notes            TEXT         NOT NULL DEFAULT '',
    created_at       TIMESTAMPTZ  NOT NULL DEFAULT now()
);

COMMENT ON TABLE role_catalog IS
    'Canonical role registry. ADR-141 uppercase form. Sole source of truth for the role-token vocabulary asserted on chora-session JWTs + x-mesh-user-roles. PLATFORM_OPERATOR is the only cross-tenant role (is_tenant_scoped=FALSE) per ADR-165.';

-- Seed the 8 pre-existing canonical roles + the new PLATFORM_OPERATOR.
INSERT INTO role_catalog (canonical_label, is_tenant_scoped, seeded_in, notes) VALUES
    ('LEARNER',           TRUE,  '0001_initial',           'membership_role.learner — default'),
    ('INSTRUCTOR',        TRUE,  '0001_initial',           'membership_role.instructor — also covers TRAINING_ADMIN at handler layer'),
    ('ADMIN',             TRUE,  '0001_initial',           'membership_role.admin — tenant-level admin'),
    ('AUDITOR',           TRUE,  '0001_initial',           'membership_role.auditor — read-only, all endpoints'),
    ('OWNER',             TRUE,  'jwt_extension',          'Tenant owner. JWT-stamped; not in PG ENUM.'),
    ('SUPPORT_AGENT',     TRUE,  'jwt_extension',          'L1-L2 customer service per chora-support domain. JWT-stamped; not in PG ENUM.'),
    ('TRAINING_ADMIN',    TRUE,  'jwt_extension',          'Instructor-with-admin-on-courses. JWT-stamped; resolves to membership_role.instructor at PG layer.'),
    ('TENANT_ADMIN',      TRUE,  'jwt_extension',          'Tenant-level admin (canonical uppercase form of membership_role.admin). JWT-stamped.'),
    ('PLATFORM_OPERATOR', FALSE, '0014_platform_operator', 'ADR-165 — sole cross-tenant role. RLS-bypass principal for chora-payments listAdminPurchases. NO tenant_memberships row; asserted ONLY via JWT.')
ON CONFLICT (canonical_label) DO NOTHING;

-- -----------------------------------------------------------------------------
-- Privilege grant — both app roles need to read the catalogue (handlers
-- that decode the JWT `roles` claim consult the registry to reject unknown
-- tokens). RW also needs INSERT for future migrations that coin new roles.
-- -----------------------------------------------------------------------------

GRANT SELECT ON role_catalog TO chora_identity_app_rw, chora_identity_app_ro;
GRANT INSERT ON role_catalog TO chora_identity_app_rw;

-- role_catalog is intentionally NOT tenant-scoped (it is the platform-wide
-- vocabulary registry) — no RLS policy is attached. The is_tenant_scoped
-- COLUMN describes per-row semantics; the TABLE itself is read-everywhere.

COMMIT;
