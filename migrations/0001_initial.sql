-- =============================================================================
-- chora-identity : 0001_initial.sql
--
-- Domain        : Identity (supporting/platform)
-- Database      : chora_identity
-- Author        : agent-a5e52e89b73ede1d2 (db-migrations-11-services)
-- Date          : 2026-05-08
-- Architecture  : Architecture Review locked 2026-05-07 (Tier 1 D1)
--
-- Aggregates owned by this database:
--   - Users (GCID = UUIDv7, opaque, cross-tenant portable; CLAUDE.md §1)
--   - User-IdP federation links (1:1 GCID ↔ {idp, subject})
--   - Tenant memberships (GCID ↔ tenant_id ↔ role)
--   - Course role assignments (auxiliary cache for cross-tenant queries)
--   - Closure sagas (5-state federated saga: ACTIVE → CLOSING → SUSPENDED →
--     PSEUDONYMIZED → COLD_ARCHIVED → CRYPTO_SHREDDED) per Tier 3 D11
--
-- HARD INVARIANT: AGIDs CANNOT hold tenant_memberships nor closure_sagas.
-- Enforced by CHECK constraints rejecting AGID-shaped identifiers (lower(gcid)
-- starting with '0197a').
-- =============================================================================

BEGIN;

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE OR REPLACE FUNCTION identity_set_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- -----------------------------------------------------------------------------
-- ENUMs
-- -----------------------------------------------------------------------------
CREATE TYPE identity_provider   AS ENUM ('oidc', 'saml', 'webauthn');
CREATE TYPE user_status         AS ENUM ('active', 'suspended', 'closed');
CREATE TYPE membership_role     AS ENUM ('learner', 'instructor', 'admin', 'auditor');
CREATE TYPE membership_status   AS ENUM ('active', 'inactive');
CREATE TYPE closure_state       AS ENUM (
    'active', 'closing', 'suspended', 'pseudonymized', 'cold_archived', 'crypto_shredded'
);
CREATE TYPE pii_class           AS ENUM ('low', 'medium', 'high', 'critical');

-- -----------------------------------------------------------------------------
-- users — Global Chora ID (GCID) is the PK. Opaque UUIDv7.
-- -----------------------------------------------------------------------------
CREATE TABLE users (
    gcid                 UUID              PRIMARY KEY DEFAULT gen_random_uuid(),
    email                VARCHAR(320)      NOT NULL,
    display_name         VARCHAR(128)      NOT NULL DEFAULT '',
    identity_provider    identity_provider NOT NULL,
    federated_subject    VARCHAR(256)      NOT NULL,                  -- IdP SUB claim
    status               user_status       NOT NULL DEFAULT 'active',
    created_at           TIMESTAMPTZ       NOT NULL DEFAULT now(),
    updated_at           TIMESTAMPTZ       NOT NULL DEFAULT now(),
    deleted_at           TIMESTAMPTZ       NULL,
    UNIQUE (identity_provider, federated_subject),
    -- AGID-shaped GCIDs are forbidden in users — agents do not have user rows.
    CHECK (lower(gcid::text) NOT LIKE '0197a%')
);

CREATE UNIQUE INDEX idx_users_email ON users (lower(email)) WHERE deleted_at IS NULL;
CREATE INDEX idx_users_status       ON users (status) WHERE deleted_at IS NULL;

CREATE TRIGGER trg_users_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION identity_set_updated_at();

-- users is identity-scoped, not tenant-scoped — RLS deferred to membership.
-- Service-side policy: only the GCID owner + admin actors may read.

-- -----------------------------------------------------------------------------
-- user_idp_links — 1 GCID may federate multiple IdP subjects (account linking)
-- -----------------------------------------------------------------------------
CREATE TABLE user_idp_links (
    link_id              UUID              PRIMARY KEY DEFAULT gen_random_uuid(),
    gcid                 UUID              NOT NULL REFERENCES users(gcid) ON DELETE RESTRICT,
    idp                  identity_provider NOT NULL,
    idp_subject          VARCHAR(256)      NOT NULL,
    linked_at            TIMESTAMPTZ       NOT NULL DEFAULT now(),
    UNIQUE (idp, idp_subject)
);

CREATE INDEX idx_user_idp_links_gcid ON user_idp_links (gcid);

-- -----------------------------------------------------------------------------
-- tenant_memberships — GCID ↔ tenant_id ↔ role
--
-- AGIDs are forbidden here per ddd-enforcement aggregate invariant #10.
-- -----------------------------------------------------------------------------
CREATE TABLE tenant_memberships (
    membership_id     UUID                PRIMARY KEY DEFAULT gen_random_uuid(),
    gcid              UUID                NOT NULL REFERENCES users(gcid) ON DELETE RESTRICT,
    tenant_id         UUID                NOT NULL,
    role              membership_role     NOT NULL DEFAULT 'learner',
    status            membership_status   NOT NULL DEFAULT 'active',
    created_at        TIMESTAMPTZ         NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ         NOT NULL DEFAULT now(),
    UNIQUE (gcid, tenant_id),
    CHECK (lower(gcid::text) NOT LIKE '0197a%')
);

CREATE INDEX idx_tenant_memberships_tenant ON tenant_memberships (tenant_id);
CREATE INDEX idx_tenant_memberships_gcid   ON tenant_memberships (gcid);
CREATE INDEX idx_tenant_memberships_role   ON tenant_memberships (role);

CREATE TRIGGER trg_tenant_memberships_updated_at
    BEFORE UPDATE ON tenant_memberships
    FOR EACH ROW EXECUTE FUNCTION identity_set_updated_at();

ALTER TABLE tenant_memberships ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON tenant_memberships
    FOR ALL USING (tenant_id = current_setting('chora.tenant_id', true)::uuid);

-- -----------------------------------------------------------------------------
-- course_role_assignments — auxiliary cache for cross-tenant role lookup
-- -----------------------------------------------------------------------------
CREATE TABLE course_role_assignments (
    assignment_id     UUID            PRIMARY KEY DEFAULT gen_random_uuid(),
    gcid              UUID            NOT NULL REFERENCES users(gcid) ON DELETE RESTRICT,
    tenant_id         UUID            NOT NULL,
    course_id         UUID            NOT NULL,                   -- cross-DB ref to chora_delivery
    role              membership_role NOT NULL,
    assigned_at       TIMESTAMPTZ     NOT NULL DEFAULT now(),
    UNIQUE (gcid, course_id, role)
);

CREATE INDEX idx_course_role_tenant ON course_role_assignments (tenant_id);
CREATE INDEX idx_course_role_gcid   ON course_role_assignments (gcid);
CREATE INDEX idx_course_role_course ON course_role_assignments (course_id);

ALTER TABLE course_role_assignments ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON course_role_assignments
    FOR ALL USING (tenant_id = current_setting('chora.tenant_id', true)::uuid);

-- -----------------------------------------------------------------------------
-- closure_sagas — 5-state federated account closure (Tier 3 D11)
--
-- pseudonymise + crypto-shred — NEVER hard-delete. Per-domain
-- PII_Closure_Map.yaml drives the federated saga stages.
-- -----------------------------------------------------------------------------
CREATE TABLE closure_sagas (
    saga_id              UUID            PRIMARY KEY DEFAULT gen_random_uuid(),
    gcid                 UUID            NOT NULL REFERENCES users(gcid) ON DELETE RESTRICT,
    tenant_id            UUID            NOT NULL,
    state                closure_state   NOT NULL DEFAULT 'closing',
    reason               TEXT            NOT NULL DEFAULT '',
    requested_by_gcid    UUID            NOT NULL,
    grace_period_days    SMALLINT        NOT NULL CHECK (grace_period_days BETWEEN 1 AND 365),
    requested_at         TIMESTAMPTZ     NOT NULL DEFAULT now(),
    grace_ends_at        TIMESTAMPTZ     NOT NULL,
    started_at           TIMESTAMPTZ     NOT NULL DEFAULT now(),
    advanced_at          TIMESTAMPTZ     NOT NULL DEFAULT now(),
    cancelled_at         TIMESTAMPTZ     NULL,
    updated_at           TIMESTAMPTZ     NOT NULL DEFAULT now(),
    CHECK (lower(gcid::text) NOT LIKE '0197a%')
);

CREATE INDEX idx_closure_sagas_tenant ON closure_sagas (tenant_id);
CREATE INDEX idx_closure_sagas_gcid   ON closure_sagas (gcid);
CREATE INDEX idx_closure_sagas_state  ON closure_sagas (state);

CREATE TRIGGER trg_closure_sagas_updated_at
    BEFORE UPDATE ON closure_sagas
    FOR EACH ROW EXECUTE FUNCTION identity_set_updated_at();

ALTER TABLE closure_sagas ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON closure_sagas
    FOR ALL USING (tenant_id = current_setting('chora.tenant_id', true)::uuid);

-- -----------------------------------------------------------------------------
-- closure_saga_history — APPEND-ONLY transition audit (per saga)
-- -----------------------------------------------------------------------------
CREATE TABLE closure_saga_history (
    history_id           UUID           PRIMARY KEY DEFAULT gen_random_uuid(),
    saga_id              UUID           NOT NULL REFERENCES closure_sagas(saga_id) ON DELETE RESTRICT,
    prior_state          closure_state  NOT NULL,
    new_state            closure_state  NOT NULL,
    reason               TEXT           NOT NULL DEFAULT '',
    actor_gcid           UUID           NOT NULL,
    transitioned_at      TIMESTAMPTZ    NOT NULL DEFAULT now()
);

CREATE INDEX idx_closure_saga_history_saga ON closure_saga_history (saga_id, transitioned_at);

CREATE OR REPLACE FUNCTION enforce_closure_saga_history_append_only()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'closure_saga_history is append-only: % rejected', TG_OP;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_csh_no_update
    BEFORE UPDATE ON closure_saga_history
    FOR EACH ROW EXECUTE FUNCTION enforce_closure_saga_history_append_only();

CREATE TRIGGER trg_csh_no_delete
    BEFORE DELETE ON closure_saga_history
    FOR EACH ROW EXECUTE FUNCTION enforce_closure_saga_history_append_only();

-- -----------------------------------------------------------------------------
-- closure_tokenised_fields — record per-field tokenisation events
-- -----------------------------------------------------------------------------
CREATE TABLE closure_tokenised_fields (
    record_id         UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    saga_id           UUID         NOT NULL REFERENCES closure_sagas(saga_id) ON DELETE RESTRICT,
    field_name        VARCHAR(128) NOT NULL,
    pii_class         pii_class    NOT NULL,
    tokenised_at      TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE INDEX idx_closure_tokenised_saga ON closure_tokenised_fields (saga_id);

COMMIT;
