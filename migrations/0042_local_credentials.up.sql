-- =============================================================================
-- chora-identity : 0042_local_credentials.up.sql
--
-- Domain        : Identity (local username/password authentication)
-- Database      : chora_identity
--
-- Purpose:
--   The login provider is local username/password. This migration adds:
--     1. the `password` value to the identity_provider ENUM so a
--        locally-authenticated user can be represented on `users`;
--     2. a minimal identity-local `tenants` registry (id + slug + name +
--        status) so the standalone seed job is self-contained — the
--        AUTHORITATIVE tenant lifecycle still lives in chora-tenancy; this
--        table only records the tenants this service has been told about;
--     3. the `local_credentials` table: one Argon2id PHC hash per GCID, with a
--        GLOBALLY UNIQUE normalised username (login sends username+password
--        only, so per-tenant uniqueness would be ambiguous);
--     4. a SECURITY DEFINER helper that returns a GCID's ACTIVE memberships
--        across tenants. `tenant_memberships` carries the tenant_isolation RLS
--        policy and the runtime role is NOBYPASSRLS, so a login-time
--        cross-tenant read cannot be expressed as a plain SELECT. The function
--        runs as its owner (the migration role, which owns the table) and is
--        granted EXECUTE only to the app roles.
--
-- No seed data is written here — seeding is the separate idempotent
-- cmd/seed job.
--
-- Idempotency: every object is created with IF NOT EXISTS / OR REPLACE, and
-- ALTER TYPE ... ADD VALUE IF NOT EXISTS is a no-op once applied.
--
-- HARD RULE: cross-database queries forbidden. This touches only chora_identity.
-- =============================================================================

-- 1. Represent locally-authenticated users. ALTER TYPE ... ADD VALUE runs
--    outside the transactional block below because a freshly-added enum value
--    cannot be used in the same transaction that adds it.
ALTER TYPE identity_provider ADD VALUE IF NOT EXISTS 'password';

BEGIN;

-- 2. Identity-local tenant registry (see header note).
CREATE TABLE IF NOT EXISTS tenants (
    id          UUID         PRIMARY KEY,
    slug        TEXT         NOT NULL,
    name        TEXT         NOT NULL DEFAULT '',
    status      TEXT         NOT NULL DEFAULT 'active',
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT tenants_slug_key UNIQUE (slug)
);

-- 3. Local credentials — one PHC hash per GCID, globally unique username.
CREATE TABLE IF NOT EXISTS local_credentials (
    gcid           UUID         PRIMARY KEY REFERENCES users(gcid) ON DELETE CASCADE,
    username       TEXT         NOT NULL,
    username_norm  TEXT         NOT NULL,
    password_hash  TEXT         NOT NULL,
    created_at     TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT local_credentials_username_norm_key UNIQUE (username_norm)
);

CREATE INDEX IF NOT EXISTS idx_local_credentials_gcid ON local_credentials (gcid);

CREATE TRIGGER trg_local_credentials_updated_at
    BEFORE UPDATE ON local_credentials
    FOR EACH ROW EXECUTE FUNCTION identity_set_updated_at();

-- 4. Login-time active-membership read (controlled RLS bypass via ownership).
CREATE OR REPLACE FUNCTION identity_active_memberships_for_gcid(p_gcid uuid)
RETURNS TABLE (tenant_id uuid, role text, created_at timestamptz)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
    SELECT tm.tenant_id, tm.role::text, tm.created_at
    FROM tenant_memberships tm
    WHERE tm.gcid = p_gcid
      AND tm.status = 'active'::membership_status
    ORDER BY tm.created_at ASC, tm.tenant_id ASC, tm.role ASC;
$$;

REVOKE ALL ON FUNCTION identity_active_memberships_for_gcid(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION identity_active_memberships_for_gcid(uuid)
    TO chora_identity_app_rw, chora_identity_app_ro;

COMMIT;
