-- =============================================================================
-- chora-identity : 0006_api_keys.sql
--
-- Domain     : Identity (supporting/platform)
-- Database   : chora_identity
-- Date       : 2026-05-12
-- Architecture: Architecture Review locked 2026-05-07 (Tier 1 D1)
-- Consolidation: M12.2.E.1 — replaces chora-iam.platform_api_keys.
--
-- Adds:
--   - api_keys table (PlatformAPIKey aggregate)
--   - RLS policy for tenant isolation
--   - Indexes for: key_hash lookup (auth hot path), (gcid, tenant_id) FK,
--     tenant_id scoped queries
--
-- HARD INVARIANTS:
--   - AGID-shaped gcid values are rejected at CHECK constraint (rule #10).
--   - key_hash stores SHA-256 of plaintext — plaintext NEVER stored.
--   - Soft delete via revoked_at; default queries filter revoked_at IS NULL.
--   - Cross-DB queries forbidden — `gcid` references users(gcid) in the SAME
--     database (chora_identity); `tenant_id` is a cross-DB UUID with no FK.
--
-- Mirrors:
--   migrations/0001_initial.sql identity_set_updated_at trigger function.
--   migrations/0005_outbox.sql outbox_events for cross-domain publish.
-- =============================================================================

BEGIN;

CREATE TABLE IF NOT EXISTS api_keys (
    id              UUID          PRIMARY KEY,
    gcid            UUID          NOT NULL REFERENCES users(gcid) ON DELETE RESTRICT,
    tenant_id       UUID          NOT NULL,
    key_hash        VARCHAR(128)  NOT NULL,
    name            VARCHAR(255)  NOT NULL,
    scopes          TEXT[]        NOT NULL DEFAULT '{}',
    expires_at      TIMESTAMPTZ,
    created_at      TIMESTAMPTZ   NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ   NOT NULL DEFAULT now(),
    revoked_at      TIMESTAMPTZ,
    CHECK (lower(gcid::text) NOT LIKE '0197a%')
);

-- Unique key_hash among non-revoked keys (authentication hot path).
CREATE UNIQUE INDEX IF NOT EXISTS uq_api_keys_key_hash_active
    ON api_keys (key_hash) WHERE revoked_at IS NULL;

-- List keys by GCID within a tenant.
CREATE INDEX IF NOT EXISTS idx_api_keys_gcid_tenant
    ON api_keys (gcid, tenant_id) WHERE revoked_at IS NULL;

-- Tenant-scoped queries.
CREATE INDEX IF NOT EXISTS idx_api_keys_tenant_id
    ON api_keys (tenant_id) WHERE revoked_at IS NULL;

-- Auto-update updated_at via the shared trigger function from 0001_initial.sql.
DO $$ BEGIN
    CREATE TRIGGER trg_api_keys_updated_at
        BEFORE UPDATE ON api_keys
        FOR EACH ROW EXECUTE FUNCTION identity_set_updated_at();
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

-- Row-Level Security — tenant isolation (DP-02).
ALTER TABLE api_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE api_keys FORCE ROW LEVEL SECURITY;

-- Aligned with the other tenant-scoped tables: GUC name `chora.tenant_id`
-- (matches 0001_initial.sql tenant_memberships + course_role_assignments).
DO $$ BEGIN
    CREATE POLICY tenant_isolation ON api_keys
        FOR ALL USING (tenant_id = current_setting('chora.tenant_id', true)::uuid);
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

COMMIT;
