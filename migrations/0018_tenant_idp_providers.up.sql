-- =============================================================================
-- chora-identity : 0018_tenant_idp_providers.up.sql
--
-- Domain        : Identity (supporting/platform)
-- Database      : chora_identity
-- Contract      : chora-contracts/openapi/identity-admin.yaml
--                 (`POST /api/v1/tenants/me/idp-providers`)
--                 services/chora-identity/internal/domain/tenant_idp_provider/
-- Story         : CHO-1682 — Tenant Lifecycle | Setup Wizard | Phase C
--                 (Identity provider + Apply / finish-setup — BE+BFF)
-- Author        : N/A (BE+BFF agent)
-- Date          : 2026-06-07
-- Architecture  : Architecture Review locked 2026-05-07 (Tier 1 D1)
--
-- Purpose:
--   Setup Wizard step 3 needs a per-tenant identity-provider configuration:
--   OIDC issuer + client credentials, or a Singpass-NDI opt-in. The wizard
--   FE collects the values; the BFF aggregator POSTs them to chora-identity
--   on Apply. This migration creates the only chora_identity-owned table
--   that holds tenant-scoped IdP config; the existing 0001 `identity_provider`
--   enum and `user_idp_links` table cover USER-IdP federation (per-GCID),
--   which is orthogonal.
--
-- Aggregate owned by this migration:
--   - TenantIdpProvider — per-tenant OIDC/SAML/Singpass config. Soft-
--     deletable; idempotent upsert keyed on `(tenant_id, provider_type)`.
--
-- Scope (RLS):
--   tenant_idp_providers IS TENANT-SCOPED. Every row carries `tenant_id`;
--   RLS policy `idp_tenant_isolation` restricts SELECT/INSERT/UPDATE/DELETE
--   to rows whose `tenant_id` matches `current_setting('chora.tenant_id')`
--   (set by the chora-go-common pgxhelpers when the request flows through
--   the gateway-stamped X-Tenant-Id header). The `admin` role
--   (current_setting('chora.role') = 'admin') bypasses the filter for
--   platform diagnostics. Mirrors the `mana_price_plan` RLS pattern from
--   0017_mana_price_plan_rules_layer.
--
-- Secret discipline (CLAUDE.md §6):
--   `client_secret` is NEVER stored in this table. The chora-identity
--   handler writes the plaintext to Secret Manager as a new version of a
--   per-tenant per-IdP resource (canonical name shape:
--   `projects/{n}/secrets/idp-client-secret-{tenant_id}-{idp_id}`) and
--   stores ONLY the resulting resource name in `client_secret_name`. The
--   OIDC handshake reads the secret at sign-in time via Workload Identity
--   Federation — not at wizard time. `client_secret_name` is NULL for
--   Singpass rows (NDI uses public-key auth, not client secret).
--
-- PII closure (Tier 3 D11):
--   Row-level: ALL fields except `id`, `tenant_id`, `provider_type` are
--   closure-saga `drop` targets. The closure-saga also schedules deletion
--   of the Secret Manager resource referenced by `client_secret_name` —
--   the row stays for audit-trail consistency but loses its referenced
--   secret. config/PII_Closure_Map.yaml must be extended in a follow-up
--   (out of scope for CHO-1682).
--
-- HARD RULE: cross-database queries forbidden — this migration touches only
-- chora_identity-local tables + types. Tenancy reads about IdP changes via
-- the `chora.identity.tenant_idp_provider.configured.v1` Pub/Sub event.
-- =============================================================================

BEGIN;

-- -----------------------------------------------------------------------------
-- ENUM — tenant_idp_provider_type
--
-- A separate enum from 0001's `identity_provider` because:
--   1. `identity_provider` includes `webauthn`, which is a user-passkey
--      kind and NOT meaningful as a tenant-scoped IdP.
--   2. We need `singpass` here, which `identity_provider` doesn't have
--      (and we'd rather not ALTER an enum used by `user_idp_links` for
--      every existing federated subject — backward compat).
-- -----------------------------------------------------------------------------
CREATE TYPE tenant_idp_provider_type AS ENUM ('oidc', 'saml', 'singpass');

-- -----------------------------------------------------------------------------
-- tenant_idp_providers — per-tenant identity-provider configuration.
-- -----------------------------------------------------------------------------
CREATE TABLE tenant_idp_providers (
    id                 UUID                     PRIMARY KEY,
    tenant_id          UUID                     NOT NULL,
    provider_type      tenant_idp_provider_type NOT NULL,
    client_id          VARCHAR(256)             NULL,
    client_secret_name VARCHAR(512)             NULL,
    discovery_url      TEXT                     NULL,
    singpass_enabled   BOOLEAN                  NOT NULL DEFAULT FALSE,
    created_at         TIMESTAMPTZ              NOT NULL DEFAULT now(),
    updated_at         TIMESTAMPTZ              NOT NULL DEFAULT now(),
    deleted_at         TIMESTAMPTZ              NULL,

    -- Per-provider validity matrix — enforced at the domain layer
    -- (services/chora-identity/internal/domain/tenant_idp_provider) AND
    -- defence-in-depth at the schema level so a misbehaving caller can't
    -- write a half-formed row:
    --   - OIDC : client_id NOT NULL, client_secret_name NOT NULL (because
    --            Secret Manager mint succeeded), discovery_url NOT NULL
    --   - SAML : discovery_url NOT NULL (metadata URL); secret optional
    --   - Singpass : client_id / client_secret_name / discovery_url MUST
    --            be NULL (NDI uses public-key auth + platform-owned discovery)
    CONSTRAINT chk_provider_validity CHECK (
        CASE provider_type
            WHEN 'oidc'     THEN client_id IS NOT NULL
                              AND client_secret_name IS NOT NULL
                              AND discovery_url IS NOT NULL
            WHEN 'saml'     THEN discovery_url IS NOT NULL
            WHEN 'singpass' THEN client_id IS NULL
                              AND client_secret_name IS NULL
                              AND discovery_url IS NULL
        END
    )
);

-- Idempotent upsert key — at most one ACTIVE row per (tenant_id, provider_type).
-- Soft-deleted rows are excluded so re-creating after a delete works without
-- a unique-constraint clash.
CREATE UNIQUE INDEX uq_tenant_idp_providers_tenant_type_active
    ON tenant_idp_providers (tenant_id, provider_type)
    WHERE deleted_at IS NULL;

-- ListByTenant + isolation queries hit (tenant_id) — covered by the unique
-- index for active rows; a separate non-unique index helps the "show me
-- ALL rows including soft-deleted" diagnostic path.
CREATE INDEX idx_tenant_idp_providers_tenant
    ON tenant_idp_providers (tenant_id)
    WHERE deleted_at IS NULL;

-- updated_at maintenance — re-use the existing identity_set_updated_at
-- trigger function from 0001_initial.
CREATE TRIGGER trg_tenant_idp_providers_updated_at
    BEFORE UPDATE ON tenant_idp_providers
    FOR EACH ROW EXECUTE FUNCTION identity_set_updated_at();

-- -----------------------------------------------------------------------------
-- Row-Level Security — tenant_id isolation.
--
-- Mirrors the mana_price_plan pattern from 0017. The `admin` role bypasses
-- so chora-identity's platform operators (PLATFORM_OPERATOR per ADR-165)
-- and migration tooling can inspect across tenants for audit / diagnostics.
-- -----------------------------------------------------------------------------
ALTER TABLE tenant_idp_providers ENABLE ROW LEVEL SECURITY;

DO $$ BEGIN
    CREATE POLICY idp_tenant_isolation ON tenant_idp_providers
        FOR ALL USING (
            tenant_id = current_setting('chora.tenant_id', true)::uuid
            OR current_setting('chora.role', true) = 'admin'
        );
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

COMMENT ON TABLE tenant_idp_providers IS
    'Per-tenant identity-provider configuration (Setup Wizard step 3, CHO-1682). Tenant-scoped RLS. client_secret lives in Secret Manager — only client_secret_name is stored here. Singpass rows omit client_id/secret/discovery (NDI uses public-key auth).';

COMMIT;
