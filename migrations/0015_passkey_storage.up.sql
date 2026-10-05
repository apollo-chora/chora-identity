-- =============================================================================
-- chora-identity : 0015_passkey_storage.up.sql
--
-- Domain        : Identity (supporting/platform)
-- Database      : chora_identity
-- Contract      : services/chora-identity/internal/adapter/pg/passkey_repository.go
--                 services/chora-identity/internal/domain/identity/webauthn.go
--                 services/chora-identity/internal/domain/identity/webauthn_repository.go
-- Architecture  : Architecture Review locked 2026-05-07 (Tier 1 D1)
-- Author        : N9 (O+ M12-backlog wave — passkey pg adapter)
-- Date          : 2026-05-26
--
-- Purpose:
--   Close the M12 deferral marked at
--   `services/chora-identity/internal/adapter/inmem/passkey_repository.go:4`:
--   ("…passkey_challenges + passkey_credentials tables; deferred to M12").
--   The in-memory PasskeyChallenge + PasskeyCredential stores were the
--   bring-up adapter for the Phyllis demo (S2.1 P0 — passkey login is the
--   entry point per audit-identity-fillgaps.md §3.1). Production wires the
--   pgx adapter (this migration) so passkey challenges + credentials survive
--   pod restart + flow through the federated closure saga (see PII closure
--   map below).
--
-- Aggregates owned by this migration:
--   - PasskeyChallenge — short-lived (5-min TTL) nonce minted during
--     /v1/auth/passkey/challenge; consumed at /v1/auth/passkey/verify.
--     Replay-protected via the {Pending → Verified → Consumed} state
--     machine + the first-save-wins invariant enforced at the adapter.
--   - PasskeyCredential — long-lived registered authenticator binding
--     (one row per credential per GCID). Holds the COSE public key, the
--     monotonic sign-count (WebAuthn §6.1.1), attestation type, and
--     revocation state.
--
-- Scope (RLS):
--   passkey_challenges + passkey_credentials are IDENTITY-SCOPED (NOT
--   tenant-scoped). The schema has no tenant_id column — credentials are
--   bound to a GCID, which is itself opaque + cross-tenant-portable per
--   CLAUDE.md §1. Mirrors the existing `users` table convention (0001_initial
--   §"users" — "users is identity-scoped, not tenant-scoped — RLS deferred
--   to membership"). No RLS policy is therefore attached; service-layer
--   policy gates per-GCID access.
--
-- PII closure (Tier 3 D11):
--   The existing `config/PII_Closure_Map.yaml` already declares the
--   `passkey_credentials` row in the per-domain closure map with three
--   `drop`-strategy columns: credential_id, public_key, aaguid. Once a
--   closure saga reaches the PSEUDONYMIZED state, these BYTEA fields are
--   nulled out — the row itself stays for audit trail consistency. This
--   migration aligns the schema column names with the closure map (i.e. we
--   name the COSE bytes column `public_key`, not `public_key_cose`, to
--   match the YAML key). The Go adapter still maps to the canonical
--   `PublicKeyCOSE` field on the domain aggregate.
--
-- HARD RULE: cross-database queries forbidden — this migration touches only
-- chora_identity-local tables + types.
-- =============================================================================

BEGIN;

-- -----------------------------------------------------------------------------
-- ENUMs
-- -----------------------------------------------------------------------------
CREATE TYPE passkey_challenge_status  AS ENUM ('pending', 'verified', 'consumed', 'expired');
CREATE TYPE passkey_credential_status AS ENUM ('active', 'revoked');

-- -----------------------------------------------------------------------------
-- passkey_challenges — short-lived nonces for the WebAuthn ceremony.
-- -----------------------------------------------------------------------------
-- challenge_id is the canonical UUIDv7 minted by the domain
-- (identity.NewPasskeyChallenge); used as the PK so callers can dedupe on
-- it. challenge_bytes is the raw CSPRNG-issued nonce (≥16B per WebAuthn
-- §13.4.3); we don't index on it.
--
-- verified_gcid is bound at MarkVerified time + carried through Consumed.
-- It is NULLable for Pending rows. AGID-shaped IDs are rejected here as a
-- defence-in-depth check against the domain aggregate invariant #10
-- (`webauthn.go.NewPasskeyCredential` already rejects AGIDs at the
-- aggregate boundary).
--
-- Status state machine (enforced by the domain aggregate; the schema only
-- carries the resulting state):
--   pending → verified → consumed   (happy path)
--   pending → expired               (TTL lapse)
--   verified → consumed             (success)
--
-- ttl is encoded by ExpiresAt absolutely; no separate retention column.
-- A scheduled cleanup is OUT OF SCOPE for this migration — a TTL sweeper
-- lands with the post-M12 retention worker (audit-identity-fillgaps.md
-- §3.1 deferred row).
-- -----------------------------------------------------------------------------
CREATE TABLE passkey_challenges (
    challenge_id      UUID                       PRIMARY KEY,
    challenge_bytes   BYTEA                      NOT NULL,
    rp_id             VARCHAR(255)               NOT NULL,
    user_handle       VARCHAR(320)               NOT NULL DEFAULT '',
    status            passkey_challenge_status   NOT NULL DEFAULT 'pending',
    verified_gcid     UUID                       NULL,
    created_at        TIMESTAMPTZ                NOT NULL DEFAULT now(),
    expires_at        TIMESTAMPTZ                NOT NULL,
    CHECK (octet_length(challenge_bytes) >= 16),
    -- AGID-shaped GCIDs are forbidden in verified_gcid — agents do not
    -- verify passkey challenges (aggregate invariant #10).
    CHECK (verified_gcid IS NULL OR lower(verified_gcid::text) NOT LIKE '0197a%')
);

-- Partial index for the TTL sweep + active-challenge lookups. NOTE: the
-- original predicate also carried `expires_at > now()`, but now() is
-- STABLE (not IMMUTABLE) and PostgreSQL rejects volatile functions in
-- index predicates — the file could never apply as written (caught by the
-- 1c debt-pass item-3 umbrella run, 2026-06-11). The btree on
-- (user_handle, expires_at) serves the range half at query time
-- (`WHERE expires_at > $1`); the partial predicate keeps only the
-- IMMUTABLE-safe status filter.
CREATE INDEX IF NOT EXISTS idx_passkey_challenges_active_by_user
    ON passkey_challenges (user_handle, expires_at)
    WHERE status IN ('pending', 'verified');

COMMENT ON TABLE passkey_challenges IS
    'Short-lived (≤5min TTL) WebAuthn challenges. Identity-scoped (no tenant_id). Replay-protected by the first-save-wins invariant on Consumed terminal state.';

-- -----------------------------------------------------------------------------
-- passkey_credentials — long-lived registered authenticators.
-- -----------------------------------------------------------------------------
-- credential_uuid is the canonical UUIDv7 PK minted by the domain
-- (identity.NewPasskeyCredential.CredentialUUID). credential_id is the raw
-- authenticator-supplied credential ID bytes (variable length per
-- WebAuthn §6.1). credential_id_hash is sha256(credential_id) — kept as
-- a fixed-width UNIQUE key so the lookup index doesn't degrade on long
-- credential IDs (some platform authenticators emit ≥120B credential IDs).
--
-- public_key holds the COSE-encoded public key (CBOR bytes). Named
-- `public_key` (not `public_key_cose`) to match the existing
-- config/PII_Closure_Map.yaml column reference for the closure saga
-- `drop` strategy.
--
-- sign_count is the WebAuthn §6.1.1 monotonic counter; we store as BIGINT
-- (the domain treats it as uint32; -1 == "authenticator does not support
-- sign-count" is handled at the aggregate not the schema).
--
-- aaguid is optional (some authenticators don't emit it during attestation
-- 'none' ceremonies). When present it is the authenticator's hardware
-- model identifier; reserved for the post-M12 attestation policy gate.
-- -----------------------------------------------------------------------------
CREATE TABLE passkey_credentials (
    credential_uuid      UUID                        PRIMARY KEY,
    gcid                 UUID                        NOT NULL REFERENCES users(gcid) ON DELETE RESTRICT,
    credential_id        BYTEA                       NOT NULL,
    credential_id_hash   VARCHAR(64)                 NOT NULL UNIQUE,
    public_key           BYTEA                       NOT NULL,
    attestation_type     VARCHAR(32)                 NOT NULL DEFAULT 'none',
    rp_id                VARCHAR(255)                NOT NULL,
    sign_count           BIGINT                      NOT NULL DEFAULT 0,
    status               passkey_credential_status   NOT NULL DEFAULT 'active',
    aaguid               UUID                        NULL,
    nickname             VARCHAR(128)                NOT NULL DEFAULT '',
    created_at           TIMESTAMPTZ                 NOT NULL DEFAULT now(),
    updated_at           TIMESTAMPTZ                 NOT NULL DEFAULT now(),
    last_used_at         TIMESTAMPTZ                 NULL,
    revoked_at           TIMESTAMPTZ                 NULL,
    CHECK (octet_length(credential_id) > 0),
    CHECK (octet_length(public_key) > 0),
    -- Defence-in-depth: AGIDs cannot register passkeys (aggregate invariant #10).
    CHECK (lower(gcid::text) NOT LIKE '0197a%'),
    CHECK (sign_count >= 0),
    -- Revoked rows MUST carry a revocation timestamp.
    CHECK ((status = 'active' AND revoked_at IS NULL) OR
           (status = 'revoked' AND revoked_at IS NOT NULL))
);

CREATE INDEX idx_passkey_credentials_gcid
    ON passkey_credentials (gcid, status);

CREATE TRIGGER trg_passkey_credentials_updated_at
    BEFORE UPDATE ON passkey_credentials
    FOR EACH ROW EXECUTE FUNCTION identity_set_updated_at();

COMMENT ON TABLE passkey_credentials IS
    'Long-lived WebAuthn credentials bound to GCID. Identity-scoped (no tenant_id). Sign-count monotonic per §6.1.1; revocation idempotent. Closure-saga drop targets: credential_id, public_key, aaguid (see config/PII_Closure_Map.yaml).';

COMMIT;
