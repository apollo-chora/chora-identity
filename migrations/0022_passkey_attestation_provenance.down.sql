-- =============================================================================
-- chora-identity : 0022_passkey_attestation_provenance.down.sql
-- Reverses 0022 — drops the ADR-187 attestation-provenance columns + index.
-- =============================================================================

DROP INDEX IF EXISTS idx_passkey_credentials_aaguid_verified;

ALTER TABLE passkey_credentials
    DROP COLUMN IF EXISTS aaguid,
    DROP COLUMN IF EXISTS attestation_verified,
    DROP COLUMN IF EXISTS authenticator_description,
    DROP COLUMN IF EXISTS mds_certification_level,
    DROP COLUMN IF EXISTS attestation_object;
