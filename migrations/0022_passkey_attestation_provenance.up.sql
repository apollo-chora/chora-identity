-- =============================================================================
-- chora-identity : 0022_passkey_attestation_provenance.up.sql
--
-- ADR-187 — WebAuthn attestation full-chain validation (FIDO MDS3). Records
-- authenticator PROVENANCE on each passkey credential at registration:
--   * aaguid                    — authenticator model id (authData.aaguid)
--   * attestation_verified      — STRICT (A1): true only when the x5c chain
--                                 validated to a trusted MDS root + sig verified
--                                 + AAGUID matched + not revoked. none/self/
--                                 unknown/cold-store all stay false.
--   * authenticator_description — MDS metadataStatement description (when known)
--   * mds_certification_level   — FIDO certification level ("L1".."L3")
--   * attestation_object        — RAW registration attestationObject (A4) so
--                                 provenance can be RE-EVALUATED offline when the
--                                 MDS store refreshes or a new format verifier
--                                 ships — no re-registration / upgrade dead-end.
--
-- attestation_type already stores the format ("none"/"packed"/...) from 0015.
-- Additive + nullable (attestation_verified DEFAULT false) → existing rows are
-- honestly "unverified provenance". Table-level RLS + grants from 0015 cover the
-- new columns; no policy change. Reversible (see .down).
-- Database: chora_identity.
-- =============================================================================

ALTER TABLE passkey_credentials
    ADD COLUMN IF NOT EXISTS aaguid                    BYTEA,
    ADD COLUMN IF NOT EXISTS attestation_verified      BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS authenticator_description TEXT,
    ADD COLUMN IF NOT EXISTS mds_certification_level   TEXT,
    ADD COLUMN IF NOT EXISTS attestation_object        BYTEA;

-- Governance/audit query helper: count verified vs unverified provenance per
-- authenticator model (partial — only rows that carry an AAGUID).
CREATE INDEX IF NOT EXISTS idx_passkey_credentials_aaguid_verified
    ON passkey_credentials (aaguid, attestation_verified)
    WHERE aaguid IS NOT NULL;
