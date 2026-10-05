-- Migration 0004: Singpass scope minimisation for curated-instructor badge.
--
-- Adds the only Singpass-derived attribute Chora persists: the OIDC `sub`
-- claim (UUID), used as a uniqueness anchor so one curated-instructor badge
-- maps to one real Singpass account holder.
--
-- Companion docs:
--   docs/design/ux_singpass_kyc.md
--   docs/design/singpass-kyc-explainer.md
--   .claude/skills/account-closure-saga/SKILL.md
--
-- Per Path A (decided 2026-05-10), Chora explicitly does NOT store:
--   - NRIC, FIN, raw or hashed
--   - Singpass-issued legal name (principalname is requested only because
--     the developer portal Step 3 requires at least one MyInfo data scope;
--     the value is discarded on receipt and never persisted)
--   - Date of birth, nationality, residential status, employment, income,
--     address, family attributes, education attributes
--
-- The badge displays the user's existing Chora display name set on the
-- user profile aggregate. The Singpass UUID is invisible to the user and
-- to staff. Persistence is encrypted via the per-user DEK (S1.4 / ADR-141)
-- and crypto-shredded on account closure (S7.1 federated saga).
--
-- Idempotent: safe to re-apply.

BEGIN;

ALTER TABLE kyc_verifications
    ADD COLUMN IF NOT EXISTS singpass_sub UUID;

-- Uniqueness anchor: one Singpass account → at most one Chora badge.
-- Partial unique index excludes NULLs (verifications that did not use
-- Singpass, e.g. manual review) and soft-deleted rows.
CREATE UNIQUE INDEX IF NOT EXISTS uq_kyc_verifications_singpass_sub
    ON kyc_verifications (singpass_sub)
    WHERE singpass_sub IS NOT NULL AND deleted_at IS NULL;

COMMENT ON COLUMN kyc_verifications.singpass_sub IS
    'OIDC sub claim from Singpass NDI ID token (UUID). The only Singpass-'
    'derived attribute Chora persists. NRIC/FIN/name/etc. are never stored. '
    'Encrypted at rest via per-user DEK; crypto-shredded on account closure.';

COMMIT;
