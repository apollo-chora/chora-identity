-- =============================================================================
-- chora-identity : 0015_passkey_storage.down.sql
--
-- Reverses 0015_passkey_storage.up.sql — drops passkey_credentials,
-- passkey_challenges, and the two ENUM types. Use this only if the M12
-- passkey pg-adapter cutover is rolled back to the in-memory bring-up
-- adapter (inmem.PasskeyChallengeRepository + inmem.PasskeyCredentialRepository).
--
-- WARNING: dropping passkey_credentials destroys the authoritative
-- WebAuthn binding state — every learner will need to re-register their
-- authenticator. Production callers MUST coordinate with the closure-saga
-- owner before running this down migration; the PII_Closure_Map.yaml
-- `drop` strategy for credential_id / public_key / aaguid expects the
-- table to exist (even if the rows are nulled).
--
-- Cross-DB queries forbidden — chora-identity touches only chora_identity.
-- =============================================================================

BEGIN;

DROP TABLE IF EXISTS passkey_credentials;
DROP TABLE IF EXISTS passkey_challenges;
DROP TYPE  IF EXISTS passkey_credential_status;
DROP TYPE  IF EXISTS passkey_challenge_status;

COMMIT;
