-- =============================================================================
-- chora-identity : 0021_user_dek_wrap.down.sql
--
-- Reverts 0021. Dropping the table discards every wrapped DEK — after this the
-- CloudKMSKeyManager can no longer persist/unwrap DEKs and the service must
-- fall back to the InMemoryKeyManager stub (dev only). Do NOT run against a
-- database holding live (non-shredded) DEKs that protect real encrypted PII.
-- =============================================================================

DROP INDEX IF EXISTS idx_user_dek_wrap_shred_sweep;
DROP TABLE IF EXISTS user_dek_wrap;
