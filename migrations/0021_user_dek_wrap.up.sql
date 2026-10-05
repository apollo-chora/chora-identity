-- =============================================================================
-- chora-identity : 0021_user_dek_wrap.up.sql
--
-- ADR-186 — crypto-shred = envelope encryption. The real CloudKMSKeyManager
-- (internal/adapter/cryptokms) mints a RANDOM per-user DEK, wraps it with the
-- shared cmek-data-plane master KEK (AAD-bound to gcid), and persists ONLY the
-- wrapped form here. Crypto-shred = tombstone the row → the DEK is
-- unrecoverable, making any PII encrypted under it permanently undecryptable.
--
-- This replaces the InMemoryKeyManager stub's HMAC-DERIVED DEK, which was
-- deterministically recomputable (a restart regenerated the identical key) and
-- therefore NOT actually shreddable.
--
-- Database: chora_identity. Keyed by gcid (GCID is globally unique +
-- tenant-portable), which is also why the federated closure subscriber — cross-
-- tenant by design — can shred without a tenant context.
--
-- NO Row-Level Security on this table — DELIBERATE (ADR-186 §D6):
--   * It holds OPAQUE master-KEK-wrapped key ciphertext keyed by gcid — NOT
--     tenant business data, NOT readable PII (useless without Cloud KMS + the
--     matching gcid AAD).
--   * The closure subscriber writes it cross-tenant (ShredDEK takes gcid only,
--     no tenant context), so a tenant-GUC RLS policy would block the shred.
--   * Therefore this adds a KEY TABLE, NOT an RLS-bypass policy — it does NOT
--     extend the ADR-184 / ADR-165 declared-bypass chain.
-- =============================================================================

CREATE TABLE IF NOT EXISTS user_dek_wrap (
    gcid             UUID        PRIMARY KEY,
    wrapped_dek      BYTEA       NOT NULL,                  -- KEK-wrapped DEK; '' once shredded
    kek_version      TEXT        NOT NULL DEFAULT '',       -- KMS encrypt resp name (re-wrap on rotation)
    kms_operation_id TEXT        NOT NULL DEFAULT '',       -- logical shred op id (audit traceback)
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at       TIMESTAMPTZ                            -- crypto-shred tombstone (NULL = alive)
);

-- Sweeper index — the daily hard-delete scan for rows past the reversible
-- window (partial: only tombstoned rows).
CREATE INDEX IF NOT EXISTS idx_user_dek_wrap_shred_sweep
    ON user_dek_wrap (deleted_at)
    WHERE deleted_at IS NOT NULL;

-- Explicit grants (the 9999_grant_app_roles.sql blanket grant is filename-
-- tracked and will not re-run after this table is added — inline + idempotent
-- guarantees app-role access, matching the closure-orchestrator 0054 pattern).
GRANT SELECT, INSERT, UPDATE, DELETE ON user_dek_wrap TO chora_identity_app_rw;
GRANT SELECT ON user_dek_wrap TO chora_identity_app_ro;
