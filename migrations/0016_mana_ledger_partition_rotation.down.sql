-- =============================================================================
-- chora-identity : 0016_mana_ledger_partition_rotation.down.sql
--
-- No-op by design. The up migration only CREATES monthly mana_ledger partitions
-- (append-only audit data). Dropping them would destroy committed ledger rows
-- and is never safe to do as an automatic rollback. To remove an EMPTY future
-- partition manually:
--   DROP TABLE IF EXISTS mana_ledger_YYYY_MM;  -- only if verified empty
-- =============================================================================

SELECT 1;
