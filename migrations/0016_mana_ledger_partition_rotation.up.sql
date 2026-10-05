-- =============================================================================
-- chora-identity : 0016_mana_ledger_partition_rotation.up.sql
--
-- Domain   : Identity (per-user mana economy, ADR-142)
-- Database : chora_identity
-- Date     : 2026-06-04
--
-- Bootstraps mana_ledger monthly partitions for the current month + the next 13
-- months (idempotent). mana_ledger is PARTITION BY RANGE (recorded_at) and has
-- NO default partition; 0002_user_economy only created the partition for the
-- month it RAN in, and the "monthly rotation" Cloud Scheduler job its comment
-- references is NOT provisioned. The result: the 2026-06 partition was missing,
-- so every CreditMana INSERT failed with
--   ERROR: no partition of relation "mana_ledger" found for row (SQLSTATE 23514)
-- which silently stranded the WS-2 per-user Stripe mana top-up credit (and all
-- subscription-grant subsidies) at the identity push-inbox. Surfaced 2026-06-04
-- once the upstream payments-webhook RLS 22P02 (chora-payments d6044c57/16c0c549)
-- and the chora-identity mesh AuthorizationPolicy gap (chora-infra 538e6169) were
-- fixed and the payment_captured event could finally reach CreditMana.
--
-- ⚠ DURABLE FIX STILL OWED (separate ops deliverable): provision the monthly
--   partition-rotation Cloud Scheduler job (or a pg_partman setup) so partitions
--   are auto-created ahead of time. This migration only buys ~14 months of
--   runway. Track as a follow-up; do NOT rely on re-running this migration.
--
-- Idempotent (IF NOT EXISTS per partition). Safe to re-run.
-- =============================================================================

BEGIN;

DO $$
DECLARE
    m     DATE;
    nm    DATE;
    pname TEXT;
    i     INT;
BEGIN
    FOR i IN 0..13 LOOP
        m     := (date_trunc('month', now()) + (i       || ' month')::interval)::DATE;
        nm    := (date_trunc('month', now()) + ((i + 1) || ' month')::interval)::DATE;
        pname := 'mana_ledger_' || to_char(m, 'YYYY_MM');
        IF NOT EXISTS (SELECT 1 FROM pg_class WHERE relname = pname) THEN
            EXECUTE format(
                'CREATE TABLE %I PARTITION OF mana_ledger FOR VALUES FROM (%L) TO (%L)',
                pname, m, nm);
            RAISE NOTICE 'created mana_ledger partition %', pname;
        END IF;
    END LOOP;
END $$;

COMMIT;
