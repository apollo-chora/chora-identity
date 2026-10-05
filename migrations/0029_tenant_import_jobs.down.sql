-- =============================================================================
-- chora-identity : 0029_tenant_import_jobs.down.sql
-- Reverts 0029_tenant_import_jobs.up.sql (CHO-2020 / ADR-221, ADR-222).
-- Children first (FKs to import_jobs), then the root, then the enum types.
-- =============================================================================

BEGIN;

DROP TABLE IF EXISTS import_batch_members;
DROP TABLE IF EXISTS import_job_rows;
DROP TABLE IF EXISTS import_jobs;

DROP TYPE IF EXISTS import_row_outcome;
DROP TYPE IF EXISTS import_job_state;
DROP TYPE IF EXISTS import_materialization_mode;
DROP TYPE IF EXISTS import_run_mode;

COMMIT;
