-- =============================================================================
-- chora-identity : 0029_tenant_import_jobs.up.sql
--
-- Domain        : Identity (supporting/platform)
-- Database      : chora_identity
-- Story         : CHO-2020 (P0) — Tenant CSV mass-import foundations
-- ADRs          : ADR-221 D1/D4/D5 (ImportJob aggregate, job lifecycle,
--                 row ledger) + ADR-222 D1/D3 (synthetic batch lifecycle,
--                 closure-saga teardown map)
-- Date          : 2026-07-03
--
-- The ImportJob aggregate: one job = one uploaded CSV run through
-- validate (dry-run) -> confirm -> chunked execution -> per-row report.
--
--   import_jobs          — the aggregate root; chunk checkpoint columns make
--                          a mid-run pod kill resumable (D6.1 / AC-2).
--   import_job_rows      — the per-line ledger (one row per data line) the
--                          validation/result/error CSVs are generated from.
--                          Same-aggregate child: intra-DB FK to import_jobs
--                          is legal (never a cross-domain FK).
--   import_batch_members — the teardown map: every MINTED synthetic
--                          principal is registered here; teardown fans out
--                          one account-closure saga per member (ADR-222 D3).
--
-- RLS (tenant_id slot; GUC chora.tenant_id):
--   - tenant-admin jobs (P6): the concrete tenant UUID.
--   - operator jobs: the NIL uuid sentinel (00000000-...-0) — operator jobs
--     span tenants, so their home scope is platform. Only the operator
--     context (chora.tenant_id = 'platform') can see them, since no real
--     tenant's GUC equals the nil uuid.
--   Policy is tenant-isolated + FORCE'd + PLATFORM-SENTINEL-AWARE with the
--   nested-NULLIF fail-closed guard — mirrors chora-tenancy
--   transaction_export_jobs (0025) / transaction_ledger (0024), the shipped
--   pattern for operator-owned job tables. First use of the sentinel
--   pattern in chora_identity (pending_invites 0026 predates it).
--   Explicitly NOT an RLS bypass (ADR-221 amends nothing): per-tenant
--   IMPORT WRITES run in RunInTenantTx(target_tenant) with RLS ON; these
--   tables only HOME the job bookkeeping.
--
-- IDs: app mints UUIDv7 (gen_random_uuid() default is the fallback only,
-- matching pending_invites/0026 + transaction_export_jobs/0025 precedent).
-- Soft-delete via deleted_at (ddd-enforcement #4) — teardown pseudonymises
-- through the closure saga, NEVER hard-deletes.
-- Grants: inherited from 9999_grant_app_roles.sql default privileges
-- (same pattern as tenancy 0025).
--
-- HARD RULE: cross-database queries forbidden. chora_identity-local only.
-- =============================================================================

BEGIN;

-- CREATE TYPE has no IF NOT EXISTS — guard for re-apply safety (stale-GCS
-- re-apply gotcha, see tenancy 0026).
DO $$
BEGIN
    CREATE TYPE import_run_mode AS ENUM
        ('operator_create_new', 'operator_existing_only', 'tenant_admin', 'sync');
EXCEPTION
    WHEN duplicate_object THEN NULL;
END $$;

DO $$
BEGIN
    CREATE TYPE import_materialization_mode AS ENUM
        ('cold_invite', 'synthetic', 'synthetic_login');
EXCEPTION
    WHEN duplicate_object THEN NULL;
END $$;

DO $$
BEGIN
    CREATE TYPE import_job_state AS ENUM
        ('validating', 'awaiting_confirm', 'running',
         'completed', 'completed_with_errors', 'failed', 'cancelled');
EXCEPTION
    WHEN duplicate_object THEN NULL;
END $$;

DO $$
BEGIN
    CREATE TYPE import_row_outcome AS ENUM
        ('created_tenant', 'invited', 'granted', 'merged',
         'minted', 'skipped', 'error');
EXCEPTION
    WHEN duplicate_object THEN NULL;
END $$;

-- ---------------------------------------------------------------------------
-- import_jobs — aggregate root
-- ---------------------------------------------------------------------------
CREATE TABLE import_jobs (
    job_id                 UUID          PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id              UUID          NOT NULL,  -- concrete tenant (tenant-admin) | nil-uuid (operator)
    import_batch_id        UUID          NOT NULL,  -- synthetic-lifecycle handle (teardown scope, ADR-222)
    actor_gcid             UUID          NOT NULL,  -- uploader; the confirmer is audited via governance event
    run_mode               import_run_mode NOT NULL,
    materialization_mode   import_materialization_mode NOT NULL DEFAULT 'cold_invite',
    send_invites           BOOLEAN       NOT NULL DEFAULT TRUE,   -- GQ-4 job-level toggle (P3 wiring)
    state                  import_job_state NOT NULL DEFAULT 'validating',
    source_filename        TEXT          NULL,
    source_bytes           BIGINT        NULL,
    gcs_object             TEXT          NULL,      -- uploaded CSV in the imports bucket (CMEK, 30d — M-11)
    detected_delimiter     TEXT          NULL,      -- ',' | ';' | 'TAB' (M-1 echo for the report)
    total_rows             INT           NOT NULL DEFAULT 0,  -- data rows found at validation
    valid_rows             INT           NOT NULL DEFAULT 0,
    error_rows             INT           NOT NULL DEFAULT 0,
    tenant_count           INT           NOT NULL DEFAULT 0,  -- distinct tenant blocks
    processed_rows         INT           NOT NULL DEFAULT 0,  -- execution progress
    last_processed_row     INT           NOT NULL DEFAULT 0,  -- checkpoint: last CSV line finished (pod-death resume, D4)
    counts_jsonb           JSONB         NOT NULL DEFAULT '{}'::jsonb,  -- ImportOutcomeCounts projection
    error_csv_object       TEXT          NULL,      -- generated report objects (signed-URL'd at read)
    result_csv_object      TEXT          NULL,
    credentials_csv_object TEXT          NULL,      -- ADR-222 D2 #3: object PATH only; passwords never in DB
    failure_reason         TEXT          NULL,      -- FileError / system failure (state=failed)
    started_at             TIMESTAMPTZ   NULL,
    completed_at           TIMESTAMPTZ   NULL,
    created_at             TIMESTAMPTZ   NOT NULL DEFAULT now(),
    updated_at             TIMESTAMPTZ   NOT NULL DEFAULT now(),
    deleted_at             TIMESTAMPTZ   NULL
);

-- M-7: at most ONE live job per actor (terminal/soft-deleted jobs don't block).
CREATE UNIQUE INDEX uq_import_jobs_active_actor
    ON import_jobs (actor_gcid)
    WHERE state IN ('validating', 'awaiting_confirm', 'running')
      AND deleted_at IS NULL;

-- List path: a scope's jobs newest-first.
CREATE INDEX idx_import_jobs_tenant_recent
    ON import_jobs (tenant_id, created_at DESC)
    WHERE deleted_at IS NULL;

-- Batch lookup (teardown resolves batch -> jobs).
CREATE INDEX idx_import_jobs_batch ON import_jobs (import_batch_id);

-- Crashed-run reaper: running jobs oldest-first.
CREATE INDEX idx_import_jobs_running
    ON import_jobs (created_at)
    WHERE state = 'running' AND deleted_at IS NULL;

CREATE TRIGGER trg_import_jobs_updated_at
    BEFORE UPDATE ON import_jobs
    FOR EACH ROW EXECUTE FUNCTION identity_set_updated_at();

ALTER TABLE import_jobs ENABLE ROW LEVEL SECURITY;
ALTER TABLE import_jobs FORCE ROW LEVEL SECURITY;
-- Platform-sentinel-aware (mirrors tenancy 0025): 'platform' GUC => all rows
-- (operator context); a real tenant uuid => that tenant's rows; empty/unset
-- => fail closed (nested NULLIF guard, no 22P02 on empty GUC).
CREATE POLICY import_jobs_tenant_isolation ON import_jobs
    FOR ALL
    USING (
        current_setting('chora.tenant_id', true) = 'platform'
        OR tenant_id = NULLIF(NULLIF(current_setting('chora.tenant_id', true), ''), 'platform')::uuid
    )
    WITH CHECK (
        current_setting('chora.tenant_id', true) = 'platform'
        OR tenant_id = NULLIF(NULLIF(current_setting('chora.tenant_id', true), ''), 'platform')::uuid
    );

-- ---------------------------------------------------------------------------
-- import_job_rows — per-line ledger (validation + execution outcomes)
-- ---------------------------------------------------------------------------
CREATE TABLE import_job_rows (
    row_id             UUID          PRIMARY KEY DEFAULT gen_random_uuid(),
    job_id             UUID          NOT NULL REFERENCES import_jobs(job_id),
    tenant_id          UUID          NOT NULL,  -- RLS slot: matches the parent job's home scope
    line_number        INT           NOT NULL,  -- physical CSV line (header = 1)
    target_tenant_slug TEXT          NULL,      -- from the CSV (block identity pre-creation)
    target_tenant_id   UUID          NULL,      -- resolved/created tenant (cross-domain ref by UUID, no FK)
    email              VARCHAR(320)  NULL,      -- normalized (M-4); NULL on header-error rows
    display_name       TEXT          NULL,
    roles              TEXT[]        NULL,      -- canonical role list (post-alias, GQ-6)
    external_ref       TEXT          NULL,      -- verbatim text (M-5)
    send_invite        BOOLEAN       NULL,      -- per-row override (NULL = job toggle)
    outcome            import_row_outcome NULL, -- NULL until validated/executed
    errors_jsonb       JSONB         NULL,      -- [{field, code, reason}] (multi-error lines, e.g. header line 1)
    minted_gcid        UUID          NULL,      -- synthetic mint result (ADR-222 D1)
    invite_id          UUID          NULL,      -- pending_invites result (ADR-194 seam)
    processed_at       TIMESTAMPTZ   NULL,
    created_at         TIMESTAMPTZ   NOT NULL DEFAULT now(),
    updated_at         TIMESTAMPTZ   NOT NULL DEFAULT now(),
    deleted_at         TIMESTAMPTZ   NULL,
    UNIQUE (job_id, line_number)
);

-- Chunk scan: next unprocessed lines of a job in file order.
CREATE INDEX idx_import_job_rows_job_line ON import_job_rows (job_id, line_number);

-- Report generation: a job's rows by outcome.
CREATE INDEX idx_import_job_rows_job_outcome ON import_job_rows (job_id, outcome);

CREATE TRIGGER trg_import_job_rows_updated_at
    BEFORE UPDATE ON import_job_rows
    FOR EACH ROW EXECUTE FUNCTION identity_set_updated_at();

ALTER TABLE import_job_rows ENABLE ROW LEVEL SECURITY;
ALTER TABLE import_job_rows FORCE ROW LEVEL SECURITY;
CREATE POLICY import_job_rows_tenant_isolation ON import_job_rows
    FOR ALL
    USING (
        current_setting('chora.tenant_id', true) = 'platform'
        OR tenant_id = NULLIF(NULLIF(current_setting('chora.tenant_id', true), ''), 'platform')::uuid
    )
    WITH CHECK (
        current_setting('chora.tenant_id', true) = 'platform'
        OR tenant_id = NULLIF(NULLIF(current_setting('chora.tenant_id', true), ''), 'platform')::uuid
    );

-- ---------------------------------------------------------------------------
-- import_batch_members — teardown map (ADR-222 D3)
-- ---------------------------------------------------------------------------
CREATE TABLE import_batch_members (
    member_id        UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    import_batch_id  UUID         NOT NULL,
    job_id           UUID         NOT NULL REFERENCES import_jobs(job_id),
    tenant_id        UUID         NOT NULL,  -- RLS slot: matches the parent job's home scope
    gcid             UUID         NOT NULL,  -- minted synthetic principal
    member_tenant_id UUID         NOT NULL,  -- tenant the principal was minted INTO (cross-domain ref, no FK)
    gcip_uid         TEXT         NULL,      -- synthetic_login GCIP account uid (saga deletes it, ADR-222 D2 #5)
    saga_id          UUID         NULL,      -- account-closure saga enqueued at teardown
    torn_down_at     TIMESTAMPTZ  NULL,      -- saga enqueue time (completion is saga-async)
    created_at       TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ  NOT NULL DEFAULT now(),
    deleted_at       TIMESTAMPTZ  NULL,
    UNIQUE (import_batch_id, gcid)
);

-- Teardown fan-out: all live members of a batch.
CREATE INDEX idx_import_batch_members_batch
    ON import_batch_members (import_batch_id)
    WHERE deleted_at IS NULL;

-- Reverse lookup: which batch minted this GCID (saga completion callback).
CREATE INDEX idx_import_batch_members_gcid ON import_batch_members (gcid);

CREATE TRIGGER trg_import_batch_members_updated_at
    BEFORE UPDATE ON import_batch_members
    FOR EACH ROW EXECUTE FUNCTION identity_set_updated_at();

ALTER TABLE import_batch_members ENABLE ROW LEVEL SECURITY;
ALTER TABLE import_batch_members FORCE ROW LEVEL SECURITY;
CREATE POLICY import_batch_members_tenant_isolation ON import_batch_members
    FOR ALL
    USING (
        current_setting('chora.tenant_id', true) = 'platform'
        OR tenant_id = NULLIF(NULLIF(current_setting('chora.tenant_id', true), ''), 'platform')::uuid
    )
    WITH CHECK (
        current_setting('chora.tenant_id', true) = 'platform'
        OR tenant_id = NULLIF(NULLIF(current_setting('chora.tenant_id', true), ''), 'platform')::uuid
    );

COMMIT;

-- =============================================================================
-- VERIFICATION (manual, after apply):
--   -- sentinel scoping: operator context sees nil-uuid jobs, tenants don't:
--   BEGIN; SET LOCAL chora.tenant_id = 'platform';
--     INSERT INTO import_jobs (tenant_id, import_batch_id, actor_gcid, run_mode)
--       VALUES ('00000000-0000-0000-0000-000000000000', gen_random_uuid(), gen_random_uuid(), 'operator_create_new');
--     SELECT count(*) FROM import_jobs;  -- 1
--   COMMIT;
--   BEGIN; SET LOCAL chora.tenant_id = '<any-real-tenant-uuid>';
--     SELECT count(*) FROM import_jobs;  -- 0
--   COMMIT;
--   -- M-7: a second live job for the same actor must violate uq_import_jobs_active_actor.
-- =============================================================================
