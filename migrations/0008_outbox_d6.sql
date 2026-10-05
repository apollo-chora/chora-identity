-- =============================================================================
-- chora-identity : 0008_outbox_d6.sql
--
-- M12.3 Wave 2 (w2a-identity) — upgrades the existing outbox_events table to
-- the canonical D6.2 contract by adding the top-level columns required for
-- Pillar 3 multi-tenant chaos isolation indexing + RLS, per
-- `.claude/skills/agentic-resilience-d6/SKILL.md` Pillar 2.
--
-- Mirrors the canonical chora-guardrail D6.2 migration:
--   services/chora-guardrail/migrations/0004_outbox.sql
-- And the parallel chora-delivery alignment:
--   services/chora-delivery/migrations/0004_outbox_d6.sql
--
-- Predecessor migration 0005_outbox.sql created outbox_events with the
-- chora-go-common shared schema (aggregate_type / aggregate_id columns).
-- This migration extends — does NOT replace — that schema with:
--
--   1. Top-level tenant_id column (D6.3 multi-tenant isolation indexing).
--   2. Top-level gcid column (subject — may be NULL for system events).
--   3. Top-level idempotency_key column UNIQUE (dedupe).
--   4. RLS policy on outbox_events keyed by app.current_tenant GUC.
--   5. Indexes on (tenant_id, status, occurred_at) for D6.3 indexed lookup.
--
-- Domain    : Identity (supporting/platform)
-- Database  : chora_identity
-- Date      : 2026-05-12
--
-- HARD INVARIANTS
--   * tenant_id is captured as a top-level column (Pillar 3 isolation
--     indexing — production identity emits events for many tenants on the
--     same Pub/Sub pipe). Identity also emits cross-tenant platform events
--     (envelope.tenant_id="platform") — RLS policy treats NULL/empty GUC
--     as permissive so the dispatcher operates without tenant context.
--   * idempotency_key + envelope mandatory per CLAUDE.md cross-cutting rule.
--   * Cross-DB queries remain forbidden — domain subscribers (chora-tenancy,
--     chora-creation, etc.) read events from Pub/Sub, never from this table.
--
-- Idempotency
--   * IF NOT EXISTS on every DDL — re-runs are no-ops.
--   * Column adds default NULL to permit backfill of pre-existing rows
--     (current rows are seed-time only — backfill is a no-op in practice).
-- =============================================================================

BEGIN;

-- 1) tenant_id column on outbox_events (Pillar 3 top-level isolation key).
--    NOTE: nullable to permit backfill of pre-existing rows; application
--    layer enforces non-empty at insert time (see internal/adapter/outbox).
ALTER TABLE outbox_events
    ADD COLUMN IF NOT EXISTS tenant_id UUID;

ALTER TABLE outbox_events
    ADD COLUMN IF NOT EXISTS gcid UUID;

ALTER TABLE outbox_events
    ADD COLUMN IF NOT EXISTS idempotency_key TEXT;

-- 2) Indexes for Pillar 3 multi-tenant + idempotency.
CREATE INDEX IF NOT EXISTS outbox_events_tenant_idx
    ON outbox_events (tenant_id, status, occurred_at);

CREATE UNIQUE INDEX IF NOT EXISTS outbox_events_idempotency_idx
    ON outbox_events (idempotency_key)
    WHERE idempotency_key IS NOT NULL;

-- 3) RLS — same pattern as chora-guardrail outbox + closure outbox + AI Kernel
--    outbox + chora-delivery outbox. Identity's emit path is inherently
--    multi-tenant (one pod fans out events for many tenants per minute);
--    production wires the GUC via per-connection SET LOCAL app.current_tenant.
--    RLS policy remains permissive when the GUC is unset to keep the relay
--    dispatcher functional (the dispatcher operates without a tenant context).
ALTER TABLE outbox_events ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS outbox_events_tenant_isolation ON outbox_events;
CREATE POLICY outbox_events_tenant_isolation ON outbox_events
    USING (
        current_setting('app.current_tenant', TRUE) IS NULL
        OR current_setting('app.current_tenant', TRUE) = ''
        OR tenant_id IS NULL
        OR tenant_id::TEXT = current_setting('app.current_tenant', TRUE)
    );

COMMIT;
