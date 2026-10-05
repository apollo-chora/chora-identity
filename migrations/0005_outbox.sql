-- =============================================================================
-- chora-identity : 0005_outbox.sql
--
-- Adds the transactional outbox primitive to chora_identity per the
-- Phyllis Wave-B service-wiring directive (`feedback_resilience_priority`).
--
-- Domain  : Identity (supporting/platform)
-- Database: chora_identity
-- Author  : agent-adc76a416bb263224 (Phyllis A-Service-Wiring-Identity)
-- Date    : 2026-05-11
--
-- Schema: copies the canonical fixture in
--   libs/chora-go-common/outbox/sql_fixtures/outbox_events.up.sql + outbox_poll_checkpoints.up.sql
-- so the existing chora-go-common/outbox PostgresRecorder + Relay drop in
-- without modification.
--
-- HARD INVARIANT: outbox rows live in the SAME database as the domain
-- they serve (chora_identity). Cross-DB queries remain forbidden — the
-- Relay process publishes to Cloud Pub/Sub and downstream subscribers
-- (chora-tenancy, chora-creation, etc.) consume via Pub/Sub.
-- =============================================================================

BEGIN;

-- -----------------------------------------------------------------------------
-- outbox_events — atomic enqueue inside the domain transaction
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS outbox_events (
    id              TEXT        PRIMARY KEY,
    aggregate_type  TEXT        NOT NULL,
    aggregate_id    TEXT        NOT NULL,
    event_type      TEXT        NOT NULL,
    topic           TEXT        NOT NULL,
    payload         BYTEA       NOT NULL,
    envelope        JSONB       NOT NULL,
    occurred_at     TIMESTAMPTZ NOT NULL,
    status          TEXT        NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending','published','failed','deadlettered')),
    retry_count     INT         NOT NULL DEFAULT 0,
    last_error      TEXT        NOT NULL DEFAULT '',
    last_attempt_at TIMESTAMPTZ,
    published_at    TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS outbox_events_pending_idx
    ON outbox_events (occurred_at ASC)
    WHERE status = 'pending';

CREATE INDEX IF NOT EXISTS outbox_events_aggregate_idx
    ON outbox_events (aggregate_type, aggregate_id, occurred_at DESC);

CREATE INDEX IF NOT EXISTS outbox_events_topic_idx
    ON outbox_events (topic, status);

-- -----------------------------------------------------------------------------
-- outbox_poll_checkpoints — per-(worker, topic) resume cursor
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS outbox_poll_checkpoints (
    worker_id                  TEXT        NOT NULL,
    topic                      TEXT        NOT NULL,
    last_processed_outbox_id   TEXT        NOT NULL,
    last_processed_occurred_at TIMESTAMPTZ NOT NULL,
    updated_at                 TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (worker_id, topic)
);

CREATE INDEX IF NOT EXISTS outbox_poll_checkpoints_topic_idx
    ON outbox_poll_checkpoints (topic, updated_at DESC);

-- -----------------------------------------------------------------------------
-- outbox_dead_letters — permanent failure tracker
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS outbox_dead_letters (
    outbox_event_id   TEXT        PRIMARY KEY REFERENCES outbox_events(id),
    failure_reason    TEXT        NOT NULL,
    attempt_count     INT         NOT NULL,
    worker_id         TEXT        NOT NULL,
    deadlettered_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    resolved_at       TIMESTAMPTZ,
    resolution_note   TEXT        NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS outbox_dead_letters_unresolved_idx
    ON outbox_dead_letters (deadlettered_at DESC)
    WHERE resolved_at IS NULL;

-- -----------------------------------------------------------------------------
-- idempotency_keys — multi-pod webhook + cross-domain command dedupe
-- -----------------------------------------------------------------------------
-- Per `feedback_resilience_priority`: every webhook + cross-domain command
-- handler that honours an `Idempotency-Key` header writes the key here so a
-- replay returns the cached response instead of re-executing the side
-- effect. UUIDv7 keys; rows expire when ttl_at < now() and are reaped by a
-- cron job (M14+).
--
-- Schema matches chora-go-common/idempotent.PostgresStore (Mark/Seen/Process).
CREATE TABLE IF NOT EXISTS idempotency_keys (
    key           TEXT        PRIMARY KEY,
    processed_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    ttl_at        TIMESTAMPTZ NOT NULL,
    result_hash   TEXT        NULL
);

CREATE INDEX IF NOT EXISTS idempotency_keys_ttl_idx
    ON idempotency_keys (ttl_at);

COMMIT;
