-- 0011_outbox_wipe_json_pending.up.sql
--
-- Outbox payload encoding migration (codebase-wide JSON→binary-protobuf fix).
--
-- Background
-- ----------
-- Pre-fix outbox rows on chora_identity.outbox_events held JSON-marshalled
-- payload bytes that the event-bus schema contract (BINARY encoding) rejects at
-- publish time with "Invalid binary proto message". The dispatcher retries
-- until MaxAttempts then dead-letters; the row never publishes.
--
-- Fix
-- ---
-- internal/adapter/events/protomarshal now emits canonical binary protobuf
-- bytes for every Schema-Registry-attached chora.identity.* topic surfaced
-- by this service. Both inner publishers (CloudPublisher + outbox.Publisher)
-- swap json.Marshal → encodeXxxPayload → protomarshal.MarshalPayload.
--
-- Topics now binary-encoded:
--
--   * chora.identity.user_mana.{credited,debited,refunded,snapshot_taken}.v1
--   * chora.identity.kyc.{submitted,verified,rejected}.v1
--   * chora.identity.user_subscription.{created,cancelled,renewed,plan_changed}.v1
--   * chora.identity.role.granted.v1
--   * chora.identity.account.lifecycle_changed.v1
--
-- New rows written after the fix carry binary bytes and publish cleanly.
-- This migration drains pre-fix JSON-payload rows out of the pending queue
-- so the dispatcher stops retrying them; rows that NEVER successfully
-- published (still 'pending') are safe to mark 'failed' — no downstream
-- subscriber ever saw them.
--
-- Replay strategy
-- ---------------
-- We mark-failed rather than translate-and-retry: the producer-side handlers
-- (kyc, user_mana, user_subscription, role, account_lifecycle, etc.) are
-- idempotent on envelope.idempotency_key — re-triggering the originating
-- domain flow will emit a fresh correctly-encoded outbox row. Translating
-- JSON-decoded fields back into the typed proto would be more error-prone
-- than re-emission for these telemetry / projection events.
--
-- Account-closure saga is the lone exception that may need targeted replay;
-- the closure orchestrator runbook tracks per-saga state separately and
-- can resume from chora_identity.account_closure_saga without needing the
-- pending pre-fix events.
--
-- Idempotent: re-running is a no-op (the WHERE clause matches no rows after
-- the first pass).
UPDATE outbox_events
SET status          = 'failed',
    last_error      = 'codebase-wide outbox protobuf encoding fix #33 — pre-fix JSON-payload row drained',
    last_attempt_at = now()
WHERE status = 'pending'
  AND topic IN (
    'chora.identity.user_mana.credited.v1',
    'chora.identity.user_mana.debited.v1',
    'chora.identity.user_mana.refunded.v1',
    'chora.identity.user_mana.snapshot_taken.v1',
    'chora.identity.kyc.submitted.v1',
    'chora.identity.kyc.verified.v1',
    'chora.identity.kyc.rejected.v1',
    'chora.identity.user_subscription.created.v1',
    'chora.identity.user_subscription.cancelled.v1',
    'chora.identity.user_subscription.renewed.v1',
    'chora.identity.user_subscription.plan_changed.v1',
    'chora.identity.role.granted.v1',
    'chora.identity.account.lifecycle_changed.v1'
  );
