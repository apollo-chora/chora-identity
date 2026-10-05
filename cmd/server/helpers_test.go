// helpers_test.go — pure-helper coverage for the chora-identity composition
// root.
//
// The composition root (main / configureAttestation / bootstrap*) is
// intentionally NOT driven here: main() blocks on SIGINT and boots real
// infra (pgx pool, NATS bus, OTLP exporter, net listeners), so it is a
// documented plateau. Everything below it that is pure or env-seam testable
// IS covered: env fallbacks, the no-env bootstrap no-ops, the eventbus
// consumer tuning, and the FIDO MDS attestation helpers
// (attestation_wiring_test.go).
package main

import (
	"context"
	"testing"
	"time"
)

// -----------------------------------------------------------------------------
// envOrDefault
// -----------------------------------------------------------------------------

func TestEnvOrDefault_UnsetReturnsDefault(t *testing.T) {
	t.Setenv("CHORA_HELPERS_TEST_UNSET", "")
	if got := envOrDefault("CHORA_HELPERS_TEST_UNSET", "def"); got != "def" {
		t.Errorf("envOrDefault(unset) = %q, want %q", got, "def")
	}
}

func TestEnvOrDefault_SetReturnsValue(t *testing.T) {
	t.Setenv("CHORA_HELPERS_TEST_SET", "val")
	if got := envOrDefault("CHORA_HELPERS_TEST_SET", "def"); got != "val" {
		t.Errorf("envOrDefault(set) = %q, want %q", got, "val")
	}
}

// -----------------------------------------------------------------------------
// workerID — dispatcher worker identity from env / hostname / fallback
// -----------------------------------------------------------------------------

func TestWorkerID_EnvWins(t *testing.T) {
	t.Setenv("CHORA_OUTBOX_WORKER_ID", "w-42")
	t.Setenv("HOSTNAME", "")
	if got := workerID(); got != "w-42" {
		t.Errorf("workerID = %q, want %q", got, "w-42")
	}
}

func TestWorkerID_HostnameFallback(t *testing.T) {
	t.Setenv("CHORA_OUTBOX_WORKER_ID", "")
	t.Setenv("HOSTNAME", "pod-abc-123")
	if got := workerID(); got != "pod-abc-123" {
		t.Errorf("workerID = %q, want %q", got, "pod-abc-123")
	}
}

func TestWorkerID_LocalFallback(t *testing.T) {
	t.Setenv("CHORA_OUTBOX_WORKER_ID", "")
	t.Setenv("HOSTNAME", "")
	if got := workerID(); got != "chora-identity-local" {
		t.Errorf("workerID = %q, want %q", got, "chora-identity-local")
	}
}

// -----------------------------------------------------------------------------
// inboxFromEnv — consumer-side dedupe store selector
// -----------------------------------------------------------------------------

func TestInboxFromEnv_ReturnsMemoryStore(t *testing.T) {
	t.Setenv("CHORA_INBOX_USE_POSTGRES", "")
	got := inboxFromEnv()
	if got == nil {
		t.Fatal("inboxFromEnv() returned nil store")
	}
	// The memory store must actually claim + dedupe a key so the returned
	// store is usable by subscribers, not a stub.
	ctx := context.Background()
	ran := 0
	err := got.Process(ctx, "k1", 30*time.Second, func() error { ran++; return nil })
	if err != nil {
		t.Fatalf("memory store Process: %v", err)
	}
	if err := got.Process(ctx, "k1", 30*time.Second, func() error { ran++; return nil }); err != nil {
		t.Fatalf("memory store Process (dup): %v", err)
	}
	if ran != 1 {
		t.Errorf("Process ran fn %d times, want 1 (idempotent dedupe)", ran)
	}
}

func TestInboxFromEnv_PostgresFlagLogsAndReturnsMemory(t *testing.T) {
	t.Setenv("CHORA_INBOX_USE_POSTGRES", "true")
	// The PostgresStore swap is deferred; the flag must be tolerated
	// (logged) and the memory store returned so dev/test keep working.
	got := inboxFromEnv()
	if got == nil {
		t.Fatal("inboxFromEnv() returned nil store with CHORA_INBOX_USE_POSTGRES=true")
	}
}

// -----------------------------------------------------------------------------
// consumerConfig — shared durable-consumer tuning
// -----------------------------------------------------------------------------

func TestConsumerConfig_CanonicalTuning(t *testing.T) {
	t.Parallel()
	cfg := consumerConfig("chora-identity.closure-pseudonymise", "chora.identity.pii.pseudonymise.requested.v1")
	if cfg.Name != "chora-identity.closure-pseudonymise" {
		t.Errorf("Name = %q", cfg.Name)
	}
	if cfg.Subject != "chora.identity.pii.pseudonymise.requested.v1" {
		t.Errorf("Subject = %q", cfg.Subject)
	}
	if cfg.MaxDeliver != 5 {
		t.Errorf("MaxDeliver = %d, want 5", cfg.MaxDeliver)
	}
	if cfg.AckWait != 30*time.Second {
		t.Errorf("AckWait = %v, want 30s", cfg.AckWait)
	}
	if len(cfg.Backoff) != 4 {
		t.Errorf("Backoff len = %d, want 4", len(cfg.Backoff))
	}
	if cfg.DLQSubject != "_dlq.chora.identity.pii.pseudonymise.requested.v1" {
		t.Errorf("DLQSubject = %q", cfg.DLQSubject)
	}
}

// -----------------------------------------------------------------------------
// bootstrap* no-op paths — env unset ⇒ nil pool / nil bus / nil db.
// The configured paths dial real infra and are a documented plateau
// (live-only, fail-loud by design).
// -----------------------------------------------------------------------------

func TestBootstrapDBPool_UnsetEnvIsNil(t *testing.T) {
	t.Setenv("CHORA_DB_DSN", "")
	t.Setenv("CHORA_DB_DSN_SECRET_ID", "")
	pool, shutdown := bootstrapDBPool(context.Background())
	if pool != nil {
		t.Errorf("pool = %v, want nil for unset env", pool)
	}
	if shutdown != nil {
		t.Errorf("shutdown func returned non-nil for unset env")
	}
}

func TestBootstrapBus_UnsetEnvIsNil(t *testing.T) {
	t.Setenv("NATS_URL", "")
	bus, shutdown := bootstrapBus(context.Background())
	if bus != nil {
		t.Errorf("bus = %v, want nil for unset env", bus)
	}
	if shutdown != nil {
		t.Errorf("shutdown func returned non-nil for unset env")
	}
}

func TestBootstrapOutboxDB_UnsetEnvIsNil(t *testing.T) {
	t.Setenv("CHORA_OUTBOX_DSN", "")
	t.Setenv("CHORA_OUTBOX_DSN_SECRET_ID", "")
	db, shutdown := bootstrapOutboxDB(context.Background())
	if db != nil {
		t.Errorf("db = %v, want nil for unset env", db)
	}
	if shutdown != nil {
		t.Errorf("shutdown func returned non-nil for unset env")
	}
}
