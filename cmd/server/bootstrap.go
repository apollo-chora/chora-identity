// bootstrap.go — production wiring helpers for the chora-identity server.
//
// Per `feedback_resilience_priority` + secrets-and-env skill: every
// production dependency is sourced from env vars (Terraform / Secret
// Manager). Local dev sees nil pools / nil pubsub clients so the server
// keeps the in-memory adapter fallback working out of the box.
//
// Environment contract:
//
//	CHORA_DB_DSN_SECRET_ID  — environment-backed secret name resolving
//	                          to a chora_identity DSN (app_rw role).
//	CHORA_DB_DSN            — direct DSN (dev override; takes priority
//	                          over SECRET_ID).
//	CHORA_DB_PROJECT        — project label used for secret resolution.
//	                          Defaults to chora-local.
//	CHORA_DB_REWRITE_FROM_PORT — when set, rewrites DSN port (e.g. 6432
//	                             → 5432). Used to bypass a pooler until
//	                             the sidecar lands.
//	CHORA_DB_REWRITE_TO_PORT   — companion to FROM_PORT.
//
//	CHORA_LOCAL_KEK         — base64 32-byte master KEK for DEK envelope
//	                          encryption (required at boot).
//	NATS_URL                — NATS JetStream broker URL for the event bus.
//
// All values empty in dev → fallthrough to in-memory adapters.
package main

import (
	"context"
	"database/sql"
	"errors"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	cgcdb "github.com/apollo-chora/chora-common/db"
	"github.com/apollo-chora/chora-common/eventbus"
	"github.com/apollo-chora/chora-common/idempotent"
	cgcsecrets "github.com/apollo-chora/chora-common/secrets"

	"github.com/apollo-chora/chora-identity/internal/adapter/outbox"
	"github.com/apollo-chora/chora-identity/internal/domain/identity"
)

// bootstrapDBPool returns a pgxpool.Pool for chora_identity when the
// environment is configured for it; nil otherwise. The closure returned
// is the shutdown hook (Close pool); caller defers it.
func bootstrapDBPool(ctx context.Context) (*pgxpool.Pool, func()) {
	dsn := os.Getenv("CHORA_DB_DSN")
	secretID := os.Getenv("CHORA_DB_DSN_SECRET_ID")
	if dsn == "" && secretID == "" {
		log.Printf("identity: CHORA_DB_DSN / CHORA_DB_DSN_SECRET_ID unset — using in-memory repositories")
		return nil, nil
	}

	project := os.Getenv("CHORA_DB_PROJECT")
	if project == "" {
		project = "chora-local"
	}

	var fetcher cgcdb.SecretFetcher
	var sclient *cgcsecrets.Client
	if secretID != "" && dsn == "" {
		c, err := cgcsecrets.NewClient(ctx, project)
		if err != nil {
			log.Fatalf("identity: secret manager init failed (env set, fail-loud): %v", err)
		}
		sclient = c
		fetcher = c
	}

	rewriteFrom, _ := strconv.Atoi(os.Getenv("CHORA_DB_REWRITE_FROM_PORT"))
	rewriteTo, _ := strconv.Atoi(os.Getenv("CHORA_DB_REWRITE_TO_PORT"))

	// Env-driven bootstrap context (default 30s). Under a concurrent
	// multi-pod cold-start, connection-pooler + secret resolution can
	// exceed 30s. Set CHORA_BOOTSTRAP_TIMEOUT_SECONDS to tune.
	bootstrapSecs, _ := strconv.Atoi(os.Getenv("CHORA_BOOTSTRAP_TIMEOUT_SECONDS"))
	if bootstrapSecs <= 0 {
		bootstrapSecs = 30
	}
	bootstrapCtx, cancel := context.WithTimeout(ctx, time.Duration(bootstrapSecs)*time.Second)
	defer cancel()

	pool, err := cgcdb.Bootstrap(bootstrapCtx, cgcdb.BootstrapOptions{
		DSN:             dsn,
		SecretID:        secretID,
		SecretFetcher:   fetcher,
		RewriteFromPort: rewriteFrom,
		RewriteToPort:   rewriteTo,
		AppName:         serviceName + "@" + version,
		RuntimeParams:   identityDBRuntimeParams(),
	})
	if err != nil {
		if sclient != nil {
			_ = sclient.Close()
		}
		log.Fatalf("identity: pgx pool bootstrap failed (env set, fail-loud — kubelet will CrashLoopBackOff): %v", err)
	}

	shutdown := func() {
		pool.Close()
		if sclient != nil {
			_ = sclient.Close()
		}
	}
	return pool, shutdown
}

// bootstrapBus returns a NATS JetStream eventbus when NATS_URL is set,
// otherwise nil (the caller falls back to the in-memory bus). The returned
// closure is the shutdown hook; caller defers it.
//
// Environment contract:
//
//	NATS_URL — JetStream broker URL (e.g. nats://127.0.0.1:4222).
//	           Unset → nil bus (in-process fallback; NOT durable).
func bootstrapBus(ctx context.Context) (eventbus.Bus, func()) {
	url := strings.TrimSpace(os.Getenv("NATS_URL"))
	if url == "" {
		return nil, nil
	}
	bus, err := eventbus.NewJetStream(eventbus.JetStreamConfig{URL: url})
	if err != nil {
		log.Printf("identity: NATS JetStream init failed: %v — falling back to in-memory bus", err)
		return nil, nil
	}
	return bus, func() { _ = bus.Close() }
}

// bindSubscription spawns the durable-consumer goroutine for one subject,
// mirroring the closure + user_mana_topup bindings in main.go. The consumer
// name is the subject itself — eventbus.SanitizeConsumerName makes it a
// legal durable name, and each topic gets its own durable + DLQ this way.
func bindSubscription(ctx context.Context, bus eventbus.Bus, subject string, handler eventbus.Handler) {
	go func() {
		log.Printf("identity: subscriber binding %s", subject)
		if err := bus.Subscribe(ctx, consumerConfig(subject, subject), handler); err != nil && !errors.Is(err, context.Canceled) {
			log.Printf("identity: subscriber %s exited: %v", subject, err)
		}
	}()
}

// consumerConfig is the shared durable-consumer tuning for every
// chora-identity subscriber: at-least-once with a 30s ack window, five
// delivery attempts, and the canonical _dlq.<subject> dead-letter routing.
//
// The dotted Pub/Sub subscription id is safe as Name — eventbus sanitises it
// to a NATS-legal durable name internally.
func consumerConfig(name, subject string) eventbus.ConsumerConfig {
	return eventbus.ConsumerConfig{
		Name:       name,
		Subject:    subject,
		MaxDeliver: 5,
		AckWait:    30 * time.Second,
		Backoff: []time.Duration{
			1 * time.Second, 5 * time.Second, 15 * time.Second, 30 * time.Second,
		},
		DLQSubject: eventbus.DLQSubject(subject),
	}
}

// -----------------------------------------------------------------------------
// selectUserRepository — composition-root wiring helper (B2 fix, 2026-05-15)
// -----------------------------------------------------------------------------
//
// The chora-identity composition root constructs TWO candidate
// UserRepository instances:
//
//   - pgUsers : *pg.UserRepository backed by the chora_identity DB pool
//     (real users; canonical Phyllis gcid `00000000-0000-7000-8000-
//     000000001999` lives here).
//   - fallback : in-memory comic seed (Phyllis/Mr Chen comic-fixture
//     gcids — `01935b5a-9bcf-7000-8000-…`).
//
// The bug class — `_ = wired later` discards — has now bitten this code
// path FOUR times (A7 chora-tenancy /api/* stores, D0.1c chora-identity
// resolve UserRepository, #27 chora-creation AtomRepository RLS-blind
// reads, and now B2 chora-identity /me + /api/users/{gcid} bearer-auth).
//
// This helper makes the binding decision deterministic + testable:
//
//	pgUsers non-nil                     → return pgUsers (production path)
//	pgUsers nil, env == "prod"/"production" → fail loud with
//	                                       errPgxUserRepoRequired
//	pgUsers nil, other env              → return fallback (dev mode with
//	                                       comic seeds; logged at caller)
//
// Per `feedback_no_stubs_real_wiring` (2026-05-14): production MUST fail
// loud rather than silently bind to an empty in-mem stub that 401s every
// canonical session.
var errPgxUserRepoRequired = errors.New("chora-identity: pgx-backed UserRepository required in production — chora_identity DB pool unavailable")

func selectUserRepository(pgUsers, fallback identity.UserRepository, env string) (identity.UserRepository, error) {
	if pgUsers != nil {
		return pgUsers, nil
	}
	if strings.EqualFold(env, "prod") || strings.EqualFold(env, "production") {
		return nil, errPgxUserRepoRequired
	}
	return fallback, nil
}

// -----------------------------------------------------------------------------
// selectPasskeyBackend — passkey persistence backend decision (CHO-2198)
// -----------------------------------------------------------------------------
//
// Passkeys (WebAuthn credentials) are AUTH CREDENTIALS. They used to be stored
// in-memory even with a healthy chora_identity pool because the durable pgx
// adapter was opt-in behind CHORA_IDENTITY_PASSKEY_BACKEND=pg — an UNSET env
// silently selected the volatile in-memory store, so a pod restart dropped
// every registered passkey (a credential-durability defect, CHO-2198).
//
// This helper makes durability the DEFAULT whenever the pool is healthy and
// keeps in-memory ONLY as an explicit, loudly-announced dev override:
//
//	envVal (CHORA_IDENTITY_PASSKEY_BACKEND) │ poolHealthy │ result
//	────────────────────────────────────────┼─────────────┼───────────────────
//	"" (unset)                               │ true        │ pg (durable)
//	"" (unset)                               │ false       │ error (fail loud)
//	"pg"                                     │ true        │ pg (durable)
//	"pg"                                     │ false       │ error (fail loud)
//	"memory" / "inmem"                       │ any         │ memory (caller WARNs)
//	anything else                            │ any         │ error (fail loud)
//
// Per the CLAUDE.md hard invariant ("never silently fall back") + the F1
// directive: a credential store MUST NOT silently run on volatile memory. A
// missing pool with no explicit dev override is fatal — local dev without a
// DB opts in via CHORA_IDENTITY_PASSKEY_BACKEND=memory.
type passkeyBackend string

const (
	passkeyBackendPg     passkeyBackend = "pg"
	passkeyBackendMemory passkeyBackend = "memory"
)

var (
	errPasskeyPgPoolRequired = errors.New("chora-identity: durable pgx passkey store required but chora_identity pool is unavailable — passkeys are auth credentials and MUST NOT be silently stored in volatile memory; set CHORA_IDENTITY_PASSKEY_BACKEND=memory to explicitly opt into the non-durable dev store")
	errPasskeyBackendUnknown = errors.New("chora-identity: unrecognised CHORA_IDENTITY_PASSKEY_BACKEND (want one of: unset|pg|memory)")
)

func selectPasskeyBackend(poolHealthy bool, envVal string) (passkeyBackend, error) {
	switch strings.ToLower(strings.TrimSpace(envVal)) {
	case "memory", "inmem":
		// Explicit dev override — volatile store even when a pool exists. The
		// caller MUST emit a loud WARNING (passkeys are not durable here).
		return passkeyBackendMemory, nil
	case "", "pg":
		// Durable-by-default: unset behaves like "pg". Either way a healthy
		// pool is required; refuse rather than silently run a credential store
		// on volatile memory.
		if poolHealthy {
			return passkeyBackendPg, nil
		}
		return "", errPasskeyPgPoolRequired
	default:
		return "", errPasskeyBackendUnknown
	}
}

// bootstrapOutboxDB returns a *sql.DB pointing at chora_identity for the
// D6.2 outbox adapter. Environment contract:
//
//	CHORA_OUTBOX_DSN — direct DSN (dev override). When unset, the caller
//	                   falls back to the InMemoryStore (single-replica
//	                   only; NOT durable across restart).
//
// Per `feedback_no_inline_config`: no inline URLs/secrets — the DSN is
// resolved from the environment (directly, or through the env-backed
// chora-common/secrets client). The actual driver registration is provided
// by the pgx stdlib driver imported in cmd/server — this file does not
// import a driver directly so downstream binaries stay slim.
func bootstrapOutboxDB(ctx context.Context) (*sql.DB, func()) {
	dsn := os.Getenv("CHORA_OUTBOX_DSN")
	secretID := os.Getenv("CHORA_OUTBOX_DSN_SECRET_ID")
	if dsn == "" && secretID == "" {
		return nil, nil
	}

	var sclient *cgcsecrets.Client
	if dsn == "" {
		project := os.Getenv("CHORA_DB_PROJECT")
		if project == "" {
			project = "chora-local"
		}
		c, err := cgcsecrets.NewClient(ctx, project)
		if err != nil {
			log.Fatalf("identity: outbox secret manager init failed (env set, fail-loud): %v", err)
		}
		sclient = c
		bootstrapSecs, _ := strconv.Atoi(os.Getenv("CHORA_BOOTSTRAP_TIMEOUT_SECONDS"))
		if bootstrapSecs <= 0 {
			bootstrapSecs = 30
		}
		resolveCtx, cancel := context.WithTimeout(ctx, time.Duration(bootstrapSecs)*time.Second)
		defer cancel()
		resolved, err := c.GetSecret(resolveCtx, secretID)
		if err != nil {
			_ = c.Close()
			log.Fatalf("identity: outbox secret fetch %q failed (env set, fail-loud): %v", secretID, err)
		}
		dsn = resolved
	}

	if rewriteFrom, _ := strconv.Atoi(os.Getenv("CHORA_DB_REWRITE_FROM_PORT")); rewriteFrom != 0 {
		if rewriteTo, _ := strconv.Atoi(os.Getenv("CHORA_DB_REWRITE_TO_PORT")); rewriteTo != 0 {
			rewritten, err := cgcdb.RewriteDSNPort(dsn, rewriteFrom, rewriteTo)
			if err != nil {
				if sclient != nil {
					_ = sclient.Close()
				}
				log.Fatalf("identity: outbox DSN port rewrite failed (env set, fail-loud): %v", err)
			}
			dsn = rewritten
		}
	}

	db, err := sql.Open("pgx", dsn)
	if err != nil {
		db, err = sql.Open("postgres", dsn)
	}
	if err != nil {
		if sclient != nil {
			_ = sclient.Close()
		}
		log.Fatalf("identity: outbox sql.Open failed (env set, fail-loud): %v", err)
	}
	if pingErr := db.PingContext(ctx); pingErr != nil {
		_ = db.Close()
		if sclient != nil {
			_ = sclient.Close()
		}
		log.Fatalf("identity: outbox db.Ping failed (env set, fail-loud): %v", pingErr)
	}
	return db, func() {
		_ = db.Close()
		if sclient != nil {
			_ = sclient.Close()
		}
	}
}

// workerID returns the dispatcher worker identifier sourced from
// CHORA_OUTBOX_WORKER_ID or HOSTNAME. Falls back to a stable string for
// local dev. The dispatcher requires a non-empty value (panics otherwise).
func workerID() string {
	if v := os.Getenv("CHORA_OUTBOX_WORKER_ID"); v != "" {
		return v
	}
	if v := os.Getenv("HOSTNAME"); v != "" {
		return v
	}
	return "chora-identity-local"
}

// sqlDBAdapter bridges *sql.DB (driver-typed *sql.Rows) to the outbox's
// SQLDB interface (which uses outbox.SQLRows so tests can stub). Since
// *sql.Rows already satisfies outbox.SQLRows's method set (Next + Scan +
// Close + Err), the adapter is a thin wrapper.
type sqlDBAdapter struct {
	db *sql.DB
}

func (a sqlDBAdapter) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	return a.db.ExecContext(ctx, query, args...)
}

func (a sqlDBAdapter) QueryContext(ctx context.Context, query string, args ...any) (outbox.SQLRows, error) {
	return a.db.QueryContext(ctx, query, args...)
}

// Compile-time check: sqlDBAdapter satisfies outbox.SQLDB.
var _ outbox.SQLDB = sqlDBAdapter{}

// inboxFromEnv constructs the consumer-side inbox store used by every
// chora-identity subscriber for dedupe across pod-restart + multi-replica
// failure modes (per `.claude/skills/agentic-resilience-d6/SKILL.md`
// Pillar 2 consumer-side dual).
//
// Production wires PostgresStore against chora_identity.idempotency_keys
// (migration 0007). Dev / tests fall through to the in-memory MemoryStore.
//
// Per `feedback_no_inline_config`: no inline DSN — the connection is
// sourced from CHORA_INBOX_DSN (or reuses CHORA_OUTBOX_DSN when unset).
// PostgresStore wiring is intentionally future-gated; for now the
// MemoryStore fallback covers single-replica + same-pod dedup, which
// matches the test surface.
func inboxFromEnv() idempotent.Store {
	// PostgresStore wiring is gated to land alongside the relay daemon in
	// M14+; expose the seam now via env so the production swap is a
	// configuration change, not a code change.
	if os.Getenv("CHORA_INBOX_USE_POSTGRES") == "true" {
		log.Printf("identity: CHORA_INBOX_USE_POSTGRES=true requested — PostgresStore wiring deferred to M14+ relay")
	}
	return idempotent.NewMemoryStore()
}

// identityDBRuntimeParams returns the per-connection Postgres GUCs that keep a
// DB write from hanging forever (fail-loud). Platform-wide rollout of the
// CHO-2005 fix (2026-07-04); mirrors chora-consumption's
// consumptionDBRuntimeParams. Set on every pooled connection via
// BootstrapOptions.RuntimeParams.
//
//   - lock_timeout=3s: a statement blocked on a row lock ERRORs ("canceling
//     statement due to lock timeout") instead of waiting indefinitely and
//     leaking the request goroutine — under the gateway's 6s per-call
//     timeout, so this service fails loud (500) before the gateway 504s.
//   - idle_in_transaction_session_timeout=60s: reaps a leaked open
//     transaction so its row locks release.
//
// No statement_timeout (owner steer): long read paths must not be capped.
func identityDBRuntimeParams() map[string]string {
	return map[string]string{
		"lock_timeout":                        "3s",
		"idle_in_transaction_session_timeout": "60s",
	}
}
