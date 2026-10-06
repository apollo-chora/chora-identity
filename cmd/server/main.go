// Package main is the chora-identity service entrypoint.
//
// Service: chora-identity (Identity supporting domain — IAM + GCID portability
//   - local username/password auth + WebAuthn).
//
// Topic prefix: chora.identity.*
//
// This is the standalone, cloud-neutral build: PostgreSQL repositories,
// local Argon2id credentials, a NATS JetStream event bus, OTLP tracing, and
// local AES-256-GCM DEK envelope encryption. The former Google Cloud
// dependencies (Identity Platform login, Cloud KMS, Secret Manager, Pub/Sub,
// Cloud Trace, Cloud Build/Deploy) have been removed.
package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"net"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	healthgrpc "google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"

	// pgx stdlib driver — registered for sql.Open("pgx", dsn) used by
	// the per-domain outbox PostgresStore in bootstrap.go.
	_ "github.com/jackc/pgx/v5/stdlib"

	identityv1 "github.com/apollo-chora/chora-contracts/gen/go/chora/services/identity/v1"

	"github.com/apollo-chora/chora-common/durabilityguard"
	"github.com/apollo-chora/chora-common/eventbus"
	grpcconn "github.com/apollo-chora/chora-common/grpcconn"
	"github.com/apollo-chora/chora-common/idempotent"
	"github.com/apollo-chora/chora-identity/internal/adapter/apikey_crypto"
	"github.com/apollo-chora/chora-identity/internal/adapter/apikey_events"
	"github.com/apollo-chora/chora-identity/internal/adapter/apikey_inmem"
	"github.com/apollo-chora/chora-identity/internal/adapter/cryptolocal"
	"github.com/apollo-chora/chora-identity/internal/adapter/events"
	grpcadapter "github.com/apollo-chora/chora-identity/internal/adapter/grpc"
	httpadapter "github.com/apollo-chora/chora-identity/internal/adapter/http"
	"github.com/apollo-chora/chora-identity/internal/adapter/idp/singpass"
	"github.com/apollo-chora/chora-identity/internal/adapter/inmem"
	"github.com/apollo-chora/chora-identity/internal/adapter/jwksinmem"
	"github.com/apollo-chora/chora-identity/internal/adapter/outbox"
	"github.com/apollo-chora/chora-identity/internal/adapter/payments"
	"github.com/apollo-chora/chora-identity/internal/adapter/pg"
	"github.com/apollo-chora/chora-identity/internal/adapter/repo"
	tipevents "github.com/apollo-chora/chora-identity/internal/adapter/tenant_idp_provider_events"
	"github.com/apollo-chora/chora-identity/internal/adapter/tenant_idp_secrets"
	"github.com/apollo-chora/chora-identity/internal/domain/apikey"
	"github.com/apollo-chora/chora-identity/internal/domain/crypto"
	exprules "github.com/apollo-chora/chora-identity/internal/domain/exp_rules"
	"github.com/apollo-chora/chora-identity/internal/domain/identity"
	"github.com/apollo-chora/chora-identity/internal/domain/kyc"
	tip "github.com/apollo-chora/chora-identity/internal/domain/tenant_idp_provider"
	mana "github.com/apollo-chora/chora-identity/internal/domain/user_mana"
	"github.com/apollo-chora/chora-identity/internal/observability"
)

const (
	serviceName = "chora-identity"
	version     = "0.1.0"
)

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// OTLP wiring per Tier 3 D13 — direct to Cloud Trace in prod, stdout in dev.
	//
	// Per C(a).S1 path (b) — tracker #151 — OTLP init runs in its own
	// goroutine with its own (env-tunable, default 15s) deadline + fail-
	// soft semantics. Timeout / init-error degrade to a no-op shutdown,
	// so the rest of bootstrap (pgx pool, Pub/Sub clients) gets the FULL
	// CHORA_BOOTSTRAP_TIMEOUT_SECONDS budget. Previously a slow Cloud
	// Trace TLS handshake could swallow the shared budget and crash-
	// loop the pod under PgBouncer 4-container cold-start.
	otlpHandle := observability.InitAsync(ctx)
	defer func() {
		// Use a fresh background context — the parent ctx may already be
		// cancelled by the time shutdown runs. WaitContext blocks until
		// init settles (no-op by shutdown time because pgx-pool init
		// below already gave OTLP best-effort wall-clock to land).
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		res := otlpHandle.WaitContext(shutdownCtx)
		if err := res.Shutdown(shutdownCtx); err != nil {
			log.Printf("trace shutdown error: %v", err)
		}
	}()

	// ----------------------------------------------------------------------
	// Repository wiring — keep concrete inmem repos in scope for seeding +
	// in-mem-only handler dependencies. The pgx-backed users repo (when
	// the environment is configured) overrides the user-aggregate port
	// passed into HTTP handlers; legacy in-mem repos remain wired for
	// memberships / snapshots / course roles + the Blocking Function
	// idempotency lookup which depends on inmem.FindByFederatedSubject
	// (a method off the concrete struct, replaced by the pgx adapter's
	// equivalent in M14+).
	// ----------------------------------------------------------------------
	inmemUsers := inmem.NewUserRepository()
	memberships := inmem.NewMembershipRepository()
	snapshots := inmem.NewSnapshotRepository()
	courseRoles := inmem.NewCourseRoleRepository()

	var pgUsers identity.UserRepository
	var pgMemberSearch identity.TenantMemberSearchRepo
	var tenantBootstrappedUpserter events.TenantMembershipUpserter
	var tipRepo tip.Repository
	// L1 Tenant lane (CHO-1707) — concrete pg repos for the
	// tenant-members admin handler (FindByEmail + AddMembership/ChangeRole
	// run against pg, NOT the legacy inmem membership repo).
	var pgUsersConcrete *pg.UserRepository
	var pgMembershipAdmin *pg.MembershipAdminRepository
	var pendingInviteRepo *pg.PendingInviteRepository // WS3 / ADR-194 D2 — cold-invite store
	pool, poolShutdown := bootstrapDBPool(ctx)
	if poolShutdown != nil {
		defer poolShutdown()
	}
	if pool != nil {
		querier := pg.NewPgxPoolQuerier(pool)
		pgUsersConcrete = pg.NewUserRepository(querier)
		pgUsers = pgUsersConcrete
		pgMembershipAdmin = pg.NewMembershipAdminRepository(querier)
		pendingInviteRepo = pg.NewPendingInviteRepository(querier) // WS3 / CHO-1873
		// B6.1 (2026-05-16) — searchTenantMembers picker. The TenantMember
		// SearchRepository wraps every SELECT in RunInTenantTx so RLS scopes
		// the result set per `SET LOCAL chora.tenant_id` (migration 0001's
		// tenant_isolation policy on tenant_memberships).
		pgMemberSearch = pg.NewTenantMemberSearchRepository(querier)
		// CHO-1630 Phase 2 — mirror upserter consumed by the
		// TenantBootstrappedSubscriber.
		tenantBootstrappedUpserter = pg.NewMembershipBootstrapUpserter(querier)
		// CHO-1682 — Setup Wizard Phase C: per-tenant IdP provider
		// aggregate. The repository wraps every SQL call in
		// RunInTenantTx so migration 0006_setup_wizard's RLS policy
		// (SET LOCAL chora.tenant_id) scopes reads + writes per tenant.
		tipRepo = pg.NewTenantIdpProviderRepository(querier)
		log.Printf("identity: pgx UserRepository + TenantMemberSearchRepository + MembershipBootstrapUpserter + TenantIdpProviderRepository wired (pool=chora_identity)")
	}

	// resolveUsers + routerUsers are the SAME UserRepository binding decision —
	// the pgx-backed adapter when chora_identity DB is wired (production +
	// canonical Phyllis gcid `00000000-0000-7000-8000-000000001999` lives
	// here); the inmem comic-seed repo when the pool is absent (dev).
	//
	// History — same bug class as #27 / A7 / D0.1c:
	//   - D0.1c (2026-05-14) fixed POST /v1/identity/resolve by binding
	//     `resolveUsers` to pgUsers. The mint flow's email→GCID path was
	//     wired through but the gcid→User lookup path (GET /me + bearer-
	//     auth on the legacy router) was still falling back to the inmem
	//     comic-seed repo — every authed call returned 401
	//     IDENTITY_UNKNOWN_GCID for canonical Phyllis. Surfaced 2026-05-15
	//     by docs/m13/phyllis-demo-rehearsal-v3-2026-05-15.md as B2.
	//   - B2 fix (2026-05-15) extracts the binding decision into
	//     selectUserRepository (bootstrap.go) so both call-sites + future
	//     handlers stay consistent + the production-fail-loud invariant is
	//     unit-testable.
	//
	// Per `feedback_no_stubs_real_wiring`: production MUST refuse to bind
	// the inmem fallback (it 401s every canonical session).
	choraEnv := os.Getenv("CHORA_ENV")
	resolveUsers, err := selectUserRepository(pgUsers, inmemUsers, choraEnv)
	if err != nil {
		log.Fatalf("identity: %v — check CHORA_DB_DSN_SECRET_ID", err)
	}
	if pgUsers != nil {
		log.Printf("identity: /v1/identity/resolve + /me bound to pgx UserRepository (pool=chora_identity)")
	} else {
		log.Printf("identity: chora_identity DB pool unavailable — /v1/identity/resolve + /me falling back to inmem UserRepository (dev only; resolves comic-seed fixtures only)")
	}

	// routerUsers — the UserRepository the legacy `handler` (which mounts
	// /me + bearer-auth + /api/users/{gcid} + /api/users/{gcid}/portability)
	// binds to. MUST match resolveUsers so authed sessions resolve against
	// the same canonical store the mint path writes to. Bug class fixed
	// here is B2 (2026-05-15) — see comment block above.
	routerUsers := resolveUsers

	// Seed Comic Ch4 P8 fixtures unless explicitly disabled. Production wiring
	// (M12+ Cloud SQL) will replace this with a denormalised projection
	// refreshed via Pub/Sub from chora.delivery.* events. Seeded into the
	// inmem repo only — the comic gcids (`01935b5a-9bcf-…`) are dev/test
	// fixtures and are NEVER written to chora_identity.users.
	if os.Getenv("CHORA_IDENTITY_DISABLE_COMIC_SEED") == "" {
		if err := inmem.SeedComicFixtures(inmemUsers, courseRoles); err != nil {
			log.Printf("comic seed failed (non-fatal): %v", err)
		}
	}

	// routerUsers — pgx-backed in prod (canonical chora_identity.users —
	// includes Phyllis gcid `00000000-0000-7000-8000-000000001999`),
	// inmem comic-seed in dev. Drives /me + bearer-auth + /api/users/{gcid}.
	// B2 fix (2026-05-15) — see selectUserRepository binding block above.
	handler := httpadapter.NewRouterWithCourseRoles(routerUsers, memberships, snapshots, courseRoles)

	// -----------------------------------------------------------------------
	// Per-user economy wiring (BE-USR-1, ADR-142, ADR-164 Stage E)
	// -----------------------------------------------------------------------
	// Per ADR-164 Wave 1 Stage E: the inline Stripe SDK has been replaced by
	// a gRPC client to chora-payments. CHORA_PAYMENTS_GRPC_ADDR is the
	// chora-payments mesh target (e.g. "chora-payments:9090").
	//
	// Boot fails LOUD on missing env when CHORA_ENV=prod; in dev the
	// PaymentsClient is left nil — purchase routes return 503
	// ECONOMY_PAYMENTS_UNCONFIGURED.
	var paymentsClient httpadapter.PaymentsSubscriptionCreator
	// paymentsKyc is the same concrete client exposed via the KYC-fee port
	// (ADR-164 Stage A.5 — manual-doc $9.99 fee via chora-payments Checkout).
	var paymentsKyc httpadapter.PaymentsKycClient
	var paymentsClientClose func() error
	if addr := strings.TrimSpace(os.Getenv("CHORA_PAYMENTS_GRPC_ADDR")); addr != "" {
		conn, err := grpc.NewClient(addr,
			grpc.WithTransportCredentials(insecure.NewCredentials()),
		)
		if err != nil {
			log.Fatalf("identity: grpc.NewClient %s (chora-payments): %v", addr, err)
		}
		client, err := payments.NewPaymentsClient(conn)
		if err != nil {
			_ = conn.Close()
			log.Fatalf("identity: payments client: %v", err)
		}
		paymentsClient = client
		paymentsKyc = client
		paymentsClientClose = conn.Close
		log.Printf("identity: chora-payments gRPC client wired (addr=%s)", addr)
	} else {
		if strings.EqualFold(os.Getenv("CHORA_ENV"), "prod") ||
			strings.EqualFold(os.Getenv("CHORA_ENV"), "production") {
			log.Fatalf("identity: CHORA_PAYMENTS_GRPC_ADDR required when CHORA_ENV=prod (ADR-164 Stage E)")
		}
		log.Printf("identity: CHORA_PAYMENTS_GRPC_ADDR unset — /api/v1/me/subscriptions purchase disabled (dev mode)")
	}
	if paymentsClientClose != nil {
		defer func() {
			if err := paymentsClientClose(); err != nil {
				log.Printf("identity: chora-payments gRPC conn.Close: %v", err)
			}
		}()
	}

	subRepo := repo.NewInMemUserSubscriptionRepo()
	// WS-2.7 — durable mana wallet. Mana is the umbrella LLM-spend currency
	// (ADR-142 §4); under WS-1 hard-block metering an in-memory wallet would
	// reset balances on every pod restart and lock users out of LLM. When the
	// chora_identity pool is wired, use the pg-backed store (user_mana +
	// mana_ledger + mana_subsidy_allocations, migrations 0002/0003, per-user
	// RLS); fall back to in-memory only when the pool is absent (dev).
	var manaStore mana.Store = repo.NewInMemManaStore()
	if pool != nil {
		manaStore = pg.NewManaStore(pg.NewPgxPoolQuerier(pool))
		log.Printf("identity: pg-backed user_mana wallet wired (pool=chora_identity; durable across restart)")
	} else {
		log.Printf("identity: in-memory user_mana wallet (chora_identity pool absent; NOT durable across restart)")
	}
	// KYC verification store. The W4 Exam BC admission gate (ADR-190 D2) reads
	// the VERIFIED claim via GetLatestByGcid; an in-memory store empties on every
	// pod restart, so the gate would refuse ALL candidates. Use the pg-backed
	// repo (kyc_verifications, migrations 0002/0003/0004, per-user RLS) when the
	// chora_identity pool is wired; fall back to in-memory only when absent (dev).
	var kycRepo kyc.Repository = repo.NewInMemKycRepo()
	if pool != nil {
		kycRepo = pg.NewKycRepository(pg.NewPgxPoolQuerier(pool))
		log.Printf("identity: pg-backed kyc_verifications repo wired (pool=chora_identity; durable across restart)")
	} else {
		log.Printf("identity: in-memory kyc repo (chora_identity pool absent; NOT durable across restart)")
	}

	// ----------------------------------------------------------------------
	// Event publisher wiring — D6.2 producer-side outbox per
	// `feedback_d6_resilience_first_class` + `.claude/skills/agentic-
	// resilience-d6/SKILL.md` Pillar 2.
	//
	// M12.3 W2a (2026-05-12) — the outbox.Publisher writes events to
	// chora_identity.outbox_events (migrations 0005 + 0008) inside the
	// caller's transaction; the outbox.Dispatcher (background goroutine)
	// drains pending rows to the NATS JetStream event bus. The HTTP handler
	// crash window between domain state-write and bus publish no longer
	// drops events.
	//
	// Fallbacks (no inline config per `feedback_no_inline_config`):
	//   - CHORA_OUTBOX_DSN unset / DB pool unavailable → in-memory store
	//     (single-replica only; not durable across restart)
	//   - NATS_URL unset → chora-common eventbus InMemoryBus
	//     (in-process events; tests + local dev)
	// ----------------------------------------------------------------------
	recorder := events.NewRecorder()
	var publisher events.Publisher = recorder

	// Outbox store: prefer Postgres-backed when chora_identity DB is wired;
	// fall back to in-memory for dev / tests.
	var outboxStoreImpl outbox.Store
	outboxDB, outboxClose := bootstrapOutboxDB(ctx)
	if outboxClose != nil {
		defer outboxClose()
	}
	if outboxDB != nil {
		outboxStoreImpl = outbox.NewPostgresStore(
			sqlDBAdapter{db: outboxDB},
			outbox.PostgresStoreOptions{WorkerID: workerID()},
		)
		log.Printf("identity: outbox PostgresStore wired (worker_id=%s)", workerID())
	} else {
		outboxStoreImpl = outbox.NewInMemoryStore()
		log.Printf("identity: outbox InMemoryStore wired (CHORA_OUTBOX_DSN unset; not durable across restart)")
	}

	// Event bus: NATS JetStream when NATS_URL is wired, in-memory otherwise.
	// The outbox dispatcher takes the Publisher view of whichever is wired;
	// subscribers below bind to the full JetStream bus (only available when
	// NATS is configured — the in-memory bus is publish-only here).
	jetBus, busShutdown := bootstrapBus(ctx)
	if busShutdown != nil {
		defer busShutdown()
	}
	var outboxBus outbox.Bus = eventbus.NewInMemoryBus()
	if jetBus != nil {
		outboxBus = jetBus
		log.Printf("identity: NATS JetStream event bus wired (url=%s)", os.Getenv("NATS_URL"))
	} else {
		log.Printf("identity: in-memory event bus wired (NATS_URL unset; NOT durable across restart)")
	}

	// Outbox publisher swaps in for the legacy events.Recorder when the
	// caller-side wiring is ready. Existing call-sites continue to use the
	// events.Publisher interface; we wire the outbox publisher as the
	// "publisher" variable so HTTP handlers + adapter wiring inherit it.
	outboxPub := outbox.NewPublisher(outbox.PublisherConfig{
		Store:         outboxStoreImpl,
		SourceProject: events.SourceProject,
		SourceService: events.SourceService,
	})
	publisher = outboxPub

	// Background outbox dispatcher (one per pod). Per
	// `feedback_d6_resilience_first_class` B.6.2.a — dispatcher is the
	// retry + DLQ ladder for the producer-side outbox. Graceful shutdown
	// drains pending batches before exit.
	dispatcher := outbox.NewDispatcher(outbox.DispatcherConfig{
		Store:        outboxStoreImpl,
		Bus:          outboxBus,
		WorkerID:     workerID(),
		MaxAttempts:  5,
		PollInterval: 250 * time.Millisecond,
	})
	dispatcherCtx, dispatcherCancel := context.WithCancel(ctx)
	defer dispatcherCancel()
	go func() {
		if err := dispatcher.Run(dispatcherCtx, 100); err != nil && err != context.Canceled && err != context.DeadlineExceeded {
			log.Printf("identity: outbox dispatcher exited: %v", err)
		}
	}()

	// Keep the in-memory recorder addressable for legacy direct-publish
	// call-sites that need to read recorded events for test assertions.
	_ = recorder
	economyPub := events.NewEconomyPublisher(publisher)

	// Singpass authorize URL — sourced from env (per S2.1 inline-config fix
	// + S6.3 §4 Singpass env-routing audit). When unset, the legacy
	// /api/v1/me/kyc/singpass:initiate handler returns IDENTITY_KYC_MISCONFIGURED;
	// the new /v1/me/kyc/singpass route uses the singpass adapter directly so
	// it constructs the URL from SINGPASS_ISSUER_URL via singpass.Config.
	singpassAuthURL := os.Getenv("SINGPASS_AUTHORIZATION_URL")
	if singpassAuthURL == "" {
		log.Printf("WARNING: SINGPASS_AUTHORIZATION_URL not set — legacy /api/v1/me/kyc/singpass:initiate route will be disabled until configured")
	}
	economyHandler := httpadapter.NewEconomyHandlerWithOptions(
		routerUsers, subRepo, manaStore, kycRepo, paymentsClient, economyPub,
		httpadapter.EconomyHandlerOptions{
			SingpassAuthURL:        singpassAuthURL,
			SubscriptionSuccessURL: os.Getenv("STRIPE_SUBSCRIPTION_SUCCESS_URL"),
			SubscriptionCancelURL:  os.Getenv("STRIPE_SUBSCRIPTION_CANCEL_URL"),
		},
	)

	// -----------------------------------------------------------------------
	// Passkey/WebAuthn wiring (S2.1 P0 — passkey login is the entry point)
	// -----------------------------------------------------------------------
	// Per audit-identity-fillgaps.md §3.1 + Phyllis MVP §3 Step 1.
	rpID := os.Getenv("RP_ID")
	if rpID == "" {
		rpID = "chora.site"
	}
	// Phase A4 (CHO-1718): the passkey dev HS256 JWT mint is REMOVED —
	// /v1/auth/passkey/verify now returns the verified (gcid, email) and
	// chora-gateway composes the standard session-mint pipeline (resolve →
	// roles → HS256 session JWT). IDP_ISSUER_URL / IDP_AUDIENCE /
	// JWT_SIGNING_KEY are no longer read for the passkey handler.
	// Passkey repo backend selection — durable-by-default (CHO-2198).
	// Originally N9 M12-backlog wave (2026-05-26); closed the deferral marked
	// at internal/adapter/inmem/passkey_repository.go:4.
	//
	// Passkeys are WebAuthn AUTH CREDENTIALS. selectPasskeyBackend (bootstrap.go)
	// makes the pgx-backed store (migration 0015_passkey_storage, chora_identity
	// DB) the DEFAULT whenever the pool is healthy — no env opt-in required — so
	// a pod restart no longer drops every registered passkey. In-memory is
	// available ONLY as an explicit dev override
	// (CHORA_IDENTITY_PASSKEY_BACKEND=memory), announced with a loud WARNING; a
	// missing pool with no override is fatal (never silently run a credential
	// store on volatile memory).
	var (
		passkeyChallenges  identity.PasskeyChallengeRepository
		passkeyCredentials identity.PasskeyCredentialRepository
	)
	passkeyBackendChoice, err := selectPasskeyBackend(pool != nil, os.Getenv("CHORA_IDENTITY_PASSKEY_BACKEND"))
	if err != nil {
		log.Fatalf("identity: passkey backend selection failed (fail-loud — passkeys are auth credentials; refusing volatile storage): %v", err)
	}
	switch passkeyBackendChoice {
	case passkeyBackendPg:
		passkeyQuerier := pg.NewPgxPoolQuerier(pool)
		passkeyChallenges = pg.NewPasskeyChallengeRepository(passkeyQuerier)
		passkeyCredentials = pg.NewPasskeyCredentialRepository(passkeyQuerier)
		log.Printf("identity: passkey stores = pgx durable (pool=chora_identity, migration=0015)")
	case passkeyBackendMemory:
		log.Printf("WARNING: identity: passkey stores = IN-MEMORY (CHORA_IDENTITY_PASSKEY_BACKEND=memory) — NOT durable; every registered passkey is LOST on restart. Dev/local only; never set this in production.")
		passkeyChallenges = inmem.NewPasskeyChallengeRepository()
		passkeyCredentials = inmem.NewPasskeyCredentialRepository()
	}

	// -----------------------------------------------------------------------
	// DEK key manager (Tier 3 D11 — per-user DEK + crypto-shred terminal).
	// -----------------------------------------------------------------------
	// Local envelope encryption (ADR-186, cloud-neutral): a random per-user DEK
	// is wrapped with the process master KEK (AES-256-GCM, AAD-bound to the
	// gcid) and ONLY the wrapped form is persisted — in
	// chora_identity.user_dek_wrap (migration 0021) when a pg pool is wired, in
	// memory otherwise. Crypto-shred = tombstone the wrapped row. The master KEK
	// comes from CHORA_LOCAL_KEK (base64, 32 bytes). A missing KEK is a HARD boot
	// error: envelope encryption is never silently disabled.
	var dekKM crypto.KeyManager
	var dekStore crypto.WrappedDEKStore
	if pool != nil {
		dekStore = pg.NewUserDEKWrapRepository(pg.NewPgxPoolQuerier(pool))
		log.Printf("identity: DEK wrapped-key store = pgx durable (user_dek_wrap, migration 0021)")
	} else {
		dekStore = cryptolocal.NewInMemoryWrappedDEKStore()
		log.Printf("WARNING: identity: DEK wrapped-key store = IN-MEMORY (no chora_identity pool) — wrapped DEKs are LOST on restart")
	}
	localKM, kmErr := cryptolocal.NewLocalKEKKeyManagerFromEnv(dekStore)
	if kmErr != nil {
		log.Fatalf("identity: DEK manager init failed (fail-loud — envelope encryption is required): %v", kmErr)
	}
	dekKM = localKM
	log.Printf("identity: DEK manager = LocalKEKKeyManager (AES-256-GCM envelope encryption, ADR-186)")

	passkeyHandler := httpadapter.NewPasskeyHandlerWithDEK(
		routerUsers, passkeyChallenges, passkeyCredentials, dekKM,
		httpadapter.PasskeyHandlerConfig{
			RPID:                rpID,
			ChallengeTTLSeconds: 300, // 5 min
		})
	// ADR-187: wire WebAuthn attestation verification (FIDO MDS) when enabled
	// via env. Default off → no-op, registration behaviour unchanged.
	configureAttestation(ctx, passkeyHandler)

	// -----------------------------------------------------------------------
	// Cross-domain subscribers (S2.1 P0/P1 — enrollment + closure)
	// -----------------------------------------------------------------------
	// M12.3 W2a inbox wiring (2026-05-12): every subscriber gets a
	// chora-go-common/idempotent.Store for dedupe across pod-restart +
	// multi-replica failure modes. Production passes PostgresStore against
	// chora_identity.idempotency_keys (migration 0007); dev / tests use
	// the in-memory MemoryStore.
	//
	// PostgresStore env-gated factory will be wired once the relay daemon
	// lands (M14+); for now every replica gets its OWN MemoryStore,
	// which is single-replica-correct + documents the production swap-in
	// seam.
	inboxStore := inboxFromEnv()
	enrollSub := events.NewEnrollmentSubscriber(courseRoles, economyPub, inboxStore)
	// Closure terminal-step chain (CHO-1719): tombstones mirror
	// config/PII_Closure_Map.yaml (env-overridable); the DEK manager provides
	// the crypto-shred seam. The former external-IdP account deletion is gone
	// with the login provider — credentials are local, so there is no upstream
	// account to free; pseudonymise + DEK shred are the terminal steps.
	closureSub := events.NewClosureSubscriberWithTerminal(
		routerUsers, economyPub, dekKM, nil,
		events.ClosureTombstones{
			EmailPattern: os.Getenv("CHORA_CLOSURE_EMAIL_TOMBSTONE_PATTERN"),
			DisplayName:  os.Getenv("CHORA_CLOSURE_DISPLAY_TOMBSTONE"),
		},
		inboxStore,
	)
	// Per ADR-164 Wave 1 Stage E: PaymentsSubscriber consumes the 4
	// chora.payments.user_subscription.*.v1 topics + drives the
	// chora-identity-owned UserSubscription FSM (mana entitlement
	// lifecycle). It uses its OWN MemoryStore inbox per replica so
	// dedupe state is independent from the shared inboxStore used by
	// enrollment + closure subscribers. Production swap-in is a
	// PostgresStore against chora_identity.idempotency_keys.
	paymentsInbox := idempotent.NewMemoryStore()
	paymentsSub := events.NewPaymentsSubscriber(subRepo, paymentsInbox)
	// KycFeeSubscriber consumes chora.payments.identity_kyc_fee.*.v1 + gates
	// manual-doc KYC review-queue entry on the $9.99 fee being captured
	// (ADR-142 + ADR-164 Stage A.5). Own MemoryStore inbox per replica.
	kycFeeInbox := idempotent.NewMemoryStore()
	kycFeeSub := events.NewKycFeeSubscriber(kycRepo, economyPub, kycFeeInbox)
	// CHO-1630 Phase 2 — chora.tenancy.tenant.bootstrapped.v1 subscriber.
	// Mirrors the H+ Setup-Tenant Phase 1 (CHO-1628) tenant_id/owner_gcid
	// pair into chora_identity.tenant_memberships so the BFF session-mint
	// can find the bootstrapped tenant for the caller. Wired only when
	// the pg pool is available — the upserter is nil otherwise and
	// constructing the subscriber would panic.
	var tenantBootstrappedSub *events.TenantBootstrappedSubscriber
	if tenantBootstrappedUpserter != nil {
		tenantBootstrappedInbox := idempotent.NewMemoryStore()
		tenantBootstrappedSub = events.NewTenantBootstrappedSubscriber(
			tenantBootstrappedUpserter, tenantBootstrappedInbox,
		)
		log.Printf("identity: TenantBootstrappedSubscriber wired for %s (CHO-1630)",
			events.TopicTenancyTenantBootstrappedV1)
	} else {
		log.Printf("identity: TenantBootstrappedSubscriber DISABLED (no chora_identity pool)")
	}
	// Cross-domain subscriber bindings (production): each subscriber is
	// bound to its canonical subject(s) on the NATS JetStream bus as a
	// durable consumer (at-least-once, DLQ-routed). The handler adapters
	// (internal/adapter/events/eventbus_bindings.go) decode each producer's
	// wire format — JSON for chora.delivery.enrollment.created.v1, Protobuf
	// for the chora.payments.* + chora.tenancy.tenant.bootstrapped.v1
	// families — onto the subscribers' payload structs.
	//
	// In dev (NATS_URL unset) the subscribers stay unbound: the in-memory
	// bus is publish-only here, so direct invocation remains the dev path.
	if jetBus != nil {
		bindSubscription(ctx, jetBus, events.TopicEnrollmentCreated, events.EnrollmentHandler(enrollSub))
		paymentsHandler := events.PaymentsHandler(paymentsSub)
		for _, subject := range paymentsSub.SubscribedTopics() {
			bindSubscription(ctx, jetBus, subject, paymentsHandler)
		}
		kycFeeHandler := events.KycFeeHandler(kycFeeSub)
		for _, subject := range kycFeeSub.SubscribedTopics() {
			bindSubscription(ctx, jetBus, subject, kycFeeHandler)
		}
		if tenantBootstrappedSub != nil {
			bindSubscription(ctx, jetBus, events.TopicTenancyTenantBootstrappedV1, events.TenantBootstrappedHandler(tenantBootstrappedSub))
		}
	} else {
		_ = enrollSub             // dev: direct invocation only
		_ = paymentsSub           // dev: direct invocation only
		_ = kycFeeSub             // dev: direct invocation only
		_ = tenantBootstrappedSub // dev: direct invocation only
	}

	// Federated closure-saga pull binding (CHO-1719 / Tier 3 D11): consume
	// chora.identity.pii.pseudonymise.requested.v1 and run the identity
	// terminal steps (pseudonymise+soft-delete → DEK shred), acking on
	// chora.identity.account.pseudonymised.v1 through the durable outbox
	// (economyPub → outbox dispatcher). Bound only when NATS is wired.
	if jetBus != nil {
		closureSubName := os.Getenv("CHORA_CLOSURE_SUBSCRIPTION")
		if closureSubName == "" {
			closureSubName = "chora-identity.closure-pseudonymise"
		}
		go func() {
			log.Printf("identity: closure subscriber binding %s -> %s", closureSubName, events.TopicPseudonymiseRequested)
			if err := jetBus.Subscribe(ctx, consumerConfig(closureSubName, events.TopicPseudonymiseRequested), events.ClosurePullHandler(closureSub)); err != nil && !errors.Is(err, context.Canceled) {
				log.Printf("identity: closure subscriber exited: %v", err)
			}
		}()
	} else {
		_ = closureSub // dev: direct invocation only
	}

	// ── WS-2.1 (per-user Stripe mana top-up) — owner clean-DDD consume seam,
	// 2026-06-04. chora-identity owns the per-GCID user_mana wallet, so it
	// consumes its OWN credit event (chora.payments.user_mana_topup.
	// payment_captured.v1 → CreditMana source=topup) directly rather than
	// routing the credit through chora-delivery. manaStore is the SAME store
	// the gRPC ManaService + HTTP economy handler use, so the credit is
	// immediately visible to GET /api/v1/me/mana. Bound to the event bus.
	userManaTopUpSub := events.NewUserManaTopUpSubscriber(
		mana.NewQuoter(manaStore), idempotent.NewMemoryStore())
	if jetBus != nil {
		manaTopUpSubName := os.Getenv("CHORA_USER_MANA_TOPUP_SUBSCRIPTION")
		if manaTopUpSubName == "" {
			manaTopUpSubName = "chora-identity.user-mana-topup"
		}
		go func() {
			log.Printf("identity: user_mana_topup subscriber binding %s -> %s", manaTopUpSubName, events.TopicPaymentsUserManaTopUpCaptured)
			if err := jetBus.Subscribe(ctx, consumerConfig(manaTopUpSubName, events.TopicPaymentsUserManaTopUpCaptured), events.UserManaTopUpHandler(userManaTopUpSub)); err != nil && !errors.Is(err, context.Canceled) {
				log.Printf("identity: user_mana_topup subscriber exited: %v", err)
			}
		}()
	} else {
		_ = userManaTopUpSub
	}

	// -----------------------------------------------------------------------
	// Singpass NDI adapter wiring (S6.3 — full OIDC + MyInfo)
	// -----------------------------------------------------------------------
	// All endpoints + secrets via env / Secret Manager (no inline config):
	//   SINGPASS_ISSUER_URL        — sandbox: https://stg-id.singpass.gov.sg
	//   SINGPASS_AUTHORIZATION_URL — optional override; defaults to {Issuer}/auth
	//   SINGPASS_TOKEN_URL         — optional override; defaults to {Issuer}/token
	//   SINGPASS_USERINFO_URL      — optional override; defaults to {Issuer}/userinfo
	//   SINGPASS_MYINFO_URL        — sandbox: {Issuer}/person
	//   SINGPASS_CLIENT_ID         — assigned by NDI onboarding (Secret Manager)
	//   SINGPASS_CLIENT_SECRET     — assigned by NDI onboarding (Secret Manager)
	//   SINGPASS_REDIRECT_URI      — chora.site/v1/me/kyc/singpass/callback
	//
	// NDI sits OUTSIDE Identity Platform's federation list; chora-identity
	// directly handles the OIDC exchange + invokes the Blocking Function path
	// to mint GCID claims after Singpass token verification.
	singpassClient := singpass.New(singpass.Config{
		IssuerURL:        os.Getenv("SINGPASS_ISSUER_URL"),
		AuthorizationURL: os.Getenv("SINGPASS_AUTHORIZATION_URL"),
		TokenURL:         os.Getenv("SINGPASS_TOKEN_URL"),
		UserInfoURL:      os.Getenv("SINGPASS_USERINFO_URL"),
		MyInfoURL:        os.Getenv("SINGPASS_MYINFO_URL"),
		ClientID:         os.Getenv("SINGPASS_CLIENT_ID"),
		ClientSecret:     os.Getenv("SINGPASS_CLIENT_SECRET"),
		RedirectURI:      os.Getenv("SINGPASS_REDIRECT_URI"),
		Publisher:        events.NewSingpassPublisher(publisher),
	})
	singpassRedirectURI := os.Getenv("SINGPASS_REDIRECT_URI")
	if singpassRedirectURI == "" {
		singpassRedirectURI = "https://chora.site/v1/me/kyc/singpass/callback"
	}

	prefillRepo := repo.NewInMemPrefillRepo()
	stateRepo := singpassStateRepoFromEnv(ctx)
	governancePub := events.NewGovernancePublisher(publisher)

	kycHandler := httpadapter.NewKycHandler(httpadapter.KycHandlerConfig{
		Users:         routerUsers,
		KycRepo:       kycRepo,
		PrefillRepo:   prefillRepo,
		StateRepo:     stateRepo,
		Singpass:      singpassClient,
		EconomyPub:    economyPub,
		GovernancePub: governancePub,
		RedirectURI:   singpassRedirectURI,
		// Manual-doc $9.99 fee collection via chora-payments (ADR-164 A.5).
		// nil in dev (CHORA_PAYMENTS_GRPC_ADDR unset) → submitManual 503.
		Payments:      paymentsKyc,
		FeeSuccessURL: os.Getenv("KYC_FEE_SUCCESS_URL"),
		FeeCancelURL:  os.Getenv("KYC_FEE_CANCEL_URL"),
	})

	// The economy handler mounts /api/v1/me/* on a fresh ServeMux that
	// shadows the existing handler at the same path namespace. We compose
	// by wrapping handler so /api/v1/me/* routes resolve to the economy
	// handler before falling through to the legacy router.
	economyMux := http.NewServeMux()
	economyHandler.RegisterRoutes(economyMux)
	passkeyHandler.RegisterRoutes(economyMux)
	kycHandler.RegisterRoutes(economyMux)

	// SP2.9 — GCID-scoped UI preferences (A+ dashboard-as-hub layout) on the
	// User profile aggregate (users.ui_preferences JSONB, migration 0034).
	//   GET /api/v1/me/preferences
	//   PUT /api/v1/me/preferences/dashboard-layout
	// pgx-backed when the chora_identity pool is wired; in-mem in dev (no pool)
	// so the route is always mountable. Scoped by gcid = the authed caller.
	var uiPrefs identity.UIPreferencesRepository = inmem.NewUIPreferencesRepository()
	if pool != nil {
		uiPrefs = pg.NewUIPreferencesRepository(pg.NewPgxPoolQuerier(pool))
	}
	httpadapter.NewMePreferencesHandler(routerUsers, uiPrefs).RegisterRoutes(economyMux)

	// -----------------------------------------------------------------------
	// Login provider removed (username/password replaces Identity Platform).
	// -----------------------------------------------------------------------
	// The Identity Platform Blocking Function webhook, its Admin REST
	// claims-setter, and the external-IdP account-deletion terminal step are
	// all gone. Authentication is now local username/password:
	// POST /v1/auth/verify-credentials (see verify_credentials_handler.go).
	// There is no external IdP account to provision claims on or delete.

	// -----------------------------------------------------------------------
	// JWKS endpoint (SP-4 + SP-5)
	// -----------------------------------------------------------------------
	// Exposes chora-identity's public signing keys at /.well-known/jwks.json
	// so external relying parties can verify JWTs Chora signs as an OIDC
	// client (private_key_jwt grant). Keys are generated per-process at boot
	// via jwksinmem; wire a durable key store when external RPs need stable
	// keys across restarts.
	jwksProvider, err := jwksinmem.New()
	if err != nil {
		log.Fatalf("jwks provider init failed: %v", err)
	}
	jwksHandler := httpadapter.NewJWKSHandler(jwksProvider)

	// -----------------------------------------------------------------------
	// API Key handler wiring (M12.2.E.1 consolidation — ported from
	// chora-iam.APIKeyService). In-memory repo for the M10 skeleton; the
	// pg-backed implementation lands when migrations/0006_api_keys.sql is
	// applied + the apikey_pg adapter is written (deferred to Tier 2).
	//
	// Outbox-first per `feedback_resilience_priority`: the apikey_events
	// publisher delegates to the same events.Publisher that the rest of the
	// service uses; in production it writes to outbox_events in chora_identity
	// and the Relay drains the rows to the event bus.
	// -----------------------------------------------------------------------
	apiKeyRepo := apikey_inmem.NewRepository()
	apiKeyHasher := apikey_crypto.NewSHA256Hasher()
	apiKeyPub := apikey_events.NewPublisher(publisher, "", "")
	apiKeyService := apikey.NewService(apiKeyRepo, apiKeyHasher, apiKeyPub)
	apiKeyRouter := httpadapter.NewAPIKeyRouter(apiKeyService)

	// W0-F1 durability gate (CHO-2198): classify the actually-wired bindings
	// (report-only unless CHORA_DURABILITY_GUARD=enforce). This keys on the
	// resolved adapter's shape, so resolveUsers reports DURABLE when it binds
	// to the pg UserRepository even though inmem.NewUserRepository() also
	// exists — the exact case a name-based scan gets wrong.
	durabilityguard.Guard("chora-identity", []durabilityguard.Binding{
		{Port: "users", Adapter: resolveUsers},
		// ⚠ memberships, snapshots and api_keys below are IN-MEMORY and are
		// left that way deliberately (traced 2026-09-02, CHO-2419 follow-up).
		// Each is reached only by a legacy route on this service's own mux,
		// and nothing calls those routes: enumerating every upstream
		// chora-gateway builds gives 20 distinct `IdentityURL + ...` paths and
		// none of them is /api/memberships, /api/users/{gcid}/portability/* or
		// /api/identity/api-keys, and chora-web calls none of them either.
		// The live membership surface is /api/v1/admin/tenant-members, which is
		// pg-backed through pgMembershipAdmin.
		//
		// ⚠ The live mesh policy DOES allow all three paths, so the allowlist
		// is WIDER THAN ITS CALLER and reads as reachable when it is not. That
		// is recorded rather than narrowed, and these bindings are recorded
		// rather than deleted, for one reason: "no caller today" and "safe to
		// remove" are different claims, and removing HTTP surface that turns
		// out to have one caller costs an outage. Empty stores behind doors
		// nobody opens cost nothing. Owner decision, not ours.
		//
		// ⚠ Do NOT "fix" these by writing pg adapters. Nothing writes to them,
		// so an adapter would change nothing and look like a fix.
		{Port: "memberships", Adapter: memberships},
		{Port: "course_roles", Adapter: courseRoles},
		{Port: "snapshots", Adapter: snapshots},
		{Port: "user_subscriptions", Adapter: subRepo},
		{Port: "singpass_state", Adapter: stateRepo},
		{Port: "myinfo_prefill", Adapter: prefillRepo},
		{Port: "api_keys", Adapter: apiKeyRepo},
		{Port: "jwks", Adapter: jwksProvider},
	}, nil)

	// -----------------------------------------------------------------------
	// Bucket 2 (2026-05-14 multi-tenant identity): POST /v1/identity/resolve
	// -----------------------------------------------------------------------
	// Wires:
	//   - chora-identity ↔ chora-tenancy gRPC client (Cloud Service Mesh mTLS;
	//     plain insecure creds inside the mesh since the sidecar handles TLS).
	//   - GCIDResolvedPublisher → events.Publisher (outbox-backed in prod via
	//     the outboxPub publisher above; in-memory recorder when CHORA_OUTBOX_DSN
	//     unset).
	//   - ResolveHandler → users repo + tenancy gRPC client + event publisher.
	//
	// Env contract (no inline config per feedback_no_inline_config):
	//   SVC_TENANCY_GRPC_URL — gRPC target, e.g. "chora-tenancy:9090"
	//
	// Boot fails LOUD on missing env when CHORA_ENV=prod; in dev the resolve
	// route is intentionally NOT mounted (falls through to legacy handlers).
	var resolveHandler *httpadapter.ResolveHandler
	// adminMembershipUpserter is the ADR-182 authoritative add-member
	// write path (tenancy UpsertMembership) consumed by the
	// tenant-members admin handler below. Stays nil without a tenancy
	// conn (dev) — the handler then keeps the legacy mirror-only path.
	var adminMembershipUpserter httpadapter.AuthoritativeMembershipUpserter
	tenancyGRPCURL := strings.TrimSpace(os.Getenv("SVC_TENANCY_GRPC_URL"))
	if tenancyGRPCURL == "" {
		if strings.EqualFold(os.Getenv("CHORA_ENV"), "prod") ||
			strings.EqualFold(os.Getenv("CHORA_ENV"), "production") {
			log.Fatalf("identity: SVC_TENANCY_GRPC_URL required when CHORA_ENV=prod (Bucket 2 multi-tenant resolve)")
		}
		log.Printf("identity: SVC_TENANCY_GRPC_URL unset — /v1/identity/resolve disabled (dev mode)")
	} else {
		// Keepalive-warm dial (chora-go-common/grpcconn): keeps the subchannel
		// alive across idle gaps + eager-Connects at boot, so the first write
		// to tenancy (UpsertMembership) no longer pays a cold re-dial through
		// the mesh sidecars — root-fix for the cold-start 504. insecure creds:
		// mTLS is supplied by Cloud Service Mesh PeerAuth.
		conn, err := grpcconn.Dial(tenancyGRPCURL)
		if err != nil {
			log.Fatalf("identity: grpc.NewClient %s: %v", tenancyGRPCURL, err)
		}
		defer func() {
			if cerr := conn.Close(); cerr != nil {
				log.Printf("identity: tenancy gRPC conn.Close: %v", cerr)
			}
		}()
		tenancyClient, err := grpcadapter.NewTenancyClient(conn)
		if err != nil {
			log.Fatalf("identity: tenancy client: %v", err)
		}
		// ADR-182 auto-enrol: zero-membership resolves enrol the GCID into
		// the public chora-master tenant (learner+author) via tenancy
		// UpsertMembership, with best-effort identity-mirror upserts.
		// PUBLIC_TENANT_SLUG overrides the slug (default chora-master).
		var enrolMirror grpcadapter.MirrorUpserter
		if tenantBootstrappedUpserter != nil {
			enrolMirror = tenantBootstrappedUpserter
		}
		publicEnroller, err := grpcadapter.NewPublicTenantEnroller(
			conn, os.Getenv("PUBLIC_TENANT_SLUG"), enrolMirror)
		if err != nil {
			log.Fatalf("identity: public tenant enroller: %v", err)
		}
		adminUpserter, err := grpcadapter.NewAdminMembershipUpserter(conn)
		if err != nil {
			log.Fatalf("identity: admin membership upserter: %v", err)
		}
		adminMembershipUpserter = adminUpserter
		gcidResolvedPub := events.NewGCIDResolvedPublisher(publisher)
		// Adapter: httpadapter.EventPublisher → events.GCIDResolvedPublisher.
		// We CAN'T type-pun events.GCIDResolvedPublisher directly because the
		// publisher's PublishGCIDResolved takes events.GCIDResolvedEvent while
		// the http port takes httpadapter.EmittedEvent. The shim below is the
		// thin field-copy bind.
		evShim := &gcidResolvedShim{inner: gcidResolvedPub}
		// WS3 (CHO-1873 / ADR-194 D2) — cold-invite apply at resolve time.
		// Reuses the WS2 grant machinery (authoritative upserter + pg mirror
		// grant). Nil when the pg pool is absent (dev) — resolve then keeps the
		// auto-enrol-only path.
		var inviteApplier httpadapter.InviteApplier
		if pendingInviteRepo != nil && pgMembershipAdmin != nil {
			inviteApplier = httpadapter.NewPendingInviteApplier(
				pendingInviteRepo, adminMembershipUpserter, pgMembershipAdmin)
			log.Printf("identity: cold-invite apply wired into /v1/identity/resolve")
		}
		resolveHandler = httpadapter.NewResolveHandler(httpadapter.ResolveHandlerConfig{
			Users:         resolveUsers, // pgx-backed in prod — see resolveUsers wiring above
			Tenancy:       tenancyClient,
			Events:        evShim,
			Enroller:      publicEnroller,
			InviteApplier: inviteApplier,
			SourceProject: envOrDefault("CHORA_SOURCE_PROJECT", "chora-local"),
		})
		if resolveHandler == nil {
			log.Fatalf("identity: NewResolveHandler returned nil — UserRepository or TenancyClient dependency missing")
		}
		log.Printf("identity: /v1/identity/resolve wired (tenancy=%s)", tenancyGRPCURL)
	}

	// -----------------------------------------------------------------------
	// Setup Wizard Phase C — POST + GET /api/v1/tenants/me/idp-providers
	// (CHO-1682 upsert + CHO-1692 list-for-hydration).
	// -----------------------------------------------------------------------
	// Wires:
	//   - tipRepo (chora_identity DB, RLS-scoped via RunInTenantTx)
	//   - SecretManager: env-backed adapter (chora-common/secrets resolves
	//     IdP client secrets from the environment).
	//   - EventPublisher: outbox-backed events.Publisher → eventbus subject
	//     `chora.identity.tenant_idp_provider.upserted.v1`.
	//
	// The handler dispatches GET (list, returns {"items":[]} for fresh
	// tenants — see meIdpProviderListResponse) + POST (upsert) on the same
	// path. Without pgx wiring the handler is intentionally NOT mounted so
	// dev pods that lack a chora_identity pool surface a clean 404 rather
	// than a wrong-shape stub.
	var meIdpHandler *httpadapter.MeIdpProvidersHandler
	if tipRepo != nil {
		tipSecrets := tenant_idp_secrets.NewInMemory(tenant_idp_secrets.InMemoryConfig{})
		tipPub := tipevents.NewPublisher(publisher, "", "")
		tipService := tip.NewService(tipRepo, tipSecrets, tipPub)
		meIdpHandler = httpadapter.NewMeIdpProvidersHandler(tipService)
		log.Printf("identity: /api/v1/tenants/me/idp-providers wired (CHO-1682 POST + CHO-1692 GET)")
	} else {
		log.Printf("identity: /api/v1/tenants/me/idp-providers DISABLED — no chora_identity pool")
	}

	composed := http.NewServeMux()

	// -----------------------------------------------------------------------
	// Local username/password login — POST /v1/auth/verify-credentials
	// -----------------------------------------------------------------------
	// The frozen auth contract the gateway mints sessions against. Requires the
	// pg pool (local_credentials + the membership helper, migration 0042);
	// without it the route is intentionally NOT mounted so a misconfigured pod
	// surfaces a clean 404 rather than a wrong-shape stub.
	if pool != nil {
		authnRepo := pg.NewAuthnRepository(pg.NewPgxPoolQuerier(pool))
		verifyCredsHandler := httpadapter.NewVerifyCredentialsHandler(httpadapter.VerifyCredentialsConfig{
			Credentials: authnRepo,
			Users:       resolveUsers,
			Memberships: authnRepo,
		})
		verifyCredsHandler.RegisterRoutes(composed)
		log.Printf("identity: /v1/auth/verify-credentials wired (local username/password, migration 0042)")
	} else {
		log.Printf("identity: /v1/auth/verify-credentials DISABLED — no chora_identity pool")
	}

	composed.Handle("/.well-known/jwks.json", jwksHandler)
	composed.Handle("/api/identity/api-keys", apiKeyRouter)
	composed.Handle("/api/identity/api-keys/", apiKeyRouter)
	if meIdpHandler != nil {
		composed.Handle("/api/v1/tenants/me/idp-providers", meIdpHandler)
		// CHO-1694 — trailing-slash mount captures DELETE
		// /idp-providers/{providerType} alongside the exact-path GET/POST
		// mount above. Same handler routes by URL + method.
		composed.Handle("/api/v1/tenants/me/idp-providers/", meIdpHandler)
	}
	if resolveHandler != nil {
		composed.Handle("/v1/identity/resolve", resolveHandler)
	}
	// CHO-2205 — pending-invite read-through for the gateway mint allowlist.
	// GET /api/v1/internal/pending-invite?email=X → {has_pending_invite}. Pure
	// MatchByEmail read (no GCID mint); reuses the WS3 cold-invite store. Gated
	// on the pg repo being wired — dev-without-pg leaves the route unmounted, so
	// the gateway mint gate fails closed. The mesh path allow-list entry lives
	// in chora-infra/k8s/services/chora-identity/authz-allow-gateway.yaml.
	if pendingInviteRepo != nil {
		// CHO-2207: the pg UserRepository (FindByEmail) authorizes an existing
		// member on re-authentication, in addition to CHO-2205 pending invites.
		// Pass a nil INTERFACE (not a typed-nil) when the pg repo is absent, so
		// the handler's `knownUser != nil` guard is honest.
		var knownUser httpadapter.KnownUserLookup
		if pgUsersConcrete != nil {
			knownUser = pgUsersConcrete
		}
		composed.Handle("/api/v1/internal/pending-invite",
			httpadapter.NewPendingInviteCheckHandler(pendingInviteRepo, knownUser))
		log.Printf("identity: /api/v1/internal/pending-invite wired (CHO-2205 read-through + CHO-2207 member re-auth)")
	}
	// B6.1 (2026-05-16) — searchTenantMembers picker (contract:
	// chora-contracts/openapi/identity-admin.yaml). Only mount when the pgx
	// pool is wired: the in-memory adapter is not implemented for this route
	// since it would mask the RLS-tx contract that production REQUIRES.
	// Per `feedback_no_stubs_real_wiring`: refuse to bind a fake — return
	// 404 in unconfigured envs (clearer signal than a wrong-shape stub).
	if pgMemberSearch != nil {
		// L1 Tenant lane (CHO-1707) — the dispatcher keeps GET on the B6.1
		// search handler and adds POST add-member-by-email + PATCH
		// {gcid}/role (both pg-backed; the legacy inmem membership repo is
		// NOT used on this surface). Trailing-slash mount captures the
		// /{gcid}/role item path.
		// ADR-182: authoritative chora_tenancy.members write rides first
		// when the tenancy conn is up; mirror-only otherwise (dev).
		tenantMembersAdmin := httpadapter.NewTenantMembersAdminHandlerWithTenancy(
			// governancePub backs the S4 (CHO-2000) operator cross-tenant
			// learner-directory read's fail-closed IMDA-D1 audit.
			httpadapter.NewSearchTenantMembersHandler(pgMemberSearch, governancePub),
			pgUsersConcrete, pgMembershipAdmin, adminMembershipUpserter)
		composed.Handle("/api/v1/admin/tenant-members", tenantMembersAdmin)
		composed.Handle("/api/v1/admin/tenant-members/", tenantMembersAdmin)
		log.Printf("identity: /api/v1/admin/tenant-members wired (search + add-by-email + role-change, pg-backed)")

		// WS2 (CHO-1872 / ADR-194 D1) — operator cross-tenant grant. Distinct
		// handler from the tenant-scoped member admin above: PLATFORM_OPERATOR-
		// only gate, tenant-from-body, idempotent multi-role grant, IMDA-D1
		// evidence. RLS stays ENFORCED via the pg repo's
		// RunInTenantTx(body.tenant_id) — NOT a bypass surface.
		grantMembership := httpadapter.NewGrantTenantMembershipHandler(
			pgUsersConcrete, pgMembershipAdmin, adminMembershipUpserter, governancePub)
		composed.Handle("/api/v1/admin/tenant-memberships", grantMembership)
		log.Printf("identity: /api/v1/admin/tenant-memberships wired (operator cross-tenant grant, pg-backed)")

		// WS3 (CHO-1873 / ADR-194 D2) — cold-invite admin API. POST unifies
		// add-by-email (grant an existing user NOW, retiring the 404 dead-end)
		// with the cold-invite (persist a `pending` invite the resolve seam
		// auto-applies at first login); GET list + DELETE revoke are tenant-
		// scoped admin. The operator cross-tenant create (tenant from body)
		// composes with WS2 D1. Same pg stores + authoritative upserter +
		// governance publisher as WS1/WS2; all four are non-nil here (assigned
		// together under `pool != nil`). Trailing-slash mount captures the
		// /{inviteId} revoke item path.
		tenantInvites := httpadapter.NewTenantInvitesHandler(
			pgUsersConcrete, pgMembershipAdmin, adminMembershipUpserter, pendingInviteRepo, governancePub)
		composed.Handle("/api/v1/admin/tenant-invites", tenantInvites)
		composed.Handle("/api/v1/admin/tenant-invites/", tenantInvites)
		log.Printf("identity: /api/v1/admin/tenant-invites wired (cold-invite create/list/revoke, pg-backed)")

		// CHO-2327 — directory-projection backfill. Re-emits
		// chora.identity.user.profile_updated.v1 for every live user with a
		// non-empty display_name so downstream directories (chora-delivery.
		// user_directory → R+ Offering Roster/Transcript) catch up for members
		// whose display_name predates the projection. adminGate fail-closed;
		// uses identity's OWN DB + transactional outbox (no external creds).
		httpadapter.NewAdminDirectoryBackfillHandler(pgUsersConcrete).RegisterRoutes(composed)
		log.Printf("identity: /api/v1/admin/directory/backfill wired (name-projection replay, pg-backed)")
	} else {
		log.Printf("identity: /api/v1/admin/tenant-members NOT wired — chora_identity DB pool absent")
	}
	composed.Handle("/api/v1/me/", economyMux)
	composed.Handle("/api/v1/me/subscriptions", economyMux)
	composed.Handle("/api/v1/me/mana", economyMux)
	// W4 Exam BC follow-up A (ADR-190 D2) — INTERNAL service-to-service by-GCID
	// verification-claim read consumed by chora-delivery's exam admission gate
	// (verify + admit) over the mesh. Service-to-service ONLY: NOT in the
	// allow-from-gateway allowlist, so the sidecar default-deny keeps the BFF /
	// learners out of /internal/*; authz-allow-delivery-internal.yaml grants
	// only the chora-delivery SA principal. Reuses the SAME kycRepo as the
	// self-scoped GET /v1/me/kyc/status — no new store, no new migration.
	composed.Handle("/internal/v1/identity/verification-status",
		httpadapter.NewInternalVerificationHandler(kycRepo))
	// W4 Exam BC follow-up B (CHO-2103) — staff-gated manual-doc KYC verify/reject.
	// KycFeeSubscriber promotes manual_doc pending→submitted on fee capture, but
	// only Singpass auto-verifies; manual_doc had no path past `submitted`. This
	// staff action completes submitted→verified (emit kyc.verified.v1) / →rejected,
	// unblocking the admit gate above for manual-doc candidates. adminGate is
	// fail-closed (TRAINING_ADMIN/TENANT_ADMIN + tenant ctx); RLS is person-scoped
	// (self-scopes to the subject gcid), NOT an admin bypass — same durable kycRepo,
	// no new store/migration. Subtree mount captures {gcid}/verify|reject.
	composed.Handle("/api/v1/admin/kyc/",
		httpadapter.NewAdminKycVerifyHandler(kycRepo, economyPub, governancePub))
	log.Printf("identity: /api/v1/admin/kyc/{gcid}/verify|reject wired (staff manual-doc KYC review, CHO-2103)")
	composed.Handle("/api/v1/me/marketplace/familiar-plans", economyMux)
	composed.Handle("/api/v1/me/kyc/status", economyMux)
	composed.Handle("/api/v1/me/kyc/singpass:initiate", economyMux)
	composed.Handle("/api/v1/me/kyc/manual", economyMux)
	composed.Handle("/v1/me/billing/stripe-customer", economyMux)
	composed.Handle("/v1/me/kyc/singpass", economyMux)
	composed.Handle("/v1/me/kyc/singpass/callback", economyMux)
	composed.Handle("/v1/me/kyc/manual", economyMux)
	composed.Handle("/v1/me/kyc/status", economyMux)
	composed.Handle("/v1/me/myinfo-prefill", economyMux)
	composed.Handle("/v1/auth/passkey/challenge", economyMux)
	composed.Handle("/v1/auth/passkey/verify", economyMux)
	composed.Handle("/", handler)
	handler = composed

	// Wrap the entire handler chain with the OTel HTTP middleware so every
	// request emits a span that auto-correlates with Cloud Trace via the
	// configured OTLP exporter. Per audit-identity-fillgaps.md §4.3 this
	// closes the "TracerProvider but no spans" gap.
	tracedHandler := observability.HTTPMiddleware()(handler)

	srv := &http.Server{
		Addr:              ":" + port,
		Handler:           tracedHandler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	go func() {
		log.Printf("service=%s version=%s listening on %s", serviceName, version, srv.Addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("server error: %v", err)
		}
	}()

	// -----------------------------------------------------------------------
	// gRPC server for ManaService (P4 wire-up, 2026-05-15)
	// -----------------------------------------------------------------------
	// chora-creation + chora-consumption + chora-tenancy call ManaService via
	// gRPC over the service mesh (mTLS via Cloud Service Mesh sidecar; plain
	// insecure creds inside the mesh since istio-proxy terminates TLS). The
	// HTTP path (port 8080) handles /api/v1/me/mana[/topup] for the FE; the
	// gRPC path (port 9090 by default; canonical mesh port) handles
	// inter-service Deduct/Credit/GetBalance calls.
	//
	// CRITICAL: manaStore is SHARED with the HTTP economy handler so credits
	// via HTTP (e.g. POST /api/v1/me/mana/topup) are immediately visible to
	// gRPC DeductMana callers (and vice versa). The Quoter is stateless over
	// the store so we can construct a fresh one for the gRPC path; it's the
	// SAME mana.Store implementation under the hood.
	//
	// Per `feedback_no_inline_config`: gRPC port comes from env. Default 9090
	// matches the Cloud Service Mesh canonical port the other Chora services
	// already use (e.g. chora-tenancy:9090 — see chora-identity deployment.yaml
	// SVC_TENANCY_GRPC_URL).
	grpcPort := os.Getenv("GRPC_PORT")
	if grpcPort == "" {
		grpcPort = "9090"
	}
	grpcLis, err := net.Listen("tcp", ":"+grpcPort)
	if err != nil {
		log.Fatalf("identity: gRPC net.Listen :%s: %v", grpcPort, err)
	}
	grpcSrv := grpc.NewServer()

	// gRPC Health check — required for Cloud Service Mesh probe routing and
	// Cloud Deploy VERIFY Job smoke (skaffold verify block invokes
	// `grpc.health.v1.Health/Check` against this surface). Mirror the
	// pattern from chora-sharing / chora-consumption / chora-tenancy.
	healthSrv := healthgrpc.NewServer()
	healthSrv.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)
	healthSrv.SetServingStatus("chora.services.identity.v1.ManaService", healthpb.HealthCheckResponse_SERVING)
	healthSrv.SetServingStatus("chora.services.identity.v1.Identity", healthpb.HealthCheckResponse_SERVING)
	healthSrv.SetServingStatus("chora.services.identity.v1.KycService", healthpb.HealthCheckResponse_SERVING)
	healthpb.RegisterHealthServer(grpcSrv, healthSrv)

	// Bind ManaService — the canonical wire surface for chora-creation's
	// ManaClient (commits d958890c + 6ce3a0d9). Cast manaStore to the
	// domain mana.Store interface so the proto bridge sees the same
	// in-memory state the HTTP economy handler writes to.
	var manaStoreIface mana.Store = manaStore
	// WS-1 umbrella metering (ADR-142 §4): the chora-model-gateway metering
	// seam charges by action_code via DeductMana(action_code, units=0). The
	// Quoter resolves units==0 against the seeded mana_action_pricing catalogue
	// through a Pricer. The catalogue lives in chora_identity (pg), so the
	// Pricer is wired only when the pool is present; in-memory dev has no
	// catalogue table and never receives gateway-metered units==0 debits.
	manaQuoterOpts := []mana.QuoterOption{}
	if pool != nil {
		// ADR-178 / CHO-1661 — the configurable price-plan rules layer supersedes
		// the flat mana_action_pricing lookup. The PricePlanResolver resolves
		// (action_code, tenant, tier) via precedence tenant-override > platform
		// default plan > flat mana_action_pricing catalogue floor; the back-fill
		// (migration 0017) mirrors every catalogue price into the default plan, so
		// activation is price-neutral.
		//
		// FU-4(b): wired via WithPriceResolver (NOT the flat WithPricer shim) so
		// the units==0 path is TENANT/TIER/CONTEXT-aware — an H+ price-plan
		// override now actually applies (the CostForAction shim dropped tenant_id)
		// — and per_item batch pricing multiplies by context.item_count
		// server-side. This is the lever that makes qgen authoring prices
		// configurable once chora-creation debits via units==0.
		manaQuoterOpts = append(manaQuoterOpts,
			mana.WithPriceResolver(mana.NewPricePlanResolver(pg.NewManaPricePlanStore(pg.NewPgxPoolQuerier(pool)))))
		log.Printf("identity: mana price-plan resolver wired (ADR-178/FU-4b; tenant/tier/context-aware; precedence tenant>plan>catalogue; per_item ×item_count)")
	} else {
		log.Printf("identity: mana catalogue pricing NOT wired (chora_identity pool absent; units==0 catalogue-priced debits will error)")
	}
	manaQuoter := mana.NewQuoter(manaStoreIface, manaQuoterOpts...)
	manaCore := grpcadapter.NewManaServer(manaQuoter, manaStoreIface, economyPub)
	identityv1.RegisterManaServiceServer(grpcSrv, grpcadapter.NewManaProtoServer(manaCore))

	// Bind the Identity service (GetMe) — the service-to-service GCID→profile
	// resolver. The proto + generated client shipped long ago (chora-notifications
	// email recipient resolver + chora-gateway phyllis_handler call GetMe), and
	// the health surface above advertises Identity as SERVING, but the server was
	// never registered → callers got `Unimplemented`. Closes that API-First (AP-01)
	// gap (CHO-1634). Reuses the same UserRepository as /me + /v1/identity/resolve.
	identityv1.RegisterIdentityServer(grpcSrv, grpcadapter.NewIdentityProtoServer(resolveUsers))

	// Bind ExpRuleService — the configurable per-source familiar-EXP rules
	// resolver (ADR-218 D6). chora-consumption's familiar growth award path calls
	// ResolveExpRule to unify onto identity's ExpRuleResolver (its in-code
	// growth/curve.go map becomes the fail-loud fallback; parity seeds — migration
	// 0029 — return identical values). The exp_source_def / exp_rule_plan /
	// exp_rule tables live in chora_identity (migrations 0027 + 0029), so the
	// resolver is wired only when the pool is present; in dev without a pool the
	// RPC returns Unimplemented rather than a wrong-shape stub.
	if pool != nil {
		expRuleStore := pg.NewExpRuleStore(pg.NewPgxPoolQuerier(pool))
		identityv1.RegisterExpRuleServiceServer(grpcSrv,
			grpcadapter.NewExpRuleProtoServer(exprules.NewExpRuleResolver(expRuleStore)))
		healthSrv.SetServingStatus("chora.services.identity.v1.ExpRuleService", healthpb.HealthCheckResponse_SERVING)
		log.Printf("identity: ExpRuleService gRPC bound (ADR-218 D6; pool=chora_identity; precedence tenant>plan>catalogue)")
	} else {
		log.Printf("identity: ExpRuleService NOT bound (chora_identity pool absent; ResolveExpRule → Unimplemented in dev)")
	}

	go func() {
		log.Printf("service=%s grpc listening on :%s (ManaService + Identity + ExpRuleService bound)", serviceName, grpcPort)
		if err := grpcSrv.Serve(grpcLis); err != nil && err != grpc.ErrServerStopped {
			log.Fatalf("grpc server error: %v", err)
		}
	}()

	// Wait for SIGINT/SIGTERM, then drain.
	<-ctx.Done()
	log.Printf("shutting down...")

	// Drain gRPC first — in-flight ManaService calls finish + clients see
	// EOF cleanly before the HTTP path drains.
	grpcShutdownDone := make(chan struct{})
	go func() {
		grpcSrv.GracefulStop()
		close(grpcShutdownDone)
	}()
	select {
	case <-grpcShutdownDone:
		log.Printf("grpc server drained")
	case <-time.After(10 * time.Second):
		log.Printf("grpc graceful-stop deadline exceeded — forcing stop")
		grpcSrv.Stop()
	}

	drainCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(drainCtx); err != nil {
		log.Printf("server shutdown error: %v", err)
	}
}

// envOrDefault returns the env var value or def when unset / empty.
func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// gcidResolvedShim adapts the events.GCIDResolvedPublisher (which takes
// the events-package-native GCIDResolvedEvent) to the http port shape
// (httpadapter.EventPublisher with httpadapter.EmittedEvent). Bucket 2
// hexagonal layering: events package cannot import http adapter; the
// thin shim binding lives at the composition root (here).
type gcidResolvedShim struct {
	inner *events.GCIDResolvedPublisher
}

func (s *gcidResolvedShim) PublishGCIDResolved(ctx context.Context, ev httpadapter.EmittedEvent) error {
	return s.inner.PublishGCIDResolved(ctx, events.GCIDResolvedEvent{
		GCID:             ev.GCID,
		TenantID:         ev.TenantID,
		Email:            ev.Email,
		FirebaseUID:      ev.FirebaseUID,
		IdempotencyKey:   ev.IdempotencyKey,
		MembershipsCount: ev.MembershipsCount,
	})
}
