// Command seed is the idempotent local-user provisioning job for
// chora-identity.
//
// It reads its inputs from the environment and, in ONE transaction, upserts a
// tenant plus, for each configured seed user, a user row, the user's Argon2id
// credential, and an ACTIVE membership in identity's local tenant_memberships
// mirror. Every write is keyed on a STABLE identifier (deterministic GCID,
// fixed tenant UUID, normalised username, (gcid,tenant_id,role)), so re-running
// the job is a no-op.
//
// AFTER that transaction commits, when SVC_TENANCY_GRPC_URL is set, each
// seeded membership is ALSO upserted into chora-tenancy — the AUTHORITATIVE
// membership store — over the sanctioned ADR-182 gRPC path (the same
// AdminMembershipUpserter the admin add-member handler uses; never a direct
// SQL connection to chora_tenancy's database). Without the tenancy rows,
// verify-credentials derives no surfaces and every minted session carries
// surfaces: null. When SVC_TENANCY_GRPC_URL is unset the job logs a warning
// and provisions the identity mirror only (dev mode); when it is set but the
// dial or an upsert fails, the job exits non-zero rather than silently
// provisioning a mirror the sessions cannot use. The one softening is a
// bounded startup-race retry: TRANSIENT upsert failures (gRPC
// Unavailable/DeadlineExceeded and connection-refused transport errors — in
// Compose identity-seed can start before chora-tenancy's gRPC server accepts
// connections, and grpcconn.Dial's eager Connect() does not prove readiness)
// are retried a hardcoded number of times with a short backoff. The bound is
// deliberately NOT env-tunable: the retry window is a property of the deploy
// race, not of the seeded data, and the seed context already bounds the whole
// job. Permanent failures fail the upsert immediately; a tenancy still
// unavailable after the bound fails the job non-zero.
//
// Seed users:
//
//	admin      — always seeded (role `admin`).
//	instructor — seeded when CHORA_SEED_INSTRUCTOR_USERNAME is set, with roles
//	             `instructor` AND `author`. The second role exists because the
//	             demo instructor AUTHORS atoms: in chora-tenancy's
//	             roleSurfaceMap `instructor` maps to `rplus` only, while
//	             `author` (like `learner`) maps to `aplus` — the surface that
//	             gates A+ authoring — so an instructor-only account cannot
//	             create atoms.
//	student    — seeded when CHORA_SEED_STUDENT_USERNAME is set. There is no
//	             `student` value in the stored membership_role vocabulary
//	             ({learner,instructor,admin,auditor,author,owner} — see
//	             internal/domain/identity/membership.go); the student account is
//	             seeded with role `learner`.
//
// PLATFORM_OPERATOR is deliberately NOT seedable here: it is the sole
// cross-tenant role (ADR-165) with no membership_role ENUM value and no
// tenant_memberships row — see migrations/0014_platform_operator_role.up.sql.
//
// Argon2id uses a random salt, so the stored hash is NOT rewritten on every
// run: it is only replaced when it no longer verifies against the configured
// password. The cleartext password is never logged or committed.
//
// Environment:
//
//	CHORA_DB_DSN              — chora_identity connection string (required)
//	CHORA_SEED_TENANT_ID      — tenant UUID (required)
//	CHORA_SEED_TENANT_SLUG    — tenant slug (required)
//	CHORA_SEED_ADMIN_USERNAME — admin username (required)
//	CHORA_SEED_ADMIN_EMAIL    — admin email (required)
//	CHORA_SEED_ADMIN_PASSWORD — admin password (required)
//	CHORA_SEED_INSTRUCTOR_USERNAME  — instructor username (optional)
//	CHORA_SEED_INSTRUCTOR_EMAIL     — instructor email (required when username set)
//	CHORA_SEED_INSTRUCTOR_PASSWORD  — instructor password (required when username set)
//	CHORA_SEED_STUDENT_USERNAME     — student username (optional)
//	CHORA_SEED_STUDENT_EMAIL        — student email (required when username set)
//	CHORA_SEED_STUDENT_PASSWORD     — student password (required when username set)
//	SVC_TENANCY_GRPC_URL      — chora-tenancy gRPC target, e.g.
//	                            "chora-tenancy:9090" (optional). When set, the
//	                            seeded memberships are upserted into
//	                            chora-tenancy after the identity transaction
//	                            commits; when unset, only the identity mirror
//	                            is provisioned (dev mode).
//
// Every seeded account also receives the demo mana grant (see
// applyDemoSeedGrant) inside the same transaction, so a demo never has to run
// a real payment/top-up flow.
//
// Usage:
//
//	CHORA_DB_DSN=... CHORA_SEED_TENANT_ID=... ... go run ./cmd/seed
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	grpcconn "github.com/apollo-chora/chora-common/grpcconn"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	grpcadapter "github.com/apollo-chora/chora-identity/internal/adapter/grpc"
	"github.com/apollo-chora/chora-identity/internal/adapter/pg"
	"github.com/apollo-chora/chora-identity/internal/domain/authn"
	"github.com/apollo-chora/chora-identity/internal/domain/identity"
)

const (
	// demoSeedGrantUnits is the demo balance every seeded account starts with.
	demoSeedGrantUnits = int64(1_000_000_000)
	// demoSeedGrantPrefix makes the seed's idempotency key deterministic, so a
	// re-run is a no-op rather than a second grant.
	demoSeedGrantPrefix = "demo-seed:v1:"
)

// seedNamespace is the fixed UUIDv5 namespace for deterministic seed GCIDs.
// Changing it changes every seeded GCID — do not.
var seedNamespace = uuid.MustParse("6f2c1d2e-3a4b-5c6d-8e9f-0a1b2c3d4e5f")

type config struct {
	DSN        string
	TenantID   string
	TenantSlug string
	Username   string
	Email      string
	Password   string

	InstructorUsername string
	InstructorEmail    string
	InstructorPassword string

	StudentUsername string
	StudentEmail    string
	StudentPassword string
}

func loadConfig() (config, error) {
	c := config{
		DSN:        strings.TrimSpace(os.Getenv("CHORA_DB_DSN")),
		TenantID:   strings.TrimSpace(os.Getenv("CHORA_SEED_TENANT_ID")),
		TenantSlug: strings.TrimSpace(os.Getenv("CHORA_SEED_TENANT_SLUG")),
		Username:   strings.TrimSpace(os.Getenv("CHORA_SEED_ADMIN_USERNAME")),
		Email:      strings.TrimSpace(os.Getenv("CHORA_SEED_ADMIN_EMAIL")),
		Password:   os.Getenv("CHORA_SEED_ADMIN_PASSWORD"),

		InstructorUsername: strings.TrimSpace(os.Getenv("CHORA_SEED_INSTRUCTOR_USERNAME")),
		InstructorEmail:    strings.TrimSpace(os.Getenv("CHORA_SEED_INSTRUCTOR_EMAIL")),
		InstructorPassword: os.Getenv("CHORA_SEED_INSTRUCTOR_PASSWORD"),

		StudentUsername: strings.TrimSpace(os.Getenv("CHORA_SEED_STUDENT_USERNAME")),
		StudentEmail:    strings.TrimSpace(os.Getenv("CHORA_SEED_STUDENT_EMAIL")),
		StudentPassword: os.Getenv("CHORA_SEED_STUDENT_PASSWORD"),
	}
	required := map[string]string{
		"CHORA_DB_DSN":              c.DSN,
		"CHORA_SEED_TENANT_ID":      c.TenantID,
		"CHORA_SEED_TENANT_SLUG":    c.TenantSlug,
		"CHORA_SEED_ADMIN_USERNAME": c.Username,
		"CHORA_SEED_ADMIN_EMAIL":    c.Email,
		"CHORA_SEED_ADMIN_PASSWORD": c.Password,
	}
	// Optional seed users: a set username pulls in its email + password.
	if c.InstructorUsername != "" {
		required["CHORA_SEED_INSTRUCTOR_EMAIL"] = c.InstructorEmail
		required["CHORA_SEED_INSTRUCTOR_PASSWORD"] = c.InstructorPassword
	}
	if c.StudentUsername != "" {
		required["CHORA_SEED_STUDENT_EMAIL"] = c.StudentEmail
		required["CHORA_SEED_STUDENT_PASSWORD"] = c.StudentPassword
	}
	var missing []string
	for k, v := range required {
		if v == "" {
			missing = append(missing, k)
		}
	}
	if len(missing) > 0 {
		return c, fmt.Errorf("missing required env: %s", strings.Join(missing, ", "))
	}
	if _, err := uuid.Parse(c.TenantID); err != nil {
		return c, fmt.Errorf("CHORA_SEED_TENANT_ID is not a UUID: %w", err)
	}
	if !identity.LooseValidEmail(c.Email) {
		return c, fmt.Errorf("CHORA_SEED_ADMIN_EMAIL is not a valid email")
	}
	if len(c.Password) > authn.MaxPasswordBytes {
		return c, fmt.Errorf("CHORA_SEED_ADMIN_PASSWORD exceeds %d bytes", authn.MaxPasswordBytes)
	}
	if c.InstructorUsername != "" {
		if !identity.LooseValidEmail(c.InstructorEmail) {
			return c, fmt.Errorf("CHORA_SEED_INSTRUCTOR_EMAIL is not a valid email")
		}
		if len(c.InstructorPassword) > authn.MaxPasswordBytes {
			return c, fmt.Errorf("CHORA_SEED_INSTRUCTOR_PASSWORD exceeds %d bytes", authn.MaxPasswordBytes)
		}
	}
	if c.StudentUsername != "" {
		if !identity.LooseValidEmail(c.StudentEmail) {
			return c, fmt.Errorf("CHORA_SEED_STUDENT_EMAIL is not a valid email")
		}
		if len(c.StudentPassword) > authn.MaxPasswordBytes {
			return c, fmt.Errorf("CHORA_SEED_STUDENT_PASSWORD exceeds %d bytes", authn.MaxPasswordBytes)
		}
	}
	return c, nil
}

// seedGcid derives the deterministic GCID for a seeded user, keyed on the
// normalised username. The "chora-identity-local-admin" name string is kept
// verbatim so the seeded admin's GCID is stable across this refactor.
func seedGcid(usernameNorm string) string {
	return uuid.NewSHA1(seedNamespace, []byte("chora-identity-local-admin:"+usernameNorm)).String()
}

// membershipID derives the deterministic membership UUID.
func membershipID(gcid, tenantID, role string) string {
	return uuid.NewSHA1(seedNamespace, []byte("membership:"+gcid+":"+tenantID+":"+role)).String()
}

// seedUser is one seeded account: user row + Argon2id credential + one
// membership per role.
type seedUser struct {
	Username string
	Email    string
	Password string
	// Roles are the seeded account's membership roles. The instructor carries
	// two (see seedUsers); every other persona carries one.
	Roles []identity.Role
}

// seedUsers builds the ordered seed list: the admin (always) plus the
// instructor and student when their usernames are configured. The student
// account carries role `learner` — the stored membership_role vocabulary has
// no `student` value (see internal/domain/identity/membership.go). The
// instructor carries `instructor` AND `author`: the demo instructor authors
// atoms, and in chora-tenancy's roleSurfaceMap `instructor` maps to `rplus`
// while `author` (like `learner`) maps to the `aplus` surface that gates A+
// authoring — an instructor-only account cannot create atoms.
func seedUsers(cfg config) ([]seedUser, error) {
	users := []seedUser{{
		Username: cfg.Username,
		Email:    cfg.Email,
		Password: cfg.Password,
		Roles:    []identity.Role{identity.RoleAdmin},
	}}
	if cfg.InstructorUsername != "" {
		users = append(users, seedUser{
			Username: cfg.InstructorUsername,
			Email:    cfg.InstructorEmail,
			Password: cfg.InstructorPassword,
			Roles:    []identity.Role{identity.RoleInstructor, identity.RoleAuthor},
		})
	}
	if cfg.StudentUsername != "" {
		users = append(users, seedUser{
			Username: cfg.StudentUsername,
			Email:    cfg.StudentEmail,
			Password: cfg.StudentPassword,
			Roles:    []identity.Role{identity.RoleLearner},
		})
	}
	seen := map[string]bool{}
	for _, u := range users {
		norm := authn.NormalizeUsername(u.Username)
		if seen[norm] {
			return nil, fmt.Errorf("duplicate seed username: %q", u.Username)
		}
		seen[norm] = true
	}
	return users, nil
}

func main() {
	log.SetFlags(log.LstdFlags | log.LUTC)

	cfg, err := loadConfig()
	if err != nil {
		log.Fatalf("seed: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	pool, err := pgxpool.New(ctx, cfg.DSN)
	if err != nil {
		log.Fatalf("seed: pgxpool: %v", err)
	}
	defer pool.Close()

	runCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	// Authoritative chora-tenancy memberships (ADR-182). Unset → the seed
	// provisions the identity mirror only (dev mode) and run() skips the
	// tenancy upserts. Set → dial fails LOUDLY: a configured-but-broken
	// tenancy must not seed a mirror the sessions cannot use.
	var tenancyUps tenancyMembershipUpserter
	tenancyGRPCURL := strings.TrimSpace(os.Getenv("SVC_TENANCY_GRPC_URL"))
	if tenancyGRPCURL == "" {
		log.Printf("seed: SVC_TENANCY_GRPC_URL unset — chora-tenancy memberships will NOT be provisioned (identity mirror only; verify-credentials will mint sessions with surfaces: null)")
	} else {
		// Keepalive-warm dial (chora-go-common/grpcconn): the same helper
		// cmd/server/main.go uses for its tenancy conn — eager-connects at
		// boot and keeps the subchannel alive across idle gaps. insecure
		// creds: mTLS is supplied by Cloud Service Mesh PeerAuth.
		conn, err := grpcconn.Dial(tenancyGRPCURL)
		if err != nil {
			log.Fatalf("seed: tenancy grpc dial %s: %v", tenancyGRPCURL, err)
		}
		defer func() {
			if cerr := conn.Close(); cerr != nil {
				log.Printf("seed: tenancy gRPC conn.Close: %v", cerr)
			}
		}()
		tenancyUps, err = grpcadapter.NewAdminMembershipUpserter(conn)
		if err != nil {
			log.Fatalf("seed: tenancy upserter: %v", err)
		}
	}

	if err := run(runCtx, pool, cfg, tenancyUps); err != nil {
		log.Fatalf("seed: %v", err)
	}
}

// tenancyMembershipUpserter is the seed's slice of the ADR-182 authoritative
// write port (httpadapter.AuthoritativeMembershipUpserter, implemented by
// *grpcadapter.AdminMembershipUpserter against chora-tenancy's
// UpsertMembership RPC). Declared structurally so tests can fake it without
// dialing a real server.
type tenancyMembershipUpserter interface {
	UpsertMembershipByTenantID(ctx context.Context, gcid, tenantID string, roles []string) (bool, error)
}

func run(ctx context.Context, pool *pgxpool.Pool, cfg config, tenancyUps tenancyMembershipUpserter) error {
	users, err := seedUsers(cfg)
	if err != nil {
		return err
	}

	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback(ctx)
		}
	}()

	// tenant_memberships carries the tenant_isolation RLS policy; set the GUC
	// so the membership write passes WITH CHECK under a NOBYPASSRLS runtime
	// role. (No-op for an owner/superuser DSN.)
	if _, err := tx.Exec(ctx, fmt.Sprintf("SET LOCAL chora.tenant_id = '%s'", cfg.TenantID)); err != nil {
		return fmt.Errorf("set tenant guc: %w", err)
	}

	// 1. Tenant (identity-local registry; authoritative lifecycle is elsewhere).
	if _, err := tx.Exec(ctx, `
        INSERT INTO tenants (id, slug, name, status)
        VALUES ($1::uuid, $2, $3, 'active')
        ON CONFLICT (id) DO UPDATE
        SET slug = EXCLUDED.slug,
            name = EXCLUDED.name,
            status = 'active',
            updated_at = now()`,
		cfg.TenantID, cfg.TenantSlug, cfg.TenantSlug,
	); err != nil {
		return fmt.Errorf("upsert tenant: %w", err)
	}

	// 2. One user + credential + active membership per seed user.
	for _, u := range users {
		if err := upsertUser(ctx, tx, cfg.TenantID, u); err != nil {
			return err
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	committed = true

	// 3. Authoritative chora-tenancy memberships (ADR-182) — strictly AFTER
	// the identity transaction commits: a seeded user's GCID must already
	// exist before tenancy can grant them membership. tenancyUps is nil when
	// SVC_TENANCY_GRPC_URL is unset (dev mode) — main() already logged the
	// warning; a tenancy whose target cannot even be dialled never reaches
	// here because main() fails on the dial. upsertMembershipWithRetry absorbs
	// a short startup race on the upserts (transient failures only); anything
	// else still fails the run here.
	if tenancyUps != nil {
		if err := provisionTenancyMemberships(ctx, tenancyUps, cfg.TenantID, users); err != nil {
			return err
		}
	}

	// Never log the passwords.
	labels := make([]string, 0, len(users))
	for _, u := range users {
		roleNames := make([]string, 0, len(u.Roles))
		for _, r := range u.Roles {
			roleNames = append(roleNames, string(r))
		}
		labels = append(labels, u.Username+"("+strings.Join(roleNames, "+")+")")
	}
	log.Printf("seed: ok — tenant=%s slug=%s users=%s",
		cfg.TenantID, cfg.TenantSlug, strings.Join(labels, ","))
	return nil
}

// provisionTenancyMemberships upserts every seeded (gcid, tenant, role) into
// chora-tenancy over the sanctioned gRPC path — one additive
// UpsertMembership call per role, the same per-role shape the admin
// add-member handler uses. chora-tenancy's UpsertMembership is idempotent
// (it inserts one members row per MISSING (tenant, gcid, role)), so a re-run
// re-issues the same calls and creates nothing: the seed stays a no-op.
func provisionTenancyMemberships(ctx context.Context, upserter tenancyMembershipUpserter, tenantID string, users []seedUser) error {
	for _, u := range users {
		gcid := seedGcid(authn.NormalizeUsername(u.Username))
		for _, role := range u.Roles {
			if _, err := upsertMembershipWithRetry(ctx, upserter, gcid, tenantID, string(role)); err != nil {
				return fmt.Errorf("tenancy membership upsert (gcid=%s tenant=%s role=%s): %w", gcid, tenantID, role, err)
			}
			log.Printf("seed: tenancy membership upserted — gcid=%s tenant=%s role=%s", gcid, tenantID, role)
		}
	}
	return nil
}

// Tenancy upsert retry bound — hardcoded, NOT env-tunable. This is a startup
// race (Compose may start identity-seed before chora-tenancy's gRPC server
// accepts connections), not an outage, so the window must stay short: a
// genuinely down tenancy has to fail the seed promptly, not after a long
// retry marathon.
//
//	tenancyUpsertMaxAttempts = 6, tenancyUpsertBaseBackoff = 100ms doubling:
//	  ~3.1s of total backoff (100+200+400+800+1600ms) — comfortably covers a
//	  first-boot gRPC server coming up (container start + migrations), while
//	  a hard-down tenancy fails the seed within seconds of the first upsert.
//	tenancyUpsertRetryDeadline = 10s per upsert: cuts off an RPC that hangs
//	  (half-open mesh connection) instead of failing fast, so it can be
//	  retried rather than blocking the seed. Derived from the caller's ctx, so
//	  the seed's overall 30s run context still bounds the whole job — worst
//	  case (4 upserts × the per-call bound) can never outlive it.
const (
	tenancyUpsertMaxAttempts   = 6
	tenancyUpsertBaseBackoff   = 100 * time.Millisecond
	tenancyUpsertRetryDeadline = 10 * time.Second
)

// isTransientTenancyError reports whether err is a startup-race-class failure
// the seed may retry: gRPC Unavailable/DeadlineExceeded statuses, and
// connection-refused-style transport errors (a not-yet-listening chora-tenancy
// surfaces the dialer's raw ECONNREFUSED rather than a gRPC status).
// Everything else — InvalidArgument, PermissionDenied, FailedPrecondition,
// AlreadyExists, NotFound, Unauthenticated, and any non-gRPC error — is
// permanent and must fail the seed immediately.
func isTransientTenancyError(err error) bool {
	if err == nil {
		return false
	}
	if st, ok := status.FromError(err); ok {
		return st.Code() == codes.Unavailable || st.Code() == codes.DeadlineExceeded
	}
	return strings.Contains(strings.ToLower(err.Error()), "connection refused")
}

// upsertMembershipWithRetry issues one (gcid, tenant, role) UpsertMembership,
// retrying TRANSIENT failures only, within the bound above. A permanent error
// returns on the first attempt; a transient error that outlives the bound
// returns the last error non-nil — the run still fails non-zero. The per-role
// upsert shape (one additive call per role) and the caller's ordering are
// unchanged.
func upsertMembershipWithRetry(ctx context.Context, upserter tenancyMembershipUpserter, gcid, tenantID, role string) (bool, error) {
	retryCtx, cancel := context.WithTimeout(ctx, tenancyUpsertRetryDeadline)
	defer cancel()

	backoff := tenancyUpsertBaseBackoff
	for attempt := 1; ; attempt++ {
		ok, err := upserter.UpsertMembershipByTenantID(retryCtx, gcid, tenantID, []string{role})
		if err == nil {
			return ok, nil
		}
		if !isTransientTenancyError(err) {
			return false, err
		}
		if attempt >= tenancyUpsertMaxAttempts {
			log.Printf("seed: tenancy upsert giving up after %d attempts (gcid=%s tenant=%s role=%s): %v",
				attempt, gcid, tenantID, role, err)
			return false, fmt.Errorf("giving up after %d attempts: %w", attempt, err)
		}
		log.Printf("seed: tenancy upsert transient failure (gcid=%s tenant=%s role=%s attempt=%d/%d): %v — retrying",
			gcid, tenantID, role, attempt, tenancyUpsertMaxAttempts, err)
		timer := time.NewTimer(backoff)
		select {
		case <-retryCtx.Done():
			timer.Stop()
			return false, fmt.Errorf("retry deadline exceeded after %d attempts: %w", attempt, err)
		case <-timer.C:
		}
		backoff *= 2
	}
}

// upsertUser writes one seed user (user row, Argon2id credential, active
// membership) inside the seed transaction.
func upsertUser(ctx context.Context, tx pgx.Tx, tenantID string, u seedUser) error {
	usernameNorm := authn.NormalizeUsername(u.Username)
	gcid := seedGcid(usernameNorm)

	// User (deterministic GCID; local password provider).
	if _, err := tx.Exec(ctx, `
        INSERT INTO users (gcid, email, display_name, identity_provider, federated_subject, status)
        VALUES ($1::uuid, $2, $3, 'password'::identity_provider, $4, 'active')
        ON CONFLICT (gcid) DO UPDATE
        SET email = EXCLUDED.email,
            display_name = EXCLUDED.display_name,
            identity_provider = EXCLUDED.identity_provider,
            federated_subject = EXCLUDED.federated_subject,
            status = 'active',
            deleted_at = NULL,
            updated_at = now()`,
		gcid, u.Email, u.Username, usernameNorm,
	); err != nil {
		return fmt.Errorf("upsert user: %w", err)
	}

	// Credential — only re-hash when the stored hash no longer verifies.
	hash, err := resolveHash(ctx, tx, gcid, usernameNorm, u.Password)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `
        INSERT INTO local_credentials (gcid, username, username_norm, password_hash)
        VALUES ($1::uuid, $2, $3, $4)
        ON CONFLICT (gcid) DO UPDATE
        SET username = EXCLUDED.username,
            username_norm = EXCLUDED.username_norm,
            password_hash = EXCLUDED.password_hash,
            updated_at = now()`,
		gcid, u.Username, usernameNorm, hash,
	); err != nil {
		return fmt.Errorf("upsert credential: %w", err)
	}

	// Active membership — one mirror row per role (the instructor carries two).
	for _, role := range u.Roles {
		if _, err := tx.Exec(ctx, `
        INSERT INTO tenant_memberships (membership_id, gcid, tenant_id, role, status)
        VALUES ($1::uuid, $2::uuid, $3::uuid, $4::membership_role, 'active'::membership_status)
        ON CONFLICT (gcid, tenant_id, role) DO UPDATE
        SET status = 'active',
            updated_at = now()`,
			membershipID(gcid, tenantID, string(role)), gcid, tenantID, string(role),
		); err != nil {
			return fmt.Errorf("upsert membership: %w", err)
		}
	}

	return applyDemoSeedGrant(ctx, pg.NewTxBridge(tx), gcid)
}

// demoSeedGrantKey derives the deterministic demo-grant idempotency key for a
// seeded account. Because it is stable across runs, a re-run finds the existing
// ledger row and credits nothing.
func demoSeedGrantKey(gcid string) string {
	return demoSeedGrantPrefix + gcid
}

// applyDemoSeedGrant credits a seeded wallet with the demo balance, inside the
// seed transaction.
//
// ADDITIVE + IDEMPOTENT. The idempotency key is deterministic
// (`demo-seed:v1:<gcid>`), so on a re-run the in-transaction re-check finds the
// existing ledger row and does NOTHING: the grant is never re-added, and a
// balance the user has since spent is never reset. Because the credit and the
// ledger row are written by the same atomic primitive that the seed tx wraps, a
// seed failure rolls the grant back too — a failed seed changes neither.
//
// The grant is a free demo mint (direction mint, reason demo_grant), NOT a
// `topup`: `topup` means a paid purchase, and reusing it would mislabel free
// demo mana as revenue-bearing.
func applyDemoSeedGrant(ctx context.Context, tx pg.Tx, gcid string) error {
	// Scope the write to this user. The seed DSN is the table owner and so
	// bypasses RLS, but setting the GUC keeps the grant correct for EVERY
	// seeded user even if the DSN ever becomes the NOBYPASSRLS app role.
	if err := tx.Exec(ctx, fmt.Sprintf("SET LOCAL chora.user_gcid = '%s'", gcid)); err != nil {
		return fmt.Errorf("set user guc: %w", err)
	}
	res, err := pg.SeedDemoGrant(ctx, tx, gcid, demoSeedGrantKey(gcid), demoSeedGrantUnits)
	if err != nil {
		return fmt.Errorf("demo seed grant: %w", err)
	}
	if res != nil && res.Replayed {
		// Already applied by an earlier run — nothing was credited.
		log.Printf("seed: demo grant already applied for gcid=%s (idempotency_key=%s) — skipped",
			gcid, demoSeedGrantPrefix+gcid)
	}
	return nil
}

// resolveHash returns the PHC hash to persist. It reads the existing credential
// (if any) and returns it UNCHANGED when it still verifies against the supplied
// password — Argon2id's random salt means a re-hash would churn the row on
// every run.
func resolveHash(ctx context.Context, tx pgx.Tx, gcid, usernameNorm, password string) (string, error) {
	var existingGcid, existingHash string
	err := tx.QueryRow(ctx,
		`SELECT gcid::text, password_hash FROM local_credentials WHERE username_norm = $1`,
		usernameNorm,
	).Scan(&existingGcid, &existingHash)
	switch {
	case err == nil:
		if existingGcid == gcid {
			if ok, verr := authn.VerifyPassword(password, existingHash); verr == nil && ok {
				return existingHash, nil
			}
		}
	case errors.Is(err, pgx.ErrNoRows):
		// No credential yet — hash below.
	default:
		return "", fmt.Errorf("read credential: %w", err)
	}

	hash, err := authn.HashPassword(password)
	if err != nil {
		return "", fmt.Errorf("hash password: %w", err)
	}
	return hash, nil
}
