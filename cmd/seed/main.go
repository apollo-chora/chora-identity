// Command seed is the idempotent local-user provisioning job for
// chora-identity.
//
// It reads its inputs from the environment and, in ONE transaction, upserts a
// tenant plus, for each configured seed user, a user row, the user's Argon2id
// credential, and an ACTIVE membership. Every write is keyed on a STABLE
// identifier (deterministic GCID, fixed tenant UUID, normalised username,
// (gcid,tenant_id,role)), so re-running the job is a no-op.
//
// Seed users:
//
//	admin      — always seeded (role `admin`).
//	instructor — seeded when CHORA_SEED_INSTRUCTOR_USERNAME is set (role
//	             `instructor`).
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

// seedUser is one seeded account: user row + Argon2id credential + membership.
type seedUser struct {
	Username string
	Email    string
	Password string
	Role     identity.Role
}

// seedUsers builds the ordered seed list: the admin (always) plus the
// instructor and student when their usernames are configured. The student
// account carries role `learner` — the stored membership_role vocabulary has
// no `student` value (see internal/domain/identity/membership.go).
func seedUsers(cfg config) ([]seedUser, error) {
	users := []seedUser{{
		Username: cfg.Username,
		Email:    cfg.Email,
		Password: cfg.Password,
		Role:     identity.RoleAdmin,
	}}
	if cfg.InstructorUsername != "" {
		users = append(users, seedUser{
			Username: cfg.InstructorUsername,
			Email:    cfg.InstructorEmail,
			Password: cfg.InstructorPassword,
			Role:     identity.RoleInstructor,
		})
	}
	if cfg.StudentUsername != "" {
		users = append(users, seedUser{
			Username: cfg.StudentUsername,
			Email:    cfg.StudentEmail,
			Password: cfg.StudentPassword,
			Role:     identity.RoleLearner,
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

	if err := run(runCtx, pool, cfg); err != nil {
		log.Fatalf("seed: %v", err)
	}
}

func run(ctx context.Context, pool *pgxpool.Pool, cfg config) error {
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

	// Never log the passwords.
	labels := make([]string, 0, len(users))
	for _, u := range users {
		labels = append(labels, u.Username+"("+string(u.Role)+")")
	}
	log.Printf("seed: ok — tenant=%s slug=%s users=%s",
		cfg.TenantID, cfg.TenantSlug, strings.Join(labels, ","))
	return nil
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

	// Active membership.
	if _, err := tx.Exec(ctx, `
        INSERT INTO tenant_memberships (membership_id, gcid, tenant_id, role, status)
        VALUES ($1::uuid, $2::uuid, $3::uuid, $4::membership_role, 'active'::membership_status)
        ON CONFLICT (gcid, tenant_id, role) DO UPDATE
        SET status = 'active',
            updated_at = now()`,
		membershipID(gcid, tenantID, string(u.Role)), gcid, tenantID, string(u.Role),
	); err != nil {
		return fmt.Errorf("upsert membership: %w", err)
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
