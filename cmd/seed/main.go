// Command seed is the idempotent local-admin provisioning job for
// chora-identity.
//
// It reads its inputs from the environment and, in ONE transaction, upserts a
// tenant, a user, the user's Argon2id credential, and an ACTIVE admin
// membership. Every write is keyed on a STABLE identifier (deterministic GCID,
// fixed tenant UUID, normalised username, (gcid,tenant_id,role)), so re-running
// the job is a no-op.
//
// Argon2id uses a random salt, so the stored hash is NOT rewritten on every
// run: it is only replaced when it no longer verifies against
// CHORA_SEED_ADMIN_PASSWORD. The cleartext password is never logged or
// committed.
//
// Environment:
//
//	CHORA_DB_DSN              — chora_identity connection string (required)
//	CHORA_SEED_TENANT_ID      — tenant UUID (required)
//	CHORA_SEED_TENANT_SLUG    — tenant slug (required)
//	CHORA_SEED_ADMIN_USERNAME — admin username (required)
//	CHORA_SEED_ADMIN_EMAIL    — admin email (required)
//	CHORA_SEED_ADMIN_PASSWORD — admin password (required)
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

	"github.com/apollo-chora/chora-identity/internal/domain/authn"
	"github.com/apollo-chora/chora-identity/internal/domain/identity"
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
}

func loadConfig() (config, error) {
	c := config{
		DSN:        strings.TrimSpace(os.Getenv("CHORA_DB_DSN")),
		TenantID:   strings.TrimSpace(os.Getenv("CHORA_SEED_TENANT_ID")),
		TenantSlug: strings.TrimSpace(os.Getenv("CHORA_SEED_TENANT_SLUG")),
		Username:   strings.TrimSpace(os.Getenv("CHORA_SEED_ADMIN_USERNAME")),
		Email:      strings.TrimSpace(os.Getenv("CHORA_SEED_ADMIN_EMAIL")),
		Password:   os.Getenv("CHORA_SEED_ADMIN_PASSWORD"),
	}
	var missing []string
	for k, v := range map[string]string{
		"CHORA_DB_DSN":              c.DSN,
		"CHORA_SEED_TENANT_ID":      c.TenantID,
		"CHORA_SEED_TENANT_SLUG":    c.TenantSlug,
		"CHORA_SEED_ADMIN_USERNAME": c.Username,
		"CHORA_SEED_ADMIN_EMAIL":    c.Email,
		"CHORA_SEED_ADMIN_PASSWORD": c.Password,
	} {
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
	return c, nil
}

// adminGcid derives the deterministic GCID for the seeded admin.
func adminGcid(usernameNorm string) string {
	return uuid.NewSHA1(seedNamespace, []byte("chora-identity-local-admin:"+usernameNorm)).String()
}

// membershipID derives the deterministic membership UUID.
func membershipID(gcid, tenantID, role string) string {
	return uuid.NewSHA1(seedNamespace, []byte("membership:"+gcid+":"+tenantID+":"+role)).String()
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
	// Never log the password.
	log.Printf("seed: ok — tenant=%s slug=%s username=%s gcid=%s",
		cfg.TenantID, cfg.TenantSlug, authn.NormalizeUsername(cfg.Username), adminGcid(authn.NormalizeUsername(cfg.Username)))
}

func run(ctx context.Context, pool *pgxpool.Pool, cfg config) error {
	usernameNorm := authn.NormalizeUsername(cfg.Username)
	gcid := adminGcid(usernameNorm)
	const role = string(identity.RoleAdmin)

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

	// 2. User (deterministic GCID; local password provider).
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
		gcid, cfg.Email, cfg.Username, usernameNorm,
	); err != nil {
		return fmt.Errorf("upsert user: %w", err)
	}

	// 3. Credential — only re-hash when the stored hash no longer verifies.
	hash, err := resolveHash(ctx, tx, gcid, usernameNorm, cfg.Password)
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
		gcid, cfg.Username, usernameNorm, hash,
	); err != nil {
		return fmt.Errorf("upsert credential: %w", err)
	}

	// 4. Active admin membership.
	if _, err := tx.Exec(ctx, `
        INSERT INTO tenant_memberships (membership_id, gcid, tenant_id, role, status)
        VALUES ($1::uuid, $2::uuid, $3::uuid, 'admin'::membership_role, 'active'::membership_status)
        ON CONFLICT (gcid, tenant_id, role) DO UPDATE
        SET status = 'active',
            updated_at = now()`,
		membershipID(gcid, cfg.TenantID, role), gcid, cfg.TenantID,
	); err != nil {
		return fmt.Errorf("upsert membership: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	committed = true
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
