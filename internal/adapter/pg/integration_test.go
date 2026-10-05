//go:build integration

// integration_test.go — live Cloud SQL integration tests gated behind
// the `integration` build tag. Run with:
//
//	export GOOGLE_APPLICATION_CREDENTIALS=$HOME/.config/gcloud/sa-keys/dale-cli-chora-local.json
//	export CHORA_TEST_DSN_SECRET_ID=chora-dev-cloudsql-chora_identity-app_rw-dsn
//	export CHORA_TEST_DB_PROJECT=chora-local
//	go test -tags integration ./internal/adapter/pg/...
//
// These tests connect to the live chora_identity database (single-zone
// asia-southeast1-a Cloud SQL Enterprise Plus, per
// `project_session_2026_05_11_wave_a_close.md`) via the local Cloud
// SQL Auth Proxy on :5432.
//
// Test suite:
//
//  1. Round-trip Save → GetByGcid (validates UPSERT contract)
//  2. RLS isolation: insert tenant_membership under tenant A, query
//     under tenant B → 0 rows. Closes the deferred RLS check from
//     Wave A.
package pg_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	cgcdb "github.com/apollo-chora/chora-common/db"
	cgcsecrets "github.com/apollo-chora/chora-common/secrets"

	"github.com/apollo-chora/chora-identity/internal/adapter/pg"
	"github.com/apollo-chora/chora-identity/internal/domain/identity"
)

// liveDB returns a pgxpool.Pool connected to chora_identity. Skips the
// test when CHORA_TEST_DSN_SECRET_ID is unset.
func liveDB(t *testing.T) *pgxpool.Pool {
	t.Helper()

	dsn := os.Getenv("CHORA_TEST_DSN")
	secretID := os.Getenv("CHORA_TEST_DSN_SECRET_ID")
	if dsn == "" && secretID == "" {
		t.Skip("set CHORA_TEST_DSN or CHORA_TEST_DSN_SECRET_ID to run integration tests")
	}

	project := os.Getenv("CHORA_TEST_DB_PROJECT")
	if project == "" {
		project = "chora-local"
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var fetcher cgcdb.SecretFetcher
	var sclient *cgcsecrets.Client
	if secretID != "" && dsn == "" {
		c, err := cgcsecrets.NewClient(ctx, project)
		if err != nil {
			t.Fatalf("secret manager: %v", err)
		}
		sclient = c
		fetcher = c
	}

	pool, err := cgcdb.Bootstrap(ctx, cgcdb.BootstrapOptions{
		DSN:             dsn,
		SecretID:        secretID,
		SecretFetcher:   fetcher,
		RewriteFromPort: 6432,
		RewriteToPort:   5432,
		AppName:         "chora-identity-pg-integration-test",
	})
	if err != nil {
		if sclient != nil {
			_ = sclient.Close()
		}
		t.Fatalf("bootstrap: %v", err)
	}
	t.Cleanup(func() {
		pool.Close()
		if sclient != nil {
			_ = sclient.Close()
		}
	})
	return pool
}

func TestIntegration_UserRepository_RoundTrip(t *testing.T) {
	pool := liveDB(t)
	q := pg.NewPgxPoolQuerier(pool)
	r := pg.NewUserRepository(q)

	ctx := context.Background()

	u, err := identity.NewUser(identity.NewUserParams{
		Email:            fmt.Sprintf("phyllis+%s@chora.dev", uuid.NewString()[:8]),
		IdentityProvider: identity.ProviderWebAuthn,
		FederatedSubject: "sub-it-" + uuid.NewString(),
	})
	if err != nil {
		t.Fatalf("new user: %v", err)
	}

	if err := r.Save(ctx, u); err != nil {
		t.Fatalf("save: %v", err)
	}
	t.Cleanup(func() {
		// Soft-delete the test row so it doesn't accumulate. We can't
		// hard-delete (RESTRICT FK from membership) but soft-delete keeps
		// the table tidy.
		_, _ = pool.Exec(context.Background(),
			`UPDATE users SET deleted_at = now() WHERE gcid = $1`, u.Gcid)
	})

	got, err := r.GetByGcid(ctx, u.Gcid)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Gcid != u.Gcid {
		t.Errorf("gcid: got %q want %q", got.Gcid, u.Gcid)
	}
	if got.Email != u.Email {
		t.Errorf("email: got %q want %q", got.Email, u.Email)
	}
	if got.IdentityProvider != u.IdentityProvider {
		t.Errorf("idp: got %q want %q", got.IdentityProvider, u.IdentityProvider)
	}

	// Idempotent UPSERT — second Save must not error.
	got.DisplayName = "Phyllis"
	if err := r.Save(ctx, got); err != nil {
		t.Fatalf("save (idempotent): %v", err)
	}
	again, err := r.GetByGcid(ctx, u.Gcid)
	if err != nil {
		t.Fatalf("get (post-upsert): %v", err)
	}
	if again.DisplayName != "Phyllis" {
		t.Errorf("upsert did not update display_name: got %q", again.DisplayName)
	}
}

func TestIntegration_GetByGcid_NotFound(t *testing.T) {
	pool := liveDB(t)
	q := pg.NewPgxPoolQuerier(pool)
	r := pg.NewUserRepository(q)

	missing, _ := uuid.NewV7()
	_, err := r.GetByGcid(context.Background(), missing.String())
	if err == nil {
		t.Fatalf("expected ErrUserNotFound")
	}
	if !errors.Is(err, identity.ErrUserNotFound) {
		t.Errorf("expected identity.ErrUserNotFound, got %v", err)
	}
}

// TestIntegration_RLS_TenantIsolation verifies that tenant_memberships
// rows inserted under tenant A are NOT visible under tenant B. This
// closes the deferred RLS isolation test from Wave A.
//
// Methodology:
//
//  1. Open transaction A → SET LOCAL chora.tenant_id = A → INSERT membership
//     for new gcid → COMMIT.
//  2. Open transaction B → SET LOCAL chora.tenant_id = B → SELECT count
//     from tenant_memberships WHERE gcid = the new gcid → assert 0.
//  3. Open transaction C → SET LOCAL chora.tenant_id = A → SELECT count
//     from tenant_memberships WHERE gcid = new gcid → assert 1.
func TestIntegration_RLS_TenantIsolation(t *testing.T) {
	pool := liveDB(t)
	ctx := context.Background()

	// Fresh user (parent of the membership row — FK constraint).
	u, _ := identity.NewUser(identity.NewUserParams{
		Email:            fmt.Sprintf("rls+%s@chora.dev", uuid.NewString()[:8]),
		IdentityProvider: identity.ProviderWebAuthn,
		FederatedSubject: "sub-rls-" + uuid.NewString(),
	})
	q := pg.NewPgxPoolQuerier(pool)
	if err := pg.NewUserRepository(q).Save(ctx, u); err != nil {
		t.Fatalf("save user: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(),
			`DELETE FROM tenant_memberships WHERE gcid = $1`, u.Gcid)
		_, _ = pool.Exec(context.Background(),
			`UPDATE users SET deleted_at = now() WHERE gcid = $1`, u.Gcid)
	})

	tenantA, _ := uuid.NewV7()
	tenantB, _ := uuid.NewV7()

	// --- Insert under tenant A
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin A: %v", err)
	}
	if _, err := tx.Exec(ctx, fmt.Sprintf("SET LOCAL chora.tenant_id = '%s'", tenantA.String())); err != nil {
		_ = tx.Rollback(ctx)
		t.Fatalf("set local A: %v", err)
	}
	membershipID, _ := uuid.NewV7()
	if _, err := tx.Exec(ctx, `
        INSERT INTO tenant_memberships (membership_id, gcid, tenant_id, role, status, created_at, updated_at)
        VALUES ($1, $2, $3, 'learner', 'active', now(), now())`,
		membershipID.String(), u.Gcid, tenantA.String()); err != nil {
		_ = tx.Rollback(ctx)
		t.Fatalf("insert under tenant A: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit A: %v", err)
	}

	// --- Read under tenant B — must see 0 rows
	tx2, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin B: %v", err)
	}
	defer tx2.Rollback(ctx)
	if _, err := tx2.Exec(ctx, fmt.Sprintf("SET LOCAL chora.tenant_id = '%s'", tenantB.String())); err != nil {
		t.Fatalf("set local B: %v", err)
	}
	var countB int
	if err := tx2.QueryRow(ctx,
		`SELECT count(*) FROM tenant_memberships WHERE gcid = $1`,
		u.Gcid).Scan(&countB); err != nil {
		t.Fatalf("count under B: %v", err)
	}
	if countB != 0 {
		t.Errorf("RLS LEAK: tenant B saw %d rows for tenant A's gcid", countB)
	}

	// --- Read under tenant A — must see 1 row
	tx3, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin A2: %v", err)
	}
	defer tx3.Rollback(ctx)
	if _, err := tx3.Exec(ctx, fmt.Sprintf("SET LOCAL chora.tenant_id = '%s'", tenantA.String())); err != nil {
		t.Fatalf("set local A2: %v", err)
	}
	var countA int
	if err := tx3.QueryRow(ctx,
		`SELECT count(*) FROM tenant_memberships WHERE gcid = $1`,
		u.Gcid).Scan(&countA); err != nil {
		t.Fatalf("count under A: %v", err)
	}
	if countA != 1 {
		t.Errorf("expected 1 row under tenant A, got %d", countA)
	}

	t.Logf("RLS isolation OK: tenant A=%d row(s), tenant B=%d row(s)", countA, countB)
}
