//go:build integration

// tenant_idp_provider_repository_integration_test.go — live DB tests for
// Setup Wizard Phase C (CHO-1682) pgx repository.
//
// Run against the local chora-infra/local Postgres OR a Cloud SQL Auth
// Proxy port-forwarded to :5432. See package doc for env shape.
//
//	export TENANT_IDP_TEST_DSN="postgres://chora_identity_app_rw:dev@127.0.0.1:5432/chora_identity?sslmode=disable"
//	go test -tags integration ./services/chora-identity/internal/adapter/pg/ -run TenantIdpProvider
//
// The migration 0018_tenant_idp_providers MUST have been applied first.
package pg_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/apollo-chora/chora-identity/internal/adapter/pg"
	tip "github.com/apollo-chora/chora-identity/internal/domain/tenant_idp_provider"
)

func tipDsn(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("TENANT_IDP_TEST_DSN")
	if dsn == "" {
		t.Skip("TENANT_IDP_TEST_DSN unset; skipping live DB test")
	}
	return dsn
}

func newTipRepo(t *testing.T) (*pg.TenantIdpProviderRepository, *pgxpool.Pool) {
	t.Helper()
	dsn := tipDsn(t)
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("pgxpool.New: %v", err)
	}
	repo := pg.NewTenantIdpProviderRepository(pg.NewPgxPoolQuerier(pool))
	return repo, pool
}

func mustUUIDv7(t *testing.T) string {
	t.Helper()
	u, err := uuid.NewV7()
	if err != nil {
		t.Fatalf("uuidv7: %v", err)
	}
	return u.String()
}

func TestTenantIdpProviderRepository_Integration_UpsertGet_RoundTrip(t *testing.T) {
	repo, pool := newTipRepo(t)
	defer pool.Close()

	ctx := context.Background()
	tenantID := mustUUIDv7(t)
	id := mustUUIDv7(t)
	now := time.Now().UTC().Truncate(time.Microsecond)

	p := &tip.TenantIdpProvider{
		ID:               id,
		TenantID:         tenantID,
		ProviderType:     tip.ProviderOIDC,
		ClientID:         "client-acme",
		ClientSecretName: "projects/chora-local/secrets/idp-client-secret-" + tenantID + "-" + id,
		DiscoveryURL:     "https://issuer.example.com/.well-known/openid-configuration",
		CreatedAt:        now,
		UpdatedAt:        now,
	}
	if err := repo.Upsert(ctx, p); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	if p.ID != id {
		t.Errorf("ID after Upsert = %q; want %q", p.ID, id)
	}

	got, err := repo.Get(ctx, tenantID, tip.ProviderOIDC)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.ClientID != "client-acme" {
		t.Errorf("ClientID = %q", got.ClientID)
	}
	if got.DiscoveryURL != "https://issuer.example.com/.well-known/openid-configuration" {
		t.Errorf("DiscoveryURL = %q", got.DiscoveryURL)
	}

	// Clean up.
	if err := repo.SoftDelete(ctx, tenantID, tip.ProviderOIDC, time.Now().UTC()); err != nil {
		t.Fatalf("SoftDelete: %v", err)
	}
	if _, err := repo.Get(ctx, tenantID, tip.ProviderOIDC); err == nil {
		t.Error("Get after SoftDelete should return ErrNotFound")
	}
}

func TestTenantIdpProviderRepository_Integration_IdempotentUpsert_ReusesID(t *testing.T) {
	repo, pool := newTipRepo(t)
	defer pool.Close()

	ctx := context.Background()
	tenantID := mustUUIDv7(t)
	firstID := mustUUIDv7(t)
	secondID := mustUUIDv7(t)
	now := time.Now().UTC().Truncate(time.Microsecond)

	p1 := &tip.TenantIdpProvider{
		ID: firstID, TenantID: tenantID, ProviderType: tip.ProviderOIDC,
		ClientID: "c1", ClientSecretName: "sn1",
		DiscoveryURL: "https://i1.example/openid",
		CreatedAt:    now, UpdatedAt: now,
	}
	if err := repo.Upsert(ctx, p1); err != nil {
		t.Fatalf("first Upsert: %v", err)
	}

	// Re-upsert under a NEW UUIDv7 — the pg layer should keep the original
	// ID via ON CONFLICT...RETURNING.
	p2 := &tip.TenantIdpProvider{
		ID: secondID, TenantID: tenantID, ProviderType: tip.ProviderOIDC,
		ClientID: "c2", ClientSecretName: "sn2",
		DiscoveryURL: "https://i2.example/openid",
		CreatedAt:    now, UpdatedAt: now.Add(1 * time.Minute),
	}
	if err := repo.Upsert(ctx, p2); err != nil {
		t.Fatalf("second Upsert: %v", err)
	}
	if p2.ID != firstID {
		t.Errorf("ID after re-upsert = %q; want first ID %q (ON CONFLICT...RETURNING failed)", p2.ID, firstID)
	}

	got, err := repo.Get(ctx, tenantID, tip.ProviderOIDC)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.ClientID != "c2" {
		t.Errorf("ClientID = %q; want c2 (in-place UPDATE failed)", got.ClientID)
	}

	// Clean up.
	_ = repo.SoftDelete(ctx, tenantID, tip.ProviderOIDC, time.Now().UTC())
}

func TestTenantIdpProviderRepository_Integration_ListByTenant_FiltersSoftDeleted(t *testing.T) {
	repo, pool := newTipRepo(t)
	defer pool.Close()

	ctx := context.Background()
	tenantID := mustUUIDv7(t)
	now := time.Now().UTC().Truncate(time.Microsecond)

	// Seed an OIDC row.
	oidcID := mustUUIDv7(t)
	if err := repo.Upsert(ctx, &tip.TenantIdpProvider{
		ID: oidcID, TenantID: tenantID, ProviderType: tip.ProviderOIDC,
		ClientID: "c", ClientSecretName: "sn",
		DiscoveryURL: "https://x.example/openid",
		CreatedAt:    now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("seed OIDC: %v", err)
	}
	// Seed a Singpass row.
	singpassID := mustUUIDv7(t)
	if err := repo.Upsert(ctx, &tip.TenantIdpProvider{
		ID: singpassID, TenantID: tenantID, ProviderType: tip.ProviderSingpass,
		SingpassEnabled: true,
		CreatedAt:       now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("seed Singpass: %v", err)
	}

	rows, err := repo.ListByTenant(ctx, tenantID)
	if err != nil {
		t.Fatalf("ListByTenant: %v", err)
	}
	if len(rows) != 2 {
		t.Errorf("rows = %d; want 2 (OIDC + Singpass)", len(rows))
	}

	// Soft-delete OIDC, re-list.
	_ = repo.SoftDelete(ctx, tenantID, tip.ProviderOIDC, time.Now().UTC())
	rows, err = repo.ListByTenant(ctx, tenantID)
	if err != nil {
		t.Fatalf("ListByTenant after soft-delete: %v", err)
	}
	if len(rows) != 1 {
		t.Errorf("rows after soft-delete = %d; want 1 (Singpass only)", len(rows))
	}

	// Clean up Singpass.
	_ = repo.SoftDelete(ctx, tenantID, tip.ProviderSingpass, time.Now().UTC())
}
