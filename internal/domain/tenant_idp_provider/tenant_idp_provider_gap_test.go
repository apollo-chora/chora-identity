// Coverage top-up for the TenantIdpProvider Service — ListByTenant,
// SoftDelete, the Upsert error/keep-secret branches and the SAML path.
// Reuses the port fakes from tenant_idp_provider_test.go (same package).
package tenant_idp_provider

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestService_ListByTenant_EmptyTenant(t *testing.T) {
	t.Parallel()
	svc, _, _, _ := newService(t)
	_, err := svc.ListByTenant(context.Background(), "   ")
	if !errors.Is(err, ErrInvalidInput) {
		t.Errorf("err = %v; want ErrInvalidInput", err)
	}
}

func TestService_ListByTenant_ReturnsRepoRows(t *testing.T) {
	t.Parallel()
	svc, repo, _, _ := newService(t)
	ctx := context.Background()

	if _, err := svc.Upsert(ctx, UpsertInput{
		TenantID: tenantA, ProviderType: ProviderOIDC,
		ClientID: "c", ClientSecret: "s",
		DiscoveryURL: "https://issuer.example.com/.well-known/openid-configuration",
		ActorGCID:    gcidA,
	}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	rows, err := svc.ListByTenant(ctx, tenantA)
	if err != nil {
		t.Fatalf("ListByTenant: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("rows = %d; want 1", len(rows))
	}
	if rows[0].ProviderType != ProviderOIDC {
		t.Errorf("provider = %q; want oidc", rows[0].ProviderType)
	}
	// Rows for other tenants are not returned.
	_ = repo
	other, err := svc.ListByTenant(ctx, "01970000-0000-7000-8000-0000000000bb")
	if err != nil {
		t.Fatalf("ListByTenant(other): %v", err)
	}
	if len(other) != 0 {
		t.Errorf("other tenant rows = %d; want 0", len(other))
	}
}

func TestService_SoftDelete_EmptyTenant(t *testing.T) {
	t.Parallel()
	svc, _, _, _ := newService(t)
	err := svc.SoftDelete(context.Background(), " ", ProviderOIDC)
	if !errors.Is(err, ErrInvalidInput) {
		t.Errorf("err = %v; want ErrInvalidInput", err)
	}
}

func TestService_SoftDelete_UnknownProviderType(t *testing.T) {
	t.Parallel()
	svc, _, _, _ := newService(t)
	err := svc.SoftDelete(context.Background(), tenantA, ProviderType("bogus"))
	if !errors.Is(err, ErrInvalidInput) {
		t.Errorf("err = %v; want ErrInvalidInput", err)
	}
}

func TestService_SoftDelete_DisconnectsRow(t *testing.T) {
	t.Parallel()
	svc, repo, _, _ := newService(t)
	ctx := context.Background()

	if _, err := svc.Upsert(ctx, UpsertInput{
		TenantID: tenantA, ProviderType: ProviderOIDC,
		ClientID: "c", ClientSecret: "s",
		DiscoveryURL: "https://issuer.example.com/.well-known/openid-configuration",
		ActorGCID:    gcidA,
	}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	fixed := time.Date(2026, 7, 1, 8, 0, 0, 0, time.UTC)
	svc.SetClock(func() time.Time { return fixed })

	if err := svc.SoftDelete(ctx, tenantA, ProviderOIDC); err != nil {
		t.Fatalf("SoftDelete: %v", err)
	}
	// The row is now hidden from reads and carries the clock-provided stamp.
	if _, err := repo.Get(ctx, tenantA, ProviderOIDC); !errors.Is(err, ErrNotFound) {
		t.Errorf("Get post-delete err = %v; want ErrNotFound", err)
	}
	row := repo.byKey[tenantA+"|oidc"]
	if row == nil || row.DeletedAt == nil || !row.DeletedAt.Equal(fixed) {
		t.Errorf("DeletedAt = %v; want %v", repo.byKey[tenantA+"|oidc"].DeletedAt, fixed)
	}
}

// -----------------------------------------------------------------------------
// Upsert — previously-uncovered branches
// -----------------------------------------------------------------------------

func TestService_Upsert_RepoLookupErrorSurfaces(t *testing.T) {
	t.Parallel()
	svc, repo, _, _ := newService(t)
	repo.getErr = errors.New("db down")

	_, err := svc.Upsert(context.Background(), UpsertInput{
		TenantID: tenantA, ProviderType: ProviderOIDC,
		ClientID: "c", ClientSecret: "s",
		DiscoveryURL: "https://issuer.example.com/.well-known/openid-configuration",
		ActorGCID:    gcidA,
	})
	if err == nil || !strings.Contains(err.Error(), "db down") {
		t.Errorf("err = %v; want wrapped lookup error", err)
	}
}

func TestService_Upsert_ReapplyExistingKeepsSecretName(t *testing.T) {
	t.Parallel()
	svc, _, sm, _ := newService(t)
	ctx := context.Background()

	first, err := svc.Upsert(ctx, UpsertInput{
		TenantID: tenantA, ProviderType: ProviderOIDC,
		ClientID: "c", ClientSecret: "s1",
		DiscoveryURL: "https://issuer.example.com/.well-known/openid-configuration",
		ActorGCID:    gcidA,
	})
	if err != nil {
		t.Fatalf("first Upsert: %v", err)
	}
	if first.ClientSecretName == "" {
		t.Fatal("expected minted secret name on first Upsert")
	}

	// Re-apply WITHOUT a client_secret (CHO-1692 hydration round-trip): the
	// previously stored Secret Manager name must be reused verbatim — NO new
	// version minted.
	second, err := svc.Upsert(ctx, UpsertInput{
		TenantID: tenantA, ProviderType: ProviderOIDC,
		ClientID:     "c-updated",
		DiscoveryURL: "https://issuer.example.com/.well-known/openid-configuration",
		ActorGCID:    gcidA,
	})
	if err != nil {
		t.Fatalf("re-apply: %v", err)
	}
	if second.ClientSecretName != first.ClientSecretName {
		t.Errorf("secret name changed: %q → %q", first.ClientSecretName, second.ClientSecretName)
	}
	if sm.callCount != 1 {
		t.Errorf("SecretManager calls = %d; want 1 (no new version on keep-secret re-apply)", sm.callCount)
	}
	if second.ClientID != "c-updated" {
		t.Errorf("ClientID = %q; want c-updated", second.ClientID)
	}
}

func TestService_Upsert_RepoUpsertFailure(t *testing.T) {
	t.Parallel()
	svc, repo, _, pub := newService(t)
	repo.upsertErr = errors.New("write failed")

	_, err := svc.Upsert(context.Background(), UpsertInput{
		TenantID: tenantA, ProviderType: ProviderOIDC,
		ClientID: "c", ClientSecret: "s",
		DiscoveryURL: "https://issuer.example.com/.well-known/openid-configuration",
		ActorGCID:    gcidA,
	})
	if err == nil || !strings.Contains(err.Error(), "write failed") {
		t.Errorf("err = %v; want wrapped upsert error", err)
	}
	if len(pub.events) != 0 {
		t.Errorf("event published despite repo failure; events=%d", len(pub.events))
	}
}

func TestService_Upsert_PublishFailure(t *testing.T) {
	t.Parallel()
	svc, repo, _, pub := newService(t)
	pub.err = errors.New("outbox down")

	_, err := svc.Upsert(context.Background(), UpsertInput{
		TenantID: tenantA, ProviderType: ProviderOIDC,
		ClientID: "c", ClientSecret: "s",
		DiscoveryURL: "https://issuer.example.com/.well-known/openid-configuration",
		ActorGCID:    gcidA,
	})
	if err == nil || !strings.Contains(err.Error(), "outbox down") {
		t.Errorf("err = %v; want wrapped publish error", err)
	}
	// The row IS persisted even though publishing failed (outbox semantics —
	// the publisher failure is surfaced so the caller can retry the event).
	if _, err := repo.Get(context.Background(), tenantA, ProviderOIDC); err != nil {
		t.Errorf("row missing after publish failure: %v", err)
	}
}

// -----------------------------------------------------------------------------
// SAML provider path (validate + Upsert)
// -----------------------------------------------------------------------------

func TestService_Upsert_SAML_HappyPath(t *testing.T) {
	t.Parallel()
	svc, _, sm, pub := newService(t)
	got, err := svc.Upsert(context.Background(), UpsertInput{
		TenantID:     tenantA,
		ProviderType: ProviderSAML,
		ClientID:     "saml-sp-id",
		DiscoveryURL: "https://idp.example.com/saml/metadata",
		ActorGCID:    gcidA,
	})
	if err != nil {
		t.Fatalf("Upsert saml: %v", err)
	}
	if got.ProviderType != ProviderSAML {
		t.Errorf("ProviderType = %q", got.ProviderType)
	}
	if got.DiscoveryURL != "https://idp.example.com/saml/metadata" {
		t.Errorf("DiscoveryURL = %q", got.DiscoveryURL)
	}
	// SAML has no client secret — Secret Manager must not be touched.
	if sm.callCount != 0 {
		t.Errorf("SecretManager calls = %d; want 0 for saml", sm.callCount)
	}
	if len(pub.events) != 1 {
		t.Errorf("publisher events = %d; want 1", len(pub.events))
	}
}

func TestService_Upsert_SAML_RejectsInvalidDiscoveryURL(t *testing.T) {
	t.Parallel()
	svc, _, _, _ := newService(t)
	_, err := svc.Upsert(context.Background(), UpsertInput{
		TenantID:     tenantA,
		ProviderType: ProviderSAML,
		DiscoveryURL: "ftp://idp.example.com/metadata",
		ActorGCID:    gcidA,
	})
	if !errors.Is(err, ErrInvalidInput) {
		t.Errorf("err = %v; want ErrInvalidInput", err)
	}
}

func TestService_Upsert_SAML_RejectsMissingDiscoveryURL(t *testing.T) {
	t.Parallel()
	svc, _, _, _ := newService(t)
	_, err := svc.Upsert(context.Background(), UpsertInput{
		TenantID:     tenantA,
		ProviderType: ProviderSAML,
		ActorGCID:    gcidA,
	})
	if !errors.Is(err, ErrInvalidInput) {
		t.Errorf("err = %v; want ErrInvalidInput", err)
	}
}
