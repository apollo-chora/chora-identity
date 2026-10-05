// Tests written FIRST (RED phase) per .claude/rules/development-execution.md.
// Setup Wizard Phase C (CHO-1682) — tenant identity-provider domain.
//
// Mirrors the apikey/ domain pattern: hexagonal ports
// (Repository + SecretManager + EventPublisher), Service entry point,
// in-memory fakes for each port owned by the test file. Validation
// per provider_type (OIDC requires client_id+secret+discovery_url,
// Singpass forbids them) lives on the Service, not the aggregate.
package tenant_idp_provider

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// In-memory fakes for the domain ports.
// ---------------------------------------------------------------------------

type fakeRepo struct {
	mu        sync.Mutex
	upsertErr error
	getErr    error
	byKey     map[string]*TenantIdpProvider // (tenant_id|provider_type) → row
	byTenant  map[string][]*TenantIdpProvider
}

func newFakeRepo() *fakeRepo {
	return &fakeRepo{
		byKey:    map[string]*TenantIdpProvider{},
		byTenant: map[string][]*TenantIdpProvider{},
	}
}

func (r *fakeRepo) Upsert(_ context.Context, p *TenantIdpProvider) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.upsertErr != nil {
		return r.upsertErr
	}
	key := p.TenantID + "|" + string(p.ProviderType)
	if existing, ok := r.byKey[key]; ok {
		// In-place update preserves ID.
		p.ID = existing.ID
	}
	r.byKey[key] = p
	// Replace per-tenant list deterministically.
	var list []*TenantIdpProvider
	for _, v := range r.byKey {
		if v.TenantID == p.TenantID && v.DeletedAt == nil {
			list = append(list, v)
		}
	}
	r.byTenant[p.TenantID] = list
	return nil
}

func (r *fakeRepo) Get(_ context.Context, tenantID string, pt ProviderType) (*TenantIdpProvider, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.getErr != nil {
		return nil, r.getErr
	}
	v, ok := r.byKey[tenantID+"|"+string(pt)]
	if !ok || v.DeletedAt != nil {
		return nil, ErrNotFound
	}
	clone := *v
	return &clone, nil
}

func (r *fakeRepo) ListByTenant(_ context.Context, tenantID string) ([]TenantIdpProvider, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]TenantIdpProvider, 0)
	for _, v := range r.byTenant[tenantID] {
		out = append(out, *v)
	}
	return out, nil
}

func (r *fakeRepo) SoftDelete(_ context.Context, tenantID string, pt ProviderType, now time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	v, ok := r.byKey[tenantID+"|"+string(pt)]
	if !ok {
		return ErrNotFound
	}
	t := now
	v.DeletedAt = &t
	return nil
}

type fakeSecretManager struct {
	mu        sync.Mutex
	stored    map[string]string // resource_name → plaintext (for assertion only)
	storeErr  error
	nextName  string // optional override
	callCount int
}

func newFakeSecretManager() *fakeSecretManager {
	return &fakeSecretManager{stored: map[string]string{}}
}

// Store mints a secret resource (or adds a new version to an existing one)
// and returns the canonical resource name the DB should reference.
func (s *fakeSecretManager) Store(_ context.Context, tenantID, idpID, plaintext string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.callCount++
	if s.storeErr != nil {
		return "", s.storeErr
	}
	name := s.nextName
	if name == "" {
		// Default deterministic name format the production adapter will mirror.
		name = "projects/chora-local/secrets/idp-client-secret-" + tenantID + "-" + idpID
	}
	s.stored[name] = plaintext
	return name, nil
}

type fakePublisher struct {
	mu     sync.Mutex
	events []PublishedEvent
	err    error
}

func (p *fakePublisher) Publish(_ context.Context, evt PublishedEvent) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.err != nil {
		return p.err
	}
	p.events = append(p.events, evt)
	return nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func newService(t *testing.T) (*Service, *fakeRepo, *fakeSecretManager, *fakePublisher) {
	t.Helper()
	repo := newFakeRepo()
	sm := newFakeSecretManager()
	pub := &fakePublisher{}
	svc := NewService(repo, sm, pub)
	return svc, repo, sm, pub
}

const (
	tenantA = "01970000-0000-7000-8000-00000000000a"
	gcidA   = "01935f12-0000-7000-8000-0000000000ff"
)

// ---------------------------------------------------------------------------
// Happy path — OIDC upsert mints a Secret Manager secret and persists the row
// ---------------------------------------------------------------------------

func TestService_Upsert_OIDC_CreatesRowAndMintsSecret(t *testing.T) {
	t.Parallel()
	svc, repo, sm, pub := newService(t)

	got, err := svc.Upsert(context.Background(), UpsertInput{
		TenantID:     tenantA,
		ProviderType: ProviderOIDC,
		ClientID:     "client-acme",
		ClientSecret: "shhh-very-secret",
		DiscoveryURL: "https://issuer.example.com/.well-known/openid-configuration",
		ActorGCID:    gcidA,
	})
	if err != nil {
		t.Fatalf("Upsert: unexpected error: %v", err)
	}

	// Aggregate has expected values.
	if got.TenantID != tenantA {
		t.Errorf("TenantID = %q; want %q", got.TenantID, tenantA)
	}
	if got.ProviderType != ProviderOIDC {
		t.Errorf("ProviderType = %q; want oidc", got.ProviderType)
	}
	if got.ClientID != "client-acme" {
		t.Errorf("ClientID = %q", got.ClientID)
	}
	if got.ClientSecretName == "" {
		t.Error("ClientSecretName empty — Secret Manager mint result should be persisted")
	}
	// The plaintext secret MUST NOT be on the aggregate.
	if got.ClientSecret() != "" {
		t.Error("aggregate must NOT expose plaintext client_secret post-Upsert")
	}
	// Secret Manager was actually called.
	if sm.callCount != 1 {
		t.Errorf("SecretManager.Store calls = %d; want 1", sm.callCount)
	}
	// Repo persisted the row.
	if r, err := repo.Get(context.Background(), tenantA, ProviderOIDC); err != nil || r == nil {
		t.Errorf("repo.Get post-upsert err=%v row=%v", err, r)
	}
	// Event published.
	if len(pub.events) != 1 {
		t.Fatalf("publisher events = %d; want 1", len(pub.events))
	}
	if pub.events[0].Topic != TopicConfigured {
		t.Errorf("event topic = %q; want %q", pub.events[0].Topic, TopicConfigured)
	}
	if pub.events[0].TenantID != tenantA {
		t.Errorf("event tenant = %q", pub.events[0].TenantID)
	}
}

// ---------------------------------------------------------------------------
// Idempotent upsert keyed on (tenant_id, provider_type) — same ID kept
// ---------------------------------------------------------------------------

func TestService_Upsert_OIDC_Idempotent_SameTenantSameType_ReusesRow(t *testing.T) {
	t.Parallel()
	svc, _, sm, _ := newService(t)

	first, err := svc.Upsert(context.Background(), UpsertInput{
		TenantID: tenantA, ProviderType: ProviderOIDC,
		ClientID: "client-1", ClientSecret: "s1",
		DiscoveryURL: "https://issuer.example.com/.well-known/openid-configuration",
		ActorGCID:    gcidA,
	})
	if err != nil {
		t.Fatalf("first Upsert: %v", err)
	}
	second, err := svc.Upsert(context.Background(), UpsertInput{
		TenantID: tenantA, ProviderType: ProviderOIDC,
		ClientID: "client-2", ClientSecret: "s2",
		DiscoveryURL: "https://issuer2.example.com/.well-known/openid-configuration",
		ActorGCID:    gcidA,
	})
	if err != nil {
		t.Fatalf("second Upsert: %v", err)
	}
	if first.ID != second.ID {
		t.Errorf("idempotent upsert must reuse ID; first=%q second=%q", first.ID, second.ID)
	}
	if second.ClientID != "client-2" {
		t.Errorf("ClientID not updated; got %q", second.ClientID)
	}
	if second.DiscoveryURL != "https://issuer2.example.com/.well-known/openid-configuration" {
		t.Errorf("DiscoveryURL not updated; got %q", second.DiscoveryURL)
	}
	// Both upserts mint a fresh Secret Manager version.
	if sm.callCount != 2 {
		t.Errorf("SecretManager calls = %d; want 2 (each upsert adds a new version)", sm.callCount)
	}
}

// ---------------------------------------------------------------------------
// Singpass upsert — NO Secret Manager call; client_secret forbidden in input
// ---------------------------------------------------------------------------

func TestService_Upsert_Singpass_NoSecretManagerCall(t *testing.T) {
	t.Parallel()
	svc, _, sm, pub := newService(t)

	got, err := svc.Upsert(context.Background(), UpsertInput{
		TenantID:        tenantA,
		ProviderType:    ProviderSingpass,
		SingpassEnabled: true,
		ActorGCID:       gcidA,
	})
	if err != nil {
		t.Fatalf("Upsert singpass: %v", err)
	}
	if got.ProviderType != ProviderSingpass {
		t.Errorf("ProviderType = %q; want singpass", got.ProviderType)
	}
	if got.ClientSecretName != "" {
		t.Errorf("ClientSecretName = %q; want empty for singpass (NDI uses public key)", got.ClientSecretName)
	}
	if sm.callCount != 0 {
		t.Errorf("SecretManager called %d times; want 0 for singpass", sm.callCount)
	}
	if len(pub.events) != 1 {
		t.Errorf("publisher events = %d; want 1", len(pub.events))
	}
}

func TestService_Upsert_Singpass_RejectsClientSecret(t *testing.T) {
	t.Parallel()
	svc, _, _, _ := newService(t)
	_, err := svc.Upsert(context.Background(), UpsertInput{
		TenantID:     tenantA,
		ProviderType: ProviderSingpass,
		ClientSecret: "should-not-be-here",
		ActorGCID:    gcidA,
	})
	if !errors.Is(err, ErrInvalidInput) {
		t.Errorf("expected ErrInvalidInput when singpass + client_secret; got %v", err)
	}
}

func TestService_Upsert_Singpass_RejectsClientIDOrDiscovery(t *testing.T) {
	t.Parallel()
	svc, _, _, _ := newService(t)
	if _, err := svc.Upsert(context.Background(), UpsertInput{
		TenantID: tenantA, ProviderType: ProviderSingpass, ClientID: "x", ActorGCID: gcidA,
	}); !errors.Is(err, ErrInvalidInput) {
		t.Errorf("singpass + client_id should reject; got %v", err)
	}
	if _, err := svc.Upsert(context.Background(), UpsertInput{
		TenantID: tenantA, ProviderType: ProviderSingpass,
		DiscoveryURL: "https://x.example/.well-known/openid-configuration",
		ActorGCID:    gcidA,
	}); !errors.Is(err, ErrInvalidInput) {
		t.Errorf("singpass + discovery_url should reject; got %v", err)
	}
}

// ---------------------------------------------------------------------------
// OIDC validation — required fields
// ---------------------------------------------------------------------------

func TestService_Upsert_OIDC_RejectsMissingClientID(t *testing.T) {
	t.Parallel()
	svc, _, _, _ := newService(t)
	_, err := svc.Upsert(context.Background(), UpsertInput{
		TenantID: tenantA, ProviderType: ProviderOIDC,
		ClientSecret: "s", DiscoveryURL: "https://x.example/.well-known/openid-configuration",
		ActorGCID: gcidA,
	})
	if !errors.Is(err, ErrInvalidInput) {
		t.Errorf("expected ErrInvalidInput; got %v", err)
	}
}

func TestService_Upsert_OIDC_RejectsMissingClientSecret(t *testing.T) {
	t.Parallel()
	svc, _, _, _ := newService(t)
	_, err := svc.Upsert(context.Background(), UpsertInput{
		TenantID: tenantA, ProviderType: ProviderOIDC,
		ClientID: "c", DiscoveryURL: "https://x.example/.well-known/openid-configuration",
		ActorGCID: gcidA,
	})
	if !errors.Is(err, ErrInvalidInput) {
		t.Errorf("expected ErrInvalidInput; got %v", err)
	}
}

func TestService_Upsert_OIDC_RejectsNonHttpDiscoveryURL(t *testing.T) {
	t.Parallel()
	svc, _, _, _ := newService(t)
	_, err := svc.Upsert(context.Background(), UpsertInput{
		TenantID: tenantA, ProviderType: ProviderOIDC,
		ClientID: "c", ClientSecret: "s",
		DiscoveryURL: "ftp://nope.example/openid",
		ActorGCID:    gcidA,
	})
	if !errors.Is(err, ErrInvalidInput) {
		t.Errorf("expected ErrInvalidInput on non-http(s) discovery_url; got %v", err)
	}
}

// ---------------------------------------------------------------------------
// Validation — common
// ---------------------------------------------------------------------------

func TestService_Upsert_RejectsEmptyTenantID(t *testing.T) {
	t.Parallel()
	svc, _, _, _ := newService(t)
	_, err := svc.Upsert(context.Background(), UpsertInput{
		ProviderType: ProviderOIDC,
		ClientID:     "c", ClientSecret: "s",
		DiscoveryURL: "https://x.example/.well-known/openid-configuration",
		ActorGCID:    gcidA,
	})
	if !errors.Is(err, ErrInvalidInput) {
		t.Errorf("expected ErrInvalidInput for empty tenant; got %v", err)
	}
}

func TestService_Upsert_RejectsUnknownProviderType(t *testing.T) {
	t.Parallel()
	svc, _, _, _ := newService(t)
	_, err := svc.Upsert(context.Background(), UpsertInput{
		TenantID:     tenantA,
		ProviderType: ProviderType("bogus"),
		ActorGCID:    gcidA,
	})
	if !errors.Is(err, ErrInvalidInput) {
		t.Errorf("expected ErrInvalidInput on unknown provider_type; got %v", err)
	}
}

// ---------------------------------------------------------------------------
// Secret Manager failure ⇒ no DB row, no event (atomic)
// ---------------------------------------------------------------------------

func TestService_Upsert_SecretManagerFailure_NoDbRowNoEvent(t *testing.T) {
	t.Parallel()
	svc, repo, sm, pub := newService(t)
	sm.storeErr = errors.New("smithereens — secret manager down")

	_, err := svc.Upsert(context.Background(), UpsertInput{
		TenantID: tenantA, ProviderType: ProviderOIDC,
		ClientID: "c", ClientSecret: "s",
		DiscoveryURL: "https://x.example/.well-known/openid-configuration",
		ActorGCID:    gcidA,
	})
	if err == nil {
		t.Fatal("expected error from Secret Manager failure")
	}
	// No DB row leaked.
	if _, err := repo.Get(context.Background(), tenantA, ProviderOIDC); !errors.Is(err, ErrNotFound) {
		t.Errorf("DB row leaked after secret-manager failure; got err=%v", err)
	}
	// No event emitted.
	if len(pub.events) != 0 {
		t.Errorf("event leaked after secret-manager failure; events=%d", len(pub.events))
	}
}

// ---------------------------------------------------------------------------
// Topic + ProviderType enums
// ---------------------------------------------------------------------------

func TestTopicTaxonomy(t *testing.T) {
	t.Parallel()
	if TopicConfigured != "chora.identity.tenant_idp_provider.configured.v1" {
		t.Errorf("TopicConfigured = %q; want canonical taxonomy chora.identity.tenant_idp_provider.configured.v1", TopicConfigured)
	}
}

func TestProviderType_IsKnown(t *testing.T) {
	t.Parallel()
	for _, pt := range []ProviderType{ProviderOIDC, ProviderSAML, ProviderSingpass} {
		if !pt.IsKnown() {
			t.Errorf("%q reports unknown", pt)
		}
	}
	if ProviderType("nope").IsKnown() {
		t.Error("unknown provider type should report unknown")
	}
}
