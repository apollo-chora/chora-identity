// Coverage top-up — exercises edge cases of NewService, SetClock, and
// validateHTTPSURL so the package clears the 85% domain coverage gate
// per .claude/rules/development-execution.md.
package tenant_idp_provider

import (
	"context"
	"testing"
	"time"
)

func TestNewService_NilRepo_Panics(t *testing.T) {
	t.Parallel()
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic on nil repo")
		}
	}()
	_ = NewService(nil, newFakeSecretManager(), &fakePublisher{})
}

func TestNewService_NilSecretManager_Panics(t *testing.T) {
	t.Parallel()
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic on nil secret manager")
		}
	}()
	_ = NewService(newFakeRepo(), nil, &fakePublisher{})
}

func TestNewService_NilPublisher_Panics(t *testing.T) {
	t.Parallel()
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic on nil publisher")
		}
	}()
	_ = NewService(newFakeRepo(), newFakeSecretManager(), nil)
}

func TestService_SetClock_OverridesTimestamps(t *testing.T) {
	t.Parallel()
	svc, _, _, _ := newService(t)
	fixed := time.Date(2026, 6, 7, 12, 0, 0, 0, time.UTC)
	svc.SetClock(func() time.Time { return fixed })

	got, err := svc.Upsert(context.Background(), UpsertInput{
		TenantID: tenantA, ProviderType: ProviderOIDC,
		ClientID: "c", ClientSecret: "s",
		DiscoveryURL: "https://x.example/.well-known/openid-configuration",
		ActorGCID:    gcidA,
	})
	if err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	if !got.CreatedAt.Equal(fixed) {
		t.Errorf("CreatedAt = %v; want %v", got.CreatedAt, fixed)
	}
	if !got.UpdatedAt.Equal(fixed) {
		t.Errorf("UpdatedAt = %v; want %v", got.UpdatedAt, fixed)
	}
}

// validateHTTPSURL was previously only exercised on a non-http(s) scheme.
// These hit the empty-string + malformed + missing-host branches.
func TestValidateHTTPSURL_EdgeCases(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"empty":          "",
		"missing-host":   "https://",
		"malformed":      "://nohost",
		"missing-scheme": "example.com/openid-configuration",
		"unsupported-ws": "ws://example.com/openid",
	}
	for name, in := range cases {
		if err := validateHTTPSURL(in); err == nil {
			t.Errorf("[%s] validateHTTPSURL(%q) returned nil; want non-nil", name, in)
		}
	}

	// Happy paths for completeness.
	for _, in := range []string{
		"http://example.com/openid-configuration",
		"https://issuer.example.com/.well-known/openid-configuration",
	} {
		if err := validateHTTPSURL(in); err != nil {
			t.Errorf("validateHTTPSURL(%q) returned %v; want nil", in, err)
		}
	}
}
