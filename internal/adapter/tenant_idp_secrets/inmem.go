// Package tenant_idp_secrets is the environment-backed secret store for the
// Setup Wizard Phase C tenant identity-provider domain.
//
// The login provider is local username/password, so this store no longer
// depends on any managed secret service. Secret values are sourced from the
// process environment through github.com/apollo-chora/chora-common/secrets,
// and the canonical reference name travels with the tenant_idp_providers row.
//
// Reference name shape:
//
//	projects/{project}/secrets/idp-client-secret-{tenant_id}-{idp_id}
//
// where `{project}` defaults to the value of CHORA_SECRET_PROJECT (falling back
// to `chora-local`) and is overridable via the constructor's `ProjectID` field
// for tests. The `projects/...` shape is a logical, stable reference — not a
// live cloud resource path.
//
// A value supplied at runtime via Store is held in-process for the process
// lifetime (diagnostics / local dev); the canonical environment variable is the
// durable source of truth.
package tenant_idp_secrets

import (
	"context"
	"errors"
	"strings"
	"sync"

	"github.com/apollo-chora/chora-common/env"
)

// DefaultProjectID is the project label used to build reference names when
// none is supplied. CHORA_SECRET_PROJECT names the namespace the secret lives
// in; the fallback keeps single-project deployments working unconfigured.
var DefaultProjectID = env.GetOrDefault("CHORA_SECRET_PROJECT", "chora-local")

// InMemoryConfig configures the adapter.
type InMemoryConfig struct {
	// ProjectID — project label used in the reference-name format.
	// Defaults to DefaultProjectID when empty.
	ProjectID string
}

// InMemory is a deterministic SecretManager that stores values in a map keyed
// by the reference name. Implements `tenant_idp_provider.SecretManager`.
type InMemory struct {
	projectID string

	mu     sync.Mutex
	stored map[string]string // reference_name → plaintext (for assertion)
}

// NewInMemory constructs the adapter.
func NewInMemory(cfg InMemoryConfig) *InMemory {
	pid := cfg.ProjectID
	if pid == "" {
		pid = DefaultProjectID
	}
	return &InMemory{projectID: pid, stored: map[string]string{}}
}

// Store mints (or adds a new version of) a secret reference and returns the
// canonical name. Empty plaintext is rejected — the domain Service already
// validates upstream, so this is defence-in-depth.
func (s *InMemory) Store(_ context.Context, tenantID, idpID, plaintext string) (string, error) {
	if strings.TrimSpace(tenantID) == "" {
		return "", errors.New("tenant_idp_secrets: tenant_id required")
	}
	if strings.TrimSpace(idpID) == "" {
		return "", errors.New("tenant_idp_secrets: idp_id required")
	}
	if strings.TrimSpace(plaintext) == "" {
		return "", errors.New("tenant_idp_secrets: empty secret rejected")
	}
	name := s.nameFor(tenantID, idpID)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stored[name] = plaintext
	return name, nil
}

// nameFor returns the canonical reference name for a (tenant, idp) pair.
func (s *InMemory) nameFor(tenantID, idpID string) string {
	return "projects/" + s.projectID + "/secrets/idp-client-secret-" + tenantID + "-" + idpID
}

// Peek returns the plaintext stored at a reference name. For tests + local
// diagnostics ONLY.
func (s *InMemory) Peek(name string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.stored[name]
	return v, ok
}
