// Package tenant_idp_provider is the TenantIdpProvider aggregate — the
// per-tenant identity-provider configuration captured by the H+ Setup
// Wizard step 3 (CHO-1682, parent CHO-1405).
//
// Domain ownership : chora-identity (IdP federation is an identity-domain
//
//	primitive — NOT a tenancy concern).
//
// Aggregate root   : TenantIdpProvider.
// Idempotency key  : (tenant_id, provider_type) — at most one row per pair.
// Soft delete      : DeletedAt timestamp; default queries filter
//
//	DeletedAt IS NULL. Switching `provider_type` for a
//	tenant soft-deletes the prior row (NOT in scope for
//	Phase C; the wizard exposes only Upsert).
//
// Secret discipline: `client_secret` is NEVER stored on the aggregate or in
//
//	the DB. The SecretManager port mints a CMEK-encrypted
//	Secret Manager resource and returns its name; the
//	domain stores ONLY the name. Aggregate exposes a
//	`ClientSecret()` accessor that always returns "" so
//	a caller cannot accidentally surface plaintext.
//
// Topic taxonomy   : chora.identity.tenant_idp_provider.configured.v1.
//
// Hexagonal: this package depends only on standard library + google/uuid.
// Concrete adapters (pg repo, Secret Manager wrapper, outbox publisher)
// live under internal/adapter/.
package tenant_idp_provider

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// ---------------------------------------------------------------------------
// Sentinel errors
// ---------------------------------------------------------------------------

// ErrInvalidInput — input failed validation (empty fields, wrong provider /
// field combination, malformed discovery URL, etc).
var ErrInvalidInput = errors.New("tenant_idp_provider: invalid input")

// ErrNotFound — repository lookup miss.
var ErrNotFound = errors.New("tenant_idp_provider: not found")

// ---------------------------------------------------------------------------
// Provider types
// ---------------------------------------------------------------------------

// ProviderType is the kind of IdP a tenant has configured. Mirrors the
// `tenant_idp_provider_type` Postgres ENUM that ships in migration 0018.
type ProviderType string

const (
	ProviderOIDC     ProviderType = "oidc"
	ProviderSAML     ProviderType = "saml"
	ProviderSingpass ProviderType = "singpass"
)

// IsKnown reports whether the value is one of the canonical types.
func (p ProviderType) IsKnown() bool {
	switch p {
	case ProviderOIDC, ProviderSAML, ProviderSingpass:
		return true
	}
	return false
}

// ---------------------------------------------------------------------------
// Event taxonomy
// ---------------------------------------------------------------------------

// EventConfigured is the canonical event_type string for "the tenant set
// up (or replaced) their identity provider". Full topic embeds this in
// the chora.{domain}.{aggregate}.{event_type}.v{N} convention.
const EventConfigured = "tenant_idp_provider.configured"

// TopicConfigured is the canonical Pub/Sub topic — see pub-sub-topology.
const TopicConfigured = "chora.identity.tenant_idp_provider.configured.v1"

// ---------------------------------------------------------------------------
// Aggregate
// ---------------------------------------------------------------------------

// TenantIdpProvider is the aggregate root. The plaintext `client_secret`
// supplied at Upsert never lands on the aggregate — only the Secret Manager
// resource name does.
type TenantIdpProvider struct {
	ID               string       `json:"id"`
	TenantID         string       `json:"tenant_id"`
	ProviderType     ProviderType `json:"provider_type"`
	ClientID         string       `json:"client_id"`
	ClientSecretName string       `json:"client_secret_name"`
	DiscoveryURL     string       `json:"discovery_url"`
	SingpassEnabled  bool         `json:"singpass_enabled"`
	CreatedAt        time.Time    `json:"created_at"`
	UpdatedAt        time.Time    `json:"updated_at"`
	DeletedAt        *time.Time   `json:"deleted_at,omitempty"`

	// plaintext is never serialised, never persisted, never accessor-exposed.
	// Present only as a defensive zero on a fresh aggregate.
}

// ClientSecret intentionally returns "" — the aggregate has no plaintext.
// Kept as a method (rather than an absent field) so callers that need to
// "render the persisted state" have a uniform shape, but the value is
// always the empty string. The real secret lives in Secret Manager.
func (p *TenantIdpProvider) ClientSecret() string { return "" }

// ---------------------------------------------------------------------------
// Ports
// ---------------------------------------------------------------------------

// Repository is the persistence port.
type Repository interface {
	Upsert(ctx context.Context, p *TenantIdpProvider) error
	Get(ctx context.Context, tenantID string, pt ProviderType) (*TenantIdpProvider, error)
	ListByTenant(ctx context.Context, tenantID string) ([]TenantIdpProvider, error)
	SoftDelete(ctx context.Context, tenantID string, pt ProviderType, now time.Time) error
}

// SecretManager is the secret-store port. Production adapter wraps the
// Google Cloud Secret Manager client; tests inject a fake. Store is called
// per Upsert — implementations MAY mint a new resource on first call and
// add a new version on subsequent calls; the returned name is what the
// DB stores.
type SecretManager interface {
	Store(ctx context.Context, tenantID, idpID, plaintext string) (string, error)
}

// PublishedEvent carries the outbox-bound payload for
// `chora.identity.tenant_idp_provider.configured.v1`. The Traceparent /
// Tracestate fields carry W3C trace context from the inbound HTTP
// request — adapters MUST honor them so the outbox envelope satisfies
// the `events.NewEnvelope`'s traceparent invariant (see
// `services/chora-identity/internal/adapter/events/events.go`).
type PublishedEvent struct {
	Topic        string
	TenantID     string
	ActorGCID    string
	Traceparent  string
	Tracestate   string
	EventID      string
	EventType    string
	IdpID        string
	ProviderType ProviderType
}

// EventPublisher is the outbound event port. Production wires it to the
// outbox pattern.
type EventPublisher interface {
	Publish(ctx context.Context, evt PublishedEvent) error
}

// ---------------------------------------------------------------------------
// Service
// ---------------------------------------------------------------------------

// Service is the domain entry point — validates inputs, mints the Secret
// Manager resource (when applicable), upserts the row, publishes the event.
type Service struct {
	repo Repository
	sm   SecretManager
	pub  EventPublisher

	mu sync.Mutex
	// clock is a test seam; production uses time.Now().UTC().
	clock func() time.Time
}

// NewService constructs a Service with explicit port dependencies. Panics
// on any nil port so wiring bugs fail loud at boot, not request time.
func NewService(repo Repository, sm SecretManager, pub EventPublisher) *Service {
	if repo == nil || sm == nil || pub == nil {
		panic("tenant_idp_provider.NewService: nil port")
	}
	return &Service{
		repo:  repo,
		sm:    sm,
		pub:   pub,
		clock: func() time.Time { return time.Now().UTC() },
	}
}

// SetClock is a test seam.
func (s *Service) SetClock(c func() time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clock = c
}

// ListByTenant returns all ACTIVE rows for the tenant. Thin forward to
// the Repository — exposed on the Service so the HTTP handler only
// depends on one port. The read-side hydrates the Setup Wizard on
// re-entry (CHO-1692); `client_secret` is never on the aggregate so
// the response inherits the no-plaintext-on-the-wire invariant.
func (s *Service) ListByTenant(ctx context.Context, tenantID string) ([]TenantIdpProvider, error) {
	if strings.TrimSpace(tenantID) == "" {
		return nil, fmt.Errorf("%w: tenant_id required", ErrInvalidInput)
	}
	return s.repo.ListByTenant(ctx, tenantID)
}

// SoftDelete marks the (tenant, provider_type) row deleted (CHO-1694).
// Backs the H+ IdP Federation page's Disconnect CTA. Returns
// ErrNotFound when no active row exists — the handler maps that to
// HTTP 404 so the FE can show a "already disconnected" message
// instead of a generic 500.
//
// The Secret Manager entry is INTENTIONALLY NOT destroyed here.
// Plaintext rotation is a separate operation; the soft-delete is
// reversible by a future Upsert that reuses the same `client_secret_name`.
// A future hard-purge job (out of scope for v1) will sweep both.
func (s *Service) SoftDelete(ctx context.Context, tenantID string, pt ProviderType) error {
	if strings.TrimSpace(tenantID) == "" {
		return fmt.Errorf("%w: tenant_id required", ErrInvalidInput)
	}
	if !pt.IsKnown() {
		return fmt.Errorf("%w: unknown provider_type %q", ErrInvalidInput, pt)
	}
	return s.repo.SoftDelete(ctx, tenantID, pt, s.clock())
}

// UpsertInput is the constructor params for Service.Upsert.
type UpsertInput struct {
	TenantID        string
	ProviderType    ProviderType
	ClientID        string
	ClientSecret    string // plaintext — handled by SecretManager, NOT stored
	DiscoveryURL    string
	SingpassEnabled bool
	ActorGCID       string // who did the action (for event audit)
	// W3C trace context extracted from the inbound request — flows through
	// to the outbox envelope so the event is stitched to the calling span.
	Traceparent string
	Tracestate  string
}

// Upsert validates input + mints the Secret Manager secret (when applicable)
// + persists / replaces the row + publishes the event. Returns the persisted
// aggregate (without plaintext).
//
// Idempotent on (tenant_id, provider_type) — re-Upsert with the same pair
// reuses the existing row's ID (the Repository.Upsert adapter is in charge
// of the actual DB-level upsert).
func (s *Service) Upsert(ctx context.Context, in UpsertInput) (*TenantIdpProvider, error) {
	now := s.clock()

	// Look up any existing row first — needed BEFORE validate() so we can
	// distinguish "new IdP (must supply client_secret)" from "re-apply on
	// existing IdP (empty client_secret means 'keep previously stored
	// value')". CHO-1692 hydration deliberately omits client_secret from
	// the FE-side state (Secret Manager invariant — secrets are never
	// re-exposed), so an unchanged step 3 Apply round-trips with an empty
	// client_secret. Rejecting that would force the user to re-enter the
	// secret on every wizard re-entry, which defeats the hydration UX.
	var existing *TenantIdpProvider
	if row, err := s.repo.Get(ctx, in.TenantID, in.ProviderType); err == nil {
		existing = row
	} else if !errors.Is(err, ErrNotFound) {
		return nil, fmt.Errorf("tenant_idp_provider: lookup existing: %w", err)
	}

	if err := s.validate(in, existing); err != nil {
		return nil, err
	}

	id := ""
	if existing != nil {
		id = existing.ID
	} else {
		u, err := uuid.NewV7()
		if err != nil {
			return nil, fmt.Errorf("tenant_idp_provider: uuidv7: %w", err)
		}
		id = u.String()
	}

	// Mint the Secret Manager resource for OIDC (Singpass never has a secret).
	// When re-applying on an existing row WITHOUT a new client_secret value,
	// reuse the existing client_secret_name verbatim — no Secret Manager
	// round-trip (and no new version added to the secret).
	secretName := ""
	if in.ProviderType == ProviderOIDC {
		if existing != nil && strings.TrimSpace(in.ClientSecret) == "" {
			secretName = existing.ClientSecretName
		} else {
			name, err := s.sm.Store(ctx, in.TenantID, id, in.ClientSecret)
			if err != nil {
				// Atomicity: no DB row, no event when Secret Manager fails.
				return nil, fmt.Errorf("tenant_idp_provider: secret manager: %w", err)
			}
			secretName = name
		}
	}

	p := &TenantIdpProvider{
		ID:               id,
		TenantID:         in.TenantID,
		ProviderType:     in.ProviderType,
		ClientID:         in.ClientID,
		ClientSecretName: secretName,
		DiscoveryURL:     in.DiscoveryURL,
		SingpassEnabled:  in.SingpassEnabled,
		CreatedAt:        now,
		UpdatedAt:        now,
	}
	if err := s.repo.Upsert(ctx, p); err != nil {
		return nil, fmt.Errorf("tenant_idp_provider: upsert: %w", err)
	}

	// Mint a fresh UUIDv7 for the event so re-upserts (which legitimately
	// emit a new event each time) don't collide with the outbox's
	// idempotency_key uniqueness. IdpID stays stable so consumers can
	// correlate multiple events to the same aggregate.
	eventUUID, err := uuid.NewV7()
	if err != nil {
		return nil, fmt.Errorf("tenant_idp_provider: event uuidv7: %w", err)
	}
	if err := s.pub.Publish(ctx, PublishedEvent{
		Topic:        TopicConfigured,
		TenantID:     in.TenantID,
		ActorGCID:    in.ActorGCID,
		Traceparent:  in.Traceparent,
		Tracestate:   in.Tracestate,
		EventID:      eventUUID.String(),
		EventType:    EventConfigured,
		IdpID:        id,
		ProviderType: in.ProviderType,
	}); err != nil {
		return nil, fmt.Errorf("tenant_idp_provider: publish: %w", err)
	}

	return p, nil
}

// validate enforces the per-provider-type input matrix. `existing` is
// the row currently persisted for (tenant, provider_type), or nil when
// this Upsert will create a new aggregate. The client_secret-required
// check is RELAXED when existing != nil: re-applies of an unchanged
// step 3 from CHO-1692 hydration round-trip with an empty client_secret
// and we want to keep the previously stored Secret Manager version
// rather than force the user to re-paste it.
func (s *Service) validate(in UpsertInput, existing *TenantIdpProvider) error {
	if strings.TrimSpace(in.TenantID) == "" {
		return fmt.Errorf("%w: tenant_id required", ErrInvalidInput)
	}
	if !in.ProviderType.IsKnown() {
		return fmt.Errorf("%w: unknown provider_type %q", ErrInvalidInput, in.ProviderType)
	}
	switch in.ProviderType {
	case ProviderOIDC:
		if strings.TrimSpace(in.ClientID) == "" {
			return fmt.Errorf("%w: oidc requires client_id", ErrInvalidInput)
		}
		if strings.TrimSpace(in.ClientSecret) == "" && existing == nil {
			return fmt.Errorf("%w: oidc requires client_secret", ErrInvalidInput)
		}
		if err := validateHTTPSURL(in.DiscoveryURL); err != nil {
			return fmt.Errorf("%w: oidc discovery_url: %v", ErrInvalidInput, err)
		}
	case ProviderSAML:
		// SAML metadata URL still must be http(s).
		if err := validateHTTPSURL(in.DiscoveryURL); err != nil {
			return fmt.Errorf("%w: saml discovery_url: %v", ErrInvalidInput, err)
		}
	case ProviderSingpass:
		// Singpass uses NDI public-key auth — these fields MUST be absent.
		if strings.TrimSpace(in.ClientID) != "" {
			return fmt.Errorf("%w: singpass forbids client_id (use NDI public-key auth)", ErrInvalidInput)
		}
		if strings.TrimSpace(in.ClientSecret) != "" {
			return fmt.Errorf("%w: singpass forbids client_secret (use NDI public-key auth)", ErrInvalidInput)
		}
		if strings.TrimSpace(in.DiscoveryURL) != "" {
			return fmt.Errorf("%w: singpass forbids discovery_url (platform-owned NDI metadata)", ErrInvalidInput)
		}
	}
	return nil
}

func validateHTTPSURL(s string) error {
	if strings.TrimSpace(s) == "" {
		return errors.New("required")
	}
	u, err := url.Parse(s)
	if err != nil {
		return err
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("scheme %q not http(s)", u.Scheme)
	}
	if u.Host == "" {
		return errors.New("host empty")
	}
	return nil
}
