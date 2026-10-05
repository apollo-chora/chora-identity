// Package apikey is the PlatformAPIKey aggregate (M12.2.E.1 — consolidated
// from chora-iam/internal/domain/api_key_service.go).
//
// Domain ownership: chora-identity (Identity supporting domain).
// Aggregate root : APIKey.
// Soft delete    : RevokedAt timestamp; default queries filter RevokedAt IS NULL.
// AGID guard     : AGID-shape identifiers MAY NOT generate API keys (rule #10).
// Topic taxonomy : chora.identity.api_key.{event_type}.v1 per pub-sub-topology.
//
// Hexagonal: this package depends only on the standard library + google/uuid.
// Adapters (in-memory repo, SHA-256 hasher, Pub/Sub publisher) live under
// internal/adapter/apikey_*.
//
// This file replaces the legacy chora-iam.PlatformAPIKey + APIKeyService +
// chora.iam.events topic. Legacy code is retained in chora-iam/ until the
// M11.9 archive tag drops it.
package apikey

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// ---------------------------------------------------------------------------
// Limits + canonical names
// ---------------------------------------------------------------------------

// MaxActivePerGcid is the upper bound on concurrent active API keys per GCID
// (carried forward from chora-iam.MaxAPIKeysPerGCID = 5).
const MaxActivePerGcid = 5

// EventCreated / EventRevoked are the event_type strings; full canonical topic
// names embed them in the locked architecture taxonomy.
const (
	EventCreated = "api_key.created"
	EventRevoked = "api_key.revoked"
)

// TopicCreated / TopicRevoked are the Pub/Sub topics:
//
//	chora.identity.api_key.created.v1
//	chora.identity.api_key.revoked.v1
//
// Per pub-sub-topology skill: chora.{domain}.{aggregate}.{event_type}.v{N}.
const (
	TopicCreated = "chora.identity.api_key.created.v1"
	TopicRevoked = "chora.identity.api_key.revoked.v1"
)

// ---------------------------------------------------------------------------
// Sentinel errors
// ---------------------------------------------------------------------------

// ErrLimitExceeded — GCID already holds MaxActivePerGcid keys.
var ErrLimitExceeded = errors.New("apikey: max active keys per gcid exceeded")

// ErrAGIDForbidden — agents (AGID-shape) MAY NOT hold platform API keys.
var ErrAGIDForbidden = errors.New("apikey: AGID-shape gcid forbidden (agents cannot hold API keys)")

// ErrInvalidInput — generic input validation failure.
var ErrInvalidInput = errors.New("apikey: invalid input")

// ErrNotFound — repository lookup miss.
var ErrNotFound = errors.New("apikey: not found")

// ---------------------------------------------------------------------------
// Aggregate root
// ---------------------------------------------------------------------------

// APIKey is the platform API key aggregate. KeyHash stores the SHA-256 of the
// plaintext key; the plaintext is returned ONCE on Generate and never stored.
type APIKey struct {
	ID        string     `json:"id"`
	Gcid      string     `json:"gcid"`
	TenantID  string     `json:"tenant_id"`
	KeyHash   string     `json:"-"`
	Name      string     `json:"name"`
	Scopes    []string   `json:"scopes"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
}

// IsActive returns true iff the key is neither revoked nor expired.
func (k *APIKey) IsActive(now time.Time) bool {
	if k.RevokedAt != nil {
		return false
	}
	if k.ExpiresAt != nil && !now.Before(*k.ExpiresAt) {
		return false
	}
	return true
}

// ---------------------------------------------------------------------------
// Ports (interfaces depended on by the domain)
// ---------------------------------------------------------------------------

// Repository is the persistence port. Concrete adapters live under
// internal/adapter/apikey_inmem (in-memory) + internal/adapter/pg (Cloud SQL,
// deferred to Tier 2).
type Repository interface {
	ListByGcid(ctx context.Context, gcid string) ([]APIKey, error)
	Save(ctx context.Context, k *APIKey) error
	Revoke(ctx context.Context, id string) error
}

// Hasher is the cryptographic port — produces the plaintext key + its hash.
// Production adapter (SHA-256 with sk_live_ prefix) lives at
// internal/adapter/apikey_crypto.
type Hasher interface {
	Generate() (string, error)
	Hash(plaintext string) string
}

// PublishedEvent carries an outbox-bound event payload — the publisher adapter
// is responsible for envelope construction + outbox enqueue per the locked
// architecture's mandatory envelope fields (event_id / idempotency_key /
// tenant_id / gcid / occurred_at / published_at / traceparent / tracestate /
// source_project / source_service / schema_version).
type PublishedEvent struct {
	Topic     string
	TenantID  string
	Gcid      string
	EventID   string
	EventType string
	APIKeyID  string
	Name      string
	Scopes    []string
}

// EventPublisher is the outbound event port. Production wires it to the outbox
// pattern; tests inject a fake.
type EventPublisher interface {
	Publish(ctx context.Context, evt PublishedEvent) error
}

// ---------------------------------------------------------------------------
// Service — domain entry point
// ---------------------------------------------------------------------------

// Service orchestrates API key lifecycle.
type Service struct {
	repo   Repository
	hasher Hasher
	pub    EventPublisher
}

// NewService constructs a Service with explicit port dependencies.
func NewService(repo Repository, hasher Hasher, pub EventPublisher) *Service {
	return &Service{repo: repo, hasher: hasher, pub: pub}
}

// GenerateInput is the constructor params for Service.Generate.
type GenerateInput struct {
	Gcid      string
	TenantID  string
	Name      string
	Scopes    []string
	ExpiresAt *time.Time
}

// Generate issues a fresh API key. Returns the persisted APIKey + the plaintext
// (only returned once; the caller MUST surface it to the user and discard).
//
// Invariants enforced:
//   - GCID must not be AGID-shape (rule #10).
//   - Name must be non-empty after trimming.
//   - At most MaxActivePerGcid active keys per GCID.
func (s *Service) Generate(ctx context.Context, in GenerateInput) (*APIKey, string, error) {
	if IsAGID(in.Gcid) {
		return nil, "", ErrAGIDForbidden
	}
	if strings.TrimSpace(in.Name) == "" {
		return nil, "", fmt.Errorf("%w: name required", ErrInvalidInput)
	}
	if strings.TrimSpace(in.Gcid) == "" {
		return nil, "", fmt.Errorf("%w: gcid required", ErrInvalidInput)
	}
	if strings.TrimSpace(in.TenantID) == "" {
		return nil, "", fmt.Errorf("%w: tenant_id required", ErrInvalidInput)
	}

	existing, err := s.repo.ListByGcid(ctx, in.Gcid)
	if err != nil {
		return nil, "", fmt.Errorf("apikey: list existing: %w", err)
	}
	active := 0
	now := time.Now().UTC()
	for i := range existing {
		if existing[i].IsActive(now) {
			active++
		}
	}
	if active >= MaxActivePerGcid {
		return nil, "", ErrLimitExceeded
	}

	plaintext, err := s.hasher.Generate()
	if err != nil {
		return nil, "", fmt.Errorf("apikey: generate plaintext: %w", err)
	}
	keyHash := s.hasher.Hash(plaintext)

	id, err := uuid.NewV7()
	if err != nil {
		return nil, "", fmt.Errorf("apikey: uuidv7: %w", err)
	}

	scopes := append([]string(nil), in.Scopes...)
	k := &APIKey{
		ID:        id.String(),
		Gcid:      in.Gcid,
		TenantID:  in.TenantID,
		KeyHash:   keyHash,
		Name:      strings.TrimSpace(in.Name),
		Scopes:    scopes,
		ExpiresAt: in.ExpiresAt,
		CreatedAt: now,
	}

	if err := s.repo.Save(ctx, k); err != nil {
		return nil, "", fmt.Errorf("apikey: save: %w", err)
	}

	if err := s.pub.Publish(ctx, PublishedEvent{
		Topic:     TopicCreated,
		TenantID:  in.TenantID,
		Gcid:      in.Gcid,
		EventID:   id.String(),
		EventType: EventCreated,
		APIKeyID:  k.ID,
		Name:      k.Name,
		Scopes:    scopes,
	}); err != nil {
		return nil, "", fmt.Errorf("apikey: publish created: %w", err)
	}

	return k, plaintext, nil
}

// List returns all (active + revoked) API keys for the GCID. Callers filter
// on RevokedAt in the read path.
func (s *Service) List(ctx context.Context, gcid string) ([]APIKey, error) {
	if strings.TrimSpace(gcid) == "" {
		return nil, fmt.Errorf("%w: gcid required", ErrInvalidInput)
	}
	keys, err := s.repo.ListByGcid(ctx, gcid)
	if err != nil {
		return nil, fmt.Errorf("apikey: list: %w", err)
	}
	return keys, nil
}

// RevokeInput carries the revocation request — keyed by API key ID.
type RevokeInput struct {
	ID       string
	Gcid     string
	TenantID string
}

// Revoke marks the API key as revoked (soft-delete) + publishes the revoked
// event. Idempotent at the repository layer.
func (s *Service) Revoke(ctx context.Context, in RevokeInput) error {
	if strings.TrimSpace(in.ID) == "" {
		return fmt.Errorf("%w: id required", ErrInvalidInput)
	}
	if err := s.repo.Revoke(ctx, in.ID); err != nil {
		return fmt.Errorf("apikey: revoke: %w", err)
	}
	eventID, err := uuid.NewV7()
	if err != nil {
		return fmt.Errorf("apikey: uuidv7: %w", err)
	}
	if err := s.pub.Publish(ctx, PublishedEvent{
		Topic:     TopicRevoked,
		TenantID:  in.TenantID,
		Gcid:      in.Gcid,
		EventID:   eventID.String(),
		EventType: EventRevoked,
		APIKeyID:  in.ID,
	}); err != nil {
		return fmt.Errorf("apikey: publish revoked: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// AGID detection — mirrors identity.IsAGID for the local invariant guard.
//
// Per CLAUDE.md §1 §3 + ddd-enforcement rule #10: AGIDs (agent identities) MUST
// NOT hold TenantMembership and MUST NOT mint platform API keys. The skeleton
// heuristic is "AGIDs start with '0197A' (case-insensitive)". Production wires
// to the AGID registry; the shape guard catches the obvious cases.
// ---------------------------------------------------------------------------

// IsAGID reports whether the identifier matches the AGID heuristic.
func IsAGID(id string) bool {
	if id == "" {
		return false
	}
	return strings.HasPrefix(strings.ToLower(id), "0197a")
}
