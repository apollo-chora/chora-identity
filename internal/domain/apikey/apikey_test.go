// Tests written FIRST (RED phase) per .claude/rules/development-execution.md.
// Ported + refactored from chora-iam/internal/domain/api_key_service_test.go
// to the chora-identity hexagonal layout (M12.2.E.1 consolidation).
package apikey

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Test helpers — in-memory fakes for the domain ports (Repository / Hasher /
// EventPublisher). All implemented inline in this _test.go so the production
// adapters can stay clean.
// ---------------------------------------------------------------------------

type fakeRepo struct {
	mu      sync.Mutex
	saved   []*APIKey
	listErr error
	saveErr error
	delErr  error
	preList []APIKey
	revoked []string
}

func (r *fakeRepo) ListByGcid(_ context.Context, _ string) ([]APIKey, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.listErr != nil {
		return nil, r.listErr
	}
	out := make([]APIKey, 0, len(r.preList))
	out = append(out, r.preList...)
	return out, nil
}

func (r *fakeRepo) Save(_ context.Context, k *APIKey) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.saveErr != nil {
		return r.saveErr
	}
	clone := *k
	r.saved = append(r.saved, &clone)
	return nil
}

func (r *fakeRepo) Revoke(_ context.Context, id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.delErr != nil {
		return r.delErr
	}
	r.revoked = append(r.revoked, id)
	return nil
}

type fakeHasher struct {
	plaintext string
	hashed    string
	genErr    error
}

func (h *fakeHasher) Generate() (string, error) {
	if h.genErr != nil {
		return "", h.genErr
	}
	return h.plaintext, nil
}

func (h *fakeHasher) Hash(_ string) string { return h.hashed }

type fakePublisher struct {
	mu    sync.Mutex
	calls []publishedEvent
	err   error
}

type publishedEvent struct {
	Topic    string
	TenantID string
	Gcid     string
	EventID  string
	Type     string
}

func (p *fakePublisher) Publish(_ context.Context, evt PublishedEvent) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.err != nil {
		return p.err
	}
	p.calls = append(p.calls, publishedEvent{
		Topic:    evt.Topic,
		TenantID: evt.TenantID,
		Gcid:     evt.Gcid,
		EventID:  evt.EventID,
		Type:     evt.EventType,
	})
	return nil
}

// ---------------------------------------------------------------------------
// Domain tests — TDD RED phase.
// ---------------------------------------------------------------------------

func TestService_Generate_Success(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	repo := &fakeRepo{}
	hasher := &fakeHasher{
		plaintext: "sk_" + "live_abc123def456abc123def456abc123de",
		hashed:    "hashed-key",
	}
	pub := &fakePublisher{}

	svc := NewService(repo, hasher, pub)
	key, plaintext, err := svc.Generate(ctx, GenerateInput{
		Gcid:     "01975555-0000-7000-8000-000000000001",
		TenantID: "01970000-0000-7000-8000-000000000001",
		Name:     "Test Key",
		Scopes:   []string{"read", "write"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if plaintext != "sk_"+"live_abc123def456abc123def456abc123de" {
		t.Fatalf("plaintext mismatch: %q", plaintext)
	}
	if key.KeyHash != "hashed-key" {
		t.Fatalf("key_hash mismatch: %q", key.KeyHash)
	}
	if key.Name != "Test Key" {
		t.Fatalf("name mismatch: %q", key.Name)
	}
	if key.Gcid != "01975555-0000-7000-8000-000000000001" {
		t.Fatalf("gcid mismatch: %q", key.Gcid)
	}
	if key.TenantID != "01970000-0000-7000-8000-000000000001" {
		t.Fatalf("tenant_id mismatch: %q", key.TenantID)
	}
	if len(key.Scopes) != 2 || key.Scopes[0] != "read" || key.Scopes[1] != "write" {
		t.Fatalf("scopes mismatch: %v", key.Scopes)
	}
	if key.ExpiresAt != nil {
		t.Fatalf("expires_at should be nil; got %v", key.ExpiresAt)
	}
	if key.ID == "" {
		t.Fatalf("id must be assigned")
	}
	if len(repo.saved) != 1 {
		t.Fatalf("expected 1 save call; got %d", len(repo.saved))
	}
	if len(pub.calls) != 1 {
		t.Fatalf("expected 1 publish call; got %d", len(pub.calls))
	}
	if pub.calls[0].Type != EventCreated {
		t.Fatalf("unexpected event_type %q", pub.calls[0].Type)
	}
	if pub.calls[0].Topic != TopicCreated {
		t.Fatalf("unexpected topic %q", pub.calls[0].Topic)
	}
}

func TestService_Generate_LimitExceeded(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	existing := make([]APIKey, MaxActivePerGcid)
	for i := range existing {
		existing[i] = APIKey{ID: "id-" + string(rune('a'+i)), Gcid: "g"}
	}
	repo := &fakeRepo{preList: existing}
	hasher := &fakeHasher{plaintext: "sk_" + "live_unused"}
	pub := &fakePublisher{}

	svc := NewService(repo, hasher, pub)
	_, _, err := svc.Generate(ctx, GenerateInput{
		Gcid:     "g",
		TenantID: "t",
		Name:     "x",
	})
	if !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("expected ErrLimitExceeded; got %v", err)
	}
	if len(repo.saved) != 0 {
		t.Fatalf("save must NOT be called when limit hit")
	}
	if len(pub.calls) != 0 {
		t.Fatalf("publish must NOT be called when limit hit")
	}
}

func TestService_Generate_WithExpiry(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	repo := &fakeRepo{}
	hasher := &fakeHasher{plaintext: "sk_" + "live_0123456789abcdef0123456789abcdef", hashed: "h"}
	pub := &fakePublisher{}

	expiresAt := time.Now().Add(30 * 24 * time.Hour).UTC()
	svc := NewService(repo, hasher, pub)
	key, plaintext, err := svc.Generate(ctx, GenerateInput{
		Gcid:      "01975555-0000-7000-8000-000000000001",
		TenantID:  "01970000-0000-7000-8000-000000000001",
		Name:      "Expiring",
		Scopes:    []string{"read"},
		ExpiresAt: &expiresAt,
	})
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if plaintext == "" {
		t.Fatalf("plaintext must be non-empty")
	}
	if key.ExpiresAt == nil || !key.ExpiresAt.Equal(expiresAt) {
		t.Fatalf("expires_at mismatch: got %v want %v", key.ExpiresAt, expiresAt)
	}
}

func TestService_Generate_GenerateKeyError(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	repo := &fakeRepo{}
	hasher := &fakeHasher{genErr: errors.New("rng failure")}
	pub := &fakePublisher{}

	svc := NewService(repo, hasher, pub)
	_, _, err := svc.Generate(ctx, GenerateInput{Gcid: "g", TenantID: "t", Name: "x"})
	if err == nil {
		t.Fatalf("expected error")
	}
	if len(repo.saved) != 0 {
		t.Fatalf("save must NOT be called on hasher failure")
	}
}

func TestService_Generate_RejectsAGID(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	repo := &fakeRepo{}
	hasher := &fakeHasher{plaintext: "sk_" + "live_unused"}
	pub := &fakePublisher{}

	svc := NewService(repo, hasher, pub)
	_, _, err := svc.Generate(ctx, GenerateInput{
		// AGID-shaped per CLAUDE.md §1 §3 + ddd-enforcement rule #10.
		Gcid:     "0197a000-0000-7000-8000-000000000001",
		TenantID: "01970000-0000-7000-8000-000000000001",
		Name:     "agent-key",
	})
	if !errors.Is(err, ErrAGIDForbidden) {
		t.Fatalf("expected ErrAGIDForbidden; got %v", err)
	}
}

func TestService_Generate_RejectsEmptyName(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	repo := &fakeRepo{}
	hasher := &fakeHasher{plaintext: "sk_" + "live_unused"}
	pub := &fakePublisher{}

	svc := NewService(repo, hasher, pub)
	_, _, err := svc.Generate(ctx, GenerateInput{
		Gcid:     "01975555-0000-7000-8000-000000000001",
		TenantID: "01970000-0000-7000-8000-000000000001",
		Name:     "   ",
	})
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected ErrInvalidInput; got %v", err)
	}
}

func TestService_List(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	repo := &fakeRepo{
		preList: []APIKey{
			{ID: "k1", Gcid: "g", Name: "Key 1"},
			{ID: "k2", Gcid: "g", Name: "Key 2"},
		},
	}
	hasher := &fakeHasher{}
	pub := &fakePublisher{}

	svc := NewService(repo, hasher, pub)
	keys, err := svc.List(ctx, "g")
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("expected 2 keys; got %d", len(keys))
	}
	if keys[0].Name != "Key 1" || keys[1].Name != "Key 2" {
		t.Fatalf("unexpected order: %+v", keys)
	}
}

func TestService_List_Empty(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	repo := &fakeRepo{}
	hasher := &fakeHasher{}
	pub := &fakePublisher{}

	svc := NewService(repo, hasher, pub)
	keys, err := svc.List(ctx, "g")
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if len(keys) != 0 {
		t.Fatalf("expected empty; got %d", len(keys))
	}
}

func TestService_Revoke_Success(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	repo := &fakeRepo{}
	hasher := &fakeHasher{}
	pub := &fakePublisher{}

	svc := NewService(repo, hasher, pub)
	if err := svc.Revoke(ctx, RevokeInput{
		ID:       "01975555-0000-7000-8000-000000000099",
		Gcid:     "01975555-0000-7000-8000-000000000001",
		TenantID: "01970000-0000-7000-8000-000000000001",
	}); err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if len(repo.revoked) != 1 {
		t.Fatalf("expected 1 revoke call")
	}
	if len(pub.calls) != 1 || pub.calls[0].Type != EventRevoked {
		t.Fatalf("expected EventRevoked publish; got %+v", pub.calls)
	}
	if pub.calls[0].Topic != TopicRevoked {
		t.Fatalf("expected topic %q; got %q", TopicRevoked, pub.calls[0].Topic)
	}
}

func TestService_Revoke_RepoError(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	repo := &fakeRepo{delErr: errors.New("db error")}
	hasher := &fakeHasher{}
	pub := &fakePublisher{}

	svc := NewService(repo, hasher, pub)
	err := svc.Revoke(ctx, RevokeInput{
		ID:       "01975555-0000-7000-8000-000000000099",
		Gcid:     "01975555-0000-7000-8000-000000000001",
		TenantID: "01970000-0000-7000-8000-000000000001",
	})
	if err == nil {
		t.Fatalf("expected error")
	}
	if len(pub.calls) != 0 {
		t.Fatalf("publish must NOT be called when revoke fails")
	}
}

// ---------------------------------------------------------------------------
// Topic taxonomy compliance — locked architecture (pub-sub-topology):
// chora.{domain}.{aggregate}.{event_type}.v{N}
// ---------------------------------------------------------------------------

func TestTopicTaxonomy(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		topic string
	}{
		{"created", TopicCreated},
		{"revoked", TopicRevoked},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, want := topicDomain(tt.topic), "identity"; got != want {
				t.Fatalf("topic %q domain = %q; want %q", tt.topic, got, want)
			}
			if got, want := topicAggregate(tt.topic), "api_key"; got != want {
				t.Fatalf("topic %q aggregate = %q; want %q", tt.topic, got, want)
			}
		})
	}
}

// helpers extracting domain/aggregate from "chora.{domain}.{aggregate}.{event}.v{N}"
func topicDomain(t string) string {
	parts := splitTopic(t)
	if len(parts) < 2 {
		return ""
	}
	return parts[1]
}

func topicAggregate(t string) string {
	parts := splitTopic(t)
	if len(parts) < 3 {
		return ""
	}
	return parts[2]
}

func splitTopic(t string) []string {
	parts := make([]string, 0, 5)
	start := 0
	for i := 0; i < len(t); i++ {
		if t[i] == '.' {
			parts = append(parts, t[start:i])
			start = i + 1
		}
	}
	parts = append(parts, t[start:])
	return parts
}

// ---------------------------------------------------------------------------
// AGID detection — must reject the agent-identity prefix.
// ---------------------------------------------------------------------------

func TestIsAGID(t *testing.T) {
	t.Parallel()
	cases := []struct {
		id      string
		isAgent bool
	}{
		{"0197a000-0000-7000-8000-000000000001", true},
		{"0197A000-0000-7000-8000-000000000001", true},
		{"01975555-0000-7000-8000-000000000001", false},
		{"", false},
	}
	for _, c := range cases {
		if got := IsAGID(c.id); got != c.isAgent {
			t.Fatalf("IsAGID(%q) = %v; want %v", c.id, got, c.isAgent)
		}
	}
}
