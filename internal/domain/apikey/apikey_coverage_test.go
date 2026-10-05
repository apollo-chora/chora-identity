// Additional coverage to push domain coverage above the 85% gate per
// `feedback_strict_tdd` + .claude/rules/development-execution.md. These tests
// exercise edge-cases (IsActive, save errors, list errors, missing inputs,
// publish failures) that the happy-path TDD suite didn't cover.
package apikey

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestAPIKey_IsActive(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	pastExp := now.Add(-1 * time.Hour)
	futureExp := now.Add(1 * time.Hour)
	revoked := now.Add(-1 * time.Hour)

	tests := []struct {
		name string
		k    APIKey
		want bool
	}{
		{"active_no_expiry", APIKey{}, true},
		{"active_future_expiry", APIKey{ExpiresAt: &futureExp}, true},
		{"expired", APIKey{ExpiresAt: &pastExp}, false},
		{"revoked", APIKey{RevokedAt: &revoked}, false},
		{"revoked_and_expired", APIKey{RevokedAt: &revoked, ExpiresAt: &pastExp}, false},
		{"exactly_expires_now", APIKey{ExpiresAt: &now}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.k.IsActive(now); got != tt.want {
				t.Fatalf("IsActive() = %v; want %v", got, tt.want)
			}
		})
	}
}

func TestService_Generate_ListError(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	repo := &fakeRepo{listErr: errors.New("db down")}
	svc := NewService(repo, &fakeHasher{}, &fakePublisher{})
	_, _, err := svc.Generate(ctx, GenerateInput{
		Gcid:     "01975555-0000-7000-8000-000000000001",
		TenantID: "01970000-0000-7000-8000-000000000001",
		Name:     "x",
	})
	if err == nil {
		t.Fatalf("expected list error")
	}
}

func TestService_Generate_SaveError(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	repo := &fakeRepo{saveErr: errors.New("disk full")}
	svc := NewService(repo, &fakeHasher{plaintext: "sk_" + "live_x"}, &fakePublisher{})
	_, _, err := svc.Generate(ctx, GenerateInput{
		Gcid:     "01975555-0000-7000-8000-000000000001",
		TenantID: "01970000-0000-7000-8000-000000000001",
		Name:     "x",
	})
	if err == nil {
		t.Fatalf("expected save error")
	}
}

func TestService_Generate_PublishError(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	repo := &fakeRepo{}
	hasher := &fakeHasher{plaintext: "sk_" + "live_x", hashed: "h"}
	pub := &fakePublisher{err: errors.New("topic missing")}

	svc := NewService(repo, hasher, pub)
	_, _, err := svc.Generate(ctx, GenerateInput{
		Gcid:     "01975555-0000-7000-8000-000000000001",
		TenantID: "01970000-0000-7000-8000-000000000001",
		Name:     "x",
	})
	if err == nil {
		t.Fatalf("expected publish error to propagate")
	}
}

func TestService_Generate_MissingTenant(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	svc := NewService(&fakeRepo{}, &fakeHasher{}, &fakePublisher{})
	_, _, err := svc.Generate(ctx, GenerateInput{
		Gcid: "01975555-0000-7000-8000-000000000001",
		Name: "x",
	})
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected ErrInvalidInput; got %v", err)
	}
}

func TestService_Generate_MissingGcid(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	svc := NewService(&fakeRepo{}, &fakeHasher{}, &fakePublisher{})
	_, _, err := svc.Generate(ctx, GenerateInput{
		TenantID: "01970000-0000-7000-8000-000000000001",
		Name:     "x",
	})
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected ErrInvalidInput; got %v", err)
	}
}

func TestService_List_MissingGcid(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	svc := NewService(&fakeRepo{}, &fakeHasher{}, &fakePublisher{})
	_, err := svc.List(ctx, "")
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected ErrInvalidInput; got %v", err)
	}
}

func TestService_List_RepoError(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	repo := &fakeRepo{listErr: errors.New("db")}
	svc := NewService(repo, &fakeHasher{}, &fakePublisher{})
	_, err := svc.List(ctx, "g")
	if err == nil {
		t.Fatalf("expected error")
	}
}

func TestService_Revoke_MissingID(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	svc := NewService(&fakeRepo{}, &fakeHasher{}, &fakePublisher{})
	err := svc.Revoke(ctx, RevokeInput{
		ID:       "",
		Gcid:     "01975555-0000-7000-8000-000000000001",
		TenantID: "01970000-0000-7000-8000-000000000001",
	})
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected ErrInvalidInput; got %v", err)
	}
}

func TestService_Revoke_PublishError(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	repo := &fakeRepo{}
	pub := &fakePublisher{err: errors.New("topic missing")}
	svc := NewService(repo, &fakeHasher{}, pub)
	err := svc.Revoke(ctx, RevokeInput{
		ID:       "01975555-0000-7000-9000-000000000099",
		Gcid:     "01975555-0000-7000-8000-000000000001",
		TenantID: "01970000-0000-7000-8000-000000000001",
	})
	if err == nil {
		t.Fatalf("expected publish error")
	}
}

// Counts active vs total in pre-list when some are revoked / expired — limit
// only counts active keys.
func TestService_Generate_DoesNotCountInactiveAgainstLimit(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	now := time.Now().UTC()
	past := now.Add(-1 * time.Hour)
	// 5 revoked + 1 active fixture: limit treats only active count.
	keys := make([]APIKey, MaxActivePerGcid+1)
	for i := 0; i < MaxActivePerGcid; i++ {
		t := past
		keys[i] = APIKey{ID: "rev" + string(rune('a'+i)), Gcid: "g", RevokedAt: &t}
	}
	keys[MaxActivePerGcid] = APIKey{ID: "alive", Gcid: "g"}

	repo := &fakeRepo{preList: keys}
	hasher := &fakeHasher{plaintext: "sk_" + "live_new", hashed: "h"}
	pub := &fakePublisher{}
	svc := NewService(repo, hasher, pub)

	// Should still allow because only 1 active.
	_, _, err := svc.Generate(ctx, GenerateInput{
		Gcid:     "01975555-0000-7000-8000-000000000001",
		TenantID: "01970000-0000-7000-8000-000000000001",
		Name:     "another",
	})
	if err != nil {
		t.Fatalf("expected success with %d revoked + 1 active; got %v", MaxActivePerGcid, err)
	}
}
