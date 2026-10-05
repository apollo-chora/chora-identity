// In-memory adapter tests — strict TDD RED first, then implementation lands
// in repository.go.
package apikey_inmem

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/apollo-chora/chora-identity/internal/domain/apikey"
)

func TestRepository_SaveAndList(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	repo := NewRepository()

	now := time.Now().UTC()
	k1 := &apikey.APIKey{
		ID:        "01975555-0000-7000-9000-000000000001",
		Gcid:      "g",
		TenantID:  "t",
		KeyHash:   "h1",
		Name:      "Key 1",
		CreatedAt: now,
	}
	k2 := &apikey.APIKey{
		ID:        "01975555-0000-7000-9000-000000000002",
		Gcid:      "g",
		TenantID:  "t",
		KeyHash:   "h2",
		Name:      "Key 2",
		CreatedAt: now.Add(1 * time.Second),
	}

	if err := repo.Save(ctx, k1); err != nil {
		t.Fatalf("save k1: %v", err)
	}
	if err := repo.Save(ctx, k2); err != nil {
		t.Fatalf("save k2: %v", err)
	}

	got, err := repo.ListByGcid(ctx, "g")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 keys; got %d", len(got))
	}
	// Should be sorted by CreatedAt ASC.
	if got[0].ID != k1.ID || got[1].ID != k2.ID {
		t.Fatalf("unexpected order: %v %v", got[0].ID, got[1].ID)
	}
}

func TestRepository_ListByGcid_Empty(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	repo := NewRepository()
	got, err := repo.ListByGcid(ctx, "missing")
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected empty; got %d", len(got))
	}
}

func TestRepository_Revoke_SetsRevokedAt(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	repo := NewRepository()

	k := &apikey.APIKey{
		ID:        "01975555-0000-7000-9000-000000000001",
		Gcid:      "g",
		TenantID:  "t",
		KeyHash:   "h",
		Name:      "Key",
		CreatedAt: time.Now().UTC(),
	}
	if err := repo.Save(ctx, k); err != nil {
		t.Fatalf("save: %v", err)
	}
	if err := repo.Revoke(ctx, k.ID); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	got, err := repo.ListByGcid(ctx, "g")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1; got %d", len(got))
	}
	if got[0].RevokedAt == nil {
		t.Fatalf("expected RevokedAt set")
	}
	if got[0].IsActive(time.Now().UTC()) {
		t.Fatalf("revoked key should not be active")
	}
}

func TestRepository_Revoke_NotFound(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	repo := NewRepository()
	err := repo.Revoke(ctx, "01975555-0000-7000-9000-000000000099")
	if !errors.Is(err, apikey.ErrNotFound) {
		t.Fatalf("expected ErrNotFound; got %v", err)
	}
}

func TestRepository_Save_ReplaceUpsert(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	repo := NewRepository()
	now := time.Now().UTC()
	k := &apikey.APIKey{
		ID:        "01975555-0000-7000-9000-000000000001",
		Gcid:      "g",
		TenantID:  "t",
		KeyHash:   "h",
		Name:      "Old",
		CreatedAt: now,
	}
	if err := repo.Save(ctx, k); err != nil {
		t.Fatalf("save: %v", err)
	}
	updated := *k
	updated.Name = "New"
	if err := repo.Save(ctx, &updated); err != nil {
		t.Fatalf("save updated: %v", err)
	}
	got, err := repo.ListByGcid(ctx, "g")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 1 || got[0].Name != "New" {
		t.Fatalf("expected upsert; got %+v", got)
	}
}

// TestRepository_ListByGcid_SkipsOtherGcidsAndSortsByCreation locks the
// continue-branch + ordering contract: keys for other gcids are skipped,
// and the returned set is ascending by CreatedAt regardless of save order.
func TestRepository_ListByGcid_SkipsOtherGcidsAndSortsByCreation(t *testing.T) {
	repo := NewRepository()
	earlier := apikey.APIKey{
		ID:        "11975555-0000-7000-9000-000000000001",
		Gcid:      "g",
		Name:      "first",
		Scopes:    []string{"identity:read"},
		CreatedAt: time.Now().Add(-2 * time.Hour),
	}
	later := apikey.APIKey{
		ID:        "11975555-0000-7000-9000-000000000002",
		Gcid:      "g",
		Name:      "second",
		Scopes:    []string{"identity:write"},
		CreatedAt: time.Now().Add(-time.Hour),
	}
	other := apikey.APIKey{
		ID:        "11975555-0000-7000-9000-000000000003",
		Gcid:      "other-gcid",
		Name:      "other",
		CreatedAt: time.Now(),
	}
	// Save out of order: later, other, earlier.
	if err := repo.Save(context.Background(), &later); err != nil {
		t.Fatalf("save later: %v", err)
	}
	if err := repo.Save(context.Background(), &other); err != nil {
		t.Fatalf("save other: %v", err)
	}
	if err := repo.Save(context.Background(), &earlier); err != nil {
		t.Fatalf("save earlier: %v", err)
	}

	got, err := repo.ListByGcid(context.Background(), "g")
	if err != nil {
		t.Fatalf("ListByGcid: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d keys, want 2 (other-gcid key must be skipped)", len(got))
	}
	if got[0].Name != "first" || got[1].Name != "second" {
		t.Errorf("ordering = [%s %s], want [first second] by CreatedAt", got[0].Name, got[1].Name)
	}
	// Scopes are defensively cloned — mutating the returned slice must not
	// reach the stored key's scopes.
	got[0].Scopes[0] = "mutated"
	stored, err := repo.ListByGcid(context.Background(), "g")
	if err != nil {
		t.Fatalf("re-list: %v", err)
	}
	if stored[0].Scopes[0] != "identity:read" {
		t.Errorf("stored scopes mutated through returned slice: %v", stored[0].Scopes)
	}
}
