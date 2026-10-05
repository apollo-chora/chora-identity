package tenant_idp_secrets

import (
	"context"
	"strings"
	"testing"
)

func TestInMemory_Store_HappyPath(t *testing.T) {
	t.Parallel()
	sm := NewInMemory(InMemoryConfig{})
	name, err := sm.Store(context.Background(), "tenant-a", "idp-1", "shhh")
	if err != nil {
		t.Fatalf("Store: %v", err)
	}
	wantPrefix := "projects/chora-local/secrets/idp-client-secret-tenant-a-idp-1"
	if name != wantPrefix {
		t.Errorf("name = %q; want %q", name, wantPrefix)
	}
	if v, ok := sm.Peek(name); !ok || v != "shhh" {
		t.Errorf("Peek(%q) = (%q,%v); want (shhh,true)", name, v, ok)
	}
}

func TestInMemory_Store_RespectsCustomProjectID(t *testing.T) {
	t.Parallel()
	sm := NewInMemory(InMemoryConfig{ProjectID: "chora-eval"})
	name, _ := sm.Store(context.Background(), "tenant-a", "idp-1", "x")
	if !strings.HasPrefix(name, "projects/chora-eval/secrets/") {
		t.Errorf("custom project not honoured: %q", name)
	}
}

func TestInMemory_Store_RejectsEmptyInputs(t *testing.T) {
	t.Parallel()
	sm := NewInMemory(InMemoryConfig{})
	if _, err := sm.Store(context.Background(), "", "i", "x"); err == nil {
		t.Error("expected error on empty tenant")
	}
	if _, err := sm.Store(context.Background(), "t", "", "x"); err == nil {
		t.Error("expected error on empty idp")
	}
	if _, err := sm.Store(context.Background(), "t", "i", ""); err == nil {
		t.Error("expected error on empty plaintext")
	}
}

func TestInMemory_Store_NewVersionOverwrites(t *testing.T) {
	t.Parallel()
	sm := NewInMemory(InMemoryConfig{})
	name1, _ := sm.Store(context.Background(), "t", "i", "v1")
	name2, _ := sm.Store(context.Background(), "t", "i", "v2")
	if name1 != name2 {
		t.Errorf("same (tenant,idp) should yield same resource name; got %q vs %q", name1, name2)
	}
	if v, _ := sm.Peek(name2); v != "v2" {
		t.Errorf("re-Store didn't update value; got %q", v)
	}
}
