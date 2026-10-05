package main

import (
	"testing"
)

func TestAdminGcid_Deterministic(t *testing.T) {
	a := adminGcid("admin")
	b := adminGcid("admin")
	if a != b {
		t.Fatalf("adminGcid is not deterministic: %q vs %q", a, b)
	}
	if adminGcid("other") == a {
		t.Fatal("different usernames produced the same gcid")
	}
}

func TestMembershipID_Deterministic(t *testing.T) {
	a := membershipID("g-1", "t-1", "admin")
	b := membershipID("g-1", "t-1", "admin")
	if a != b {
		t.Fatalf("membershipID is not deterministic: %q vs %q", a, b)
	}
	if membershipID("g-1", "t-1", "learner") == a {
		t.Fatal("different roles produced the same membership id")
	}
}

func TestLoadConfig_MissingEnv(t *testing.T) {
	t.Setenv("CHORA_DB_DSN", "")
	t.Setenv("CHORA_SEED_TENANT_ID", "")
	t.Setenv("CHORA_SEED_TENANT_SLUG", "")
	t.Setenv("CHORA_SEED_ADMIN_USERNAME", "")
	t.Setenv("CHORA_SEED_ADMIN_EMAIL", "")
	t.Setenv("CHORA_SEED_ADMIN_PASSWORD", "")
	if _, err := loadConfig(); err == nil {
		t.Fatal("loadConfig with no env must error")
	}
}

func TestLoadConfig_Valid(t *testing.T) {
	t.Setenv("CHORA_DB_DSN", "postgres://x")
	t.Setenv("CHORA_SEED_TENANT_ID", "22222222-2222-7222-8222-222222222222")
	t.Setenv("CHORA_SEED_TENANT_SLUG", "chora-local")
	t.Setenv("CHORA_SEED_ADMIN_USERNAME", "Admin")
	t.Setenv("CHORA_SEED_ADMIN_EMAIL", "admin@example.com")
	t.Setenv("CHORA_SEED_ADMIN_PASSWORD", "hunter2")
	c, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if c.Username != "Admin" {
		t.Errorf("username = %q", c.Username)
	}
}

func TestLoadConfig_RejectsBadTenantID(t *testing.T) {
	t.Setenv("CHORA_DB_DSN", "postgres://x")
	t.Setenv("CHORA_SEED_TENANT_ID", "not-a-uuid")
	t.Setenv("CHORA_SEED_TENANT_SLUG", "s")
	t.Setenv("CHORA_SEED_ADMIN_USERNAME", "a")
	t.Setenv("CHORA_SEED_ADMIN_EMAIL", "a@b.c")
	t.Setenv("CHORA_SEED_ADMIN_PASSWORD", "p")
	if _, err := loadConfig(); err == nil {
		t.Fatal("bad tenant id must be rejected")
	}
}
