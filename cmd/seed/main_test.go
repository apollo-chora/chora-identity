package main

import (
	"strings"
	"testing"
)

// setAdminEnv sets the required admin seed env to valid values. Optional
// instructor/student vars are cleared unless the caller sets them.
func setAdminEnv(t *testing.T) {
	t.Helper()
	t.Setenv("CHORA_DB_DSN", "postgres://x")
	t.Setenv("CHORA_SEED_TENANT_ID", "22222222-2222-7222-8222-222222222222")
	t.Setenv("CHORA_SEED_TENANT_SLUG", "chora-local")
	t.Setenv("CHORA_SEED_ADMIN_USERNAME", "Admin")
	t.Setenv("CHORA_SEED_ADMIN_EMAIL", "admin@example.com")
	t.Setenv("CHORA_SEED_ADMIN_PASSWORD", "hunter2")
	t.Setenv("CHORA_SEED_INSTRUCTOR_USERNAME", "")
	t.Setenv("CHORA_SEED_INSTRUCTOR_EMAIL", "")
	t.Setenv("CHORA_SEED_INSTRUCTOR_PASSWORD", "")
	t.Setenv("CHORA_SEED_STUDENT_USERNAME", "")
	t.Setenv("CHORA_SEED_STUDENT_EMAIL", "")
	t.Setenv("CHORA_SEED_STUDENT_PASSWORD", "")
}

func TestSeedGcid_Deterministic(t *testing.T) {
	a := seedGcid("admin")
	b := seedGcid("admin")
	if a != b {
		t.Fatalf("seedGcid is not deterministic: %q vs %q", a, b)
	}
	if seedGcid("other") == a {
		t.Fatal("different usernames produced the same gcid")
	}
}

func TestSeedGcid_AdminStableAcrossRefactor(t *testing.T) {
	// The UUIDv5 name string is pinned so the seeded admin keeps its GCID
	// across refactors — changing it orphans the existing admin row.
	const want = "e016f4dc-7b47-5d25-ab63-46bf90953ef7"
	if got := seedGcid("admin"); got != want {
		t.Fatalf("seedGcid(admin) = %q, want %q", got, want)
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
	setAdminEnv(t)
	c, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if c.Username != "Admin" {
		t.Errorf("username = %q", c.Username)
	}
	if c.InstructorUsername != "" || c.StudentUsername != "" {
		t.Errorf("optional users must default to empty, got instructor=%q student=%q",
			c.InstructorUsername, c.StudentUsername)
	}
}

func TestLoadConfig_RejectsBadTenantID(t *testing.T) {
	setAdminEnv(t)
	t.Setenv("CHORA_SEED_TENANT_ID", "not-a-uuid")
	if _, err := loadConfig(); err == nil {
		t.Fatal("bad tenant id must be rejected")
	}
}

func TestLoadConfig_InstructorUsernameRequiresEmailAndPassword(t *testing.T) {
	setAdminEnv(t)
	t.Setenv("CHORA_SEED_INSTRUCTOR_USERNAME", "instructor")
	if _, err := loadConfig(); err == nil {
		t.Fatal("instructor username without email/password must error")
	}
}

func TestLoadConfig_StudentUsernameRequiresEmailAndPassword(t *testing.T) {
	setAdminEnv(t)
	t.Setenv("CHORA_SEED_STUDENT_USERNAME", "student")
	if _, err := loadConfig(); err == nil {
		t.Fatal("student username without email/password must error")
	}
}

func TestLoadConfig_InstructorInvalidEmail(t *testing.T) {
	setAdminEnv(t)
	t.Setenv("CHORA_SEED_INSTRUCTOR_USERNAME", "instructor")
	t.Setenv("CHORA_SEED_INSTRUCTOR_EMAIL", "not-an-email")
	t.Setenv("CHORA_SEED_INSTRUCTOR_PASSWORD", "hunter2")
	if _, err := loadConfig(); err == nil {
		t.Fatal("invalid instructor email must be rejected")
	}
}

func TestLoadConfig_StudentInvalidEmail(t *testing.T) {
	setAdminEnv(t)
	t.Setenv("CHORA_SEED_STUDENT_USERNAME", "student")
	t.Setenv("CHORA_SEED_STUDENT_EMAIL", "not-an-email")
	t.Setenv("CHORA_SEED_STUDENT_PASSWORD", "hunter2")
	if _, err := loadConfig(); err == nil {
		t.Fatal("invalid student email must be rejected")
	}
}

func TestLoadConfig_InstructorPasswordTooLong(t *testing.T) {
	setAdminEnv(t)
	t.Setenv("CHORA_SEED_INSTRUCTOR_USERNAME", "instructor")
	t.Setenv("CHORA_SEED_INSTRUCTOR_EMAIL", "instructor@example.com")
	t.Setenv("CHORA_SEED_INSTRUCTOR_PASSWORD", strings.Repeat("a", 1025))
	if _, err := loadConfig(); err == nil {
		t.Fatal("over-long instructor password must be rejected")
	}
}

func TestLoadConfig_InstructorStudentValid(t *testing.T) {
	setAdminEnv(t)
	t.Setenv("CHORA_SEED_INSTRUCTOR_USERNAME", "instructor")
	t.Setenv("CHORA_SEED_INSTRUCTOR_EMAIL", "instructor@example.com")
	t.Setenv("CHORA_SEED_INSTRUCTOR_PASSWORD", "hunter2")
	t.Setenv("CHORA_SEED_STUDENT_USERNAME", "student")
	t.Setenv("CHORA_SEED_STUDENT_EMAIL", "student@example.com")
	t.Setenv("CHORA_SEED_STUDENT_PASSWORD", "hunter2")
	c, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if c.InstructorUsername != "instructor" || c.StudentUsername != "student" {
		t.Errorf("optional users not parsed: instructor=%q student=%q",
			c.InstructorUsername, c.StudentUsername)
	}
}

func TestSeedUsers_AdminOnlyByDefault(t *testing.T) {
	setAdminEnv(t)
	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	users, err := seedUsers(cfg)
	if err != nil {
		t.Fatalf("seedUsers: %v", err)
	}
	if len(users) != 1 {
		t.Fatalf("want 1 seed user (admin), got %d", len(users))
	}
	if users[0].Role != "admin" {
		t.Errorf("admin role = %q", users[0].Role)
	}
}

func TestSeedUsers_InstructorAndStudent(t *testing.T) {
	setAdminEnv(t)
	t.Setenv("CHORA_SEED_INSTRUCTOR_USERNAME", "instructor")
	t.Setenv("CHORA_SEED_INSTRUCTOR_EMAIL", "instructor@example.com")
	t.Setenv("CHORA_SEED_INSTRUCTOR_PASSWORD", "hunter2")
	t.Setenv("CHORA_SEED_STUDENT_USERNAME", "student")
	t.Setenv("CHORA_SEED_STUDENT_EMAIL", "student@example.com")
	t.Setenv("CHORA_SEED_STUDENT_PASSWORD", "hunter2")
	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	users, err := seedUsers(cfg)
	if err != nil {
		t.Fatalf("seedUsers: %v", err)
	}
	if len(users) != 3 {
		t.Fatalf("want 3 seed users, got %d", len(users))
	}
	if users[0].Username != "Admin" || users[0].Role != "admin" {
		t.Errorf("users[0] = %q role %q, want Admin/admin", users[0].Username, users[0].Role)
	}
	if users[1].Username != "instructor" || users[1].Role != "instructor" {
		t.Errorf("users[1] = %q role %q, want instructor/instructor", users[1].Username, users[1].Role)
	}
	// The student account maps to the stored `learner` membership_role.
	if users[2].Username != "student" || users[2].Role != "learner" {
		t.Errorf("users[2] = %q role %q, want student/learner", users[2].Username, users[2].Role)
	}
}

func TestSeedUsers_RejectsDuplicateUsername(t *testing.T) {
	setAdminEnv(t)
	t.Setenv("CHORA_SEED_STUDENT_USERNAME", "admin") // normalises equal to the admin
	t.Setenv("CHORA_SEED_STUDENT_EMAIL", "student@example.com")
	t.Setenv("CHORA_SEED_STUDENT_PASSWORD", "hunter2")
	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if _, err := seedUsers(cfg); err == nil {
		t.Fatal("duplicate seed username must be rejected")
	}
}
