package httpadapter

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/apollo-chora/chora-identity/internal/domain/authn"
	"github.com/apollo-chora/chora-identity/internal/domain/identity"
)

// -----------------------------------------------------------------------------
// fakes
// -----------------------------------------------------------------------------

type fakeCredRepo struct {
	byNorm map[string]*authn.Credentials
	err    error
}

func (f *fakeCredRepo) GetByUsernameNorm(_ context.Context, norm string) (*authn.Credentials, error) {
	if f.err != nil {
		return nil, f.err
	}
	c, ok := f.byNorm[norm]
	if !ok {
		return nil, authn.ErrCredentialsNotFound
	}
	return c, nil
}

func (f *fakeCredRepo) Upsert(context.Context, *authn.Credentials) error { return nil }

type fakeUserRepo struct {
	users map[string]*identity.User
}

func (f *fakeUserRepo) Save(context.Context, *identity.User) error { return nil }
func (f *fakeUserRepo) GetByGcid(_ context.Context, gcid string) (*identity.User, error) {
	u, ok := f.users[gcid]
	if !ok {
		return nil, identity.ErrUserNotFound
	}
	return u, nil
}

type fakeMemberRepo struct {
	memberships map[string][]authn.Membership
	err         error
}

func (f *fakeMemberRepo) ListActiveByGCID(_ context.Context, gcid string) ([]authn.Membership, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.memberships[gcid], nil
}

// -----------------------------------------------------------------------------
// helpers
// -----------------------------------------------------------------------------

func mustHash(t *testing.T, pw string) string {
	t.Helper()
	phc, err := authn.HashPassword(pw)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	return phc
}

func newVerifyFixture(t *testing.T) (*VerifyCredentialsHandler, *fakeCredRepo, *fakeUserRepo, *fakeMemberRepo) {
	t.Helper()
	now := time.Now()
	cred := &fakeCredRepo{byNorm: map[string]*authn.Credentials{
		"admin": {
			Gcid:         "11111111-1111-7111-8111-111111111111",
			Username:     "Admin",
			UsernameNorm: "admin",
			PasswordHash: mustHash(t, "hunter2"),
			CreatedAt:    now,
			UpdatedAt:    now,
		},
	}}
	users := &fakeUserRepo{users: map[string]*identity.User{
		"11111111-1111-7111-8111-111111111111": {
			Gcid:   "11111111-1111-7111-8111-111111111111",
			Email:  "admin@example.com",
			Status: identity.UserStatusActive,
		},
	}}
	members := &fakeMemberRepo{memberships: map[string][]authn.Membership{
		"11111111-1111-7111-8111-111111111111": {
			{TenantID: "22222222-2222-7222-8222-222222222222", Role: "admin", CreatedAt: now.Add(-48 * time.Hour)},
			{TenantID: "22222222-2222-7222-8222-222222222222", Role: "learner", CreatedAt: now.Add(-48 * time.Hour)},
		},
	}}
	h := NewVerifyCredentialsHandler(VerifyCredentialsConfig{
		Credentials: cred,
		Users:       users,
		Memberships: members,
	})
	return h, cred, users, members
}

func postVerify(t *testing.T, h *VerifyCredentialsHandler, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/verify-credentials", strings.NewReader(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func decodeVerifyBody(t *testing.T, rec *httptest.ResponseRecorder, v any) {
	t.Helper()
	if err := json.Unmarshal(rec.Body.Bytes(), v); err != nil {
		t.Fatalf("decode body %q: %v", rec.Body.String(), err)
	}
}

// -----------------------------------------------------------------------------
// tests
// -----------------------------------------------------------------------------

func TestVerifyCredentials_HappyPath(t *testing.T) {
	h, _, _, _ := newVerifyFixture(t)
	rec := postVerify(t, h, `{"username":"Admin","password":"hunter2"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var resp VerifyCredentialsResponse
	decodeVerifyBody(t, rec, &resp)
	if resp.GCID != "11111111-1111-7111-8111-111111111111" {
		t.Errorf("gcid = %q", resp.GCID)
	}
	if resp.Email != "admin@example.com" {
		t.Errorf("email = %q", resp.Email)
	}
	if resp.ActiveTenantID != "22222222-2222-7222-8222-222222222222" {
		t.Errorf("active_tenant_id = %q", resp.ActiveTenantID)
	}
	if len(resp.ActiveTenantRoles) != 2 || resp.ActiveTenantRoles[0] != "admin" || resp.ActiveTenantRoles[1] != "learner" {
		t.Errorf("active_tenant_roles = %v", resp.ActiveTenantRoles)
	}
	if len(resp.Memberships) != 1 || resp.Memberships[0].TenantID != resp.ActiveTenantID {
		t.Errorf("memberships = %+v", resp.Memberships)
	}
	// Field-for-field contract: exactly these keys.
	var raw map[string]json.RawMessage
	decodeVerifyBody(t, rec, &raw)
	for _, k := range []string{"gcid", "email", "active_tenant_id", "active_tenant_roles", "memberships"} {
		if _, ok := raw[k]; !ok {
			t.Errorf("missing contract field %q", k)
		}
	}
	if len(raw) != 5 {
		t.Errorf("response has %d fields, want 5: %v", len(raw), raw)
	}
}

func TestVerifyCredentials_WrongPasswordIs401(t *testing.T) {
	h, _, _, _ := newVerifyFixture(t)
	rec := postVerify(t, h, `{"username":"admin","password":"nope"}`)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	var env VerifyCredentialsError
	decodeVerifyBody(t, rec, &env)
	if env.Error.Code != "INVALID_CREDENTIALS" {
		t.Errorf("code = %q, want INVALID_CREDENTIALS", env.Error.Code)
	}
	if env.Error.Message == "" {
		t.Error("message is empty")
	}
}

func TestVerifyCredentials_UnknownUsernameIs401(t *testing.T) {
	h, _, _, _ := newVerifyFixture(t)
	rec := postVerify(t, h, `{"username":"ghost","password":"hunter2"}`)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	var env VerifyCredentialsError
	decodeVerifyBody(t, rec, &env)
	if env.Error.Code != "INVALID_CREDENTIALS" {
		t.Errorf("code = %q", env.Error.Code)
	}
}

func TestVerifyCredentials_DisabledUserIs403(t *testing.T) {
	h, _, users, _ := newVerifyFixture(t)
	users.users["11111111-1111-7111-8111-111111111111"].Status = identity.UserStatusSuspended
	rec := postVerify(t, h, `{"username":"admin","password":"hunter2"}`)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (body=%s)", rec.Code, rec.Body.String())
	}
	var env VerifyCredentialsError
	decodeVerifyBody(t, rec, &env)
	if env.Error.Code != "ACCOUNT_DISABLED" {
		t.Errorf("code = %q, want ACCOUNT_DISABLED", env.Error.Code)
	}
}

func TestVerifyCredentials_ZeroMembershipsIs401(t *testing.T) {
	h, _, _, members := newVerifyFixture(t)
	members.memberships["11111111-1111-7111-8111-111111111111"] = nil
	rec := postVerify(t, h, `{"username":"admin","password":"hunter2"}`)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (never mint a tenant-less principal)", rec.Code)
	}
	var env VerifyCredentialsError
	decodeVerifyBody(t, rec, &env)
	if env.Error.Code != "INVALID_CREDENTIALS" {
		t.Errorf("code = %q", env.Error.Code)
	}
}

func TestVerifyCredentials_MultipleTenantsDeterministic(t *testing.T) {
	h, _, _, members := newVerifyFixture(t)
	now := time.Now()
	members.memberships["11111111-1111-7111-8111-111111111111"] = []authn.Membership{
		{TenantID: "33333333-3333-7333-8333-333333333333", Role: "admin", CreatedAt: now},
		{TenantID: "22222222-2222-7222-8222-222222222222", Role: "learner", CreatedAt: now.Add(-72 * time.Hour)},
	}
	rec := postVerify(t, h, `{"username":"admin","password":"hunter2"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	var resp VerifyCredentialsResponse
	decodeVerifyBody(t, rec, &resp)
	if resp.ActiveTenantID != "22222222-2222-7222-8222-222222222222" {
		t.Errorf("active_tenant_id = %q, want the oldest membership", resp.ActiveTenantID)
	}
	if len(resp.Memberships) != 2 {
		t.Errorf("memberships = %d, want 2", len(resp.Memberships))
	}
}

func TestVerifyCredentials_OversizedPasswordIs401(t *testing.T) {
	h, _, _, _ := newVerifyFixture(t)
	body := `{"username":"admin","password":"` + strings.Repeat("a", authn.MaxPasswordBytes+1) + `"}`
	rec := postVerify(t, h, body)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestVerifyCredentials_MissingFieldsIs401(t *testing.T) {
	h, _, _, _ := newVerifyFixture(t)
	rec := postVerify(t, h, `{"username":"admin"}`)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestVerifyCredentials_MethodNotAllowed(t *testing.T) {
	h, _, _, _ := newVerifyFixture(t)
	req := httptest.NewRequest(http.MethodGet, "/v1/auth/verify-credentials", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", rec.Code)
	}
}

func TestVerifyCredentials_UnreadableStoredHashIs401(t *testing.T) {
	h, cred, _, _ := newVerifyFixture(t)
	cred.byNorm["admin"].PasswordHash = "not-a-phc"
	rec := postVerify(t, h, `{"username":"admin","password":"hunter2"}`)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestVerifyCredentials_MembershipLookupErrorIs500(t *testing.T) {
	h, _, _, members := newVerifyFixture(t)
	members.err = errors.New("db down")
	rec := postVerify(t, h, `{"username":"admin","password":"hunter2"}`)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
}
