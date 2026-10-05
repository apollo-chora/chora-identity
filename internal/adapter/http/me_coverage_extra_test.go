// me_coverage_extra_test.go — coverage-driver tests for the /me handlers that
// the existing suites leave unexercised:
//
//	me_handler.go           getMe repo-error/user-gone branches, bearerAuth 500,
//	                        resolveBearerGCID JWT fast-path, deriveAuthMethods /
//	                        deriveLinkedIdps non-OIDC profiles, getMeRoles
//	                        resolver errors.
//	me_preferences_handler.go toPreferencesResponse(nil) via a nil-returning store.
//	me_idp_providers_handler.go ServeHTTP sub-path 405, handleGet / handleDelete /
//	                        handlePost default-error branches.
//
// All helpers/fakes are prefixed mex_ (package-wide convention from
// me_economy_handlers_extra_test.go). Reuses the shared consts (tenantA /
// gcidA / agidX), builders (bearerReq / doPrefs / doPost / newHandler /
// newFakeRepo) and seed helpers (newSeededServer / newPrefsMuxWithStore) from
// the sibling *_test.go files in this package.
package httpadapter_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	httpadapter "github.com/apollo-chora/chora-identity/internal/adapter/http"
	"github.com/apollo-chora/chora-identity/internal/adapter/inmem"
	"github.com/apollo-chora/chora-identity/internal/domain/identity"
	tip "github.com/apollo-chora/chora-identity/internal/domain/tenant_idp_provider"
)

// -----------------------------------------------------------------------------
// Fakes
// -----------------------------------------------------------------------------

// mex_seqUserRepo is a UserRepository whose GetByGcid failures follow a
// per-call script: a nil entry means "serve from the seeded map", a non-nil
// error means "fail this call with that error". Used to make the bearer
// middleware succeed (call 1) and then drive getMe's own GetByGcid (call 2)
// into the repo-error / user-gone branches — impossible with the plain inmem
// repo since the middleware already verified the user exists.
type mex_seqUserRepo struct {
	mu      sync.Mutex
	users   map[string]*identity.User
	results []error
	calls   int
}

func newMexSeqUserRepo(results ...error) *mex_seqUserRepo {
	return &mex_seqUserRepo{users: map[string]*identity.User{}, results: results}
}

func (r *mex_seqUserRepo) Save(_ context.Context, u *identity.User) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	clone := *u
	r.users[u.Gcid] = &clone
	return nil
}

func (r *mex_seqUserRepo) GetByGcid(_ context.Context, gcid string) (*identity.User, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls++
	if i := r.calls - 1; i < len(r.results) && r.results[i] != nil {
		return nil, r.results[i]
	}
	u, ok := r.users[gcid]
	if !ok {
		return nil, identity.ErrUserNotFound
	}
	clone := *u
	return &clone, nil
}

// mex_anyUserRepo returns a fixed user for ANY gcid — including AGID-shaped or
// otherwise unparseable values — so the bearer middleware passes and the
// handler underneath (getMeRoles) sees the raw gcid string in its context.
type mex_anyUserRepo struct {
	user *identity.User
}

func (r *mex_anyUserRepo) Save(_ context.Context, u *identity.User) error {
	r.user = u
	return nil
}

func (r *mex_anyUserRepo) GetByGcid(_ context.Context, _ string) (*identity.User, error) {
	if r.user == nil {
		return nil, identity.ErrUserNotFound
	}
	clone := *r.user
	return &clone, nil
}

// mex_faultCourseRoleRepo fails every GetAssignment with a configurable error,
// driving getMeRoles into the resolver-error (500) branch.
type mex_faultCourseRoleRepo struct{ err error }

func (r mex_faultCourseRoleRepo) GetAssignment(context.Context, string, string) (*identity.CourseRoleAssignment, error) {
	return nil, r.err
}

// mex_nilPrefsStore is a UIPreferencesRepository whose GET returns (nil, nil) —
// the only way to reach toPreferencesResponse(nil) through the handler (the
// inmem store never returns nil prefs).
type mex_nilPrefsStore struct{}

func (mex_nilPrefsStore) GetUIPreferences(context.Context, string) (*identity.UIPreferences, error) {
	return nil, nil
}

func (mex_nilPrefsStore) UpsertDashboardLayout(context.Context, string, identity.DashboardLayout) error {
	return nil
}

func (mex_nilPrefsStore) UpsertHomeLayout(context.Context, string, identity.HomeLayout) error {
	return nil
}

// mex_faultIDPRepo wraps the shared fakeRepo (fakeRepo's Upsert/Get promoted)
// and lets ListByTenant / SoftDelete fail, reaching the handler 500 branches.
type mex_faultIDPRepo struct {
	*fakeRepo
	listErr       error
	softDeleteErr error
}

func (r *mex_faultIDPRepo) ListByTenant(context.Context, string) ([]tip.TenantIdpProvider, error) {
	return nil, r.listErr
}

func (r *mex_faultIDPRepo) SoftDelete(context.Context, string, tip.ProviderType, time.Time) error {
	return r.softDeleteErr
}

// -----------------------------------------------------------------------------
// Helper
// -----------------------------------------------------------------------------

// mex_meServer mounts a NewRouterWithCourseRoles around explicit repos so
// tests can inject failing fakes for /me + /me/roles.
func mex_meServer(users identity.UserRepository, courseRoles identity.CourseRoleRepository) http.Handler {
	return httpadapter.NewRouterWithCourseRoles(
		users,
		inmem.NewMembershipRepository(),
		inmem.NewSnapshotRepository(),
		courseRoles,
	)
}

// -----------------------------------------------------------------------------
// me_handler.go — getMe + bearerAuth error branches
// -----------------------------------------------------------------------------

func TestGetMe_BearerAuthRepoError_500(t *testing.T) {
	t.Parallel()
	// The FIRST GetByGcid call (bearer middleware) fails with a non-sentinel
	// error → 500 IDENTITY_REPO_ERROR (not 401).
	repo := newMexSeqUserRepo(errors.New("db unreachable"))
	srv := mex_meServer(repo, inmem.NewCourseRoleRepository())
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, bearerReq(http.MethodGet, "/me", phyllisGcid))

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s; want 500", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "IDENTITY_REPO_ERROR") {
		t.Errorf("body=%s; want IDENTITY_REPO_ERROR envelope", w.Body.String())
	}
}

func TestGetMe_UserDeletedBetweenAuthAndLookup_401(t *testing.T) {
	t.Parallel()
	// Middleware GetByGcid succeeds (call 1 → nil script entry); getMe's own
	// GetByGcid then sees ErrUserNotFound (call 2) → 401 IDENTITY_UNKNOWN_GCID.
	repo := newMexSeqUserRepo(nil, identity.ErrUserNotFound)
	_ = repo.Save(context.Background(), &identity.User{
		Gcid: phyllisGcid, Email: "phyllis@mightymind.sg",
		IdentityProvider: identity.ProviderOIDC,
	})
	srv := mex_meServer(repo, inmem.NewCourseRoleRepository())
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, bearerReq(http.MethodGet, "/me", phyllisGcid))

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d body=%s; want 401", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "IDENTITY_UNKNOWN_GCID") {
		t.Errorf("body=%s; want IDENTITY_UNKNOWN_GCID envelope", w.Body.String())
	}
}

func TestGetMe_RepoErrorBetweenAuthAndLookup_500(t *testing.T) {
	t.Parallel()
	// Same shape as above but the second call fails with a generic repo error
	// → 500 IDENTITY_REPO_ERROR from getMe.
	repo := newMexSeqUserRepo(nil, errors.New("db down"))
	_ = repo.Save(context.Background(), &identity.User{
		Gcid: phyllisGcid, Email: "phyllis@mightymind.sg",
		IdentityProvider: identity.ProviderOIDC,
	})
	srv := mex_meServer(repo, inmem.NewCourseRoleRepository())
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, bearerReq(http.MethodGet, "/me", phyllisGcid))

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s; want 500", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "IDENTITY_REPO_ERROR") {
		t.Errorf("body=%s; want IDENTITY_REPO_ERROR envelope", w.Body.String())
	}
}

// -----------------------------------------------------------------------------
// me_handler.go — bearer shape edge cases (extractBearer + resolveBearerGCID)
// -----------------------------------------------------------------------------

func TestGetMe_BearerHeaderEmptyToken_401(t *testing.T) {
	t.Parallel()
	srv := newSeededServer(t)
	r := httptest.NewRequest(http.MethodGet, "/me", nil)
	r.Header.Set("Authorization", "Bearer ")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d body=%s; want 401", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "IDENTITY_BEARER_REQUIRED") {
		t.Errorf("body=%s; want IDENTITY_BEARER_REQUIRED envelope", w.Body.String())
	}
}

func TestGetMe_JWTBearerWithoutMeshHeader_401(t *testing.T) {
	t.Parallel()
	// A JWT-shaped bearer (dot-separated) with NO chora-gcid / gcid mesh
	// headers is refused by resolveBearerGCID — the gateway should always
	// stamp the mesh header, so this is a misconfigured-edge 401.
	srv := newSeededServer(t)
	r := httptest.NewRequest(http.MethodGet, "/me", nil)
	r.Header.Set("Authorization", "Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d body=%s; want 401", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "IDENTITY_BEARER_REQUIRED") {
		t.Errorf("body=%s; want IDENTITY_BEARER_REQUIRED envelope", w.Body.String())
	}
}

// -----------------------------------------------------------------------------
// me_handler.go — deriveAuthMethods + deriveLinkedIdps non-OIDC profiles
// -----------------------------------------------------------------------------

func TestGetMe_WebAuthnProfile_AuthMethodsAndLinkedIdps(t *testing.T) {
	t.Parallel()
	repo := inmem.NewUserRepository()
	_ = repo.Save(context.Background(), &identity.User{
		Gcid: gcidA, Email: "webauthn@chora.dev", DisplayName: "Key Carrier",
		IdentityProvider: identity.ProviderWebAuthn, Status: identity.UserStatusActive,
	})
	srv := mex_meServer(repo, inmem.NewCourseRoleRepository())
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, bearerReq(http.MethodGet, "/me", gcidA))

	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s; want 200", w.Code, w.Body.String())
	}
	var got map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("invalid json: %v", err)
	}
	auth, _ := got["auth_methods"].([]any)
	if !containsAll(auth, "password", "webauthn") {
		t.Errorf("auth_methods=%v; want password + webauthn", got["auth_methods"])
	}
	idps, _ := got["linked_idps"].([]any)
	if !containsAll(idps, "webauthn") {
		t.Errorf("linked_idps=%v; want webauthn", got["linked_idps"])
	}
}

func TestGetMe_SAMLProfile_AuthMethodsAndLinkedIdps(t *testing.T) {
	t.Parallel()
	repo := inmem.NewUserRepository()
	_ = repo.Save(context.Background(), &identity.User{
		Gcid: gcidB, Email: "saml@chora.dev", DisplayName: "SAML User",
		IdentityProvider: identity.ProviderSAML, Status: identity.UserStatusActive,
	})
	srv := mex_meServer(repo, inmem.NewCourseRoleRepository())
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, bearerReq(http.MethodGet, "/me", gcidB))

	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s; want 200", w.Code, w.Body.String())
	}
	var got map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("invalid json: %v", err)
	}
	auth, _ := got["auth_methods"].([]any)
	if !containsAll(auth, "password", "saml") {
		t.Errorf("auth_methods=%v; want password + saml", got["auth_methods"])
	}
	idps, _ := got["linked_idps"].([]any)
	if !containsAll(idps, "saml") {
		t.Errorf("linked_idps=%v; want saml", got["linked_idps"])
	}
}

func TestGetMe_NoIdentityProvider_Defaults(t *testing.T) {
	t.Parallel()
	// A user without an OIDC/WebAuthn/SAML provider must still 200 with the
	// password default for auth_methods and an EMPTY linked_idps list.
	repo := inmem.NewUserRepository()
	_ = repo.Save(context.Background(), &identity.User{
		Gcid: gcidA, Email: "plain@chora.dev", DisplayName: "Plain",
		IdentityProvider: "", Status: identity.UserStatusActive,
	})
	srv := mex_meServer(repo, inmem.NewCourseRoleRepository())
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, bearerReq(http.MethodGet, "/me", gcidA))

	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s; want 200", w.Code, w.Body.String())
	}
	var got map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("invalid json: %v", err)
	}
	auth, _ := got["auth_methods"].([]any)
	if len(auth) != 1 || auth[0] != "password" {
		t.Errorf("auth_methods=%v; want [password]", got["auth_methods"])
	}
	idps, _ := got["linked_idps"].([]any)
	if len(idps) != 0 {
		t.Errorf("linked_idps=%v; want empty list", got["linked_idps"])
	}
}

// -----------------------------------------------------------------------------
// me_handler.go — getMeRoles resolver error branches
// -----------------------------------------------------------------------------

func TestGetMeRoles_AGIDGcid_401(t *testing.T) {
	t.Parallel()
	// Middleware accepts the AGID-shaped bearer (GetByGcid succeeds for any
	// value via the any-user fake); the resolver then rejects the AGID shape
	// → 401 IDENTITY_INVALID_GCID.
	repo := &mex_anyUserRepo{user: &identity.User{
		Gcid: agidX, Email: "agent@chora.dev", IdentityProvider: identity.ProviderOIDC,
	}}
	srv := mex_meServer(repo, inmem.NewCourseRoleRepository())
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, bearerReq(http.MethodGet, "/me/roles?course_id="+courseCSPO, agidX))

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d body=%s; want 401", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "IDENTITY_INVALID_GCID") {
		t.Errorf("body=%s; want IDENTITY_INVALID_GCID envelope", w.Body.String())
	}
}

func TestGetMeRoles_ResolverError_500(t *testing.T) {
	t.Parallel()
	// The resolver's repo fails with a generic error (not the sentinels) →
	// 500 IDENTITY_RESOLVER_ERROR.
	users := inmem.NewUserRepository()
	_ = users.Save(context.Background(), &identity.User{
		Gcid: phyllisGcid, Email: "phyllis@mightymind.sg",
		IdentityProvider: identity.ProviderOIDC,
	})
	srv := mex_meServer(users, mex_faultCourseRoleRepo{err: errors.New("assignment store unreachable")})
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, bearerReq(http.MethodGet, "/me/roles?course_id="+courseCSPO, phyllisGcid))

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s; want 500", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "IDENTITY_RESOLVER_ERROR") {
		t.Errorf("body=%s; want IDENTITY_RESOLVER_ERROR envelope", w.Body.String())
	}
}

// -----------------------------------------------------------------------------
// me_preferences_handler.go — toPreferencesResponse(nil)
// -----------------------------------------------------------------------------

func TestMePreferences_GET_NilPrefsStore_200EmptyEnvelope(t *testing.T) {
	t.Parallel()
	// A store returning (nil, nil) drives toPreferencesResponse(nil): both
	// omitempty fields disappear → a bare {} envelope.
	mux := newPrefsMuxWithStore(t, mex_nilPrefsStore{})
	w := doPrefs(t, mux, http.MethodGet, "/api/v1/me/preferences", "")

	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s; want 200", w.Code, w.Body.String())
	}
	if strings.TrimSpace(w.Body.String()) != "{}" {
		t.Errorf("body=%s; want bare {} envelope (layouts omitted)", w.Body.String())
	}
}

// -----------------------------------------------------------------------------
// me_idp_providers_handler.go — ServeHTTP dispatch + error branches
// -----------------------------------------------------------------------------

func TestMeIdp_ServeHTTP_SubPathNonDelete_405(t *testing.T) {
	t.Parallel()
	// Anything under the base path is DELETE-only; a GET on the sub-path must
	// be 405 (not dispatched to handleGet).
	h, _, _, _ := newHandler(t)
	r := httptest.NewRequest(http.MethodGet, "/api/v1/tenants/me/idp-providers/oidc", nil)
	r.Header.Set("X-Tenant-Id", tenantA)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status=%d body=%s; want 405", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "method_not_allowed") {
		t.Errorf("body=%s; want method_not_allowed envelope", w.Body.String())
	}
}

func TestMeIdp_GET_RepoError_500(t *testing.T) {
	t.Parallel()
	repo := &mex_faultIDPRepo{fakeRepo: newFakeRepo(), listErr: errors.New("list exploded")}
	svc := tip.NewService(repo, &fakeSecretManager{}, &fakePublisher{})
	h := httpadapter.NewMeIdpProvidersHandler(svc)

	r := httptest.NewRequest(http.MethodGet, "/api/v1/tenants/me/idp-providers", nil)
	r.Header.Set("X-Tenant-Id", tenantA)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s; want 500", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "internal_error") {
		t.Errorf("body=%s; want internal_error envelope", w.Body.String())
	}
}

func TestMeIdp_DELETE_RepoError_500(t *testing.T) {
	t.Parallel()
	repo := &mex_faultIDPRepo{fakeRepo: newFakeRepo(), softDeleteErr: errors.New("delete exploded")}
	svc := tip.NewService(repo, &fakeSecretManager{}, &fakePublisher{})
	h := httpadapter.NewMeIdpProvidersHandler(svc)

	r := httptest.NewRequest(http.MethodDelete, "/api/v1/tenants/me/idp-providers/oidc", nil)
	r.Header.Set("X-Tenant-Id", tenantA)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s; want 500", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "internal_error") {
		t.Errorf("body=%s; want internal_error envelope", w.Body.String())
	}
}

func TestMeIdp_POST_RepoError_500(t *testing.T) {
	t.Parallel()
	// The service wraps the repo.Upsert failure in a generic error (no
	// "secret manager" marker, not ErrInvalidInput) → handler default 500.
	h, repo, _, _ := newHandler(t)
	repo.upsertErr = errors.New("upsert exploded")
	w := doPost(t, h, map[string]string{"X-Tenant-Id": tenantA, "gcid": gcidA},
		`{"provider_type":"oidc","client_id":"acme","client_secret":"shhh","discovery_url":"https://issuer.example.com/.well-known/openid-configuration"}`)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s; want 500", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "internal_error") {
		t.Errorf("body=%s; want internal_error envelope", w.Body.String())
	}
}
