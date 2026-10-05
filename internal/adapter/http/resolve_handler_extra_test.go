// resolve_handler_extra_test.go — supplementary coverage for the remaining
// branches of resolve_handler.go not exercised by resolve_handler_test.go:
//
//   - NewResolveHandler: nil-dependency guard (Users nil / Tenancy nil).
//   - lookupOrCreateUser: lookup errors, NewUser invariant error (invalid
//     email), Save error → all surface 500 IDENTITY_REPO_ERROR.
//   - lookupExistingUser: ctx fed-subject error / miss-then-2-value-hit,
//     ctx by-email error / miss, and the legacy 2-value by-email hit.
//   - ServeHTTP: post-enrol re-list error → 503; invite-applier error and
//     invite-applied-with-relist-error are non-fatal → 200; event publish
//     error is non-fatal → 200.
//
// Style matches resolve_handler_test.go: httptest recorder via doResolve,
// constructed handler instances with fakes injected. All new helper names
// are prefixed rsx_ to avoid colliding with existing package-level names.
package httpadapter_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	httpadapter "github.com/apollo-chora/chora-identity/internal/adapter/http"
	"github.com/apollo-chora/chora-identity/internal/adapter/inmem"
	"github.com/apollo-chora/chora-identity/internal/domain/identity"
)

// -----------------------------------------------------------------------------
// NewResolveHandler nil-dependency guard
// -----------------------------------------------------------------------------

func TestResolveHandlerExtra_NewResolveHandler_NilUsers_ReturnsNil(t *testing.T) {
	t.Parallel()
	h := httpadapter.NewResolveHandler(httpadapter.ResolveHandlerConfig{
		Users:   nil,
		Tenancy: &stubTenancyClient{},
	})
	if h != nil {
		t.Fatalf("NewResolveHandler with nil Users must return nil, got %+v", h)
	}
}

func TestResolveHandlerExtra_NewResolveHandler_NilTenancy_ReturnsNil(t *testing.T) {
	t.Parallel()
	h := httpadapter.NewResolveHandler(httpadapter.ResolveHandlerConfig{
		Users:   inmem.NewUserRepository(),
		Tenancy: nil,
	})
	if h != nil {
		t.Fatalf("NewResolveHandler with nil Tenancy must return nil, got %+v", h)
	}
}

func TestResolveHandlerExtra_NewResolveHandler_NoDeps_ReturnsNil(t *testing.T) {
	t.Parallel()
	h := httpadapter.NewResolveHandler(httpadapter.ResolveHandlerConfig{})
	if h != nil {
		t.Fatalf("NewResolveHandler with no deps must return nil, got %+v", h)
	}
}

// -----------------------------------------------------------------------------
// Errors that surface as 500 IDENTITY_REPO_ERROR
// -----------------------------------------------------------------------------

// rsx_lookupErrRepo implements identity.UserRepository with a ctx-carrying
// FindByFederatedSubject (pg shape) that always errors — drives the
// lookupExistingUser error branch and the ServeHTTP 500.
type rsx_lookupErrRepo struct{}

func (rsx_lookupErrRepo) Save(_ context.Context, _ *identity.User) error { return nil }

func (rsx_lookupErrRepo) GetByGcid(_ context.Context, _ string) (*identity.User, error) {
	return nil, identity.ErrUserNotFound
}

func (rsx_lookupErrRepo) FindByFederatedSubject(_ context.Context, _ string) (*identity.User, bool, error) {
	return nil, false, errors.New("rsx: federated-subject lookup down")
}

func TestResolveHandlerExtra_FederatedSubjectLookupError_500(t *testing.T) {
	t.Parallel()
	h := httpadapter.NewResolveHandler(httpadapter.ResolveHandlerConfig{
		Users:         rsx_lookupErrRepo{},
		Tenancy:       &stubTenancyClient{resp: &httpadapter.MembershipsResolution{}},
		Events:        &stubEventPublisher{},
		SourceProject: "chora-local",
	})
	w := doResolve(t, h, map[string]any{
		"email":        "err@example.com",
		"firebase_uid": "fed-err-lookup",
	})
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("want 500 got %d body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "IDENTITY_REPO_ERROR") {
		t.Fatalf("want IDENTITY_REPO_ERROR code, body=%s", w.Body.String())
	}
}

// rsx_byEmailErrRepo exposes ONLY the ctx-carrying FindByEmail (no
// federated-subject probe) and errors — the by-email error branch of
// lookupExistingUser.
type rsx_byEmailErrRepo struct{}

func (rsx_byEmailErrRepo) Save(_ context.Context, _ *identity.User) error { return nil }

func (rsx_byEmailErrRepo) GetByGcid(_ context.Context, _ string) (*identity.User, error) {
	return nil, identity.ErrUserNotFound
}

func (rsx_byEmailErrRepo) FindByEmail(_ context.Context, _ string) (*identity.User, bool, error) {
	return nil, false, errors.New("rsx: by-email lookup down")
}

func TestResolveHandlerExtra_ByEmailLookupError_500(t *testing.T) {
	t.Parallel()
	h := httpadapter.NewResolveHandler(httpadapter.ResolveHandlerConfig{
		Users:         rsx_byEmailErrRepo{},
		Tenancy:       &stubTenancyClient{resp: &httpadapter.MembershipsResolution{}},
		Events:        &stubEventPublisher{},
		SourceProject: "chora-local",
	})
	w := doResolve(t, h, map[string]any{
		"email":        "byemailerr@example.com",
		"firebase_uid": "fed-err-byemail",
	})
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("want 500 got %d body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "IDENTITY_REPO_ERROR") {
		t.Fatalf("want IDENTITY_REPO_ERROR code, body=%s", w.Body.String())
	}
}

// TestResolveHandlerExtra_NewUserInvalidEmail_500 drives the NewUser
// invariant-error branch of lookupOrCreateUser: the on-wire guard only
// checks the email is non-empty, so an email without an '@' passes the
// handler but fails identity.NewUser's LooseValidEmail check → 500.
func TestResolveHandlerExtra_NewUserInvalidEmail_500(t *testing.T) {
	t.Parallel()
	tc := &stubTenancyClient{resp: &httpadapter.MembershipsResolution{}}
	h := httpadapter.NewResolveHandler(httpadapter.ResolveHandlerConfig{
		Users:         &minimalUserRepo{byGcid: make(map[string]*identity.User)},
		Tenancy:       tc,
		Events:        &stubEventPublisher{},
		SourceProject: "chora-local",
	})
	w := doResolve(t, h, map[string]any{
		"email":        "not-an-email",
		"firebase_uid": "fed-err-newuser",
	})
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("want 500 got %d body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "IDENTITY_REPO_ERROR") {
		t.Fatalf("want IDENTITY_REPO_ERROR code, body=%s", w.Body.String())
	}
}

// rsx_saveFailingRepo has no lookup extension methods (minimal contract)
// but Save always errors — the create-then-persist failure branch.
type rsx_saveFailingRepo struct{}

func (rsx_saveFailingRepo) Save(_ context.Context, _ *identity.User) error {
	return errors.New("rsx: persist down")
}

func (rsx_saveFailingRepo) GetByGcid(_ context.Context, _ string) (*identity.User, error) {
	return nil, identity.ErrUserNotFound
}

func TestResolveHandlerExtra_SaveError_500(t *testing.T) {
	t.Parallel()
	h := httpadapter.NewResolveHandler(httpadapter.ResolveHandlerConfig{
		Users:         rsx_saveFailingRepo{},
		Tenancy:       &stubTenancyClient{resp: &httpadapter.MembershipsResolution{}},
		Events:        &stubEventPublisher{},
		SourceProject: "chora-local",
	})
	w := doResolve(t, h, map[string]any{
		"email":        "savefail@example.com",
		"firebase_uid": "fed-err-save",
	})
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("want 500 got %d body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "IDENTITY_REPO_ERROR") {
		t.Fatalf("want IDENTITY_REPO_ERROR code, body=%s", w.Body.String())
	}
}

// -----------------------------------------------------------------------------
// Post-enrol re-list failure → 503
// -----------------------------------------------------------------------------

// rsx_failingRelistTenancyClient returns a fixed first resolution then
// errors on every subsequent call — models list OK / re-list down.
type rsx_failingRelistTenancyClient struct {
	first *httpadapter.MembershipsResolution
	err   error
	calls int
}

func (s *rsx_failingRelistTenancyClient) ListMembershipsByGCID(_ context.Context, _ string) (*httpadapter.MembershipsResolution, error) {
	s.calls++
	if s.calls == 1 {
		return s.first, nil
	}
	if s.err == nil {
		s.err = errors.New("rsx: relist down")
	}
	return nil, s.err
}

func TestResolveHandlerExtra_EnrolRelistError_503(t *testing.T) {
	t.Parallel()
	tc := &rsx_failingRelistTenancyClient{
		first: &httpadapter.MembershipsResolution{Memberships: nil, DefaultTenantID: ""},
	}
	h := httpadapter.NewResolveHandler(httpadapter.ResolveHandlerConfig{
		Users:    inmem.NewUserRepository(),
		Tenancy:  tc,
		Events:   &stubEventPublisher{},
		Enroller: &fakeEnroller{},
	})
	w := doResolve(t, h, map[string]any{
		"email":        "relist@example.com",
		"firebase_uid": "fed-relist",
	})
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("want 503 got %d body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "IDENTITY_TENANCY_UNAVAILABLE") {
		t.Fatalf("want IDENTITY_TENANCY_UNAVAILABLE code, body=%s", w.Body.String())
	}
	if tc.calls != 2 {
		t.Fatalf("tenancy calls = %d, want 2 (list + failing re-list)", tc.calls)
	}
}

// -----------------------------------------------------------------------------
// WS3 invite applier — best-effort, never blocks sign-in
// -----------------------------------------------------------------------------

// rsx_inviteApplier is a configurable ApplyByEmail stub: either returns
// applied tenant IDs or an error.
type rsx_inviteApplier struct {
	applied []string
	err     error
}

func (s *rsx_inviteApplier) ApplyByEmail(_ context.Context, _, _ string) ([]string, error) {
	return s.applied, s.err
}

// TestResolveHandlerExtra_InviteApplyError_NonFatal200 — an applier error
// is logged and ignored; the response still uses the original resolution.
func TestResolveHandlerExtra_InviteApplyError_NonFatal200(t *testing.T) {
	t.Parallel()
	tc := &stubTenancyClient{resp: &httpadapter.MembershipsResolution{
		Memberships: []httpadapter.TenantMembership{{
			TenantID:   "01970000-0000-7000-8000-000000000001",
			TenantSlug: "mightymind-academy",
			Roles:      []string{"learner"},
			IsDefault:  true,
		}},
		DefaultTenantID: "01970000-0000-7000-8000-000000000001",
	}}
	h := httpadapter.NewResolveHandler(httpadapter.ResolveHandlerConfig{
		Users:         inmem.NewUserRepository(),
		Tenancy:       tc,
		Events:        &stubEventPublisher{},
		InviteApplier: &rsx_inviteApplier{err: errors.New("rsx: invite store down")},
	})
	w := doResolve(t, h, map[string]any{
		"email":        "inviteerr@example.com",
		"firebase_uid": "fed-invite-err",
	})
	if w.Code != http.StatusOK {
		t.Fatalf("want 200 (applier error non-fatal), got %d body=%s", w.Code, w.Body.String())
	}
	var body httpadapter.ResolveIdentityResponse
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v body=%s", err, w.Body.String())
	}
	if body.DefaultTenantID != "01970000-0000-7000-8000-000000000001" {
		t.Errorf("default_tenant_id = %q, want original server default", body.DefaultTenantID)
	}
	if len(body.Memberships) != 1 {
		t.Errorf("memberships len = %d, want 1 (original resolution preserved)", len(body.Memberships))
	}
}

// TestResolveHandlerExtra_InviteNoMatch_NoOp200 — no pending invite matches:
// apply returns nothing, no re-list, default stays the server default.
func TestResolveHandlerExtra_InviteNoMatch_NoOp200(t *testing.T) {
	t.Parallel()
	tc := &stubTenancyClient{resp: &httpadapter.MembershipsResolution{
		Memberships: []httpadapter.TenantMembership{{
			TenantID:   "01970000-0000-7000-8000-000000000001",
			TenantSlug: "academy-A",
			Roles:      []string{"learner"},
			IsDefault:  true,
		}},
		DefaultTenantID: "01970000-0000-7000-8000-000000000001",
	}}
	h := httpadapter.NewResolveHandler(httpadapter.ResolveHandlerConfig{
		Users:         inmem.NewUserRepository(),
		Tenancy:       tc,
		Events:        &stubEventPublisher{},
		InviteApplier: &rsx_inviteApplier{applied: nil},
	})
	w := doResolve(t, h, map[string]any{
		"email":        "invitednomatch@example.com",
		"firebase_uid": "fed-invite-nomatch",
	})
	if w.Code != http.StatusOK {
		t.Fatalf("want 200 got %d body=%s", w.Code, w.Body.String())
	}
	var body httpadapter.ResolveIdentityResponse
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v body=%s", err, w.Body.String())
	}
	if body.DefaultTenantID != "01970000-0000-7000-8000-000000000001" {
		t.Errorf("default_tenant_id = %q, want server default (no invite applied)", body.DefaultTenantID)
	}
}

// TestResolveHandlerExtra_InviteApplied_RelistError_KeepsOriginalResolution
// — the invite applied but the post-apply re-list fails: non-fatal, the
// response carries the ORIGINAL (pre-invite) resolution.
func TestResolveHandlerExtra_InviteApplied_RelistError_KeepsOriginalResolution(t *testing.T) {
	t.Parallel()
	originalTenant := "01970000-0000-7000-8000-000000000101"
	invitedTenant := "02220000-0000-7000-8000-000000000222"
	tc := &rsx_failingRelistTenancyClient{
		first: &httpadapter.MembershipsResolution{
			Memberships: []httpadapter.TenantMembership{{
				TenantID:   originalTenant,
				TenantSlug: "academy-A",
				Roles:      []string{"learner"},
				IsDefault:  true,
			}},
			DefaultTenantID: originalTenant,
		},
	}
	// Fail on the SECOND call (the post-apply re-list); the first must succeed.
	// The stub already errors from call 2 onwards.
	h := httpadapter.NewResolveHandler(httpadapter.ResolveHandlerConfig{
		Users:         inmem.NewUserRepository(),
		Tenancy:       tc,
		Events:        &stubEventPublisher{},
		InviteApplier: &rsx_inviteApplier{applied: []string{invitedTenant}},
	})
	w := doResolve(t, h, map[string]any{
		"email":        "invited@example.com",
		"firebase_uid": "fed-invite-applied-relist-err",
	})
	if w.Code != http.StatusOK {
		t.Fatalf("want 200 (re-list after invite non-fatal), got %d body=%s", w.Code, w.Body.String())
	}
	if tc.calls != 2 {
		t.Fatalf("tenancy calls = %d, want 2 (list + failing re-list)", tc.calls)
	}
	var body httpadapter.ResolveIdentityResponse
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v body=%s", err, w.Body.String())
	}
	if body.DefaultTenantID != originalTenant {
		t.Errorf("default_tenant_id = %q, want original resolution tenant %q (invited tenant not in stale memberships)",
			body.DefaultTenantID, originalTenant)
	}
	if len(body.Memberships) != 1 || body.Memberships[0].TenantID != originalTenant {
		t.Errorf("memberships = %+v, want the original resolution preserved", body.Memberships)
	}
}

// -----------------------------------------------------------------------------
// Event publish failure — non-fatal
// -----------------------------------------------------------------------------

// rsx_failingEventPublisher records the emitted event then errors, so tests
// can assert the handler still returns 200 (outbox-canonical publisher makes
// transient failures visible at the dispatcher level).
type rsx_failingEventPublisher struct {
	events []httpadapter.EmittedEvent
}

func (s *rsx_failingEventPublisher) PublishGCIDResolved(_ context.Context, ev httpadapter.EmittedEvent) error {
	s.events = append(s.events, ev)
	return errors.New("rsx: publish down")
}

func TestResolveHandlerExtra_EventPublishError_NonFatal200(t *testing.T) {
	t.Parallel()
	ep := &rsx_failingEventPublisher{}
	tc := &stubTenancyClient{resp: &httpadapter.MembershipsResolution{
		Memberships: []httpadapter.TenantMembership{{
			TenantID:   "01970000-0000-7000-8000-000000000001",
			TenantSlug: "mightymind-academy",
			Roles:      []string{"learner"},
			IsDefault:  true,
		}},
		DefaultTenantID: "01970000-0000-7000-8000-000000000001",
	}}
	h := httpadapter.NewResolveHandler(httpadapter.ResolveHandlerConfig{
		Users:         inmem.NewUserRepository(),
		Tenancy:       tc,
		Events:        ep,
		SourceProject: "chora-local",
	})
	w := doResolve(t, h, map[string]any{
		"email":        "pubfail@example.com",
		"firebase_uid": "fed-pub-err",
	})
	if w.Code != http.StatusOK {
		t.Fatalf("want 200 (event publish error non-fatal), got %d body=%s", w.Code, w.Body.String())
	}
	if len(ep.events) != 1 {
		t.Fatalf("expected 1 publish attempt, got %d", len(ep.events))
	}
	if ep.events[0].GCID == "" || ep.events[0].IdempotencyKey == "" {
		t.Errorf("publish attempt should carry gcid + idempotency_key, got %+v", ep.events[0])
	}
}

// -----------------------------------------------------------------------------
// lookupExistingUser probe-order fall-throughs
// -----------------------------------------------------------------------------

// rsx_ctxMissSubjectRepo implements the ctx-carrying federated-subject
// lookup (pg shape) that always MISSES plus a ctx-carrying by-email lookup
// that HITS the seeded row — proves the handler falls through from a clean
// federated-subject miss to the by-email probe (Go forbids one type from
// carrying the pg 3-value and inmem 2-value signatures under the same
// method name, so cross-signature fall-through is exercised by separate
// repo types).
type rsx_ctxMissSubjectRepo struct {
	byEmail map[string]*identity.User
	byGcid  map[string]*identity.User
	saved   []*identity.User
}

func newRsxCtxMissSubjectRepo() *rsx_ctxMissSubjectRepo {
	return &rsx_ctxMissSubjectRepo{
		byEmail: make(map[string]*identity.User),
		byGcid:  make(map[string]*identity.User),
	}
}

func (r *rsx_ctxMissSubjectRepo) seed(u *identity.User) {
	clone := *u
	r.byEmail[strings.ToLower(u.Email)] = &clone
	r.byGcid[u.Gcid] = &clone
}

func (r *rsx_ctxMissSubjectRepo) Save(_ context.Context, u *identity.User) error {
	clone := *u
	r.byEmail[strings.ToLower(u.Email)] = &clone
	r.byGcid[u.Gcid] = &clone
	r.saved = append(r.saved, &clone)
	return nil
}

func (r *rsx_ctxMissSubjectRepo) GetByGcid(_ context.Context, gcid string) (*identity.User, error) {
	u, ok := r.byGcid[gcid]
	if !ok {
		return nil, identity.ErrUserNotFound
	}
	clone := *u
	return &clone, nil
}

// FindByFederatedSubject (ctx, pg shape) deliberately always misses so the
// handler falls through to the by-email probes.
func (r *rsx_ctxMissSubjectRepo) FindByFederatedSubject(_ context.Context, _ string) (*identity.User, bool, error) {
	return nil, false, nil
}

// FindByEmail (ctx shape) hits on the seeded email.
func (r *rsx_ctxMissSubjectRepo) FindByEmail(_ context.Context, email string) (*identity.User, bool, error) {
	u, ok := r.byEmail[strings.ToLower(email)]
	if !ok {
		return nil, false, nil
	}
	clone := *u
	return &clone, true, nil
}

func TestResolveHandlerExtra_CtxFedSubjectMiss_FallsThroughToByEmailHit(t *testing.T) {
	t.Parallel()
	const (
		canonicalGCID = "01970000-0000-7000-8000-0000000rsx01"
		fedSubject    = "rsx-ctxmiss-fed-uid"
		email         = "ctxmiss@example.com"
	)
	repo := newRsxCtxMissSubjectRepo()
	repo.seed(&identity.User{
		Gcid:             canonicalGCID,
		Email:            email,
		IdentityProvider: identity.ProviderOIDC,
		FederatedSubject: fedSubject,
		Status:           identity.UserStatusActive,
	})
	tc := &stubTenancyClient{resp: &httpadapter.MembershipsResolution{
		Memberships: []httpadapter.TenantMembership{{
			TenantID:   "01970000-0000-7000-8000-000000000001",
			TenantSlug: "academy-A",
			Roles:      []string{"learner"},
			IsDefault:  true,
		}},
		DefaultTenantID: "01970000-0000-7000-8000-000000000001",
	}}
	h := httpadapter.NewResolveHandler(httpadapter.ResolveHandlerConfig{
		Users:         repo,
		Tenancy:       tc,
		Events:        &stubEventPublisher{},
		SourceProject: "chora-local",
	})
	w := doResolve(t, h, map[string]any{
		"email":        email,
		"firebase_uid": fedSubject,
	})
	if w.Code != http.StatusOK {
		t.Fatalf("want 200 got %d body=%s", w.Code, w.Body.String())
	}
	var body httpadapter.ResolveIdentityResponse
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v body=%s", err, w.Body.String())
	}
	if body.GCID != canonicalGCID {
		t.Fatalf("gcid = %q, want canonical %q (ctx fed-subject probe missed, by-email probe should hit)",
			body.GCID, canonicalGCID)
	}
	if len(repo.saved) != 0 {
		t.Errorf("handler Save()d %d user(s); existing user must not be re-created", len(repo.saved))
	}
}

// TestResolveHandlerExtra_ByEmailCtxMiss_CreatesNewUser — byEmailCtxRepo
// (ctx FindByEmail only) with NO matching row: the by-email probe misses,
// no 2-value fallback exists, so the handler creates the user.
func TestResolveHandlerExtra_ByEmailCtxMiss_CreatesNewUser(t *testing.T) {
	t.Parallel()
	repo := newByEmailCtxRepo() // empty on purpose
	tc := &stubTenancyClient{resp: &httpadapter.MembershipsResolution{
		Memberships: []httpadapter.TenantMembership{{
			TenantID:   "01970000-0000-7000-8000-000000000001",
			TenantSlug: "academy-A",
			Roles:      []string{"learner"},
			IsDefault:  true,
		}},
		DefaultTenantID: "01970000-0000-7000-8000-000000000001",
	}}
	h := httpadapter.NewResolveHandler(httpadapter.ResolveHandlerConfig{
		Users:         repo,
		Tenancy:       tc,
		Events:        &stubEventPublisher{},
		SourceProject: "chora-local",
	})
	w := doResolve(t, h, map[string]any{
		"email":        "byemailmiss@example.com",
		"firebase_uid": "fed-byemail-miss",
	})
	if w.Code != http.StatusOK {
		t.Fatalf("want 200 got %d body=%s", w.Code, w.Body.String())
	}
	var body httpadapter.ResolveIdentityResponse
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v body=%s", err, w.Body.String())
	}
	if body.GCID == "" {
		t.Fatalf("gcid must be non-empty after create")
	}
	if len(repo.saved) != 1 {
		t.Errorf("expected exactly 1 Save() for a brand-new user, got %d", len(repo.saved))
	}
}

// rsx_emailTwoValueRepo exposes ONLY the legacy 2-value FindByEmail — the
// last probe in lookupExistingUser's list.
type rsx_emailTwoValueRepo struct {
	byEmail map[string]*identity.User
	byGcid  map[string]*identity.User
	saved   []*identity.User
}

func newRsxEmailTwoValueRepo() *rsx_emailTwoValueRepo {
	return &rsx_emailTwoValueRepo{
		byEmail: make(map[string]*identity.User),
		byGcid:  make(map[string]*identity.User),
	}
}

func (r *rsx_emailTwoValueRepo) seed(u *identity.User) {
	clone := *u
	r.byEmail[strings.ToLower(u.Email)] = &clone
	r.byGcid[u.Gcid] = &clone
}

func (r *rsx_emailTwoValueRepo) Save(_ context.Context, u *identity.User) error {
	clone := *u
	r.byEmail[strings.ToLower(u.Email)] = &clone
	r.byGcid[u.Gcid] = &clone
	r.saved = append(r.saved, &clone)
	return nil
}

func (r *rsx_emailTwoValueRepo) GetByGcid(_ context.Context, gcid string) (*identity.User, error) {
	u, ok := r.byGcid[gcid]
	if !ok {
		return nil, identity.ErrUserNotFound
	}
	clone := *u
	return &clone, nil
}

func (r *rsx_emailTwoValueRepo) FindByEmail(email string) (*identity.User, bool) {
	u, ok := r.byEmail[strings.ToLower(email)]
	if !ok {
		return nil, false
	}
	clone := *u
	return &clone, true
}

func TestResolveHandlerExtra_ByEmailTwoValueHit_ReturnsCanonicalGCID(t *testing.T) {
	t.Parallel()
	const (
		canonicalGCID = "01970000-0000-7000-8000-0000000rsx02"
		fedSubject    = "rsx-2value-email-fed-uid"
		email         = "twovalue@example.com"
	)
	repo := newRsxEmailTwoValueRepo()
	repo.seed(&identity.User{
		Gcid:             canonicalGCID,
		Email:            email,
		IdentityProvider: identity.ProviderOIDC,
		FederatedSubject: fedSubject,
		Status:           identity.UserStatusActive,
	})
	tc := &stubTenancyClient{resp: &httpadapter.MembershipsResolution{
		Memberships: []httpadapter.TenantMembership{{
			TenantID:   "01970000-0000-7000-8000-000000000001",
			TenantSlug: "academy-A",
			Roles:      []string{"learner"},
			IsDefault:  true,
		}},
		DefaultTenantID: "01970000-0000-7000-8000-000000000001",
	}}
	h := httpadapter.NewResolveHandler(httpadapter.ResolveHandlerConfig{
		Users:         repo,
		Tenancy:       tc,
		Events:        &stubEventPublisher{},
		SourceProject: "chora-local",
	})
	w := doResolve(t, h, map[string]any{
		"email":        email,
		"firebase_uid": fedSubject,
	})
	if w.Code != http.StatusOK {
		t.Fatalf("want 200 got %d body=%s", w.Code, w.Body.String())
	}
	var body httpadapter.ResolveIdentityResponse
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v body=%s", err, w.Body.String())
	}
	if body.GCID != canonicalGCID {
		t.Fatalf("gcid = %q, want canonical %q (2-value by-email probe must hit)",
			body.GCID, canonicalGCID)
	}
	if len(repo.saved) != 0 {
		t.Errorf("handler Save()d %d user(s); existing user must not be re-created", len(repo.saved))
	}
}
