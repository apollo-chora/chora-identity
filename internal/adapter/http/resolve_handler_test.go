// resolve_handler_test.go — TDD coverage for POST /v1/identity/resolve
// (Bucket 2, 2026-05-14 multi-tenant identity arch-correct).
//
// Coverage classes per the task spec:
//
//   - Happy path: known GCID with 1 membership → 200 + canonical envelope.
//   - Multi-tenant: 2+ memberships → all surfaced + default_tenant_id picked.
//   - Lookup-or-create: unknown (email, firebase_uid) → User created with
//     fresh UUIDv7 GCID + persisted via the UserRepository.
//   - 400: missing email or firebase_uid.
//   - active_tenant_id hint accepted: caller-supplied tenant_id wins when
//     valid (user IS a member of that tenant).
//   - active_tenant_id hint rejected when NOT a member: silent fallback to
//     server-derived default_tenant_id.
//   - 404 / no memberships: chora-tenancy returns empty list → handler
//     surfaces empty memberships + clear error code.
//   - 503: gRPC client error surfaces as TENANCY_UNAVAILABLE.
//   - Event emission: chora.identity.gcid.resolved.v1 emitted on success
//     with idempotency_key = sha256(email+firebase_uid).
//
// Tests use direct method invocation; the gRPC client is a stub.
package httpadapter_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	httpadapter "github.com/apollo-chora/chora-identity/internal/adapter/http"
	"github.com/apollo-chora/chora-identity/internal/adapter/inmem"
	"github.com/apollo-chora/chora-identity/internal/domain/identity"
)

// stubTenancyClient is the test stub for httpadapter.TenancyClient.
type stubTenancyClient struct {
	resp        *httpadapter.MembershipsResolution
	err         error
	lastGCIDArg string
}

func (s *stubTenancyClient) ListMembershipsByGCID(_ context.Context, gcid string) (*httpadapter.MembershipsResolution, error) {
	s.lastGCIDArg = gcid
	if s.err != nil {
		return nil, s.err
	}
	return s.resp, nil
}

// stubEventPublisher captures emitted events for assertion.
type stubEventPublisher struct {
	events []httpadapter.EmittedEvent
}

func (s *stubEventPublisher) PublishGCIDResolved(_ context.Context, ev httpadapter.EmittedEvent) error {
	s.events = append(s.events, ev)
	return nil
}

func newResolveFixture(t *testing.T) (
	*httpadapter.ResolveHandler,
	*stubTenancyClient,
	*stubEventPublisher,
	identity.UserRepository,
) {
	t.Helper()
	users := inmem.NewUserRepository()
	tc := &stubTenancyClient{
		resp: &httpadapter.MembershipsResolution{
			Memberships: []httpadapter.TenantMembership{{
				TenantID:   "01970000-0000-7000-8000-000000000001",
				TenantSlug: "mightymind-academy",
				Roles:      []string{"learner"},
				Surfaces:   []string{"aplus", "cplus"},
				IsDefault:  true,
			}},
			DefaultTenantID: "01970000-0000-7000-8000-000000000001",
		},
	}
	ep := &stubEventPublisher{}
	h := httpadapter.NewResolveHandler(httpadapter.ResolveHandlerConfig{
		Users:         users,
		Tenancy:       tc,
		Events:        ep,
		SourceProject: "chora-local",
	})
	return h, tc, ep, users
}

func doResolve(t *testing.T, h *httpadapter.ResolveHandler, body any) *httptest.ResponseRecorder {
	t.Helper()
	b, _ := json.Marshal(body)
	r := httptest.NewRequest(http.MethodPost, "/v1/identity/resolve", bytes.NewReader(b))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

// stubInviteApplier records the resolve-time cold-invite apply call (WS3).
type stubInviteApplier struct {
	applied  []string
	gotGcid  string
	gotEmail string
}

func (s *stubInviteApplier) ApplyByEmail(_ context.Context, gcid, email string) ([]string, error) {
	s.gotGcid, s.gotEmail = gcid, email
	return s.applied, nil
}

// WS3 / ADR-194 D2: a cold-invited email, on first resolve, applies the pending
// invite and lands the invitee in the INVITED tenant (not chora-master).
func TestResolveIdentity_ColdInviteApplied_DefaultsToInvitedTenant(t *testing.T) {
	invitedTenant := "02220000-0000-7000-8000-000000000222"
	tc := &stubTenancyClient{resp: &httpadapter.MembershipsResolution{
		Memberships: []httpadapter.TenantMembership{
			{TenantID: "00000000-0000-7000-8000-000000000001", TenantSlug: "chora-master", Roles: []string{"learner", "author"}, IsDefault: true},
			{TenantID: invitedTenant, TenantSlug: "academy-x", Roles: []string{"instructor"}},
		},
		DefaultTenantID: "00000000-0000-7000-8000-000000000001",
	}}
	applier := &stubInviteApplier{applied: []string{invitedTenant}}
	h := httpadapter.NewResolveHandler(httpadapter.ResolveHandlerConfig{
		Users:         inmem.NewUserRepository(),
		Tenancy:       tc,
		InviteApplier: applier,
		SourceProject: "chora-local",
	})

	w := doResolve(t, h, map[string]any{"email": "anika@mtm.sg", "firebase_uid": "fb-cold-1"})
	if w.Code != http.StatusOK {
		t.Fatalf("want 200 got %d body=%s", w.Code, w.Body.String())
	}
	var body httpadapter.ResolveIdentityResponse
	_ = json.Unmarshal(w.Body.Bytes(), &body)

	if applier.gotEmail != "anika@mtm.sg" || applier.gotGcid == "" {
		t.Errorf("applier must be called with resolved (gcid,email); got gcid=%q email=%q", applier.gotGcid, applier.gotEmail)
	}
	if body.DefaultTenantID != invitedTenant {
		t.Errorf("default_tenant_id: got %q want the invited tenant %q", body.DefaultTenantID, invitedTenant)
	}
}

// -----------------------------------------------------------------------------
// Happy paths
// -----------------------------------------------------------------------------

func TestResolveIdentity_HappyPath(t *testing.T) {
	t.Parallel()
	h, tc, ep, _ := newResolveFixture(t)
	w := doResolve(t, h, map[string]any{
		"email":        "alice@example.com",
		"firebase_uid": "fed-sub-1",
	})
	if w.Code != http.StatusOK {
		t.Fatalf("want 200 got %d body=%s", w.Code, w.Body.String())
	}
	var body httpadapter.ResolveIdentityResponse
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v body=%s", err, w.Body.String())
	}
	if body.GCID == "" {
		t.Errorf("gcid must be non-empty")
	}
	if body.Email != "alice@example.com" {
		t.Errorf("email = %q", body.Email)
	}
	if body.FirebaseUID != "fed-sub-1" {
		t.Errorf("firebase_uid = %q", body.FirebaseUID)
	}
	if body.DefaultTenantID != "01970000-0000-7000-8000-000000000001" {
		t.Errorf("default_tenant_id = %q", body.DefaultTenantID)
	}
	if len(body.Memberships) != 1 {
		t.Fatalf("memberships len = %d, want 1", len(body.Memberships))
	}
	if body.Memberships[0].TenantSlug != "mightymind-academy" {
		t.Errorf("tenant_slug = %q", body.Memberships[0].TenantSlug)
	}
	if tc.lastGCIDArg == "" {
		t.Errorf("expected tenancy client to receive a gcid arg")
	}
	if len(ep.events) != 1 {
		t.Fatalf("expected 1 event emitted, got %d", len(ep.events))
	}
	if ep.events[0].IdempotencyKey == "" {
		t.Errorf("event idempotency_key must be populated")
	}
}

func TestResolveIdentity_MultiTenant_DefaultPicked(t *testing.T) {
	t.Parallel()
	h, tc, _, _ := newResolveFixture(t)
	tc.resp = &httpadapter.MembershipsResolution{
		Memberships: []httpadapter.TenantMembership{
			{
				TenantID:   "01970000-0000-7000-8000-000000000001",
				TenantSlug: "academy-A",
				Roles:      []string{"learner", "author"},
				Surfaces:   []string{"aplus", "cplus"},
				IsDefault:  false,
			},
			{
				TenantID:   "01970000-0000-7000-8000-000000000002",
				TenantSlug: "academy-B",
				Roles:      []string{"instructor"},
				Surfaces:   []string{"rplus"},
				IsDefault:  true,
			},
		},
		DefaultTenantID: "01970000-0000-7000-8000-000000000002",
	}
	w := doResolve(t, h, map[string]any{
		"email":        "alice@example.com",
		"firebase_uid": "fed-sub-1",
	})
	if w.Code != http.StatusOK {
		t.Fatalf("want 200 got %d body=%s", w.Code, w.Body.String())
	}
	var body httpadapter.ResolveIdentityResponse
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	if body.DefaultTenantID != "01970000-0000-7000-8000-000000000002" {
		t.Errorf("default_tenant_id = %q", body.DefaultTenantID)
	}
	if len(body.Memberships) != 2 {
		t.Fatalf("memberships len = %d, want 2", len(body.Memberships))
	}
}

func TestResolveIdentity_ActiveTenantHintAccepted(t *testing.T) {
	t.Parallel()
	h, tc, _, _ := newResolveFixture(t)
	tc.resp = &httpadapter.MembershipsResolution{
		Memberships: []httpadapter.TenantMembership{
			{
				TenantID:   "01970000-0000-7000-8000-000000000001",
				TenantSlug: "academy-A",
				Roles:      []string{"learner"},
				Surfaces:   []string{"aplus", "cplus"},
			},
			{
				TenantID:   "01970000-0000-7000-8000-000000000002",
				TenantSlug: "academy-B",
				Roles:      []string{"instructor"},
				Surfaces:   []string{"rplus"},
			},
		},
		DefaultTenantID: "01970000-0000-7000-8000-000000000002", // server default
	}
	// Caller hints academy-A — must win because user IS a member.
	w := doResolve(t, h, map[string]any{
		"email":            "alice@example.com",
		"firebase_uid":     "fed-sub-1",
		"active_tenant_id": "01970000-0000-7000-8000-000000000001",
	})
	if w.Code != http.StatusOK {
		t.Fatalf("want 200 got %d body=%s", w.Code, w.Body.String())
	}
	var body httpadapter.ResolveIdentityResponse
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	if body.DefaultTenantID != "01970000-0000-7000-8000-000000000001" {
		t.Errorf("active_tenant_id hint must win, got default_tenant_id = %q", body.DefaultTenantID)
	}
}

func TestResolveIdentity_ActiveTenantHintRejected_FallsBackToServerDefault(t *testing.T) {
	t.Parallel()
	h, tc, _, _ := newResolveFixture(t)
	tc.resp = &httpadapter.MembershipsResolution{
		Memberships: []httpadapter.TenantMembership{
			{
				TenantID:   "01970000-0000-7000-8000-000000000001",
				TenantSlug: "academy-A",
				Roles:      []string{"learner"},
				Surfaces:   []string{"aplus", "cplus"},
			},
		},
		DefaultTenantID: "01970000-0000-7000-8000-000000000001",
	}
	// User is NOT a member of "999". Must fall back to server default.
	w := doResolve(t, h, map[string]any{
		"email":            "alice@example.com",
		"firebase_uid":     "fed-sub-1",
		"active_tenant_id": "01970000-0000-7000-8000-000000000999",
	})
	if w.Code != http.StatusOK {
		t.Fatalf("want 200 got %d body=%s", w.Code, w.Body.String())
	}
	var body httpadapter.ResolveIdentityResponse
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	if body.DefaultTenantID != "01970000-0000-7000-8000-000000000001" {
		t.Errorf("default_tenant_id must fall back to server default when hint is not a membership, got %q", body.DefaultTenantID)
	}
}

func TestResolveIdentity_LookupOrCreate_UserPersisted(t *testing.T) {
	t.Parallel()
	h, _, _, users := newResolveFixture(t)
	w := doResolve(t, h, map[string]any{
		"email":        "newcomer@example.com",
		"firebase_uid": "fed-newcomer-1",
	})
	if w.Code != http.StatusOK {
		t.Fatalf("want 200 got %d body=%s", w.Code, w.Body.String())
	}
	var body httpadapter.ResolveIdentityResponse
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	if body.GCID == "" {
		t.Fatalf("gcid must be non-empty")
	}
	// User must now exist in the repo with the same GCID.
	got, err := users.GetByGcid(context.Background(), body.GCID)
	if err != nil {
		t.Fatalf("user lookup after resolve: %v", err)
	}
	if got.Email != "newcomer@example.com" {
		t.Errorf("persisted user email = %q", got.Email)
	}
}

// ctxFedSubjectRepo is a UserRepository that — like the production
// pgx adapter (pg.UserRepository) — exposes FindByFederatedSubject with
// the ctx-carrying 3-value signature `(ctx, sub) (*User, bool, error)`.
//
// D0.1c regression guard: the resolve handler's lookupOrCreateUser does a
// type assertion for exactly this signature. If the wired repo matches,
// an EXISTING user MUST be returned with their CANONICAL GCID — the
// handler must NOT mint a fresh random GCID (which would carry zero
// tenant memberships and produce a spurious 404 IDENTITY_NO_TENANT_
// MEMBERSHIP at /v1/identity/resolve, surfaced as 403 at the gateway).
type ctxFedSubjectRepo struct {
	bySubject map[string]*identity.User // keyed by federated_subject
	byGcid    map[string]*identity.User // keyed by gcid
	saved     []*identity.User
}

func newCtxFedSubjectRepo() *ctxFedSubjectRepo {
	return &ctxFedSubjectRepo{
		bySubject: make(map[string]*identity.User),
		byGcid:    make(map[string]*identity.User),
	}
}

func (r *ctxFedSubjectRepo) seed(u *identity.User) {
	clone := *u
	r.bySubject[u.FederatedSubject] = &clone
	r.byGcid[u.Gcid] = &clone
}

func (r *ctxFedSubjectRepo) Save(_ context.Context, u *identity.User) error {
	clone := *u
	r.bySubject[u.FederatedSubject] = &clone
	r.byGcid[u.Gcid] = &clone
	r.saved = append(r.saved, &clone)
	return nil
}

func (r *ctxFedSubjectRepo) GetByGcid(_ context.Context, gcid string) (*identity.User, error) {
	u, ok := r.byGcid[gcid]
	if !ok {
		return nil, identity.ErrUserNotFound
	}
	clone := *u
	return &clone, nil
}

// FindByFederatedSubject mirrors pg.UserRepository's ctx-carrying signature
// — this is the signature the resolve handler type-asserts for.
func (r *ctxFedSubjectRepo) FindByFederatedSubject(_ context.Context, sub string) (*identity.User, bool, error) {
	u, ok := r.bySubject[sub]
	if !ok {
		return nil, false, nil
	}
	clone := *u
	return &clone, true, nil
}

func TestResolveIdentity_ExistingUser_ReturnsCanonicalGCID_NotFreshlyMinted(t *testing.T) {
	t.Parallel()

	// Pre-seed the repo with the canonical user — same shape as the live
	// chora_identity.users row for daleleung76@gmail.com.
	const (
		canonicalGCID = "00000000-0000-7000-8000-000000001999"
		fedSubject    = "p4eHlkWJ1SZGhS8mhFNeYUpZskf2"
		email         = "daleleung76@gmail.com"
	)
	repo := newCtxFedSubjectRepo()
	repo.seed(&identity.User{
		Gcid:             canonicalGCID,
		Email:            email,
		IdentityProvider: identity.ProviderOIDC,
		FederatedSubject: fedSubject,
		Status:           identity.UserStatusActive,
	})

	tc := &stubTenancyClient{
		resp: &httpadapter.MembershipsResolution{
			Memberships: []httpadapter.TenantMembership{
				{
					TenantID:   "01970000-0000-7000-8000-0000000a0001",
					TenantSlug: "mtm-singapore",
					Roles:      []string{"learner"},
					Surfaces:   []string{"aplus"},
					IsDefault:  true,
				},
				{
					TenantID:   "01970000-0000-7000-8000-0000000a0002",
					TenantSlug: "chen-coaching",
					Roles:      []string{"learner"},
					Surfaces:   []string{"aplus"},
				},
			},
			DefaultTenantID: "01970000-0000-7000-8000-0000000a0001",
		},
	}
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

	// THE assertion: the handler must NOT mint a fresh GCID for a user that
	// already exists — it must return the canonical one so chora-tenancy is
	// queried with the GCID that actually has membership rows.
	if body.GCID != canonicalGCID {
		t.Fatalf("resolve returned GCID %q, want canonical %q — handler minted a fresh GCID for an EXISTING user (D0.1c root cause)",
			body.GCID, canonicalGCID)
	}
	if tc.lastGCIDArg != canonicalGCID {
		t.Errorf("chora-tenancy queried with GCID %q, want canonical %q", tc.lastGCIDArg, canonicalGCID)
	}
	// And the handler must NOT have Save()d a new user — the row already exists.
	if len(repo.saved) != 0 {
		t.Errorf("handler Save()d %d user(s); an existing user must not be re-created", len(repo.saved))
	}
}

// TestResolveIdentity_InmemRepo_ExistingUser_ReturnsCanonicalGCID guards the
// DEV wiring path. The legacy inmem.UserRepository exposes
// FindByFederatedSubject with a NON-ctx 2-value signature
// `(sub) (*User, bool)`. The resolve handler's lookupOrCreateUser must ALSO
// recognise that signature — otherwise the dev/test path silently mints a
// fresh GCID for an existing seeded user (the same class of bug as the
// production D0.1c, just on the inmem side).
func TestResolveIdentity_InmemRepo_ExistingUser_ReturnsCanonicalGCID(t *testing.T) {
	t.Parallel()

	const (
		seededGCID = "01970000-0000-7000-8000-00000000beef"
		fedSubject = "inmem-existing-fed-uid"
		email      = "existing@example.com"
	)
	users := inmem.NewUserRepository()
	if err := users.Save(context.Background(), &identity.User{
		Gcid:             seededGCID,
		Email:            email,
		IdentityProvider: identity.ProviderOIDC,
		FederatedSubject: fedSubject,
		Status:           identity.UserStatusActive,
	}); err != nil {
		t.Fatalf("seed inmem user: %v", err)
	}

	tc := &stubTenancyClient{
		resp: &httpadapter.MembershipsResolution{
			Memberships: []httpadapter.TenantMembership{{
				TenantID:   "01970000-0000-7000-8000-000000000001",
				TenantSlug: "academy-A",
				Roles:      []string{"learner"},
				Surfaces:   []string{"aplus"},
				IsDefault:  true,
			}},
			DefaultTenantID: "01970000-0000-7000-8000-000000000001",
		},
	}
	h := httpadapter.NewResolveHandler(httpadapter.ResolveHandlerConfig{
		Users:         users,
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
		t.Fatalf("decode body: %v", err)
	}
	if body.GCID != seededGCID {
		t.Fatalf("resolve returned GCID %q, want seeded %q — handler did not recognise the inmem FindByFederatedSubject signature",
			body.GCID, seededGCID)
	}
	if tc.lastGCIDArg != seededGCID {
		t.Errorf("chora-tenancy queried with GCID %q, want seeded %q", tc.lastGCIDArg, seededGCID)
	}
}

// byEmailCtxRepo exposes FindByEmail with the ctx-carrying 3-value
// signature — exercises the by-email lookup branch of lookupExistingUser.
type byEmailCtxRepo struct {
	byEmail map[string]*identity.User
	byGcid  map[string]*identity.User
	saved   []*identity.User
}

func newByEmailCtxRepo() *byEmailCtxRepo {
	return &byEmailCtxRepo{
		byEmail: make(map[string]*identity.User),
		byGcid:  make(map[string]*identity.User),
	}
}

func (r *byEmailCtxRepo) seed(u *identity.User) {
	clone := *u
	r.byEmail[strings.ToLower(u.Email)] = &clone
	r.byGcid[u.Gcid] = &clone
}

func (r *byEmailCtxRepo) Save(_ context.Context, u *identity.User) error {
	clone := *u
	r.byEmail[strings.ToLower(u.Email)] = &clone
	r.byGcid[u.Gcid] = &clone
	r.saved = append(r.saved, &clone)
	return nil
}

func (r *byEmailCtxRepo) GetByGcid(_ context.Context, gcid string) (*identity.User, error) {
	u, ok := r.byGcid[gcid]
	if !ok {
		return nil, identity.ErrUserNotFound
	}
	clone := *u
	return &clone, nil
}

func (r *byEmailCtxRepo) FindByEmail(_ context.Context, email string) (*identity.User, bool, error) {
	u, ok := r.byEmail[strings.ToLower(email)]
	if !ok {
		return nil, false, nil
	}
	clone := *u
	return &clone, true, nil
}

// TestResolveIdentity_ByEmailLookup_ExistingUser_ReturnsCanonicalGCID
// covers the by-email fallback branch of lookupExistingUser: a repo that
// has no FindByFederatedSubject but does expose FindByEmail must still
// return an existing user's canonical GCID rather than minting a fresh one.
func TestResolveIdentity_ByEmailLookup_ExistingUser_ReturnsCanonicalGCID(t *testing.T) {
	t.Parallel()

	const (
		canonicalGCID = "01970000-0000-7000-8000-0000000cafe1"
		fedSubject    = "by-email-fed-uid"
		email         = "byemail@example.com"
	)
	repo := newByEmailCtxRepo()
	repo.seed(&identity.User{
		Gcid:             canonicalGCID,
		Email:            email,
		IdentityProvider: identity.ProviderOIDC,
		FederatedSubject: fedSubject,
		Status:           identity.UserStatusActive,
	})

	tc := &stubTenancyClient{
		resp: &httpadapter.MembershipsResolution{
			Memberships: []httpadapter.TenantMembership{{
				TenantID:   "01970000-0000-7000-8000-000000000001",
				TenantSlug: "academy-A",
				Roles:      []string{"learner"},
				Surfaces:   []string{"aplus"},
				IsDefault:  true,
			}},
			DefaultTenantID: "01970000-0000-7000-8000-000000000001",
		},
	}
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
		t.Fatalf("decode body: %v", err)
	}
	if body.GCID != canonicalGCID {
		t.Fatalf("resolve returned GCID %q, want canonical %q — by-email lookup branch did not match",
			body.GCID, canonicalGCID)
	}
	if len(repo.saved) != 0 {
		t.Errorf("handler Save()d %d user(s); an existing user (found by email) must not be re-created", len(repo.saved))
	}
}

// TestResolveIdentity_NoLookupSupport_MintsFreshUser confirms the
// create-path is still reached when the wired repo exposes NEITHER a
// federated-subject NOR an email lookup — the minimal identity.User
// repository contract (Save + GetByGcid only).
func TestResolveIdentity_NoLookupSupport_MintsFreshUser(t *testing.T) {
	t.Parallel()
	tc := &stubTenancyClient{
		resp: &httpadapter.MembershipsResolution{
			Memberships: []httpadapter.TenantMembership{{
				TenantID:   "01970000-0000-7000-8000-000000000001",
				TenantSlug: "academy-A",
				Roles:      []string{"learner"},
				Surfaces:   []string{"aplus"},
				IsDefault:  true,
			}},
			DefaultTenantID: "01970000-0000-7000-8000-000000000001",
		},
	}
	repo := &minimalUserRepo{byGcid: make(map[string]*identity.User)}
	h := httpadapter.NewResolveHandler(httpadapter.ResolveHandlerConfig{
		Users:         repo,
		Tenancy:       tc,
		Events:        &stubEventPublisher{},
		SourceProject: "chora-local",
	})
	w := doResolve(t, h, map[string]any{
		"email":        "fresh@example.com",
		"firebase_uid": "fresh-fed-uid",
	})
	if w.Code != http.StatusOK {
		t.Fatalf("want 200 got %d body=%s", w.Code, w.Body.String())
	}
	var body httpadapter.ResolveIdentityResponse
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	if body.GCID == "" {
		t.Fatalf("gcid must be non-empty")
	}
	if len(repo.saved) != 1 {
		t.Errorf("expected exactly 1 Save() for a brand-new user, got %d", len(repo.saved))
	}
}

// minimalUserRepo implements ONLY identity.UserRepository (Save +
// GetByGcid) — no lookup extension methods at all.
type minimalUserRepo struct {
	byGcid map[string]*identity.User
	saved  []*identity.User
}

func (r *minimalUserRepo) Save(_ context.Context, u *identity.User) error {
	clone := *u
	r.byGcid[u.Gcid] = &clone
	r.saved = append(r.saved, &clone)
	return nil
}

func (r *minimalUserRepo) GetByGcid(_ context.Context, gcid string) (*identity.User, error) {
	u, ok := r.byGcid[gcid]
	if !ok {
		return nil, identity.ErrUserNotFound
	}
	clone := *u
	return &clone, nil
}

// -----------------------------------------------------------------------------
// Negative paths
// -----------------------------------------------------------------------------

func TestResolveIdentity_BadRequest_MissingEmail(t *testing.T) {
	t.Parallel()
	h, _, _, _ := newResolveFixture(t)
	w := doResolve(t, h, map[string]any{
		"firebase_uid": "x",
	})
	if w.Code != http.StatusBadRequest {
		t.Errorf("want 400 got %d", w.Code)
	}
}

func TestResolveIdentity_BadRequest_MissingFederatedSubject(t *testing.T) {
	t.Parallel()
	h, _, _, _ := newResolveFixture(t)
	w := doResolve(t, h, map[string]any{
		"email": "alice@example.com",
	})
	if w.Code != http.StatusBadRequest {
		t.Errorf("want 400 got %d", w.Code)
	}
}

func TestResolveIdentity_BadRequest_MalformedJSON(t *testing.T) {
	t.Parallel()
	h, _, _, _ := newResolveFixture(t)
	r := httptest.NewRequest(http.MethodPost, "/v1/identity/resolve",
		strings.NewReader("not-json"))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("want 400 got %d", w.Code)
	}
}

// CHO-1648 Phase 5 — empty memberships now returns 200 OK with
// Memberships: [] so chora-gateway can mint a bootstrap-mode JWT.
// Pre-Phase-5 this returned 404 IDENTITY_NO_TENANT_MEMBERSHIP.
func TestResolveIdentity_OK_ZeroMemberships(t *testing.T) {
	t.Parallel()
	h, tc, _, _ := newResolveFixture(t)
	tc.resp = &httpadapter.MembershipsResolution{
		Memberships:     nil,
		DefaultTenantID: "",
	}
	w := doResolve(t, h, map[string]any{
		"email":        "alice@example.com",
		"firebase_uid": "fed-sub-1",
	})
	if w.Code != http.StatusOK {
		t.Fatalf("want 200 for zero memberships (Phase 5), got %d body=%s", w.Code, w.Body.String())
	}
	var body map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	if body["gcid"] == nil || body["gcid"] == "" {
		t.Errorf("want gcid populated in 200 response, got %v", body)
	}
	memberships, _ := body["memberships"].([]any)
	if len(memberships) != 0 {
		t.Errorf("want memberships to be empty array, got %v", body["memberships"])
	}
}

// Defensive: the old 404 path is gone. Keep a vestigial test that
// asserts the new 200 contract for empty memberships so a future
// regression doesn't silently re-introduce the 404 (which would
// re-introduce the CHO-1648 circular dep).
func TestResolveIdentity_ZeroMemberships_NeverReturns404(t *testing.T) {
	t.Parallel()
	h, tc, _, _ := newResolveFixture(t)
	tc.resp = &httpadapter.MembershipsResolution{Memberships: nil, DefaultTenantID: ""}
	w := doResolve(t, h, map[string]any{
		"email":        "alice@example.com",
		"firebase_uid": "fed-sub-vestigial",
	})
	if w.Code == http.StatusNotFound {
		t.Fatalf("CHO-1648 regression: empty memberships must not 404, got %d body=%s",
			w.Code, w.Body.String())
	}
	var body map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	if body["code"] == "IDENTITY_NO_TENANT_MEMBERSHIP" {
		t.Fatal("CHO-1648 regression: IDENTITY_NO_TENANT_MEMBERSHIP body code must not appear")
	}
}

// -----------------------------------------------------------------------------
// ADR-182 auto-enrol: zero memberships at first resolve → enrol into the
// public chora-master tenant → re-list → respond with the enrolled
// membership. "Tenantless" users stop existing.
// -----------------------------------------------------------------------------

// sequencedTenancyClient returns a different resolution per call —
// models the list → enrol → re-list flow.
type sequencedTenancyClient struct {
	resps []*httpadapter.MembershipsResolution
	calls int
}

func (s *sequencedTenancyClient) ListMembershipsByGCID(_ context.Context, _ string) (*httpadapter.MembershipsResolution, error) {
	i := s.calls
	s.calls++
	if i >= len(s.resps) {
		i = len(s.resps) - 1
	}
	return s.resps[i], nil
}

type fakeEnroller struct {
	gotGCIDs []string
	err      error
}

func (f *fakeEnroller) EnsurePublicMembership(_ context.Context, gcid string) error {
	f.gotGCIDs = append(f.gotGCIDs, gcid)
	return f.err
}

func TestResolveIdentity_ZeroMemberships_AutoEnrolsPublicTenant(t *testing.T) {
	t.Parallel()
	choraMaster := httpadapter.TenantMembership{
		TenantID:   "00000000-0000-7000-8000-000000000001",
		TenantSlug: "chora-master",
		Roles:      []string{"author", "learner"},
		Surfaces:   []string{"aplus", "cplus"},
		IsDefault:  true,
	}
	tc := &sequencedTenancyClient{resps: []*httpadapter.MembershipsResolution{
		{Memberships: nil, DefaultTenantID: ""},
		{Memberships: []httpadapter.TenantMembership{choraMaster}, DefaultTenantID: choraMaster.TenantID},
	}}
	enr := &fakeEnroller{}
	h := httpadapter.NewResolveHandler(httpadapter.ResolveHandlerConfig{
		Users:    inmem.NewUserRepository(),
		Tenancy:  tc,
		Events:   &stubEventPublisher{},
		Enroller: enr,
	})

	w := doResolve(t, h, map[string]any{
		"email":        "fresh@example.com",
		"firebase_uid": "fed-sub-enrol",
	})
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d body=%s", w.Code, w.Body.String())
	}
	var body httpadapter.ResolveIdentityResponse
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(enr.gotGCIDs) != 1 || enr.gotGCIDs[0] != body.GCID {
		t.Fatalf("enroller calls: got %v want exactly [%s]", enr.gotGCIDs, body.GCID)
	}
	if tc.calls != 2 {
		t.Fatalf("tenancy list calls: got %d want 2 (list, re-list after enrol)", tc.calls)
	}
	if len(body.Memberships) != 1 || body.Memberships[0].TenantSlug != "chora-master" {
		t.Fatalf("memberships: got %+v want the chora-master enrolment", body.Memberships)
	}
	if body.DefaultTenantID != choraMaster.TenantID {
		t.Fatalf("default_tenant_id: got %q want %q", body.DefaultTenantID, choraMaster.TenantID)
	}
}

func TestResolveIdentity_NonZeroMemberships_EnrollerNotCalled(t *testing.T) {
	t.Parallel()
	users := inmem.NewUserRepository()
	tc := &stubTenancyClient{
		resp: &httpadapter.MembershipsResolution{
			Memberships: []httpadapter.TenantMembership{{
				TenantID:   "01970000-0000-7000-8000-000000000001",
				TenantSlug: "mightymind-academy",
				Roles:      []string{"learner"},
				Surfaces:   []string{"aplus"},
				IsDefault:  true,
			}},
			DefaultTenantID: "01970000-0000-7000-8000-000000000001",
		},
	}
	enr := &fakeEnroller{}
	h := httpadapter.NewResolveHandler(httpadapter.ResolveHandlerConfig{
		Users: users, Tenancy: tc, Events: &stubEventPublisher{}, Enroller: enr,
	})
	w := doResolve(t, h, map[string]any{
		"email":        "member@example.com",
		"firebase_uid": "fed-sub-member",
	})
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
	if len(enr.gotGCIDs) != 0 {
		t.Fatalf("enroller must not fire for members, got calls %v", enr.gotGCIDs)
	}
}

func TestResolveIdentity_EnrolFails_503(t *testing.T) {
	t.Parallel()
	tc := &sequencedTenancyClient{resps: []*httpadapter.MembershipsResolution{
		{Memberships: nil, DefaultTenantID: ""},
	}}
	enr := &fakeEnroller{err: errors.New("tenancy upsert down")}
	h := httpadapter.NewResolveHandler(httpadapter.ResolveHandlerConfig{
		Users: inmem.NewUserRepository(), Tenancy: tc, Events: &stubEventPublisher{}, Enroller: enr,
	})
	w := doResolve(t, h, map[string]any{
		"email":        "fresh@example.com",
		"firebase_uid": "fed-sub-enrolfail",
	})
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("want 503 on enrol failure, got %d body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "IDENTITY_ENROL_FAILED") {
		t.Fatalf("want IDENTITY_ENROL_FAILED code, body=%s", w.Body.String())
	}
}

// No enroller wired (dev mode / legacy tests) → empty memberships keep
// the Phase-5-era 200-with-empty contract; the gateway now treats that
// as an upstream inconsistency.
func TestResolveIdentity_NoEnroller_ZeroMemberships_Still200Empty(t *testing.T) {
	t.Parallel()
	h, tc, _, _ := newResolveFixture(t)
	tc.resp = &httpadapter.MembershipsResolution{Memberships: nil, DefaultTenantID: ""}
	w := doResolve(t, h, map[string]any{
		"email":        "alice@example.com",
		"firebase_uid": "fed-sub-noenroller",
	})
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
}

func TestResolveIdentity_TenancyUnavailable(t *testing.T) {
	t.Parallel()
	h, tc, _, _ := newResolveFixture(t)
	tc.err = errors.New("gRPC unavailable")
	w := doResolve(t, h, map[string]any{
		"email":        "alice@example.com",
		"firebase_uid": "fed-sub-1",
	})
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("want 503 got %d body=%s", w.Code, w.Body.String())
	}
}

func TestResolveIdentity_MethodNotAllowed(t *testing.T) {
	t.Parallel()
	h, _, _, _ := newResolveFixture(t)
	r := httptest.NewRequest(http.MethodGet, "/v1/identity/resolve", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("want 405 got %d", w.Code)
	}
}

// -----------------------------------------------------------------------------
// Event emission
// -----------------------------------------------------------------------------

func TestResolveIdentity_EmitsGCIDResolvedEvent(t *testing.T) {
	t.Parallel()
	h, _, ep, _ := newResolveFixture(t)
	_ = doResolve(t, h, map[string]any{
		"email":        "alice@example.com",
		"firebase_uid": "fed-sub-1",
	})
	if len(ep.events) != 1 {
		t.Fatalf("expected 1 event emitted, got %d", len(ep.events))
	}
	ev := ep.events[0]
	if ev.GCID == "" {
		t.Errorf("event gcid must be non-empty")
	}
	if ev.TenantID != "01970000-0000-7000-8000-000000000001" {
		t.Errorf("event tenant_id = %q", ev.TenantID)
	}
	if ev.IdempotencyKey == "" {
		t.Errorf("event idempotency_key must be populated (sha256(email+firebase_uid))")
	}
	if ev.MembershipsCount != 1 {
		t.Errorf("event memberships_count = %d, want 1", ev.MembershipsCount)
	}
}

func TestResolveIdentity_IdempotencyKeyDeterministic(t *testing.T) {
	t.Parallel()
	h, _, ep, _ := newResolveFixture(t)
	_ = doResolve(t, h, map[string]any{
		"email":        "alice@example.com",
		"firebase_uid": "fed-sub-1",
	})
	_ = doResolve(t, h, map[string]any{
		"email":        "alice@example.com",
		"firebase_uid": "fed-sub-1",
	})
	if len(ep.events) != 2 {
		t.Fatalf("expected 2 emits, got %d", len(ep.events))
	}
	if ep.events[0].IdempotencyKey != ep.events[1].IdempotencyKey {
		t.Errorf("idempotency_key must be deterministic for same (email, firebase_uid)")
	}
}
