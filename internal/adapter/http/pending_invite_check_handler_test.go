// pending_invite_check_handler_test.go — behaviour specs for the CHO-2205
// read-only pending-invite check endpoint (GET /api/v1/internal/pending-invite).
// The gateway mint allowlist reads through to live cold-invites via this
// endpoint so an admin-invited email authorizes its own first sign-in without
// a static-allowlist secret patch. PURE READ — no GCID mint, no membership write.
package httpadapter

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/apollo-chora/chora-identity/internal/domain/identity"
)

// stubInviteLookup records the email it was asked about (to assert the handler
// normalises before lookup) and returns configurable matches/err. It exposes
// ONLY MatchByEmail — the read-only contract has no MarkAccepted, so a write
// is structurally impossible on this port.
type stubInviteLookup struct {
	matches   []identity.PendingInviteMatch
	err       error
	calls     int
	lastEmail string
}

func (s *stubInviteLookup) MatchByEmail(_ context.Context, email string) ([]identity.PendingInviteMatch, error) {
	s.calls++
	s.lastEmail = email
	return s.matches, s.err
}

// stubKnownUser — CHO-2207 known-member lookup stub.
type stubKnownUser struct {
	found bool
	err   error
	calls int
}

func (s *stubKnownUser) FindByEmail(_ context.Context, _ string) (*identity.User, bool, error) {
	s.calls++
	if s.err != nil {
		return nil, false, s.err
	}
	if s.found {
		return &identity.User{}, true, nil
	}
	return nil, false, nil
}

func doInviteCheck(t *testing.T, lookup PendingInviteLookup, method, target string) *httptest.ResponseRecorder {
	t.Helper()
	return doInviteCheckWith(t, lookup, nil, method, target)
}

func doInviteCheckWith(t *testing.T, lookup PendingInviteLookup, knownUser KnownUserLookup, method, target string) *httptest.ResponseRecorder {
	t.Helper()
	h := NewPendingInviteCheckHandler(lookup, knownUser)
	if h == nil {
		t.Fatal("NewPendingInviteCheckHandler returned nil for a non-nil lookup")
	}
	r := httptest.NewRequest(method, target, nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func decodeIsKnownUser(t *testing.T, w *httptest.ResponseRecorder) bool {
	t.Helper()
	var out struct {
		IsKnownUser bool `json:"is_known_user"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode body %q: %v", w.Body.String(), err)
	}
	return out.IsKnownUser
}

func decodeHasPendingInvite(t *testing.T, w *httptest.ResponseRecorder) bool {
	t.Helper()
	var out struct {
		HasPendingInvite bool `json:"has_pending_invite"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode body %q: %v", w.Body.String(), err)
	}
	return out.HasPendingInvite
}

func TestPendingInviteCheck_LiveInvite_True(t *testing.T) {
	lookup := &stubInviteLookup{matches: []identity.PendingInviteMatch{
		{InviteID: "i1", TenantID: "t1", Roles: []string{"learner"}},
	}}
	w := doInviteCheck(t, lookup, http.MethodGet, "/api/v1/internal/pending-invite?email=bob@example.com")
	if w.Code != http.StatusOK {
		t.Fatalf("want 200 got %d body=%s", w.Code, w.Body.String())
	}
	if !decodeHasPendingInvite(t, w) {
		t.Error("want has_pending_invite=true")
	}
	if lookup.calls != 1 {
		t.Errorf("want exactly 1 MatchByEmail call, got %d", lookup.calls)
	}
}

func TestPendingInviteCheck_NoInvite_False(t *testing.T) {
	lookup := &stubInviteLookup{matches: nil}
	w := doInviteCheck(t, lookup, http.MethodGet, "/api/v1/internal/pending-invite?email=nobody@example.com")
	if w.Code != http.StatusOK {
		t.Fatalf("want 200 got %d body=%s", w.Code, w.Body.String())
	}
	if decodeHasPendingInvite(t, w) {
		t.Error("want has_pending_invite=false for zero matches")
	}
}

func TestPendingInviteCheck_NormalisesEmail(t *testing.T) {
	// Handler lower-cases + trims before the lookup (defence in depth; the pg
	// matcher normalises too). A plus-tag is preserved (distinct sub-address —
	// dale+dodlearner@ is NOT dale@).
	lookup := &stubInviteLookup{}
	_ = doInviteCheck(t, lookup, http.MethodGet, "/api/v1/internal/pending-invite?email=%20Bob%2BTag@Example.COM%20")
	if lookup.lastEmail != "bob+tag@example.com" {
		t.Errorf("lookup saw %q, want bob+tag@example.com", lookup.lastEmail)
	}
}

func TestPendingInviteCheck_MissingEmail_400(t *testing.T) {
	lookup := &stubInviteLookup{}
	w := doInviteCheck(t, lookup, http.MethodGet, "/api/v1/internal/pending-invite")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400 got %d", w.Code)
	}
	if lookup.calls != 0 {
		t.Errorf("must not hit the store for a missing email, got %d calls", lookup.calls)
	}
}

func TestPendingInviteCheck_WrongMethod_405(t *testing.T) {
	w := doInviteCheck(t, &stubInviteLookup{}, http.MethodPost, "/api/v1/internal/pending-invite?email=x@example.com")
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("want 405 got %d", w.Code)
	}
	if got := w.Header().Get("Allow"); got != "GET" {
		t.Errorf("want Allow: GET got %q", got)
	}
}

func TestPendingInviteCheck_LookupError_503(t *testing.T) {
	lookup := &stubInviteLookup{err: errors.New("db down")}
	w := doInviteCheck(t, lookup, http.MethodGet, "/api/v1/internal/pending-invite?email=x@example.com")
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("want 503 got %d body=%s", w.Code, w.Body.String())
	}
}

func TestNewPendingInviteCheckHandler_NilLookup(t *testing.T) {
	if NewPendingInviteCheckHandler(nil, nil) != nil {
		t.Fatal("want nil handler for a nil lookup (route stays unmounted rather than binding a fake)")
	}
}

// --- CHO-2207: mint authorizes an existing member on re-authentication -------

func TestPendingInviteCheck_KnownUser_NoInvite_IsKnownUserTrue(t *testing.T) {
	// The invite was consumed at first sign-in (no live pending invite), but the
	// user row exists — re-authentication must be authorized.
	lookup := &stubInviteLookup{matches: nil}
	known := &stubKnownUser{found: true}
	w := doInviteCheckWith(t, lookup, known, http.MethodGet, "/api/v1/internal/pending-invite?email=dale@example.com")
	if w.Code != http.StatusOK {
		t.Fatalf("want 200 got %d body=%s", w.Code, w.Body.String())
	}
	if decodeHasPendingInvite(t, w) {
		t.Error("want has_pending_invite=false (invite consumed)")
	}
	if !decodeIsKnownUser(t, w) {
		t.Error("want is_known_user=true for an existing member")
	}
	if known.calls != 1 {
		t.Errorf("want exactly 1 FindByEmail call, got %d", known.calls)
	}
}

func TestPendingInviteCheck_PendingInvite_ShortCircuitsUserLookup(t *testing.T) {
	// A live pending invite already authorizes — the user lookup must NOT run
	// (saves a query + prevents a user-lookup error masking a valid invite).
	lookup := &stubInviteLookup{matches: []identity.PendingInviteMatch{{InviteID: "i1"}}}
	known := &stubKnownUser{err: errors.New("must not be called")}
	w := doInviteCheckWith(t, lookup, known, http.MethodGet, "/api/v1/internal/pending-invite?email=x@example.com")
	if w.Code != http.StatusOK {
		t.Fatalf("want 200 got %d body=%s", w.Code, w.Body.String())
	}
	if !decodeHasPendingInvite(t, w) {
		t.Error("want has_pending_invite=true")
	}
	if known.calls != 0 {
		t.Errorf("user lookup must be short-circuited by a pending invite, got %d calls", known.calls)
	}
}

func TestPendingInviteCheck_UnknownEmail_BothFalse(t *testing.T) {
	lookup := &stubInviteLookup{matches: nil}
	known := &stubKnownUser{found: false}
	w := doInviteCheckWith(t, lookup, known, http.MethodGet, "/api/v1/internal/pending-invite?email=stranger@example.com")
	if w.Code != http.StatusOK {
		t.Fatalf("want 200 got %d", w.Code)
	}
	if decodeHasPendingInvite(t, w) || decodeIsKnownUser(t, w) {
		t.Error("a brand-new stranger must be neither invited nor known")
	}
}

func TestPendingInviteCheck_UserLookupError_503(t *testing.T) {
	lookup := &stubInviteLookup{matches: nil}
	known := &stubKnownUser{err: errors.New("db down")}
	w := doInviteCheckWith(t, lookup, known, http.MethodGet, "/api/v1/internal/pending-invite?email=x@example.com")
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("want 503 (fail-closed) got %d body=%s", w.Code, w.Body.String())
	}
}
