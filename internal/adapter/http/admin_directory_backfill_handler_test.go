// Package httpadapter_test — RED-phase TDD specs for the admin-gated
// directory-projection backfill endpoint (CHO-2327).
//
// Route under test (admin_directory_backfill_handler.go):
//
//	POST /api/v1/admin/directory/backfill — re-emit chora.identity.user.profile_updated.v1
//	                                        for every live user with a non-empty display_name
//
// Why: chora-delivery.user_directory only ever projected the events identity
// emits on UpdateDisplayName, so members whose name predates the projection
// render as raw GCIDs on the R+ roster. This endpoint re-emits the projection
// for the whole directory so it catches up — using identity's OWN DB + outbox
// (no external creds). Authz is fail-closed via adminGate (mesh role + tenant).
package httpadapter_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	httpadapter "github.com/apollo-chora/chora-identity/internal/adapter/http"
)

const backfillAdminTenant = "01970000-0000-7000-8000-0000000000aa"

// stubBackfiller records the acting tenant + returns canned counts / error.
type stubBackfiller struct {
	scanned, emitted int
	err              error
	gotTenant        string
	called           int
}

func (s *stubBackfiller) BackfillProfileDirectory(_ context.Context, actingTenantID string) (int, int, error) {
	s.called++
	s.gotTenant = actingTenantID
	return s.scanned, s.emitted, s.err
}

func newBackfillMux(b httpadapter.ProfileDirectoryBackfiller) *http.ServeMux {
	mux := http.NewServeMux()
	httpadapter.NewAdminDirectoryBackfillHandler(b).RegisterRoutes(mux)
	return mux
}

const backfillPath = "/api/v1/admin/directory/backfill"

func TestDirectoryBackfill_HappyPath_ReturnsCountsAndPassesActingTenant(t *testing.T) {
	t.Parallel()
	b := &stubBackfiller{scanned: 12, emitted: 12}
	mux := newBackfillMux(b)

	req := adminKycReq(backfillPath, nil, "TENANT_ADMIN", backfillAdminTenant, "")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	if b.called != 1 {
		t.Fatalf("backfiller called %d times, want 1", b.called)
	}
	if b.gotTenant != backfillAdminTenant {
		t.Errorf("acting tenant = %q, want %q (envelope provenance)", b.gotTenant, backfillAdminTenant)
	}
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("invalid json body=%s: %v", w.Body.String(), err)
	}
	if body["scanned"] != float64(12) || body["emitted"] != float64(12) {
		t.Errorf("body = %v, want scanned=12 emitted=12", body)
	}
}

func TestDirectoryBackfill_NoAdminRole_403(t *testing.T) {
	t.Parallel()
	b := &stubBackfiller{}
	mux := newBackfillMux(b)

	req := adminKycReq(backfillPath, nil, "LEARNER", backfillAdminTenant, "")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body=%s", w.Code, w.Body.String())
	}
	if b.called != 0 {
		t.Errorf("backfiller must NOT run for a non-admin caller; called=%d", b.called)
	}
}

func TestDirectoryBackfill_NoTenantContext_401(t *testing.T) {
	t.Parallel()
	b := &stubBackfiller{}
	mux := newBackfillMux(b)

	req := adminKycReq(backfillPath, nil, "TENANT_ADMIN", "", "")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body=%s", w.Code, w.Body.String())
	}
	if b.called != 0 {
		t.Errorf("backfiller must NOT run without a tenant context; called=%d", b.called)
	}
}

func TestDirectoryBackfill_GET_405(t *testing.T) {
	t.Parallel()
	b := &stubBackfiller{}
	mux := newBackfillMux(b)

	req := httptest.NewRequest(http.MethodGet, backfillPath, nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405; body=%s", w.Code, w.Body.String())
	}
}

func TestDirectoryBackfill_BackfillerError_FailsLoud500(t *testing.T) {
	t.Parallel()
	b := &stubBackfiller{err: errors.New("pg: outbox insert timeout")}
	mux := newBackfillMux(b)

	req := adminKycReq(backfillPath, nil, "OWNER", backfillAdminTenant, "")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 (fail loud); body=%s", w.Code, w.Body.String())
	}
}

func TestDirectoryBackfill_NilBackfiller_WiringGuard500(t *testing.T) {
	t.Parallel()
	// A nil backfiller is a wiring bug — the handler must 500, never a silent 200.
	mux := newBackfillMux(nil)

	req := adminKycReq(backfillPath, nil, "TENANT_ADMIN", backfillAdminTenant, "")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 (nil-backfiller wiring guard); body=%s", w.Code, w.Body.String())
	}
}

// compile-time: ensure the stub satisfies the port the handler depends on.
var _ httpadapter.ProfileDirectoryBackfiller = (*stubBackfiller)(nil)
