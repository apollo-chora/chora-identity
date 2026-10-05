// middleware_test.go — coverage for the composed middleware in middleware.go:
//
//   - tenantContext: X-Tenant-Id / gcid header extraction, the X-Chora-GCID
//     fallback, protected-path rejection (400 IDENTITY_TENANT_REQUIRED /
//     IDENTITY_GCID_REQUIRED), and public-path (/healthz, /me) passthrough.
//   - logging: the three correlation branches — traceparent present, gcid-only,
//     and bare method/path.
//
// Internal package (httpadapter) so the unexported tenantFromContext /
// gcidFromContext can be asserted directly.
package httpadapter

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// mdwTenantID + mdwGcid are the canonical header pair used across the
// middleware specs below.
const (
	mdwTenantID = "01970000-0000-7000-8000-0000000000aa"
	mdwGcid     = "01970000-0000-7000-8000-0000000ac103"
)

// mdwRecorder is a next-handler that records whether it was reached plus the
// tenant_id/gcid the tenantContext middleware extracted onto the context.
type mdwRecorder struct {
	called bool
	method string
	path   string
	tenant string
	gcid   string
}

func (m *mdwRecorder) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	m.called = true
	m.method = r.Method
	m.path = r.URL.Path
	m.tenant = tenantFromContext(r.Context())
	m.gcid = gcidFromContext(r.Context())
}

// -----------------------------------------------------------------------------
// tenantContext — protected-path rejection
// -----------------------------------------------------------------------------

func TestMDW_TenantContext_RejectsMissingTenant(t *testing.T) {
	t.Parallel()
	next := &mdwRecorder{}
	r := httptest.NewRequest(http.MethodGet, "/api/users", nil)
	r.Header.Set("gcid", mdwGcid) // gcid present, X-Tenant-Id absent
	w := httptest.NewRecorder()
	tenantContext(next).ServeHTTP(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status=%d want 400; body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "IDENTITY_TENANT_REQUIRED") {
		t.Errorf("body=%q want fragment IDENTITY_TENANT_REQUIRED", w.Body.String())
	}
	if next.called {
		t.Error("next handler must not run when X-Tenant-Id is missing")
	}
}

func TestMDW_TenantContext_RejectsMissingGcid(t *testing.T) {
	t.Parallel()
	next := &mdwRecorder{}
	r := httptest.NewRequest(http.MethodGet, "/api/users", nil)
	r.Header.Set("X-Tenant-Id", mdwTenantID) // tenant present, no gcid header
	w := httptest.NewRecorder()
	tenantContext(next).ServeHTTP(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status=%d want 400; body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "IDENTITY_GCID_REQUIRED") {
		t.Errorf("body=%q want fragment IDENTITY_GCID_REQUIRED", w.Body.String())
	}
	if next.called {
		t.Error("next handler must not run when gcid is missing")
	}
	if !strings.Contains(w.Body.String(), "gcid") {
		t.Errorf("body=%q should name the gcid header", w.Body.String())
	}
}

// -----------------------------------------------------------------------------
// tenantContext — happy path + X-Chora-GCID fallback
// -----------------------------------------------------------------------------

func TestMDW_TenantContext_StoresTenantAndGcid(t *testing.T) {
	t.Parallel()
	next := &mdwRecorder{}
	r := httptest.NewRequest(http.MethodGet, "/api/users", nil)
	r.Header.Set("X-Tenant-Id", mdwTenantID)
	r.Header.Set("gcid", mdwGcid)
	w := httptest.NewRecorder()
	tenantContext(next).ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status=%d want 200; body=%s", w.Code, w.Body.String())
	}
	if !next.called {
		t.Fatal("next handler was not reached")
	}
	if next.tenant != mdwTenantID {
		t.Errorf("tenantFromContext=%q want %q", next.tenant, mdwTenantID)
	}
	if next.gcid != mdwGcid {
		t.Errorf("gcidFromContext=%q want %q", next.gcid, mdwGcid)
	}
}

func TestMDW_TenantContext_XChoraGCIDFallback(t *testing.T) {
	t.Parallel()
	next := &mdwRecorder{}
	r := httptest.NewRequest(http.MethodGet, "/api/users", nil)
	r.Header.Set("X-Tenant-Id", mdwTenantID)
	r.Header.Set("X-Chora-GCID", mdwGcid) // aliased gcid header, no `gcid`
	w := httptest.NewRecorder()
	tenantContext(next).ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status=%d want 200; body=%s", w.Code, w.Body.String())
	}
	if !next.called {
		t.Fatal("next handler was not reached")
	}
	if next.tenant != mdwTenantID {
		t.Errorf("tenantFromContext=%q want %q", next.tenant, mdwTenantID)
	}
	if next.gcid != mdwGcid {
		t.Errorf("gcidFromContext=%q want %q (must pick up X-Chora-GCID)", next.gcid, mdwGcid)
	}
}

// -----------------------------------------------------------------------------
// tenantContext — public paths bypass extraction
// -----------------------------------------------------------------------------

func TestMDW_TenantContext_PublicPathsBypass(t *testing.T) {
	t.Parallel()
	for _, path := range []string{"/healthz", "/healthz/", "/me", "/me/roles", "/"} {
		next := &mdwRecorder{}
		r := httptest.NewRequest(http.MethodGet, path, nil) // no tenant/gcid headers
		w := httptest.NewRecorder()
		tenantContext(next).ServeHTTP(w, r)

		if w.Code != http.StatusOK {
			t.Errorf("%s: status=%d want 200; body=%s", path, w.Code, w.Body.String())
		}
		if !next.called {
			t.Errorf("%s: public path must pass through to next", path)
		}
		if next.tenant != "" || next.gcid != "" {
			t.Errorf("%s: public path must not inject tenant/gcid, got %q/%q",
				path, next.tenant, next.gcid)
		}
	}
}

// -----------------------------------------------------------------------------
// logging — the three correlation branches
// -----------------------------------------------------------------------------

func TestMDW_Logging_WithTraceparent(t *testing.T) {
	t.Parallel()
	next := &mdwRecorder{}
	r := httptest.NewRequest(http.MethodGet, "/api/users", nil)
	r.Header.Set("gcid", mdwGcid)
	r.Header.Set("traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
	w := httptest.NewRecorder()
	logging(next).ServeHTTP(w, r)

	if !next.called {
		t.Fatal("next handler was not reached")
	}
}

func TestMDW_Logging_WithGcidOnly(t *testing.T) {
	t.Parallel()
	next := &mdwRecorder{}
	r := httptest.NewRequest(http.MethodGet, "/api/users", nil)
	r.Header.Set("gcid", mdwGcid) // no traceparent
	w := httptest.NewRecorder()
	logging(next).ServeHTTP(w, r)

	if !next.called {
		t.Fatal("next handler was not reached")
	}
}

func TestMDW_Logging_Plain(t *testing.T) {
	t.Parallel()
	next := &mdwRecorder{}
	r := httptest.NewRequest(http.MethodGet, "/api/users", nil) // neither header
	w := httptest.NewRecorder()
	logging(next).ServeHTTP(w, r)

	if !next.called {
		t.Fatal("next handler was not reached")
	}
}
