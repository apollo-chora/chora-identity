// jwks_handler_extra_test.go — additional coverage for jwks_handler.go:
//
//   - RegisterRoutes: mounting the endpoint on a ServeMux and serving it,
//     including the conditional-GET (If-None-Match → 304) round trip.
//   - matchesIfNoneMatch: the comma-list / whitespace / weak-prefix (W/)
//     comparison branches of RFC 7232 §3.2, driven through ServeHTTP.
//
// The fakeJWKSProvider + freshKeyPair helpers come from the pre-existing
// jwks_handler_test.go / jwks_handler_resilience_test.go (external package);
// new identifiers carry the jkx_ prefix.
package httpadapter_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	httpadapter "github.com/apollo-chora/chora-identity/internal/adapter/http"
)

// jkxFirstETag performs a plain GET and returns the handler's ETag, used as the
// current validator for the conditional-GET specs below.
func jkxFirstETag(t *testing.T, h http.Handler) string {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("initial GET status=%d body=%s", w.Code, w.Body.String())
	}
	etag := w.Header().Get("ETag")
	if etag == "" {
		t.Fatalf("initial GET did not emit ETag")
	}
	return etag
}

// jkxConditionalGet replays a GET with the given If-None-Match header value.
func jkxConditionalGet(h http.Handler, inm string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	if inm != "" {
		r.Header.Set("If-None-Match", inm)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

// -----------------------------------------------------------------------------
// RegisterRoutes — mux mounting (0% baseline at line 153)
// -----------------------------------------------------------------------------

func TestJWKS_Extra_RegisterRoutes_MountsEndpoint(t *testing.T) {
	t.Parallel()
	h := httpadapter.NewJWKSHandler(freshKeyPair(t))
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	// Fresh GET through the mounted route.
	w := jkxConditionalGet(mux, "")
	if w.Code != http.StatusOK {
		t.Fatalf("mounted GET status=%d want 200; body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"keys"`) {
		t.Errorf("body=%q want JWKS keys array", w.Body.String())
	}
	etag := w.Header().Get("ETag")
	if etag == "" {
		t.Fatalf("mounted GET did not emit ETag")
	}

	// Conditional GET with the learned ETag → 304 Not Modified.
	w2 := jkxConditionalGet(mux, etag)
	if w2.Code != http.StatusNotModified {
		t.Fatalf("conditional GET status=%d want 304", w2.Code)
	}
	if w2.Body.Len() != 0 {
		t.Errorf("304 body must be empty, got %d bytes", w2.Body.Len())
	}
}

// -----------------------------------------------------------------------------
// If-None-Match comparison branches (line 119)
// -----------------------------------------------------------------------------

func TestJWKS_Extra_IfNoneMatch_Wildcard(t *testing.T) {
	t.Parallel()
	h := httpadapter.NewJWKSHandler(freshKeyPair(t))
	w := jkxConditionalGet(h, "*")
	if w.Code != http.StatusNotModified {
		t.Fatalf("wildcard status=%d want 304", w.Code)
	}
	if w.Body.Len() != 0 {
		t.Errorf("304 body must be empty, got %d bytes", w.Body.Len())
	}
}

func TestJWKS_Extra_IfNoneMatch_CommaListWithWeakPrefix(t *testing.T) {
	t.Parallel()
	h := httpadapter.NewJWKSHandler(freshKeyPair(t))
	etag := jkxFirstETag(t, h)

	// Comma-separated list mixing a weak-tagged stale tag + the live strong tag.
	inm := `W/"stale-tag", ` + etag
	w := jkxConditionalGet(h, inm)
	if w.Code != http.StatusNotModified {
		t.Fatalf("list status=%d want 304 (header=%q)", w.Code, inm)
	}
}

func TestJWKS_Extra_IfNoneMatch_WhitespacePaddedList(t *testing.T) {
	t.Parallel()
	h := httpadapter.NewJWKSHandler(freshKeyPair(t))
	etag := jkxFirstETag(t, h)

	// Leading/trailing whitespace + tab around the tags.
	inm := " \t" + etag + " ,\t\"other-tag\" "
	w := jkxConditionalGet(h, inm)
	if w.Code != http.StatusNotModified {
		t.Fatalf("padded-list status=%d want 304 (header=%q)", w.Code, inm)
	}
}

func TestJWKS_Extra_IfNoneMatch_WeakPrefixOnly(t *testing.T) {
	t.Parallel()
	h := httpadapter.NewJWKSHandler(freshKeyPair(t))
	etag := jkxFirstETag(t, h)

	// Weak-prefixed single tag: W/"<etag>" — the W/ prefix is stripped and the
	// quoted tag compares equal.
	inm := "W/" + etag
	w := jkxConditionalGet(h, inm)
	if w.Code != http.StatusNotModified {
		t.Fatalf("weak-prefix status=%d want 304 (header=%q)", w.Code, inm)
	}
}

func TestJWKS_Extra_IfNoneMatch_NonMatchingList_200(t *testing.T) {
	t.Parallel()
	h := httpadapter.NewJWKSHandler(freshKeyPair(t))

	// A list that contains neither the wildcard nor the live tag must NOT
	// short-circuit — a fresh 200 body is served.
	w := jkxConditionalGet(h, `"aaa", "bbb"`)
	if w.Code != http.StatusOK {
		t.Fatalf("non-matching list status=%d want 200", w.Code)
	}
	if !strings.Contains(w.Body.String(), `"keys"`) {
		t.Errorf("body=%q want JWKS keys array", w.Body.String())
	}
}
