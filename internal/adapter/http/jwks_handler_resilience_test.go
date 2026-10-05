// jwks_handler_resilience_test.go — resilience-hardening RED tests for the
// /.well-known/jwks.json endpoint per the resilience-priority directive
// (memory feedback_resilience_priority.md, 2026-05-10).
//
// Audit baseline (pre-patch): handler set Cache-Control: max-age=300 only.
// Gaps closed by these tests + the matching jwks_handler.go patch:
//
//  1. ETag — stable hash of the serialized JWKS body lets clients (Singpass
//     NDI, BFF, peer Identity-Platform federations) skip re-download when
//     key material is unchanged.
//  2. If-None-Match → 304 Not Modified — relieves the JWKS hot path under
//     key-rotation steady state without blocking rotation responsiveness.
//  3. stale-while-revalidate — keeps in-flight verification working even
//     when the JWKS provider is briefly unavailable on cache refresh.
//
// Out-of-scope (deferred to S1.4 + a follow-up Jira ticket):
//   - Last-Modified header. Requires adding LastModified() to the
//     jwks.Provider port, which cascades into the in-mem adapter, the future
//     Cloud KMS adapter, and the BFF JWKS-cache resilience consumer. ETag is
//     a strict superset of Last-Modified for our use case (handler computes
//     ETag from materialised bytes; no clock synchronisation needed).
package httpadapter_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	httpadapter "github.com/apollo-chora/chora-identity/internal/adapter/http"
	"github.com/apollo-chora/chora-identity/internal/domain/jwks"
)

// freshKeyPair returns a fakeJWKSProvider stub seeded with one EC + one RSA
// public key. Used as the deterministic input for ETag-stability checks.
func freshKeyPair(t *testing.T) *fakeJWKSProvider {
	t.Helper()
	ecPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ec keygen: %v", err)
	}
	rsaPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa keygen: %v", err)
	}
	return &fakeJWKSProvider{
		keys: []jwks.PublicKey{
			{KID: "ec-resilience-1", Alg: "ES256", EC: &ecPriv.PublicKey},
			{KID: "rsa-resilience-1", Alg: "RS256", RSA: &rsaPriv.PublicKey},
		},
	}
}

// TestJWKS_Resilience_EmitsETag asserts the handler emits an ETag header so
// downstream caches + clients can do conditional GETs.
func TestJWKS_Resilience_EmitsETag(t *testing.T) {
	t.Parallel()
	h := httpadapter.NewJWKSHandler(freshKeyPair(t))
	r := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status=%d", w.Code)
	}
	etag := w.Header().Get("ETag")
	if etag == "" {
		t.Fatalf("ETag header missing — clients cannot do conditional GETs")
	}
	// ETag must be quoted per RFC 7232 §2.3.
	if !strings.HasPrefix(etag, `"`) || !strings.HasSuffix(etag, `"`) {
		t.Errorf("ETag=%q must be quoted per RFC 7232 §2.3", etag)
	}
}

// TestJWKS_Resilience_ETag_StableAcrossRequests asserts the same key set
// produces the same ETag — i.e. ETag is content-derived, not random.
func TestJWKS_Resilience_ETag_StableAcrossRequests(t *testing.T) {
	t.Parallel()
	provider := freshKeyPair(t)
	h := httpadapter.NewJWKSHandler(provider)

	// Two back-to-back requests with no provider mutation must yield the same
	// ETag. If they don't, conditional GETs would never short-circuit.
	r1 := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	w1 := httptest.NewRecorder()
	h.ServeHTTP(w1, r1)

	r2 := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	w2 := httptest.NewRecorder()
	h.ServeHTTP(w2, r2)

	e1, e2 := w1.Header().Get("ETag"), w2.Header().Get("ETag")
	if e1 == "" || e2 == "" || e1 != e2 {
		t.Fatalf("ETag must be stable across requests — got %q vs %q", e1, e2)
	}
}

// TestJWKS_Resilience_ETag_ChangesOnKeyRotation asserts the ETag changes when
// the provider's key set changes. This is the rotation-responsiveness invariant.
func TestJWKS_Resilience_ETag_ChangesOnKeyRotation(t *testing.T) {
	t.Parallel()
	first := freshKeyPair(t)
	h1 := httpadapter.NewJWKSHandler(first)
	r1 := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	w1 := httptest.NewRecorder()
	h1.ServeHTTP(w1, r1)
	etag1 := w1.Header().Get("ETag")

	second := freshKeyPair(t) // distinct CSPRNG-generated keys
	h2 := httpadapter.NewJWKSHandler(second)
	r2 := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	w2 := httptest.NewRecorder()
	h2.ServeHTTP(w2, r2)
	etag2 := w2.Header().Get("ETag")

	if etag1 == "" || etag2 == "" {
		t.Fatalf("ETag missing — etag1=%q etag2=%q", etag1, etag2)
	}
	if etag1 == etag2 {
		t.Errorf("ETag must change across key rotation — etag1=%q etag2=%q", etag1, etag2)
	}
}

// TestJWKS_Resilience_IfNoneMatch_Returns304 asserts the handler honours
// If-None-Match per RFC 7232 §3.2 and short-circuits with 304 when the
// client-supplied tag matches the current key set.
func TestJWKS_Resilience_IfNoneMatch_Returns304(t *testing.T) {
	t.Parallel()
	h := httpadapter.NewJWKSHandler(freshKeyPair(t))

	// First request to learn the ETag.
	r1 := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	w1 := httptest.NewRecorder()
	h.ServeHTTP(w1, r1)
	etag := w1.Header().Get("ETag")
	if etag == "" {
		t.Fatalf("ETag missing on initial request")
	}

	// Second request with If-None-Match: same etag → 304.
	r2 := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	r2.Header.Set("If-None-Match", etag)
	w2 := httptest.NewRecorder()
	h.ServeHTTP(w2, r2)

	if w2.Code != http.StatusNotModified {
		t.Fatalf("status=%d want 304 Not Modified", w2.Code)
	}
	// Per RFC 7232 §4.1: 304 must echo the validators (ETag).
	if w2.Header().Get("ETag") != etag {
		t.Errorf("304 response must echo ETag header, got %q", w2.Header().Get("ETag"))
	}
	// Per RFC 7232 §4.1: 304 must NOT include a body.
	if w2.Body.Len() != 0 {
		t.Errorf("304 response must have empty body, got %d bytes", w2.Body.Len())
	}
}

// TestJWKS_Resilience_IfNoneMatch_StaleTagReturns200 asserts that if the
// client sends an outdated ETag (key rotation has happened), the handler
// returns 200 with the fresh body, not 304.
func TestJWKS_Resilience_IfNoneMatch_StaleTagReturns200(t *testing.T) {
	t.Parallel()
	h := httpadapter.NewJWKSHandler(freshKeyPair(t))

	// Send a synthetic If-None-Match that won't match the live ETag.
	r := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	r.Header.Set("If-None-Match", `"definitely-not-the-live-etag"`)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status=%d want 200 (stale tag must not short-circuit)", w.Code)
	}
	if w.Body.Len() == 0 {
		t.Errorf("200 response must include the JWKS body")
	}
}

// TestJWKS_Resilience_CacheControl_StaleWhileRevalidate asserts the handler
// emits stale-while-revalidate so transient JWKS-provider blips don't fail
// in-flight verification at intermediary CDNs / GCLB Cloud CDN.
func TestJWKS_Resilience_CacheControl_StaleWhileRevalidate(t *testing.T) {
	t.Parallel()
	h := httpadapter.NewJWKSHandler(freshKeyPair(t))
	r := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	cc := w.Header().Get("Cache-Control")
	if !strings.Contains(cc, "max-age=300") {
		t.Errorf("Cache-Control=%q missing max-age=300", cc)
	}
	if !strings.Contains(cc, "stale-while-revalidate") {
		t.Errorf("Cache-Control=%q missing stale-while-revalidate "+
			"— transient provider blips would propagate to verifiers", cc)
	}
}

// TestJWKS_Resilience_NonGet_NoETag asserts non-GET methods return 405 with
// no caching headers (avoid leaking cache state for unsupported methods).
func TestJWKS_Resilience_NonGet_NoETag(t *testing.T) {
	t.Parallel()
	h := httpadapter.NewJWKSHandler(freshKeyPair(t))
	r := httptest.NewRequest(http.MethodPost, "/.well-known/jwks.json", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status=%d want 405", w.Code)
	}
	if w.Header().Get("ETag") != "" {
		t.Errorf("ETag must not leak on 405")
	}
}
