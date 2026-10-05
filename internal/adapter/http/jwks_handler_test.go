// jwks_handler_test.go — RED-phase TDD specs for the chora-identity
// /.well-known/jwks.json endpoint (SP-4 + SP-5).
//
// Path A note: the JWKS Chora exposes here is the **chora-identity signing
// key set** (RS256 + ES256) used to sign Singpass NDI client-assertion JWTs
// (private_key_jwt grant) — not Singpass' own JWKS. The Singpass developer
// portal (Step 3 form) registers this endpoint as the RP JWKS URL so NDI
// can verify our client assertions.
//
// Production wiring loads keys from Cloud KMS via Secret Manager (S1.4 +
// secrets-and-env skill). This RED-phase test wires an in-memory provider
// so the handler is testable without external dependencies.
package httpadapter_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	httpadapter "github.com/apollo-chora/chora-identity/internal/adapter/http"
	"github.com/apollo-chora/chora-identity/internal/domain/jwks"
)

// -----------------------------------------------------------------------------
// in-memory JWKS provider — test-only helper
// -----------------------------------------------------------------------------

type fakeJWKSProvider struct {
	keys []jwks.PublicKey
}

func (f *fakeJWKSProvider) PublicKeys() []jwks.PublicKey { return f.keys }

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

func TestJWKS_Endpoint_ReturnsJWKSet(t *testing.T) {
	t.Parallel()

	// Stage one EC + one RSA public key.
	ecPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rsaPriv, _ := rsa.GenerateKey(rand.Reader, 2048)

	provider := &fakeJWKSProvider{
		keys: []jwks.PublicKey{
			{
				KID: "ec-test-1",
				Alg: "ES256",
				EC:  &ecPriv.PublicKey,
			},
			{
				KID: "rsa-test-1",
				Alg: "RS256",
				RSA: &rsaPriv.PublicKey,
			},
		},
	}

	h := httpadapter.NewJWKSHandler(provider)
	r := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if got := w.Header().Get("Content-Type"); !strings.Contains(got, "application/json") {
		t.Errorf("Content-Type=%q want application/json", got)
	}
	// Per spec: 5-min cache.
	if got := w.Header().Get("Cache-Control"); !strings.Contains(got, "max-age=300") {
		t.Errorf("Cache-Control=%q want max-age=300", got)
	}

	// Body shape: {"keys": [{...}, {...}]}.
	var body struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("invalid json: %v", err)
	}
	if len(body.Keys) != 2 {
		t.Fatalf("len(keys)=%d want 2", len(body.Keys))
	}

	// Sanity: each key has the canonical JWK fields per RFC 7517.
	seenEC, seenRSA := false, false
	for _, k := range body.Keys {
		if k["kid"] == "" {
			t.Errorf("missing kid")
		}
		if k["use"] != "sig" {
			t.Errorf("use=%v want sig", k["use"])
		}
		switch k["kty"] {
		case "EC":
			seenEC = true
			if k["crv"] != "P-256" {
				t.Errorf("crv=%v want P-256", k["crv"])
			}
			if k["alg"] != "ES256" {
				t.Errorf("alg=%v want ES256", k["alg"])
			}
			if k["x"] == "" || k["y"] == "" {
				t.Errorf("EC x/y missing")
			}
			// Public key only — no `d` (private scalar).
			if _, hasD := k["d"]; hasD {
				t.Errorf("EC key leaks private scalar `d`")
			}
		case "RSA":
			seenRSA = true
			if k["alg"] != "RS256" {
				t.Errorf("alg=%v want RS256", k["alg"])
			}
			if k["n"] == "" || k["e"] == "" {
				t.Errorf("RSA n/e missing")
			}
			// Public key only — no `d`/`p`/`q` private params.
			for _, priv := range []string{"d", "p", "q", "dp", "dq", "qi"} {
				if _, has := k[priv]; has {
					t.Errorf("RSA key leaks private param %q", priv)
				}
			}
		default:
			t.Errorf("kty=%v not EC/RSA", k["kty"])
		}
	}
	if !seenEC || !seenRSA {
		t.Errorf("expected one EC + one RSA key; saw EC=%v RSA=%v", seenEC, seenRSA)
	}
}

func TestJWKS_Endpoint_RejectsNonGet(t *testing.T) {
	t.Parallel()
	h := httpadapter.NewJWKSHandler(&fakeJWKSProvider{})
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch} {
		r := httptest.NewRequest(method, "/.well-known/jwks.json", nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s: status=%d want 405", method, w.Code)
		}
	}
}

func TestJWKS_Endpoint_EmptyProvider_ReturnsEmptyKeySet(t *testing.T) {
	t.Parallel()
	h := httpadapter.NewJWKSHandler(&fakeJWKSProvider{})
	r := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d", w.Code)
	}
	var body struct {
		Keys []map[string]any `json:"keys"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	if len(body.Keys) != 0 {
		t.Errorf("len(keys)=%d want 0", len(body.Keys))
	}
}

// TestJWKS_PublicKey_MarshalEC asserts the domain MarshalEC helper produces
// canonical RFC 7517 §6.2.1 JWK encoding.
func TestJWKS_PublicKey_MarshalEC_RFC7517(t *testing.T) {
	t.Parallel()
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pk := jwks.PublicKey{KID: "ec-1", Alg: "ES256", EC: &priv.PublicKey}
	jwk := pk.AsJWK()

	if jwk["kty"] != "EC" || jwk["crv"] != "P-256" || jwk["alg"] != "ES256" {
		t.Errorf("EC base fields wrong: %+v", jwk)
	}
	if jwk["use"] != "sig" {
		t.Errorf("use=%v", jwk["use"])
	}
	xStr, ok := jwk["x"].(string)
	if !ok || xStr == "" {
		t.Errorf("x missing/empty")
	}
	// x must be base64url (no padding) → decode roundtrip.
	if _, err := base64.RawURLEncoding.DecodeString(xStr); err != nil {
		t.Errorf("x not base64url: %v", err)
	}
}

// TestJWKS_PublicKey_MarshalRSA asserts canonical RFC 7517 §6.3.1 JWK encoding.
func TestJWKS_PublicKey_MarshalRSA_RFC7517(t *testing.T) {
	t.Parallel()
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	pk := jwks.PublicKey{KID: "rsa-1", Alg: "RS256", RSA: &priv.PublicKey}
	jwk := pk.AsJWK()

	if jwk["kty"] != "RSA" || jwk["alg"] != "RS256" {
		t.Errorf("RSA base fields wrong: %+v", jwk)
	}
	nStr, _ := jwk["n"].(string)
	eStr, _ := jwk["e"].(string)
	if nStr == "" || eStr == "" {
		t.Errorf("n/e missing")
	}
	if _, err := base64.RawURLEncoding.DecodeString(nStr); err != nil {
		t.Errorf("n not base64url: %v", err)
	}
	if _, err := base64.RawURLEncoding.DecodeString(eStr); err != nil {
		t.Errorf("e not base64url: %v", err)
	}
}
