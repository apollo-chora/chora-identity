// jwks_handler.go — GET /.well-known/jwks.json (SP-4 + SP-5).
//
// Serves chora-identity's public signing key set so external relying parties
// (Singpass NDI per Path A, plus future Identity-Platform federation peers)
// can verify JWTs Chora signs as the OIDC client (private_key_jwt grant).
//
// Cache + resilience headers (per memory feedback_resilience_priority.md):
//
//   - Cache-Control: public, max-age=300, stale-while-revalidate=60
//     5-minute fresh window keeps key rotation responsive; the 60-second
//     stale-while-revalidate window lets intermediary caches (Cloud CDN,
//     verifier-side JWKS caches) keep serving the previous body while
//     fetching a fresh one — prevents transient provider blips from
//     propagating to in-flight verification.
//   - ETag: strong validator computed as the SHA-256 of the canonicalised
//     JWKS body. RFC 7232 §2.3 — quoted, opaque, content-derived.
//   - If-None-Match: clients short-circuit with 304 Not Modified when
//     their cached body's tag still matches the live key set.
//
// Last-Modified is intentionally NOT emitted — ETag is a strict superset
// for our use case (the body is materialised on each request anyway, no
// need for a separate clock-based validator). Adding LastModified() to
// the jwks.Provider port is tracked as a follow-up Jira when the Cloud
// KMS-backed adapter lands (S1.4).
//
// Hexagonal: this adapter depends on jwks.Provider. The provider port is
// implemented by:
//
//   - adapter/jwksinmem (in-process dev key, generated at boot)
//   - future Cloud KMS-backed adapter (S1.4 + secrets-and-env skill)
//
// All key material flows from env-driven config — no inline keys per the
// no-inline-config rule. The `kid` is a stable label across rotations of
// the same logical key.
//
// Rate limiting is delegated to GCLB + Cloud Armor in front of the service
// per Tier 4 D16 — the handler does not maintain in-process rate state so
// that pod restarts don't reset attacker quotas.
package httpadapter

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"sort"

	"github.com/apollo-chora/chora-identity/internal/domain/jwks"
)

// JWKSHandler exposes /.well-known/jwks.json.
type JWKSHandler struct {
	provider jwks.Provider
}

// NewJWKSHandler constructs the handler.
func NewJWKSHandler(provider jwks.Provider) *JWKSHandler {
	return &JWKSHandler{provider: provider}
}

// ServeHTTP implements http.Handler.
func (h *JWKSHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "GET only")
		return
	}

	body, etag := h.materialise()

	// Always emit the validator + cache directives, even on 304.
	w.Header().Set("ETag", etag)
	// 5-min fresh; 60-sec stale-while-revalidate buffers transient provider
	// blips at intermediary caches (Cloud CDN / verifier JWKS caches).
	w.Header().Set("Cache-Control", "public, max-age=300, stale-while-revalidate=60")

	// RFC 7232 §3.2 — If-None-Match short-circuit.
	if matchesIfNoneMatch(r.Header.Get("If-None-Match"), etag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

// materialise serialises the current JWKS body and computes its strong ETag.
// Keys are sorted by KID before hashing so ETag is deterministic across
// provider implementations that may return slices in non-deterministic order
// (e.g. a future Cloud KMS adapter that walks Secret Manager versions in
// async batch order).
func (h *JWKSHandler) materialise() (body []byte, etag string) {
	keys := h.provider.PublicKeys()
	jwkSet := make([]map[string]any, 0, len(keys))
	for _, k := range keys {
		jwkSet = append(jwkSet, k.AsJWK())
	}
	// Stable order for deterministic ETag — sort by `kid` field.
	sort.SliceStable(jwkSet, func(i, j int) bool {
		ki, _ := jwkSet[i]["kid"].(string)
		kj, _ := jwkSet[j]["kid"].(string)
		return ki < kj
	})
	wrap := struct {
		Keys []map[string]any `json:"keys"`
	}{Keys: jwkSet}
	body, _ = json.Marshal(wrap)
	sum := sha256.Sum256(body)
	// RFC 7232 §2.3 — strong validator, quoted, opaque to clients.
	etag = `"` + hex.EncodeToString(sum[:]) + `"`
	return body, etag
}

// matchesIfNoneMatch implements RFC 7232 §3.2 If-None-Match comparison
// against the supplied current entity tag. Supports the wildcard ("*"),
// single tags, and comma-separated tag lists. Whitespace and weak prefix
// (W/) are tolerated — JWKS is idempotent so weak-vs-strong distinction
// is not security-relevant here.
func matchesIfNoneMatch(headerVal, currentTag string) bool {
	if headerVal == "" {
		return false
	}
	if headerVal == "*" {
		return true
	}
	// Split on commas, trim whitespace + optional "W/" prefix per §2.3.
	start := 0
	for i := 0; i <= len(headerVal); i++ {
		if i != len(headerVal) && headerVal[i] != ',' {
			continue
		}
		tag := headerVal[start:i]
		start = i + 1
		// Trim leading/trailing whitespace.
		for len(tag) > 0 && (tag[0] == ' ' || tag[0] == '\t') {
			tag = tag[1:]
		}
		for len(tag) > 0 && (tag[len(tag)-1] == ' ' || tag[len(tag)-1] == '\t') {
			tag = tag[:len(tag)-1]
		}
		if len(tag) >= 2 && tag[0] == 'W' && tag[1] == '/' {
			tag = tag[2:]
		}
		if tag == currentTag {
			return true
		}
	}
	return false
}

// RegisterRoutes mounts the JWKS endpoint on a mux. The route is
// unauthenticated — public key material is by design world-readable.
func (h *JWKSHandler) RegisterRoutes(mux *http.ServeMux) {
	mux.Handle("/.well-known/jwks.json", h)
}
