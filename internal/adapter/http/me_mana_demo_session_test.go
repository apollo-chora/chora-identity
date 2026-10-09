// me_mana_demo_session_test.go — the authentication boundary for
// POST /api/v1/me/mana/demo-grant.
//
// The endpoint used to sit behind bearerAuth, which resolves the caller from
// `chora-gcid` / `gcid` headers or a raw-GCID Bearer token and then only checks
// that the GCID EXISTS in the user repository — existence checking, not
// authentication. Any caller able to reach identity and name an allowlisted
// GCID therefore obtained that account's authority over a free mana grant.
//
// These specs pin the replacement boundary: a Chora session JWT verified with
// the SAME chorasession.Validator chora-gateway uses at its /api/* trust
// boundary (chora-common/auth/chorasession), with the GCID derived from the
// VALIDATED claims and every client-supplied GCID ignored for authorization.
//
// Internal package (httpadapter) so the real tenantContext middleware and the
// unexported context accessors can be exercised — the tenant-consistency check
// reads a context value that only tenantContext produces.
package httpadapter

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/apollo-chora/chora-common/auth/chorasession"
	"github.com/apollo-chora/chora-identity/internal/adapter/inmem"
	"github.com/apollo-chora/chora-identity/internal/adapter/repo"
	"github.com/apollo-chora/chora-identity/internal/domain/identity"
	mana "github.com/apollo-chora/chora-identity/internal/domain/user_mana"
)

const (
	sessSigner   = "test-demo-session-signer-key-0123456789abcdef"
	sessIssuer   = "https://auth.chora.dev"
	sessAudience = "chora-identity"
	sessTenantID = "01970000-0000-7000-8000-0000000000aa"

	sessGcidA = "01970000-0000-7000-8000-00000000da01"
	sessGcidB = "01970000-0000-7000-8000-00000000da02"
)

// sessValidator is the same validator shape chora-gateway builds from
// CHORA_SESSION_SIGNER / CHORA_SESSION_ISSUER / CHORA_SESSION_AUDIENCE.
func sessValidator(t *testing.T) *chorasession.Validator {
	t.Helper()
	v, err := chorasession.NewValidator([]byte(sessSigner), sessIssuer, sessAudience)
	if err != nil {
		t.Fatalf("NewValidator: %v", err)
	}
	return v
}

// sessJWT mints a Chora session JWT over the supplied claims, signed with the
// supplied key. Claims hold only strings and JSON numbers, so the marshal
// cannot fail — a panic here means the spec itself is malformed.
func sessJWT(t *testing.T, signer []byte, claims map[string]any) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	payloadJSON, err := json.Marshal(claims)
	if err != nil {
		panic("sessJWT: " + err.Error())
	}
	payload := base64.RawURLEncoding.EncodeToString(payloadJSON)
	mac := hmac.New(sha256.New, signer)
	mac.Write([]byte(header + "." + payload))
	return header + "." + payload + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// sessValidClaims returns a well-formed, unexpired claim set for gcid.
func sessValidClaims(gcid, tenantID string) map[string]any {
	now := time.Now().Unix()
	return map[string]any{
		"iss":       sessIssuer,
		"aud":       sessAudience,
		"sub":       gcid,
		"gcid":      gcid,
		"tenant_id": tenantID,
		"email":     gcid + "@chora.dev",
		"iat":       now - 60,
		"exp":       now + 3600,
	}
}

func sessValidJWT(t *testing.T, gcid, tenantID string) string {
	t.Helper()
	return sessJWT(t, []byte(sessSigner), sessValidClaims(gcid, tenantID))
}

// sessSwapPayload re-signs nothing: it replaces the payload segment of an
// existing token and leaves the signature untouched, producing a token whose
// claims no longer match its signature.
func sessSwapPayload(t *testing.T, token string, claims map[string]any) string {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("sessSwapPayload: %q is not a 3-segment JWT", token)
	}
	payloadJSON, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("sessSwapPayload: %v", err)
	}
	parts[1] = base64.RawURLEncoding.EncodeToString(payloadJSON)
	return strings.Join(parts, ".")
}

// sessDemoServer wires the demo handler behind the REAL tenantContext
// middleware, mirroring the production chain (logging -> tenantContext -> mux)
// so the tenant-consistency check runs against the headers the gateway
// actually forwards.
func sessDemoServer(t *testing.T, cfg DemoManaConfig, gcids ...string) (http.Handler, *mana.InMemoryStore) {
	t.Helper()
	users := inmem.NewUserRepository()
	for _, g := range gcids {
		u, err := identity.NewUser(identity.NewUserParams{
			Email: g + "@chora.dev", IdentityProvider: identity.ProviderOIDC, FederatedSubject: g,
		})
		if err != nil {
			t.Fatalf("NewUser(%s): %v", g, err)
		}
		u.Gcid = g
		if err := users.Save(context.Background(), u); err != nil {
			t.Fatalf("Save(%s): %v", g, err)
		}
	}
	store := repo.NewInMemManaStore()
	mux := http.NewServeMux()
	NewDemoManaHandler(users, store, cfg, sessValidator(t)).RegisterRoutes(mux)
	return tenantContext(mux), store
}

// sessAllowlist builds the canonical allowlist set the composition root passes
// into DemoManaConfig.
func sessAllowlist(gcids ...string) map[string]struct{} {
	set, malformed, empty := ParseDemoManaAllowedGcids(strings.Join(gcids, ","))
	if len(malformed) > 0 || len(empty) > 0 {
		panic("test gcids must be valid UUIDs: " + strings.Join(malformed, ","))
	}
	return set
}

func sessEnabled(units int64, allowed ...string) DemoManaConfig {
	return DemoManaConfig{
		Enabled:          true,
		GrantUnits:       units,
		MaxPerGcid:       10,
		TotalBudgetUnits: 1_000_000_000,
		AllowedGcids:     sessAllowlist(allowed...),
	}
}

// sessRequest builds a demo-grant request. The gateway always stamps both
// X-Tenant-Id and gcid, and tenantContext 400s without them, so both are set
// unless a spec is specifically probing their absence.
func sessRequest(t *testing.T, bearer, key, headerGcid string) *http.Request {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/me/mana/demo-grant", nil)
	if bearer != "" {
		r.Header.Set("Authorization", "Bearer "+bearer)
	}
	r.Header.Set("X-Tenant-Id", sessTenantID)
	if headerGcid != "" {
		r.Header.Set("gcid", headerGcid)
	}
	if key != "" {
		r.Header.Set("Idempotency-Key", key)
	}
	return r
}

func sessDo(t *testing.T, h http.Handler, r *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

func sessBalance(t *testing.T, store *mana.InMemoryStore, gcid string) int64 {
	t.Helper()
	m, err := store.GetMana(context.Background(), gcid)
	if err != nil {
		t.Fatalf("GetMana(%s): %v", gcid, err)
	}
	if m == nil {
		return 0
	}
	return m.BalanceUnits
}

// --- no session JWT: client-supplied identity headers must not authenticate --

func TestDemoSession_NoJWT_HeaderOnlyGcid_Returns401(t *testing.T) {
	t.Parallel()
	// The defect this boundary closes: tenantContext read gcid / X-Chora-GCID
	// straight from headers and the handler trusted them. Naming an
	// allowlisted GCID in any header, with no session JWT, must authenticate
	// nothing.
	cfg := sessEnabled(1_000_000, sessGcidA)
	h, store := sessDemoServer(t, cfg, sessGcidA)

	// tenantContext requires the `gcid` header (or X-Chora-GCID) before the
	// handler is reached, so every spec sets it; the header under test is set
	// ADDITIONALLY. The point is that none of them authenticates the caller.
	headers := []struct {
		name string
		set  func(r *http.Request)
	}{
		{"gcid", func(r *http.Request) { r.Header.Set("gcid", sessGcidA) }},
		{"X-Chora-GCID", func(r *http.Request) { r.Header.Set("X-Chora-GCID", sessGcidA) }},
		{"chora-gcid mesh", func(r *http.Request) { r.Header.Set("chora-gcid", sessGcidA) }},
		{"X-Gcid", func(r *http.Request) { r.Header.Set("X-Gcid", sessGcidA) }},
		{"all four", func(r *http.Request) {
			r.Header.Set("chora-gcid", sessGcidA)
			r.Header.Set("X-Chora-GCID", sessGcidA)
			r.Header.Set("X-Gcid", sessGcidA)
		}},
	}
	for i, tc := range headers {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := httptest.NewRequest(http.MethodPost, "/api/v1/me/mana/demo-grant", nil)
			r.Header.Set("X-Tenant-Id", sessTenantID)
			r.Header.Set("gcid", sessGcidA)
			tc.set(r)
			r.Header.Set("Idempotency-Key", "k-hdr-"+strings.Repeat("x", i))
			rec := sessDo(t, h, r)

			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401 (body=%s)", rec.Code, rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), "DEMO_SESSION_") {
				t.Errorf("body = %s, want a DEMO_SESSION_* code", rec.Body.String())
			}
			if got := sessBalance(t, store, sessGcidA); got != 0 {
				t.Errorf("balance = %d, want 0 — header identity must not grant", got)
			}
		})
	}
}

func TestDemoSession_NoAuthorizationHeader_Returns401(t *testing.T) {
	t.Parallel()
	cfg := sessEnabled(1_000_000, sessGcidA)
	h, store := sessDemoServer(t, cfg, sessGcidA)

	rec := sessDo(t, h, sessRequest(t, "", "k-no-auth", sessGcidA))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (body=%s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "DEMO_SESSION_REQUIRED") {
		t.Errorf("body = %s, want DEMO_SESSION_REQUIRED", rec.Body.String())
	}
	if got := sessBalance(t, store, sessGcidA); got != 0 {
		t.Errorf("balance = %d, want 0", got)
	}
}

// --- raw-GCID Bearer tokens are rejected -------------------------------------

func TestDemoSession_RawGcidBearer_Returns401(t *testing.T) {
	t.Parallel()
	// The legacy bearer-as-gcid shape. It is not a JWT, so it must be refused —
	// for BOTH an allowlisted and a non-allowlisted GCID: authentication comes
	// before the allowlist, so a raw GCID can never reach the 403 path.
	for _, gcid := range []string{sessGcidA, sessGcidB} {
		t.Run(gcid, func(t *testing.T) {
			t.Parallel()
			cfg := sessEnabled(1_000_000, sessGcidA)
			h, store := sessDemoServer(t, cfg, sessGcidA, sessGcidB)

			rec := sessDo(t, h, sessRequest(t, gcid, "k-raw-"+gcid, gcid))
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401 (body=%s)", rec.Code, rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), "DEMO_SESSION_") {
				t.Errorf("body = %s, want a DEMO_SESSION_* code", rec.Body.String())
			}
			if got := sessBalance(t, store, gcid); got != 0 {
				t.Errorf("balance = %d, want 0 — a raw GCID is not a session", got)
			}
		})
	}
}

// --- forged / garbage JWTs ---------------------------------------------------

func TestDemoSession_ForgedJWT_WrongSigningKey_Returns401(t *testing.T) {
	t.Parallel()
	// Well-formed claims, valid HS256 shape, but signed with a key the server
	// does not trust. The signature is verified BEFORE any claim is trusted.
	cfg := sessEnabled(1_000_000, sessGcidA)
	h, store := sessDemoServer(t, cfg, sessGcidA)

	forged := sessJWT(t, []byte("attacker-supplied-wrong-signer-key-0123456"), sessValidClaims(sessGcidA, sessTenantID))
	rec := sessDo(t, h, sessRequest(t, forged, "k-forged", sessGcidA))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (body=%s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "DEMO_SESSION_INVALID") {
		t.Errorf("body = %s, want DEMO_SESSION_INVALID", rec.Body.String())
	}
	if got := sessBalance(t, store, sessGcidA); got != 0 {
		t.Errorf("balance = %d, want 0 — a forged session must not grant", got)
	}
}

func TestDemoSession_GarbageJWT_Returns401(t *testing.T) {
	t.Parallel()
	algNone := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`)) +
		"." + base64.RawURLEncoding.EncodeToString([]byte(`{"gcid":"`+sessGcidA+`"}`)) + "."

	cases := map[string]string{
		"not a jwt":            "not-a-jwt",
		"two segments":         "a.b",
		"empty signature":      "eyJhbGciOiJIUzI1NiJ9.eyJnY2lkIjoiIn0.",
		"alg none":             algNone,
		"random base64":        "AAAA.BBBB.CCCC",
		"uuid with dots":       sessGcidA[:8] + "." + sessGcidA[9:13] + "." + sessGcidA[14:18],
		"empty bearer":         "",
		"wrong scheme":         "Basic " + sessValidJWT(t, sessGcidA, sessTenantID),
		"bearer without space": "Bearer" + sessValidJWT(t, sessGcidA, sessTenantID),
	}
	for name, token := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			cfg := sessEnabled(1_000_000, sessGcidA)
			h, store := sessDemoServer(t, cfg, sessGcidA)

			rec := sessDo(t, h, sessRequest(t, token, "k-garbage", sessGcidA))
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401 (body=%s)", rec.Code, rec.Body.String())
			}
			if got := sessBalance(t, store, sessGcidA); got != 0 {
				t.Errorf("balance = %d, want 0", got)
			}
		})
	}
}

func TestDemoSession_TamperedClaims_Returns401(t *testing.T) {
	t.Parallel()
	// A token signed correctly for the NON-allowlisted B, with the payload
	// segment swapped for one naming the allowlisted A. The signature no longer
	// matches the claims, so this must be refused — proving the claims are never
	// trusted without a matching signature.
	cfg := sessEnabled(1_000_000, sessGcidA)
	h, store := sessDemoServer(t, cfg, sessGcidA, sessGcidB)

	tampered := sessSwapPayload(t, sessValidJWT(t, sessGcidB, sessTenantID), sessValidClaims(sessGcidA, sessTenantID))
	rec := sessDo(t, h, sessRequest(t, tampered, "k-tampered", sessGcidA))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (body=%s)", rec.Code, rec.Body.String())
	}
	if got := sessBalance(t, store, sessGcidA); got != 0 {
		t.Errorf("A balance = %d, want 0 — an unverified payload must not grant", got)
	}
	if got := sessBalance(t, store, sessGcidB); got != 0 {
		t.Errorf("B balance = %d, want 0", got)
	}
}

// --- claim-level failures ----------------------------------------------------

func TestDemoSession_ExpiredJWT_Returns401(t *testing.T) {
	t.Parallel()
	claims := sessValidClaims(sessGcidA, sessTenantID)
	now := time.Now().Unix()
	claims["iat"] = now - 7200
	claims["exp"] = now - 3600

	cfg := sessEnabled(1_000_000, sessGcidA)
	h, store := sessDemoServer(t, cfg, sessGcidA)

	rec := sessDo(t, h, sessRequest(t, sessJWT(t, []byte(sessSigner), claims), "k-expired", sessGcidA))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (body=%s)", rec.Code, rec.Body.String())
	}
	if got := sessBalance(t, store, sessGcidA); got != 0 {
		t.Errorf("balance = %d, want 0 — an expired session must not grant", got)
	}
}

func TestDemoSession_WrongIssuer_Returns401(t *testing.T) {
	t.Parallel()
	claims := sessValidClaims(sessGcidA, sessTenantID)
	claims["iss"] = "https://evil.example"

	cfg := sessEnabled(1_000_000, sessGcidA)
	h, store := sessDemoServer(t, cfg, sessGcidA)

	rec := sessDo(t, h, sessRequest(t, sessJWT(t, []byte(sessSigner), claims), "k-iss", sessGcidA))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (body=%s)", rec.Code, rec.Body.String())
	}
	if got := sessBalance(t, store, sessGcidA); got != 0 {
		t.Errorf("balance = %d, want 0 — a foreign issuer must not grant", got)
	}
}

func TestDemoSession_WrongAudience_Returns401(t *testing.T) {
	t.Parallel()
	claims := sessValidClaims(sessGcidA, sessTenantID)
	claims["aud"] = "some-other-service"

	cfg := sessEnabled(1_000_000, sessGcidA)
	h, store := sessDemoServer(t, cfg, sessGcidA)

	rec := sessDo(t, h, sessRequest(t, sessJWT(t, []byte(sessSigner), claims), "k-aud", sessGcidA))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (body=%s)", rec.Code, rec.Body.String())
	}
	if got := sessBalance(t, store, sessGcidA); got != 0 {
		t.Errorf("balance = %d, want 0 — a foreign audience must not grant", got)
	}
}

func TestDemoSession_MissingGcidClaim_Returns401(t *testing.T) {
	t.Parallel()
	claims := sessValidClaims(sessGcidA, sessTenantID)
	delete(claims, "gcid")

	cfg := sessEnabled(1_000_000, sessGcidA)
	h, store := sessDemoServer(t, cfg, sessGcidA)

	rec := sessDo(t, h, sessRequest(t, sessJWT(t, []byte(sessSigner), claims), "k-nogcid", sessGcidA))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (body=%s)", rec.Code, rec.Body.String())
	}
	if got := sessBalance(t, store, sessGcidA); got != 0 {
		t.Errorf("balance = %d, want 0", got)
	}
}

// --- the GCID comes from the validated claims, not the request --------------

func TestDemoSession_ValidJWT_AllowlistedGcid_Grants(t *testing.T) {
	t.Parallel()
	cfg := sessEnabled(1_000_000, sessGcidA)
	h, store := sessDemoServer(t, cfg, sessGcidA)

	rec := sessDo(t, h, sessRequest(t, sessValidJWT(t, sessGcidA, sessTenantID), "k-ok", sessGcidA))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	if got := sessBalance(t, store, sessGcidA); got != 1_000_000 {
		t.Errorf("balance = %d, want 1000000", got)
	}
}

func TestDemoSession_ValidJWT_NonAllowlistedGcid_Returns403(t *testing.T) {
	t.Parallel()
	// A perfectly valid session for an account that is not a designated demo
	// account: authenticated, but not allowed.
	cfg := sessEnabled(1_000_000, sessGcidA)
	h, store := sessDemoServer(t, cfg, sessGcidA, sessGcidB)

	rec := sessDo(t, h, sessRequest(t, sessValidJWT(t, sessGcidB, sessTenantID), "k-denied", sessGcidB))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (body=%s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "DEMO_ACCOUNT_NOT_ALLOWED") {
		t.Errorf("body = %s, want DEMO_ACCOUNT_NOT_ALLOWED", rec.Body.String())
	}
	if got := sessBalance(t, store, sessGcidB); got != 0 {
		t.Errorf("balance = %d, want 0", got)
	}
}

func TestDemoSession_GcidComesFromClaimsNotHeaders(t *testing.T) {
	t.Parallel()
	// The session says A (allowlisted); every client-supplied GCID says B (not
	// allowlisted). If the endpoint consulted the headers it would 403. It
	// must grant to A and credit A alone.
	cfg := sessEnabled(1_000_000, sessGcidA)
	h, store := sessDemoServer(t, cfg, sessGcidA, sessGcidB)

	r := sessRequest(t, sessValidJWT(t, sessGcidA, sessTenantID), "k-claims-win", sessGcidB)
	r.Header.Set("chora-gcid", sessGcidB)
	r.Header.Set("X-Chora-GCID", sessGcidB)
	r.Header.Set("X-Gcid", sessGcidB)

	rec := sessDo(t, h, r)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	if got := sessBalance(t, store, sessGcidA); got != 1_000_000 {
		t.Errorf("A balance = %d, want 1000000 — the session GCID must win", got)
	}
	if got := sessBalance(t, store, sessGcidB); got != 0 {
		t.Errorf("B balance = %d, want 0 — header identity must not be credited", got)
	}
}

func TestDemoSession_ValidJWT_UnknownGcid_Returns401(t *testing.T) {
	t.Parallel()
	// A correctly signed session for an account that does not exist. The JWT
	// proves the token is genuine, not that the account is still there.
	cfg := sessEnabled(1_000_000, sessGcidA)
	h, store := sessDemoServer(t, cfg, sessGcidA)

	rec := sessDo(t, h, sessRequest(t, sessValidJWT(t, sessGcidB, sessTenantID), "k-ghost", sessGcidB))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (body=%s)", rec.Code, rec.Body.String())
	}
	if got := sessBalance(t, store, sessGcidB); got != 0 {
		t.Errorf("balance = %d, want 0", got)
	}
}

// --- tenant-context consistency ----------------------------------------------

func TestDemoSession_TenantContextMatchesSession_Succeeds(t *testing.T) {
	t.Parallel()
	cfg := sessEnabled(1_000_000, sessGcidA)
	h, store := sessDemoServer(t, cfg, sessGcidA)

	rec := sessDo(t, h, sessRequest(t, sessValidJWT(t, sessGcidA, sessTenantID), "k-tenant-ok", sessGcidA))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	if got := sessBalance(t, store, sessGcidA); got != 1_000_000 {
		t.Errorf("balance = %d, want 1000000", got)
	}
}

func TestDemoSession_TenantContextMismatch_Returns401(t *testing.T) {
	t.Parallel()
	// The session's active tenant is sessTenantID; the request claims a
	// different one. The two do not belong together, so the request is refused
	// rather than honoured under whichever tenant the header names.
	const otherTenant = "01970000-0000-7000-8000-0000000000bb"
	cfg := sessEnabled(1_000_000, sessGcidA)
	h, store := sessDemoServer(t, cfg, sessGcidA)

	r := sessRequest(t, sessValidJWT(t, sessGcidA, sessTenantID), "k-tenant-mismatch", sessGcidA)
	r.Header.Set("X-Tenant-Id", otherTenant)

	rec := sessDo(t, h, r)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (body=%s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "DEMO_SESSION_TENANT_MISMATCH") {
		t.Errorf("body = %s, want DEMO_SESSION_TENANT_MISMATCH", rec.Body.String())
	}
	if got := sessBalance(t, store, sessGcidA); got != 0 {
		t.Errorf("balance = %d, want 0 — a mismatched tenant must not grant", got)
	}
}

func TestDemoSession_TenantContextAbsentFromSession_Returns401(t *testing.T) {
	t.Parallel()
	// A bootstrap-mode session carries no active tenant, but the request is
	// tenant-scoped. A tenant-scoped call cannot be satisfied by a tenant-less
	// session, so this is refused rather than silently treated as consistent.
	cfg := sessEnabled(1_000_000, sessGcidA)
	h, store := sessDemoServer(t, cfg, sessGcidA)

	rec := sessDo(t, h, sessRequest(t, sessValidJWT(t, sessGcidA, ""), "k-tenant-none", sessGcidA))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (body=%s)", rec.Code, rec.Body.String())
	}
	if got := sessBalance(t, store, sessGcidA); got != 0 {
		t.Errorf("balance = %d, want 0", got)
	}
}

func TestDemoSession_MissingTenantContext_Returns400(t *testing.T) {
	t.Parallel()
	// Proves the specs above really run through tenantContext: without
	// X-Tenant-Id the request is rejected before it reaches the handler.
	cfg := sessEnabled(1_000_000, sessGcidA)
	h, _ := sessDemoServer(t, cfg, sessGcidA)

	r := sessRequest(t, sessValidJWT(t, sessGcidA, sessTenantID), "k-no-tenant", sessGcidA)
	r.Header.Del("X-Tenant-Id")

	rec := sessDo(t, h, r)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (body=%s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "IDENTITY_TENANT_REQUIRED") {
		t.Errorf("body = %s, want IDENTITY_TENANT_REQUIRED", rec.Body.String())
	}
}

// --- fail-closed wiring ------------------------------------------------------

func TestDemoSession_NilValidator_FailsClosed(t *testing.T) {
	t.Parallel()
	// If a handler is ever constructed without a session validator it must
	// refuse every request rather than fall back to a weaker identity source.
	users := inmem.NewUserRepository()
	u, err := identity.NewUser(identity.NewUserParams{
		Email: sessGcidA + "@chora.dev", IdentityProvider: identity.ProviderOIDC, FederatedSubject: sessGcidA,
	})
	if err != nil {
		t.Fatalf("NewUser: %v", err)
	}
	u.Gcid = sessGcidA
	if err := users.Save(context.Background(), u); err != nil {
		t.Fatalf("Save: %v", err)
	}
	store := repo.NewInMemManaStore()
	mux := http.NewServeMux()
	NewDemoManaHandler(users, store, sessEnabled(1_000_000, sessGcidA), nil).RegisterRoutes(mux)

	rec := sessDo(t, mux, sessRequest(t, sessValidJWT(t, sessGcidA, sessTenantID), "k-nil-validator", sessGcidA))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (body=%s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "DEMO_SESSION_UNAVAILABLE") {
		t.Errorf("body = %s, want DEMO_SESSION_UNAVAILABLE", rec.Body.String())
	}
	if got := sessBalance(t, store, sessGcidA); got != 0 {
		t.Errorf("balance = %d, want 0", got)
	}
}
