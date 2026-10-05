// HTTP handler tests for the WebAuthn / Passkey endpoints.
//
// Per Phyllis MVP §3 Step 1: every Phyllis flow starts here. We test the
// full happy path (challenge → verify → JWT-with-GCID), plus the negative
// branches that block replay/expiry/AGID/closed-user.
package httpadapter_test

import (
	"bytes"
	"context"
	"encoding/base64"
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

// helper — build a fresh handler with empty repos.
func buildPasskeyHandler(t *testing.T) (*httpadapter.PasskeyHandler, *inmem.UserRepository, *inmem.PasskeyChallengeRepository, *inmem.PasskeyCredentialRepository) {
	t.Helper()
	users := inmem.NewUserRepository()
	challenges := inmem.NewPasskeyChallengeRepository()
	credentials := inmem.NewPasskeyCredentialRepository()
	cfg := httpadapter.PasskeyHandlerConfig{
		RPID:                "chora.site",
		ChallengeTTLSeconds: 300,
		// Phase A4: JWT fields removed with the dev HS256 mint — the
		// session JWT is minted exclusively by chora-gateway. Tests here
		// exercise the login ceremony + pre-error branches (challenge
		// expiry / replay / missing fields). Registration coverage lives in
		// passkey_register_test.go; production-signature coverage in
		// passkey_signature_test.go.
	}
	h := httpadapter.NewPasskeyHandler(users, challenges, credentials, cfg)
	return h, users, challenges, credentials
}

// -----------------------------------------------------------------------------
// POST /v1/auth/passkey/challenge
// -----------------------------------------------------------------------------

func TestPasskey_Challenge_HappyPath(t *testing.T) {
	h, _, _, _ := buildPasskeyHandler(t)

	body := bytes.NewBufferString(`{"user_handle":"phyllis@mightymind.sg"}`)
	r := httptest.NewRequest(http.MethodPost, "/v1/auth/passkey/challenge", body)
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200; got %d body=%s", w.Code, w.Body.String())
	}
	var resp struct {
		ChallengeID string `json:"challenge_id"`
		Challenge   string `json:"challenge"` // base64url
		RPID        string `json:"rp_id"`
		ExpiresAt   string `json:"expires_at"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v body=%s", err, w.Body.String())
	}
	if resp.ChallengeID == "" {
		t.Fatalf("missing challenge_id")
	}
	if resp.Challenge == "" {
		t.Fatalf("missing challenge")
	}
	if resp.RPID != "chora.site" {
		t.Fatalf("rp_id mismatch: got %q", resp.RPID)
	}
}

func TestPasskey_Challenge_RejectsGet(t *testing.T) {
	h, _, _, _ := buildPasskeyHandler(t)
	r := httptest.NewRequest(http.MethodGet, "/v1/auth/passkey/challenge", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405; got %d", w.Code)
	}
}

func TestPasskey_Challenge_AllowsEmptyBody(t *testing.T) {
	// A challenge call with NO user handle (a "discoverable credential" flow)
	// is permitted by WebAuthn spec — the authenticator picks the credential.
	h, _, _, _ := buildPasskeyHandler(t)
	r := httptest.NewRequest(http.MethodPost, "/v1/auth/passkey/challenge", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200; got %d body=%s", w.Code, w.Body.String())
	}
}

// -----------------------------------------------------------------------------
// POST /v1/auth/passkey/verify
// -----------------------------------------------------------------------------

func TestPasskey_Verify_HappyPath_ExistingUser(t *testing.T) {
	h, users, _, credentials := buildPasskeyHandler(t)
	ctx := context.Background()

	// Seed an existing user + an active credential with a REAL ES256 COSE
	// key. Production hardening removed the dev shortcut — verifying an
	// existing credential REQUIRES a real signature (W3C WebAuthn L3 §7.2).
	gcid := "01935b5a-9bcf-7000-8000-0000000000aa"
	u := &identity.User{
		Gcid:               gcid,
		Email:              "phyllis@mightymind.sg",
		IdentityProvider:   identity.ProviderWebAuthn,
		FederatedSubject:   "webauthn|" + gcid,
		Status:             identity.UserStatusActive,
		VerificationStatus: identity.VerificationStatusUnverified,
	}
	_ = users.Save(ctx, u)

	priv, cose := newES256COSEPair(t)
	credID := []byte("known-cred-id-bytes")
	cred, err := identity.NewPasskeyCredential(identity.NewPasskeyCredentialParams{
		Gcid:          gcid,
		CredentialID:  credID,
		PublicKeyCOSE: cose,
		RPID:          "chora.site",
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = credentials.Save(ctx, cred)

	// Mint a challenge.
	chReq := httptest.NewRequest(http.MethodPost, "/v1/auth/passkey/challenge",
		bytes.NewBufferString(`{"user_handle":"phyllis@mightymind.sg"}`))
	chReq.Header.Set("Content-Type", "application/json")
	chRec := httptest.NewRecorder()
	h.ServeHTTP(chRec, chReq)
	if chRec.Code != http.StatusOK {
		t.Fatalf("challenge failed: %d body=%s", chRec.Code, chRec.Body.String())
	}
	var chResp struct {
		ChallengeID string `json:"challenge_id"`
		Challenge   string `json:"challenge"`
	}
	_ = json.Unmarshal(chRec.Body.Bytes(), &chResp)

	// Verify with a real ES256 signature over (authData || sha256(clientDataJSON)).
	// The clientDataJSON.challenge MUST echo the server-issued challenge (D9).
	authData := []byte("authdata-fixture-32-bytes-pad-12")
	clientData := []byte(`{"type":"webauthn.get","challenge":"` + chResp.Challenge + `"}`)
	sig := signES256ForTest(t, priv, authData, clientData)

	verifyBody := map[string]any{
		"challenge_id":       chResp.ChallengeID,
		"credential_id":      base64.StdEncoding.EncodeToString(credID),
		"sign_count":         1,
		"client_data_json":   base64.StdEncoding.EncodeToString(clientData),
		"authenticator_data": base64.StdEncoding.EncodeToString(authData),
		"signature":          base64.StdEncoding.EncodeToString(sig),
	}
	body, _ := json.Marshal(verifyBody)
	vReq := httptest.NewRequest(http.MethodPost, "/v1/auth/passkey/verify",
		bytes.NewBuffer(body))
	vReq.Header.Set("Content-Type", "application/json")
	vRec := httptest.NewRecorder()
	h.ServeHTTP(vRec, vReq)

	if vRec.Code != http.StatusOK {
		t.Fatalf("verify failed: %d body=%s", vRec.Code, vRec.Body.String())
	}
	// Phase A4: verify returns the verified identity (gcid + email) — NO
	// token. chora-gateway composes the session mint from these fields.
	var vResp map[string]any
	if err := json.Unmarshal(vRec.Body.Bytes(), &vResp); err != nil {
		t.Fatalf("decode: %v body=%s", err, vRec.Body.String())
	}
	if vResp["gcid"] != gcid {
		t.Fatalf("gcid mismatch: got %v want %q", vResp["gcid"], gcid)
	}
	if vResp["email"] != "phyllis@mightymind.sg" {
		t.Fatalf("email = %v want phyllis@mightymind.sg", vResp["email"])
	}
	if _, hasToken := vResp["token"]; hasToken {
		t.Fatalf("verify response must NOT mint a dev HS256 token (ADR-181 A4)")
	}
}

func TestPasskey_Verify_RejectsExpiredChallenge(t *testing.T) {
	h, _, challenges, _ := buildPasskeyHandler(t)
	ctx := context.Background()

	// Manually insert an expired challenge (TTL already in the past via short TTL).
	// We construct via the domain primitive to mirror real wiring.
	c, err := identity.NewPasskeyChallenge(identity.NewPasskeyChallengeParams{
		ChallengeBytes: []byte("32-bytes-of-entropy-12345678901234"),
		RPID:           "chora.site",
		TTL:            1, // 1 nanosecond TTL — already expired by the time verify runs
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = challenges.Save(ctx, c)

	verifyBody := map[string]any{
		"challenge_id":    c.ChallengeID,
		"credential_id":   "ZGVhZGJlZWY=",
		"sign_count":      1,
		"attestation_dev": true,
	}
	body, _ := json.Marshal(verifyBody)
	r := httptest.NewRequest(http.MethodPost, "/v1/auth/passkey/verify", bytes.NewBuffer(body))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 on expired challenge; got %d", w.Code)
	}
}

func TestPasskey_Verify_RejectsConsumedChallenge(t *testing.T) {
	h, _, challenges, _ := buildPasskeyHandler(t)
	ctx := context.Background()
	c, _ := identity.NewPasskeyChallenge(identity.NewPasskeyChallengeParams{
		ChallengeBytes: []byte("32-bytes-of-entropy-12345678901234"),
		RPID:           "chora.site",
		TTL:            5 * 60_000_000_000, // 5 minutes
	})
	_ = c.MarkConsumed()
	_ = challenges.Save(ctx, c)

	verifyBody := map[string]any{
		"challenge_id":    c.ChallengeID,
		"credential_id":   "ZGVhZGJlZWY=",
		"sign_count":      1,
		"attestation_dev": true,
	}
	body, _ := json.Marshal(verifyBody)
	r := httptest.NewRequest(http.MethodPost, "/v1/auth/passkey/verify", bytes.NewBuffer(body))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 on consumed challenge; got %d", w.Code)
	}
}

func TestPasskey_Verify_UnknownChallengeID(t *testing.T) {
	h, _, _, _ := buildPasskeyHandler(t)
	verifyBody := map[string]any{
		"challenge_id":    "non-existent-uuid",
		"credential_id":   "ZGVhZGJlZWY=",
		"sign_count":      1,
		"attestation_dev": true,
	}
	body, _ := json.Marshal(verifyBody)
	r := httptest.NewRequest(http.MethodPost, "/v1/auth/passkey/verify", bytes.NewBuffer(body))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 on unknown challenge; got %d", w.Code)
	}
}

func TestPasskey_Verify_MissingFields(t *testing.T) {
	h, _, _, _ := buildPasskeyHandler(t)
	r := httptest.NewRequest(http.MethodPost, "/v1/auth/passkey/verify",
		bytes.NewBufferString(`{}`))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400; got %d", w.Code)
	}
}

func TestPasskey_Verify_FreshCredentialRejected_NoAutoProvision(t *testing.T) {
	// Phase A4 (CHO-1718): the Phyllis-era "register through /verify"
	// auto-provisioning is DEAD. A never-registered credential_id must be
	// rejected with 401 and NO user/credential may be materialised. The
	// challenge stays unconsumed (the ceremony never reached verification).
	h, _, challenges, credentials := buildPasskeyHandler(t)
	ctx := context.Background()

	chReq := httptest.NewRequest(http.MethodPost, "/v1/auth/passkey/challenge",
		bytes.NewBufferString(`{"user_handle":"newbie@example.com"}`))
	chReq.Header.Set("Content-Type", "application/json")
	chRec := httptest.NewRecorder()
	h.ServeHTTP(chRec, chReq)
	if chRec.Code != http.StatusOK {
		t.Fatalf("challenge: %d", chRec.Code)
	}
	var chResp struct {
		ChallengeID string `json:"challenge_id"`
	}
	_ = json.Unmarshal(chRec.Body.Bytes(), &chResp)

	freshCredID := []byte("new-user-cred-id")
	verifyBody := map[string]any{
		"challenge_id":    chResp.ChallengeID,
		"credential_id":   base64.StdEncoding.EncodeToString(freshCredID),
		"sign_count":      0,
		"attestation_dev": true,
		"user_handle":     "newbie@example.com",
	}
	body, _ := json.Marshal(verifyBody)
	vReq := httptest.NewRequest(http.MethodPost, "/v1/auth/passkey/verify", bytes.NewBuffer(body))
	vReq.Header.Set("Content-Type", "application/json")
	vRec := httptest.NewRecorder()
	h.ServeHTTP(vRec, vReq)

	if vRec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for unknown credential; got %d body=%s", vRec.Code, vRec.Body.String())
	}
	if !strings.Contains(vRec.Body.String(), "PASSKEY_CREDENTIAL_UNKNOWN") {
		t.Fatalf("expected PASSKEY_CREDENTIAL_UNKNOWN; got %s", vRec.Body.String())
	}
	// No credential materialised.
	if _, err := credentials.GetByCredentialID(ctx, freshCredID); !errors.Is(err, identity.ErrPasskeyCredentialNotFound) {
		t.Fatalf("expected no credential; err=%v", err)
	}
	// Challenge NOT consumed — the ceremony was rejected before binding.
	c, err := challenges.GetByID(ctx, chResp.ChallengeID)
	if err != nil {
		t.Fatal(err)
	}
	if c.Status == identity.PasskeyChallengeStatusConsumed {
		t.Fatalf("challenge must not be consumed by a rejected unknown-credential verify")
	}
}
