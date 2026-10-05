// passkey_register_test.go — RED-phase TDD specs for the REAL registration
// ceremony on POST /v1/auth/passkey/register (auth-hardening Phase A4,
// ADR-181 D2, CHO-1718).
//
// The legacy "register through /verify with a placeholder COSE key" path is
// DEAD: /verify is now login-only (unknown credential → 401) and the new
// /register route parses the attestationObject (CBOR → authData →
// attestedCredentialData) and persists the REAL COSE public key, so a later
// login can actually verify the W3C §7.2 signature.
//
// CBOR/COSE fixture helpers (cborLen / cborSI / cborBS / ec2COSE / rsaCOSE /
// pad32) come from passkey_signature_test.go (same package).
package httpadapter_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"

	httpadapter "github.com/apollo-chora/chora-identity/internal/adapter/http"
	"github.com/apollo-chora/chora-identity/internal/adapter/inmem"
	"github.com/apollo-chora/chora-identity/internal/domain/identity"
)

// --- attestation fixture helpers (adapter-side) ------------------------------

func cborTS(s string) []byte {
	out := cborLen(3, uint64(len(s)))
	return append(out, s...)
}

// regAuthData builds registration authData: rpIdHash || flags(UP|AT) ||
// signCount || aaguid(16 zero) || credIdLen || credId || coseKey.
func regAuthData(rpID string, signCount uint32, credID, coseKey []byte) []byte {
	rpHash := sha256.Sum256([]byte(rpID))
	out := append([]byte{}, rpHash[:]...)
	out = append(out, 0x41) // UP | AT
	out = append(out, byte(signCount>>24), byte(signCount>>16), byte(signCount>>8), byte(signCount))
	out = append(out, make([]byte, 16)...)
	out = append(out, byte(len(credID)>>8), byte(len(credID)))
	out = append(out, credID...)
	out = append(out, coseKey...)
	return out
}

func attObjBytes(format string, authData []byte) []byte {
	out := cborLen(5, 3)
	out = append(out, cborTS("fmt")...)
	out = append(out, cborTS(format)...)
	out = append(out, cborTS("attStmt")...)
	out = append(out, cborLen(5, 0)...) // empty map
	out = append(out, cborTS("authData")...)
	out = append(out, cborBS(authData)...)
	return out
}

// loginAuthData builds assertion authData (UP only, no attested data).
func loginAuthData(rpID string, signCount uint32) []byte {
	rpHash := sha256.Sum256([]byte(rpID))
	out := append([]byte{}, rpHash[:]...)
	out = append(out, 0x01) // UP
	out = append(out, byte(signCount>>24), byte(signCount>>16), byte(signCount>>8), byte(signCount))
	return out
}

// --- harness ------------------------------------------------------------------

type registerFixture struct {
	handler     *httpadapter.PasskeyHandler
	users       *inmem.UserRepository
	challenges  *inmem.PasskeyChallengeRepository
	credentials *inmem.PasskeyCredentialRepository
	gcid        string
	email       string
}

func newRegisterFixture(t *testing.T) *registerFixture {
	t.Helper()
	users := inmem.NewUserRepository()
	challenges := inmem.NewPasskeyChallengeRepository()
	credentials := inmem.NewPasskeyCredentialRepository()

	gcid := "01970000-0000-7000-8000-0000000000d1"
	u := &identity.User{
		Gcid:               gcid,
		Email:              "register@chora.dev",
		IdentityProvider:   identity.ProviderOIDC,
		FederatedSubject:   "fed-sub-register",
		Status:             identity.UserStatusActive,
		VerificationStatus: identity.VerificationStatusUnverified,
	}
	_ = users.Save(context.Background(), u)

	h := httpadapter.NewPasskeyHandler(users, challenges, credentials,
		httpadapter.PasskeyHandlerConfig{
			RPID:                "chora.site",
			ChallengeTTLSeconds: 300,
		})
	return &registerFixture{
		handler: h, users: users, challenges: challenges, credentials: credentials,
		gcid: gcid, email: "register@chora.dev",
	}
}

// mintRegChallenge returns (challenge_id, challenge base64url).
func mintRegChallenge(t *testing.T, h *httpadapter.PasskeyHandler) (string, string) {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/v1/auth/passkey/challenge", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("challenge: %d body=%s", w.Code, w.Body.String())
	}
	var resp struct {
		ChallengeID string `json:"challenge_id"`
		Challenge   string `json:"challenge"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	return resp.ChallengeID, resp.Challenge
}

func clientDataCreate(challengeB64URL string) []byte {
	return []byte(`{"type":"webauthn.create","challenge":"` + challengeB64URL + `","origin":"https://chora.site"}`)
}

func postRegister(t *testing.T, h *httpadapter.PasskeyHandler, body map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	b, _ := json.Marshal(body)
	r := httptest.NewRequest(http.MethodPost, "/v1/auth/passkey/register", bytes.NewReader(b))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func registerBody(f *registerFixture, challengeID, challengeB64, credID string, attObj []byte) map[string]any {
	return map[string]any{
		"challenge_id":       challengeID,
		"gcid":               f.gcid,
		"credential_id":      credID,
		"client_data_json":   base64.StdEncoding.EncodeToString(clientDataCreate(challengeB64)),
		"attestation_object": base64.StdEncoding.EncodeToString(attObj),
	}
}

// --- happy paths ----------------------------------------------------------------

func TestPasskey_Register_ES256_PersistsRealCOSEKey(t *testing.T) {
	t.Parallel()
	f := newRegisterFixture(t)
	chID, chB64 := mintRegChallenge(t, f.handler)

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	cose := ec2COSE(pad32(priv.PublicKey.X.Bytes()), pad32(priv.PublicKey.Y.Bytes()))
	credID := []byte("registered-es256-cred")
	attObj := attObjBytes("none", regAuthData("chora.site", 5, credID, cose))

	w := postRegister(t, f.handler, registerBody(f, chID, chB64,
		base64.StdEncoding.EncodeToString(credID), attObj))
	if w.Code != http.StatusCreated {
		t.Fatalf("register: %d body=%s", w.Code, w.Body.String())
	}
	var resp struct {
		CredentialID string `json:"credential_id"`
		Gcid         string `json:"gcid"`
		CreatedAt    string `json:"created_at"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Gcid != f.gcid {
		t.Errorf("gcid = %q want %q", resp.Gcid, f.gcid)
	}
	if resp.CredentialID != base64.RawURLEncoding.EncodeToString(credID) {
		t.Errorf("credential_id = %q want base64url of raw id", resp.CredentialID)
	}
	if resp.CreatedAt == "" {
		t.Errorf("missing created_at")
	}

	// The persisted credential carries the REAL COSE bytes + the initial
	// sign-count from the SIGNED authData — the placeholder is dead.
	stored, err := f.credentials.GetByCredentialID(context.Background(), credID)
	if err != nil {
		t.Fatalf("stored credential: %v", err)
	}
	if !bytes.Equal(stored.PublicKeyCOSE, cose) {
		t.Errorf("stored PublicKeyCOSE != parsed attestation key")
	}
	if bytes.Contains(stored.PublicKeyCOSE, []byte("placeholder")) {
		t.Errorf("placeholder key persisted — dev-mode path still alive")
	}
	if stored.SignCount != 5 {
		t.Errorf("initial SignCount = %d want 5 (from authData)", stored.SignCount)
	}

	// Challenge is consumed (single-use preserved).
	ch, err := f.challenges.GetByID(context.Background(), chID)
	if err != nil {
		t.Fatalf("challenge: %v", err)
	}
	if ch.Status != identity.PasskeyChallengeStatusConsumed {
		t.Errorf("challenge status = %v want consumed", ch.Status)
	}

	// --- registration → login round trip: the stored key must verify a real
	// assertion (this is precisely what the placeholder could never do).
	loginChID, loginChB64 := mintRegChallenge(t, f.handler)
	_ = loginChB64
	authData := loginAuthData("chora.site", 6)
	clientData := []byte(`{"type":"webauthn.get","challenge":"` + loginChB64 + `"}`)
	sig := signES256ForTest(t, priv, authData, clientData)

	loginBodyMap := map[string]any{
		"challenge_id":       loginChID,
		"credential_id":      base64.StdEncoding.EncodeToString(credID),
		"sign_count":         0, // body value is untrusted — authData (signed) wins
		"client_data_json":   base64.StdEncoding.EncodeToString(clientData),
		"authenticator_data": base64.StdEncoding.EncodeToString(authData),
		"signature":          base64.StdEncoding.EncodeToString(sig),
	}
	lb, _ := json.Marshal(loginBodyMap)
	lr := httptest.NewRequest(http.MethodPost, "/v1/auth/passkey/verify", bytes.NewReader(lb))
	lr.Header.Set("Content-Type", "application/json")
	lw := httptest.NewRecorder()
	f.handler.ServeHTTP(lw, lr)
	if lw.Code != http.StatusOK {
		t.Fatalf("login verify after register: %d body=%s", lw.Code, lw.Body.String())
	}
	var vResp map[string]any
	_ = json.Unmarshal(lw.Body.Bytes(), &vResp)
	if vResp["gcid"] != f.gcid {
		t.Errorf("login gcid = %v want %q", vResp["gcid"], f.gcid)
	}
	if vResp["email"] != f.email {
		t.Errorf("login email = %v want %q (gateway mint composition needs it)", vResp["email"], f.email)
	}
	if _, hasToken := vResp["token"]; hasToken {
		t.Errorf("verify response still mints a dev token — HS256 path must be dead")
	}
	// Sign-count must have been taken from the signed authData (6), not the
	// lying body field (0).
	stored2, _ := f.credentials.GetByCredentialID(context.Background(), credID)
	if stored2.SignCount != 6 {
		t.Errorf("post-login SignCount = %d want 6 (from signed authData)", stored2.SignCount)
	}
}

func TestPasskey_Register_RS256_HappyPath(t *testing.T) {
	t.Parallel()
	f := newRegisterFixture(t)
	chID, chB64 := mintRegChallenge(t, f.handler)

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	cose := rsaCOSE(priv.PublicKey.N.Bytes(), big.NewInt(int64(priv.PublicKey.E)).Bytes())
	credID := []byte("registered-rs256-cred")
	attObj := attObjBytes("packed", regAuthData("chora.site", 0, credID, cose))

	w := postRegister(t, f.handler, registerBody(f, chID, chB64,
		base64.StdEncoding.EncodeToString(credID), attObj))
	if w.Code != http.StatusCreated {
		t.Fatalf("register: %d body=%s", w.Code, w.Body.String())
	}
	stored, err := f.credentials.GetByCredentialID(context.Background(), credID)
	if err != nil {
		t.Fatalf("stored credential: %v", err)
	}
	if stored.AttestationType != "packed" {
		t.Errorf("attestation type = %q want packed", stored.AttestationType)
	}
}

// --- rejection paths --------------------------------------------------------------

func TestPasskey_Register_UnknownGcid_404(t *testing.T) {
	t.Parallel()
	f := newRegisterFixture(t)
	chID, chB64 := mintRegChallenge(t, f.handler)
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cose := ec2COSE(pad32(priv.PublicKey.X.Bytes()), pad32(priv.PublicKey.Y.Bytes()))
	credID := []byte("cred-unknown-user")
	body := registerBody(f, chID, chB64, base64.StdEncoding.EncodeToString(credID),
		attObjBytes("none", regAuthData("chora.site", 0, credID, cose)))
	body["gcid"] = "01970000-0000-7000-8000-00000000dead"

	w := postRegister(t, f.handler, body)
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d want 404; body=%s", w.Code, w.Body.String())
	}
}

func TestPasskey_Register_DuplicateCredential_409(t *testing.T) {
	t.Parallel()
	f := newRegisterFixture(t)
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cose := ec2COSE(pad32(priv.PublicKey.X.Bytes()), pad32(priv.PublicKey.Y.Bytes()))
	credID := []byte("dupe-cred-id")

	chID1, chB641 := mintRegChallenge(t, f.handler)
	w1 := postRegister(t, f.handler, registerBody(f, chID1, chB641,
		base64.StdEncoding.EncodeToString(credID),
		attObjBytes("none", regAuthData("chora.site", 0, credID, cose))))
	if w1.Code != http.StatusCreated {
		t.Fatalf("first register: %d body=%s", w1.Code, w1.Body.String())
	}

	chID2, chB642 := mintRegChallenge(t, f.handler)
	w2 := postRegister(t, f.handler, registerBody(f, chID2, chB642,
		base64.StdEncoding.EncodeToString(credID),
		attObjBytes("none", regAuthData("chora.site", 0, credID, cose))))
	if w2.Code != http.StatusConflict {
		t.Errorf("duplicate register status = %d want 409; body=%s", w2.Code, w2.Body.String())
	}
}

func TestPasskey_Register_ConsumedChallenge_401(t *testing.T) {
	t.Parallel()
	f := newRegisterFixture(t)
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cose := ec2COSE(pad32(priv.PublicKey.X.Bytes()), pad32(priv.PublicKey.Y.Bytes()))
	credID := []byte("replay-cred-1")
	chID, chB64 := mintRegChallenge(t, f.handler)

	w1 := postRegister(t, f.handler, registerBody(f, chID, chB64,
		base64.StdEncoding.EncodeToString(credID),
		attObjBytes("none", regAuthData("chora.site", 0, credID, cose))))
	if w1.Code != http.StatusCreated {
		t.Fatalf("first register: %d body=%s", w1.Code, w1.Body.String())
	}

	// Same challenge again with a different credential — single-use must hold.
	credID2 := []byte("replay-cred-2")
	w2 := postRegister(t, f.handler, registerBody(f, chID, chB64,
		base64.StdEncoding.EncodeToString(credID2),
		attObjBytes("none", regAuthData("chora.site", 0, credID2, cose))))
	if w2.Code != http.StatusUnauthorized {
		t.Errorf("challenge replay status = %d want 401; body=%s", w2.Code, w2.Body.String())
	}
}

func TestPasskey_Register_ClientDataTypeWrong_400(t *testing.T) {
	t.Parallel()
	f := newRegisterFixture(t)
	chID, chB64 := mintRegChallenge(t, f.handler)
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cose := ec2COSE(pad32(priv.PublicKey.X.Bytes()), pad32(priv.PublicKey.Y.Bytes()))
	credID := []byte("wrong-type-cred")
	body := registerBody(f, chID, chB64, base64.StdEncoding.EncodeToString(credID),
		attObjBytes("none", regAuthData("chora.site", 0, credID, cose)))
	body["client_data_json"] = base64.StdEncoding.EncodeToString(
		[]byte(`{"type":"webauthn.get","challenge":"` + chB64 + `"}`)) // get ≠ create

	w := postRegister(t, f.handler, body)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d want 400; body=%s", w.Code, w.Body.String())
	}
}

func TestPasskey_Register_ChallengeMismatch_401(t *testing.T) {
	t.Parallel()
	f := newRegisterFixture(t)
	chID, _ := mintRegChallenge(t, f.handler)
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cose := ec2COSE(pad32(priv.PublicKey.X.Bytes()), pad32(priv.PublicKey.Y.Bytes()))
	credID := []byte("mismatch-cred")
	// clientDataJSON signs a DIFFERENT challenge than the one minted.
	body := registerBody(f, chID, base64.RawURLEncoding.EncodeToString([]byte("attacker-chosen-challenge-32byte")),
		base64.StdEncoding.EncodeToString(credID),
		attObjBytes("none", regAuthData("chora.site", 0, credID, cose)))

	w := postRegister(t, f.handler, body)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d want 401; body=%s", w.Code, w.Body.String())
	}
}

func TestPasskey_Register_RPIDMismatch_400(t *testing.T) {
	t.Parallel()
	f := newRegisterFixture(t)
	chID, chB64 := mintRegChallenge(t, f.handler)
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cose := ec2COSE(pad32(priv.PublicKey.X.Bytes()), pad32(priv.PublicKey.Y.Bytes()))
	credID := []byte("evil-rp-cred")
	// authData hashed for a DIFFERENT relying party.
	w := postRegister(t, f.handler, registerBody(f, chID, chB64,
		base64.StdEncoding.EncodeToString(credID),
		attObjBytes("none", regAuthData("evil.example", 0, credID, cose))))
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d want 400; body=%s", w.Code, w.Body.String())
	}
}

func TestPasskey_Register_UnsupportedAlg_400(t *testing.T) {
	t.Parallel()
	f := newRegisterFixture(t)
	chID, chB64 := mintRegChallenge(t, f.handler)
	// EdDSA OKP key {1:1, 3:-8, -1:6, -2:bytes}
	pairs := [][2][]byte{
		{cborSI(1), cborSI(1)},
		{cborSI(3), cborSI(-8)},
		{cborSI(-1), cborSI(6)},
		{cborSI(-2), cborBS(make([]byte, 32))},
	}
	cose := cborLen(5, uint64(len(pairs)))
	for _, p := range pairs {
		cose = append(cose, p[0]...)
		cose = append(cose, p[1]...)
	}
	credID := []byte("eddsa-cred")
	w := postRegister(t, f.handler, registerBody(f, chID, chB64,
		base64.StdEncoding.EncodeToString(credID),
		attObjBytes("none", regAuthData("chora.site", 0, credID, cose))))
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d want 400; body=%s", w.Code, w.Body.String())
	}
	if !bytes.Contains(w.Body.Bytes(), []byte("PASSKEY_UNSUPPORTED_ALGORITHM")) {
		t.Errorf("body should carry PASSKEY_UNSUPPORTED_ALGORITHM; got %s", w.Body.String())
	}
}

func TestPasskey_Register_CredentialIDMismatch_400(t *testing.T) {
	t.Parallel()
	f := newRegisterFixture(t)
	chID, chB64 := mintRegChallenge(t, f.handler)
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cose := ec2COSE(pad32(priv.PublicKey.X.Bytes()), pad32(priv.PublicKey.Y.Bytes()))
	credID := []byte("attested-cred-id")
	// Body rawId claims a DIFFERENT id than the attested one.
	w := postRegister(t, f.handler, registerBody(f, chID, chB64,
		base64.StdEncoding.EncodeToString([]byte("claimed-other-id")),
		attObjBytes("none", regAuthData("chora.site", 0, credID, cose))))
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d want 400; body=%s", w.Code, w.Body.String())
	}
}

func TestPasskey_Register_MissingFields_400(t *testing.T) {
	t.Parallel()
	f := newRegisterFixture(t)
	w := postRegister(t, f.handler, map[string]any{})
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d want 400; body=%s", w.Code, w.Body.String())
	}
}

func TestPasskey_Register_RejectsGet(t *testing.T) {
	t.Parallel()
	f := newRegisterFixture(t)
	r := httptest.NewRequest(http.MethodGet, "/v1/auth/passkey/register", nil)
	w := httptest.NewRecorder()
	f.handler.ServeHTTP(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d want 405", w.Code)
	}
}

// --- verify is login-only now ------------------------------------------------------

// TestPasskey_Verify_UnknownCredential_401 pins the death of the
// register-through-verify path: an unknown credential_id can no longer mint
// a fresh User + placeholder credential — it is rejected outright.
func TestPasskey_Verify_UnknownCredential_401(t *testing.T) {
	t.Parallel()
	f := newRegisterFixture(t)
	chID, chB64 := mintRegChallenge(t, f.handler)

	authData := loginAuthData("chora.site", 1)
	clientData := []byte(`{"type":"webauthn.get","challenge":"` + chB64 + `"}`)
	body, _ := json.Marshal(map[string]any{
		"challenge_id":       chID,
		"credential_id":      base64.StdEncoding.EncodeToString([]byte("never-registered")),
		"sign_count":         1,
		"user_handle":        "ghost@chora.dev",
		"client_data_json":   base64.StdEncoding.EncodeToString(clientData),
		"authenticator_data": base64.StdEncoding.EncodeToString(authData),
		"signature":          base64.StdEncoding.EncodeToString([]byte("sig")),
	})
	r := httptest.NewRequest(http.MethodPost, "/v1/auth/passkey/verify", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	f.handler.ServeHTTP(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d want 401; body=%s", w.Code, w.Body.String())
	}
	if !bytes.Contains(w.Body.Bytes(), []byte("PASSKEY_CREDENTIAL_UNKNOWN")) {
		t.Errorf("body should carry PASSKEY_CREDENTIAL_UNKNOWN; got %s", w.Body.String())
	}
	// No ghost user materialised.
	if _, err := f.users.GetByGcid(context.Background(), "ghost"); err == nil {
		t.Errorf("a user was created from an unverified credential")
	}
}
