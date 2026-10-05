// passkey_signature_test.go — production-path tests for the WebAuthn signature
// verification on /v1/auth/passkey/verify.
//
// These tests turn off the AllowDevAttestation gate and exercise the full
// COSE-key + signature path against the existing credential. They cover:
//
//  1. Valid ES256 signature → 200 (re-login of an existing credential).
//  2. Tampered signature → 401 PASSKEY_SIGNATURE_REJECTED.
//  3. Missing signature fields → 400 PASSKEY_SIGNATURE_REQUIRED.
//  4. Sign-count regression (clone detection) → 401 PASSKEY_REPLAY_DETECTED.
//  5. Valid RS256 signature → 200 (Apple/Android passkey bridge).
package httpadapter_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"

	httpadapter "github.com/apollo-chora/chora-identity/internal/adapter/http"
	"github.com/apollo-chora/chora-identity/internal/adapter/inmem"
	"github.com/apollo-chora/chora-identity/internal/domain/identity"
)

// --- COSE encoding helpers (mirror of webauthn_verify_test.go) -------------
// Tiny CBOR encoder; sufficient for ES256 / RS256 COSE_Key fixtures.

func cborLen(m byte, n uint64) []byte {
	if n < 24 {
		return []byte{(m << 5) | byte(n)}
	}
	if n < 256 {
		return []byte{(m << 5) | 24, byte(n)}
	}
	if n < 65536 {
		return []byte{(m << 5) | 25, byte(n >> 8), byte(n)}
	}
	if n < 4_294_967_296 {
		return []byte{(m << 5) | 26, byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}
	}
	return []byte{(m << 5) | 27, byte(n >> 56), byte(n >> 48), byte(n >> 40), byte(n >> 32), byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}
}

func cborSI(v int64) []byte {
	if v >= 0 {
		return cborLen(0, uint64(v))
	}
	return cborLen(1, uint64(-1-v))
}

func cborBS(b []byte) []byte {
	out := cborLen(2, uint64(len(b)))
	return append(out, b...)
}

func ec2COSE(x, y []byte) []byte {
	pairs := [][2][]byte{
		{cborSI(1), cborSI(2)},
		{cborSI(3), cborSI(-7)},
		{cborSI(-1), cborSI(1)},
		{cborSI(-2), cborBS(x)},
		{cborSI(-3), cborBS(y)},
	}
	out := cborLen(5, uint64(len(pairs)))
	for _, p := range pairs {
		out = append(out, p[0]...)
		out = append(out, p[1]...)
	}
	return out
}

func rsaCOSE(n, e []byte) []byte {
	pairs := [][2][]byte{
		{cborSI(1), cborSI(3)},
		{cborSI(3), cborSI(-257)},
		{cborSI(-1), cborBS(n)},
		{cborSI(-2), cborBS(e)},
	}
	out := cborLen(5, uint64(len(pairs)))
	for _, p := range pairs {
		out = append(out, p[0]...)
		out = append(out, p[1]...)
	}
	return out
}

func pad32(b []byte) []byte {
	if len(b) >= 32 {
		return b
	}
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return out
}

// --- Test harness ----------------------------------------------------------

type prodFixture struct {
	handler     *httpadapter.PasskeyHandler
	users       *inmem.UserRepository
	challenges  *inmem.PasskeyChallengeRepository
	credentials *inmem.PasskeyCredentialRepository
	credID      []byte
	gcid        string
	priv        any // *ecdsa.PrivateKey or *rsa.PrivateKey
	signFn      func(t *testing.T, authData, clientDataJSON []byte) []byte
}

func newProdES256Fixture(t *testing.T) *prodFixture {
	t.Helper()
	users := inmem.NewUserRepository()
	challenges := inmem.NewPasskeyChallengeRepository()
	credentials := inmem.NewPasskeyCredentialRepository()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa keygen: %v", err)
	}
	cose := ec2COSE(pad32(priv.PublicKey.X.Bytes()), pad32(priv.PublicKey.Y.Bytes()))

	gcid := "01970000-0000-7000-8000-0000000000aa"
	credID := []byte("prod-cred-id-bytes")

	u := &identity.User{
		Gcid:               gcid,
		Email:              "phyllis@mightymind.sg",
		IdentityProvider:   identity.ProviderWebAuthn,
		FederatedSubject:   "webauthn|" + gcid,
		Status:             identity.UserStatusActive,
		VerificationStatus: identity.VerificationStatusUnverified,
	}
	_ = users.Save(context.Background(), u)

	cred, _ := identity.NewPasskeyCredential(identity.NewPasskeyCredentialParams{
		Gcid:          gcid,
		CredentialID:  credID,
		PublicKeyCOSE: cose,
		RPID:          "chora.site",
	})
	_ = credentials.Save(context.Background(), cred)

	cfg := httpadapter.PasskeyHandlerConfig{
		RPID:                "chora.site",
		ChallengeTTLSeconds: 300,
		// Production hardening removed AllowDevAttestation entirely; Phase
		// A4 removed the JWT fields with the dev HS256 mint.
	}
	h := httpadapter.NewPasskeyHandler(users, challenges, credentials, cfg)

	signFn := func(t *testing.T, authData, clientDataJSON []byte) []byte {
		cdh := sha256.Sum256(clientDataJSON)
		signing := append([]byte{}, authData...)
		signing = append(signing, cdh[:]...)
		hashed := sha256.Sum256(signing)
		r, s, err := ecdsa.Sign(rand.Reader, priv, hashed[:])
		if err != nil {
			t.Fatalf("ecdsa sign: %v", err)
		}
		// ASN.1 DER (r, s)
		sig, err := asn1.Marshal(struct{ R, S *big.Int }{R: r, S: s})
		if err != nil {
			t.Fatalf("asn1 marshal: %v", err)
		}
		return sig
	}
	return &prodFixture{
		handler: h, users: users, challenges: challenges, credentials: credentials,
		credID: credID, gcid: gcid, priv: priv, signFn: signFn,
	}
}

func newProdRS256Fixture(t *testing.T) *prodFixture {
	t.Helper()
	users := inmem.NewUserRepository()
	challenges := inmem.NewPasskeyChallengeRepository()
	credentials := inmem.NewPasskeyCredentialRepository()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa keygen: %v", err)
	}
	n := priv.PublicKey.N.Bytes()
	e := big.NewInt(int64(priv.PublicKey.E)).Bytes()
	cose := rsaCOSE(n, e)

	gcid := "01970000-0000-7000-8000-0000000000bb"
	credID := []byte("prod-rsa-cred-id")

	u := &identity.User{
		Gcid:               gcid,
		Email:              "rsa@example.com",
		IdentityProvider:   identity.ProviderWebAuthn,
		FederatedSubject:   "webauthn|" + gcid,
		Status:             identity.UserStatusActive,
		VerificationStatus: identity.VerificationStatusUnverified,
	}
	_ = users.Save(context.Background(), u)

	cred, _ := identity.NewPasskeyCredential(identity.NewPasskeyCredentialParams{
		Gcid:          gcid,
		CredentialID:  credID,
		PublicKeyCOSE: cose,
		RPID:          "chora.site",
	})
	_ = credentials.Save(context.Background(), cred)

	cfg := httpadapter.PasskeyHandlerConfig{
		RPID:                "chora.site",
		ChallengeTTLSeconds: 300,
		// Production hardening removed AllowDevAttestation entirely; Phase
		// A4 removed the JWT fields with the dev HS256 mint.
	}
	h := httpadapter.NewPasskeyHandler(users, challenges, credentials, cfg)

	signFn := func(t *testing.T, authData, clientDataJSON []byte) []byte {
		cdh := sha256.Sum256(clientDataJSON)
		signing := append([]byte{}, authData...)
		signing = append(signing, cdh[:]...)
		hashed := sha256.Sum256(signing)
		sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, hashed[:])
		if err != nil {
			t.Fatalf("rsa sign: %v", err)
		}
		return sig
	}
	return &prodFixture{
		handler: h, users: users, challenges: challenges, credentials: credentials,
		credID: credID, gcid: gcid, priv: priv, signFn: signFn,
	}
}

// mintChallenge mints a challenge and returns BOTH its id and the base64url
// challenge string. The challenge string is what the SPA must echo inside
// clientDataJSON.challenge for the D9 login challenge-binding to accept.
func mintChallenge(t *testing.T, h *httpadapter.PasskeyHandler) (challengeID, challengeB64 string) {
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

// loginClientData builds a webauthn.get clientDataJSON that echoes the
// server-issued challenge — the shape a conformant SPA submits post-D9.
func loginClientData(challengeB64 string) []byte {
	return []byte(fmt.Sprintf(`{"type":"webauthn.get","challenge":%q,"origin":"https://chora.site"}`, challengeB64))
}

// --- Tests -----------------------------------------------------------------

func TestPasskey_Verify_ProductionPath_ES256_Verifies(t *testing.T) {
	t.Parallel()
	f := newProdES256Fixture(t)
	chID, challB64 := mintChallenge(t, f.handler)

	authData := []byte("authenticator-data-fixture-32B--")
	clientDataJSON := loginClientData(challB64)
	sig := f.signFn(t, authData, clientDataJSON)

	verifyBody := map[string]any{
		"challenge_id":       chID,
		"credential_id":      base64.StdEncoding.EncodeToString(f.credID),
		"sign_count":         1,
		"client_data_json":   base64.StdEncoding.EncodeToString(clientDataJSON),
		"authenticator_data": base64.StdEncoding.EncodeToString(authData),
		"signature":          base64.StdEncoding.EncodeToString(sig),
	}
	body, _ := json.Marshal(verifyBody)
	r := httptest.NewRequest(http.MethodPost, "/v1/auth/passkey/verify", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	f.handler.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", w.Code, w.Body.String())
	}
}

func TestPasskey_Verify_ProductionPath_TamperedSig_Rejected(t *testing.T) {
	t.Parallel()
	f := newProdES256Fixture(t)
	chID, challB64 := mintChallenge(t, f.handler)

	authData := []byte("authenticator-data-fixture-32B--")
	clientDataJSON := loginClientData(challB64)
	sig := f.signFn(t, authData, clientDataJSON)
	// Flip last byte
	sig[len(sig)-1] ^= 0x01

	verifyBody := map[string]any{
		"challenge_id":       chID,
		"credential_id":      base64.StdEncoding.EncodeToString(f.credID),
		"sign_count":         1,
		"client_data_json":   base64.StdEncoding.EncodeToString(clientDataJSON),
		"authenticator_data": base64.StdEncoding.EncodeToString(authData),
		"signature":          base64.StdEncoding.EncodeToString(sig),
	}
	body, _ := json.Marshal(verifyBody)
	r := httptest.NewRequest(http.MethodPost, "/v1/auth/passkey/verify", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	f.handler.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d body=%s", w.Code, w.Body.String())
	}
	if !bytes.Contains(w.Body.Bytes(), []byte("PASSKEY_SIGNATURE_REJECTED")) {
		t.Errorf("error body should be PASSKEY_SIGNATURE_REJECTED; got %s", w.Body.String())
	}
}

func TestPasskey_Verify_ProductionPath_MissingSignatureFields_400(t *testing.T) {
	t.Parallel()
	f := newProdES256Fixture(t)
	chID, _ := mintChallenge(t, f.handler)

	verifyBody := map[string]any{
		"challenge_id":  chID,
		"credential_id": base64.StdEncoding.EncodeToString(f.credID),
		"sign_count":    1,
		// no client_data_json / authenticator_data / signature → 400
	}
	body, _ := json.Marshal(verifyBody)
	r := httptest.NewRequest(http.MethodPost, "/v1/auth/passkey/verify", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	f.handler.ServeHTTP(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestPasskey_Verify_ProductionPath_RS256_Verifies(t *testing.T) {
	t.Parallel()
	f := newProdRS256Fixture(t)
	chID, challB64 := mintChallenge(t, f.handler)

	authData := []byte("rsa-auth-data-fixture-padding-x")
	clientDataJSON := loginClientData(challB64)
	sig := f.signFn(t, authData, clientDataJSON)

	verifyBody := map[string]any{
		"challenge_id":       chID,
		"credential_id":      base64.StdEncoding.EncodeToString(f.credID),
		"sign_count":         1,
		"client_data_json":   base64.StdEncoding.EncodeToString(clientDataJSON),
		"authenticator_data": base64.StdEncoding.EncodeToString(authData),
		"signature":          base64.StdEncoding.EncodeToString(sig),
	}
	body, _ := json.Marshal(verifyBody)
	r := httptest.NewRequest(http.MethodPost, "/v1/auth/passkey/verify", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	f.handler.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", w.Code, w.Body.String())
	}
}

func TestPasskey_Verify_ProductionPath_SignCountRegression_Rejected(t *testing.T) {
	t.Parallel()
	f := newProdES256Fixture(t)

	// 1st verify with sign_count=5
	chID, challB64 := mintChallenge(t, f.handler)
	authData := []byte("authenticator-data-fixture-32B--")
	clientDataJSON := []byte(fmt.Sprintf(`{"type":"webauthn.get","challenge":%q,"i":1}`, challB64))
	sig := f.signFn(t, authData, clientDataJSON)
	body, _ := json.Marshal(map[string]any{
		"challenge_id":       chID,
		"credential_id":      base64.StdEncoding.EncodeToString(f.credID),
		"sign_count":         5,
		"client_data_json":   base64.StdEncoding.EncodeToString(clientDataJSON),
		"authenticator_data": base64.StdEncoding.EncodeToString(authData),
		"signature":          base64.StdEncoding.EncodeToString(sig),
	})
	r := httptest.NewRequest(http.MethodPost, "/v1/auth/passkey/verify", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	f.handler.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("first verify: %d body=%s", w.Code, w.Body.String())
	}

	// 2nd verify with sign_count=3 (regression — clone detected)
	chID2, challB642 := mintChallenge(t, f.handler)
	authData2 := []byte("authenticator-data-fixture-32B--")
	cd2 := []byte(fmt.Sprintf(`{"type":"webauthn.get","challenge":%q,"i":2}`, challB642))
	sig2 := f.signFn(t, authData2, cd2)
	body2, _ := json.Marshal(map[string]any{
		"challenge_id":       chID2,
		"credential_id":      base64.StdEncoding.EncodeToString(f.credID),
		"sign_count":         3, // < 5 — regression
		"client_data_json":   base64.StdEncoding.EncodeToString(cd2),
		"authenticator_data": base64.StdEncoding.EncodeToString(authData2),
		"signature":          base64.StdEncoding.EncodeToString(sig2),
	})
	r2 := httptest.NewRequest(http.MethodPost, "/v1/auth/passkey/verify", bytes.NewReader(body2))
	r2.Header.Set("Content-Type", "application/json")
	w2 := httptest.NewRecorder()
	f.handler.ServeHTTP(w2, r2)
	if w2.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for clone detection, got %d body=%s", w2.Code, w2.Body.String())
	}
	if !bytes.Contains(w2.Body.Bytes(), []byte("PASSKEY_REPLAY_DETECTED")) {
		t.Errorf("body should be PASSKEY_REPLAY_DETECTED; got %s", w2.Body.String())
	}
}

// TestPasskey_Verify_ProductionPath_ReplayedChallenge_Rejected is the D9
// assertion-replay proof. An attacker captures a VALID
// (authData, clientDataJSON, signature) triple from one ceremony and replays
// it against a DIFFERENT, freshly-minted challenge. The authenticator is
// counter-less (sign_count stays 0) so the clone-detection check is a no-op —
// the ONLY thing that can reject the replay is binding the signed
// clientDataJSON.challenge to the server-issued challenge for THIS ceremony.
//
// Before D9 this returned 200 (the login path never inspected the challenge).
// After D9 it must be 401 PASSKEY_CHALLENGE_MISMATCH.
func TestPasskey_Verify_ProductionPath_ReplayedChallenge_Rejected(t *testing.T) {
	t.Parallel()
	f := newProdES256Fixture(t)

	// Ceremony 1: capture a fully-valid triple bound to challenge #1.
	_, capturedChallB64 := mintChallenge(t, f.handler)
	authData := []byte("authenticator-data-fixture-32B--") // counter-less (0)
	capturedClientData := loginClientData(capturedChallB64)
	capturedSig := f.signFn(t, authData, capturedClientData)

	// Ceremony 2: a fresh challenge. The attacker submits the OLD triple
	// (still a cryptographically valid signature) against this new challenge.
	freshChID, freshChallB64 := mintChallenge(t, f.handler)
	if capturedChallB64 == freshChallB64 {
		t.Fatal("precondition: the two minted challenges must differ")
	}
	body, _ := json.Marshal(map[string]any{
		"challenge_id":       freshChID,
		"credential_id":      base64.StdEncoding.EncodeToString(f.credID),
		"sign_count":         0,
		"client_data_json":   base64.StdEncoding.EncodeToString(capturedClientData),
		"authenticator_data": base64.StdEncoding.EncodeToString(authData),
		"signature":          base64.StdEncoding.EncodeToString(capturedSig),
	})
	r := httptest.NewRequest(http.MethodPost, "/v1/auth/passkey/verify", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	f.handler.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("replay status = %d body=%s, want 401", w.Code, w.Body.String())
	}
	if !bytes.Contains(w.Body.Bytes(), []byte("PASSKEY_CHALLENGE_MISMATCH")) {
		t.Errorf("body should be PASSKEY_CHALLENGE_MISMATCH; got %s", w.Body.String())
	}
}

// TestPasskey_Verify_ProductionPath_WrongClientDataType_Rejected pins that a
// login assertion carrying a registration-typed clientDataJSON
// ("webauthn.create") is rejected — the type discriminator must match the
// ceremony (W3C WebAuthn L3 §7.2 step 11). The challenge itself is correct, so
// only the type check can fail this one.
func TestPasskey_Verify_ProductionPath_WrongClientDataType_Rejected(t *testing.T) {
	t.Parallel()
	f := newProdES256Fixture(t)
	chID, challB64 := mintChallenge(t, f.handler)

	authData := []byte("authenticator-data-fixture-32B--")
	clientDataJSON := []byte(fmt.Sprintf(`{"type":"webauthn.create","challenge":%q}`, challB64))
	sig := f.signFn(t, authData, clientDataJSON)

	body, _ := json.Marshal(map[string]any{
		"challenge_id":       chID,
		"credential_id":      base64.StdEncoding.EncodeToString(f.credID),
		"sign_count":         1,
		"client_data_json":   base64.StdEncoding.EncodeToString(clientDataJSON),
		"authenticator_data": base64.StdEncoding.EncodeToString(authData),
		"signature":          base64.StdEncoding.EncodeToString(sig),
	})
	r := httptest.NewRequest(http.MethodPost, "/v1/auth/passkey/verify", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	f.handler.ServeHTTP(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("wrong-type status = %d body=%s, want 400", w.Code, w.Body.String())
	}
	if !bytes.Contains(w.Body.Bytes(), []byte("PASSKEY_CLIENT_DATA_TYPE")) {
		t.Errorf("body should be PASSKEY_CLIENT_DATA_TYPE; got %s", w.Body.String())
	}
}
