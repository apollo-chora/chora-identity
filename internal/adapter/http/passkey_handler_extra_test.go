// passkey_handler_extra_test.go — extended branch coverage for the passkey
// HTTP adapter (passkey_handler.go).
//
// The ceremony test files (passkey_handler_test.go, passkey_register_test.go,
// passkey_signature_test.go, passkey_dek_test.go, passkey_concurrency_test.go,
// passkey_register_attestation_test.go) drive the happy paths + validation
// branches on the shared inmem repos, which cannot inject storage failures.
// This file closes the remaining gaps: repo failure branches, malformed
// request bodies, bad base64, mis-configured RPID, non-active users, revoked
// credentials, the challenge state-machine edge cases, RegisterRoutes
// mounting, the ServeHTTP fallthrough 404, the default challenge TTL, and the
// non-fatal DEK issuance failure.
//
// Error-injection fakes (pkx*) implement the same domain ports as inmem with
// identical storage semantics (defensive copies, First-Save-Wins on Consumed
// challenges) so behaviour stays faithful. Shared crypto + registration
// fixtures (newES256COSEPair / signES256ForTest / mintChallenge /
// loginClientData / newRegisterFixture / mintRegChallenge / postRegister /
// registerBody / attObjBytes / regAuthData / ec2COSE / pad32) are reused from
// the sibling test files in this package.
package httpadapter_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	httpadapter "github.com/apollo-chora/chora-identity/internal/adapter/http"
	"github.com/apollo-chora/chora-identity/internal/adapter/inmem"
	"github.com/apollo-chora/chora-identity/internal/domain/identity"
)

// -----------------------------------------------------------------------------
// Error-injecting fakes (storage semantics mirror inmem)
// -----------------------------------------------------------------------------

// pkxConfusableChallengeRepo is a PasskeyChallengeRepository whose GetByID /
// Save can be armed to fail, so loadUsableChallenge / consumeChallenge error
// branches are reachable deterministically.
type pkxChallengeRepo struct {
	mu      sync.Mutex
	store   map[string]*identity.PasskeyChallenge
	getErr  error // when set, GetByID fails with this error
	saveErr error // when set, Save fails with this error
}

func newPkxChallengeRepo() *pkxChallengeRepo {
	return &pkxChallengeRepo{store: make(map[string]*identity.PasskeyChallenge)}
}

func (r *pkxChallengeRepo) Save(_ context.Context, c *identity.PasskeyChallenge) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.saveErr != nil {
		return r.saveErr
	}
	// First-Save-Wins: a stored Consumed entry is terminal (mirrors inmem so
	// the multi-pod single-use contract stays honest under injection).
	if ex, ok := r.store[c.ChallengeID]; ok && ex.Status == identity.PasskeyChallengeStatusConsumed {
		return identity.ErrPasskeyChallengeConsumed
	}
	clone := *c
	clone.ChallengeBytes = append([]byte(nil), c.ChallengeBytes...)
	r.store[c.ChallengeID] = &clone
	return nil
}

func (r *pkxChallengeRepo) GetByID(_ context.Context, challengeID string) (*identity.PasskeyChallenge, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.getErr != nil {
		return nil, r.getErr
	}
	c, ok := r.store[challengeID]
	if !ok {
		return nil, identity.ErrPasskeyChallengeNotFound
	}
	clone := *c
	clone.ChallengeBytes = append([]byte(nil), c.ChallengeBytes...)
	return &clone, nil
}

// seedChallenge inserts the challenge directly, bypassing error injection, so
// tests can pre-populate state before arming getErr/saveErr.
func (r *pkxChallengeRepo) seedChallenge(c *identity.PasskeyChallenge) {
	r.mu.Lock()
	defer r.mu.Unlock()
	clone := *c
	clone.ChallengeBytes = append([]byte(nil), c.ChallengeBytes...)
	r.store[c.ChallengeID] = &clone
}

// pkxCredentialRepo is a PasskeyCredentialRepository with per-method error
// injection (indexed by SHA-256(credential_id) like inmem).
type pkxCredentialRepo struct {
	mu      sync.Mutex
	store   map[string]*identity.PasskeyCredential
	getErr  error
	saveErr error
}

func newPkxCredentialRepo() *pkxCredentialRepo {
	return &pkxCredentialRepo{store: make(map[string]*identity.PasskeyCredential)}
}

func pkxCredHash(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func (r *pkxCredentialRepo) Save(_ context.Context, c *identity.PasskeyCredential) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.saveErr != nil {
		return r.saveErr
	}
	clone := *c
	clone.CredentialID = append([]byte(nil), c.CredentialID...)
	clone.PublicKeyCOSE = append([]byte(nil), c.PublicKeyCOSE...)
	r.store[pkxCredHash(c.CredentialID)] = &clone
	return nil
}

func (r *pkxCredentialRepo) GetByCredentialID(_ context.Context, credentialID []byte) (*identity.PasskeyCredential, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.getErr != nil {
		return nil, r.getErr
	}
	c, ok := r.store[pkxCredHash(credentialID)]
	if !ok {
		return nil, identity.ErrPasskeyCredentialNotFound
	}
	clone := *c
	clone.CredentialID = append([]byte(nil), c.CredentialID...)
	clone.PublicKeyCOSE = append([]byte(nil), c.PublicKeyCOSE...)
	return &clone, nil
}

func (r *pkxCredentialRepo) ListByGcid(_ context.Context, gcid string) ([]*identity.PasskeyCredential, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]*identity.PasskeyCredential, 0)
	for _, c := range r.store {
		if c.Gcid != gcid {
			continue
		}
		clone := *c
		clone.CredentialID = append([]byte(nil), c.CredentialID...)
		clone.PublicKeyCOSE = append([]byte(nil), c.PublicKeyCOSE...)
		out = append(out, &clone)
	}
	return out, nil
}

// pkxUserRepo is a UserRepository with injectable GetByGcid failure.
type pkxUserRepo struct {
	mu     sync.Mutex
	store  map[string]*identity.User
	getErr error
}

func newPkxUserRepo() *pkxUserRepo {
	return &pkxUserRepo{store: make(map[string]*identity.User)}
}

func (r *pkxUserRepo) Save(_ context.Context, u *identity.User) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	clone := *u
	r.store[u.Gcid] = &clone
	return nil
}

func (r *pkxUserRepo) GetByGcid(_ context.Context, gcid string) (*identity.User, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.getErr != nil {
		return nil, r.getErr
	}
	u, ok := r.store[gcid]
	if !ok {
		return nil, identity.ErrUserNotFound
	}
	clone := *u
	return &clone, nil
}

// pkxFailingKeyManager always fails IssueDEK so the non-fatal DEK branch on
// registration (log-and-continue) is exercised.
type pkxFailingKeyManager struct{}

func (pkxFailingKeyManager) IssueDEK(gcid string) (string, error) {
	return "", errors.New("kms unavailable")
}
func (pkxFailingKeyManager) ShredDEK(gcid string) error { return nil }
func (pkxFailingKeyManager) Encrypt(gcid string, plaintext []byte) ([]byte, error) {
	return nil, errors.New("kms unavailable")
}
func (pkxFailingKeyManager) Decrypt(gcid string, ciphertext []byte) ([]byte, error) {
	return nil, errors.New("kms unavailable")
}
func (pkxFailingKeyManager) Tokenise(gcid, field, value string) (string, error) {
	return "", errors.New("kms unavailable")
}

// -----------------------------------------------------------------------------
// Fixture on top of the injectable fakes
// -----------------------------------------------------------------------------

type pkxFix struct {
	handler     *httpadapter.PasskeyHandler
	users       *pkxUserRepo
	challenges  *pkxChallengeRepo
	credentials *pkxCredentialRepo
	gcid        string
	email       string
	credID      []byte
	priv        *ecdsa.PrivateKey
}

func pkxNewFixture(t *testing.T) *pkxFix {
	t.Helper()
	users := newPkxUserRepo()
	challenges := newPkxChallengeRepo()
	credentials := newPkxCredentialRepo()
	ctx := context.Background()

	gcid := "01970000-0000-7000-8000-0000000000c1"
	_ = users.Save(ctx, &identity.User{
		Gcid:               gcid,
		Email:              "pkx@chora.dev",
		IdentityProvider:   identity.ProviderWebAuthn,
		FederatedSubject:   "webauthn|" + gcid,
		Status:             identity.UserStatusActive,
		VerificationStatus: identity.VerificationStatusUnverified,
	})

	priv, cose := newES256COSEPair(t)
	credID := []byte("pkx-cred-id")
	cred, err := identity.NewPasskeyCredential(identity.NewPasskeyCredentialParams{
		Gcid:          gcid,
		CredentialID:  credID,
		PublicKeyCOSE: cose,
		RPID:          "chora.site",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := credentials.Save(ctx, cred); err != nil {
		t.Fatal(err)
	}

	h := httpadapter.NewPasskeyHandler(users, challenges, credentials,
		httpadapter.PasskeyHandlerConfig{RPID: "chora.site", ChallengeTTLSeconds: 300})
	return &pkxFix{
		handler: h, users: users, challenges: challenges, credentials: credentials,
		gcid: gcid, email: "pkx@chora.dev", credID: credID, priv: priv,
	}
}

// pkxVerifyBody builds a login ceremony body bound to the fixture credential;
// extra overrides/replaces any field.
func pkxVerifyBody(f *pkxFix, chID, chB64 string, authData, clientDataJSON, sig []byte, extra map[string]any) map[string]any {
	body := map[string]any{
		"challenge_id":       chID,
		"credential_id":      base64.StdEncoding.EncodeToString(f.credID),
		"sign_count":         1,
		"client_data_json":   base64.StdEncoding.EncodeToString(clientDataJSON),
		"authenticator_data": base64.StdEncoding.EncodeToString(authData),
		"signature":          base64.StdEncoding.EncodeToString(sig),
	}
	for k, v := range extra {
		body[k] = v
	}
	return body
}

func pkxPostVerify(t *testing.T, h *httpadapter.PasskeyHandler, body map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	b, _ := json.Marshal(body)
	r := httptest.NewRequest(http.MethodPost, "/v1/auth/passkey/verify", bytes.NewReader(b))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

// pkxRegisterBody mirrors registerBody but is fixture-agnostic (takes gcid).
func pkxRegisterBody(gcid, challengeID, challengeB64, credID string, attObj []byte) map[string]any {
	return map[string]any{
		"challenge_id":       challengeID,
		"gcid":               gcid,
		"credential_id":      credID,
		"client_data_json":   base64.StdEncoding.EncodeToString(clientDataCreate(challengeB64)),
		"attestation_object": base64.StdEncoding.EncodeToString(attObj),
	}
}

// pkxSeedChallenge builds a challenge with arbitrary state (bypasses the
// constructor, whose status is always Pending) for the state-machine branches.
func pkxSeedChallenge(id string, status identity.PasskeyChallengeStatus, verifiedGCID string, expiresAt time.Time) *identity.PasskeyChallenge {
	return &identity.PasskeyChallenge{
		ChallengeID:    id,
		ChallengeBytes: []byte("pkx-seeded-challenge-nonce-32"),
		RPID:           "chora.site",
		Status:         status,
		VerifiedGCID:   verifiedGCID,
		CreatedAt:      time.Now().UTC().Add(-time.Minute),
		ExpiresAt:      expiresAt,
	}
}

// -----------------------------------------------------------------------------
// RegisterRoutes / ServeHTTP dispatch
// -----------------------------------------------------------------------------

func TestPasskey_RegisterRoutes_MountsAllRoutes_DispatchThroughMux(t *testing.T) {
	t.Parallel()
	h, _, _, _ := buildPasskeyHandler(t)

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	// POST /challenge through the mux must reach the handler (200), not 404.
	r := httptest.NewRequest(http.MethodPost, "/v1/auth/passkey/challenge", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("challenge via mux: %d body=%s", w.Code, w.Body.String())
	}

	// Non-POST on a mounted path proves dispatch by triggering the handler's
	// own 405 (a 404 would mean the route is not mounted).
	r2 := httptest.NewRequest(http.MethodGet, "/v1/auth/passkey/register", nil)
	w2 := httptest.NewRecorder()
	mux.ServeHTTP(w2, r2)
	if w2.Code != http.StatusMethodNotAllowed {
		t.Fatalf("register via mux: %d want 405 (route not mounted?)", w2.Code)
	}

	// Handler-level validation (not mux-level 404) for /verify.
	r3 := httptest.NewRequest(http.MethodPost, "/v1/auth/passkey/verify",
		bytes.NewBufferString(`{}`))
	r3.Header.Set("Content-Type", "application/json")
	w3 := httptest.NewRecorder()
	mux.ServeHTTP(w3, r3)
	if w3.Code != http.StatusBadRequest {
		t.Fatalf("verify via mux: %d want 400 body=%s", w3.Code, w3.Body.String())
	}
}

func TestPasskey_ServeHTTP_UnknownPath_404(t *testing.T) {
	t.Parallel()
	h, _, _, _ := buildPasskeyHandler(t)

	for _, p := range []string{"/v1/auth/passkey/nope", "/v1/auth/passkey/challenge/"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, p, nil))
		if w.Code != http.StatusNotFound {
			t.Errorf("path %q: status=%d want 404", p, w.Code)
		}
		if !strings.Contains(w.Body.String(), "PASSKEY_NOT_FOUND") {
			t.Errorf("path %q: want PASSKEY_NOT_FOUND, got %s", p, w.Body.String())
		}
	}
}

// -----------------------------------------------------------------------------
// NewPasskeyHandlerWithDEK — default TTL branch
// -----------------------------------------------------------------------------

func TestPasskey_NewPasskeyHandlerWithDEK_ZeroTTL_DefaultsTo300s(t *testing.T) {
	t.Parallel()
	users := inmem.NewUserRepository()
	challenges := inmem.NewPasskeyChallengeRepository()
	credentials := inmem.NewPasskeyCredentialRepository()

	// TTL omitted (0) → constructor must fall back to the 300s default.
	h := httpadapter.NewPasskeyHandlerWithDEK(users, challenges, credentials, nil,
		httpadapter.PasskeyHandlerConfig{RPID: "chora.site"})

	chID, _ := mintChallenge(t, h)
	ctx := context.Background()
	ch, err := challenges.GetByID(ctx, chID)
	if err != nil {
		t.Fatalf("load challenge: %v", err)
	}
	ttl := ch.ExpiresAt.Sub(ch.CreatedAt)
	if ttl < 290*time.Second || ttl > 310*time.Second {
		t.Fatalf("default challenge TTL = %v, want ~300s", ttl)
	}
}

// -----------------------------------------------------------------------------
// POST /v1/auth/passkey/challenge — error branches
// -----------------------------------------------------------------------------

func TestPasskey_Challenge_MissingRPID_500(t *testing.T) {
	t.Parallel()
	h := httpadapter.NewPasskeyHandler(
		inmem.NewUserRepository(), inmem.NewPasskeyChallengeRepository(),
		inmem.NewPasskeyCredentialRepository(),
		httpadapter.PasskeyHandlerConfig{RPID: "", ChallengeTTLSeconds: 300})

	r := httptest.NewRequest(http.MethodPost, "/v1/auth/passkey/challenge", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d want 500; body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "IDENTITY_PASSKEY_MISCONFIGURED") {
		t.Fatalf("want IDENTITY_PASSKEY_MISCONFIGURED, got %s", w.Body.String())
	}
}

func TestPasskey_Challenge_MalformedBody_400(t *testing.T) {
	t.Parallel()
	h, _, _, _ := buildPasskeyHandler(t)

	r := httptest.NewRequest(http.MethodPost, "/v1/auth/passkey/challenge",
		bytes.NewBufferString(`{"user_handle":`)) // broken JSON
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status=%d want 400; body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "PASSKEY_INVALID_BODY") {
		t.Fatalf("want PASSKEY_INVALID_BODY, got %s", w.Body.String())
	}
}

func TestPasskey_Challenge_SaveError_500(t *testing.T) {
	t.Parallel()
	f := pkxNewFixture(t)
	f.challenges.saveErr = errors.New("pgx: connection refused")

	r := httptest.NewRequest(http.MethodPost, "/v1/auth/passkey/challenge", nil)
	w := httptest.NewRecorder()
	f.handler.ServeHTTP(w, r)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d want 500; body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "PASSKEY_REPO_ERROR") {
		t.Fatalf("want PASSKEY_REPO_ERROR, got %s", w.Body.String())
	}
}

// -----------------------------------------------------------------------------
// POST /v1/auth/passkey/register — error branches
// -----------------------------------------------------------------------------

func TestPasskey_Register_MissingRPID_500(t *testing.T) {
	t.Parallel()
	h := httpadapter.NewPasskeyHandler(
		inmem.NewUserRepository(), inmem.NewPasskeyChallengeRepository(),
		inmem.NewPasskeyCredentialRepository(),
		httpadapter.PasskeyHandlerConfig{RPID: "", ChallengeTTLSeconds: 300})

	r := httptest.NewRequest(http.MethodPost, "/v1/auth/passkey/register",
		bytes.NewBufferString(`{}`))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d want 500; body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "IDENTITY_PASSKEY_MISCONFIGURED") {
		t.Fatalf("want IDENTITY_PASSKEY_MISCONFIGURED, got %s", w.Body.String())
	}
}

func TestPasskey_Register_MalformedBody_400(t *testing.T) {
	t.Parallel()
	f := newRegisterFixture(t)

	r := httptest.NewRequest(http.MethodPost, "/v1/auth/passkey/register",
		bytes.NewBufferString(`{"challenge_id":`))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	f.handler.ServeHTTP(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status=%d want 400; body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "PASSKEY_INVALID_BODY") {
		t.Fatalf("want PASSKEY_INVALID_BODY, got %s", w.Body.String())
	}
}

func TestPasskey_Register_GcidRequired_400(t *testing.T) {
	t.Parallel()
	f := newRegisterFixture(t)
	w := postRegister(t, f.handler, map[string]any{"challenge_id": "some-challenge"})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status=%d want 400; body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "PASSKEY_GCID_REQUIRED") {
		t.Fatalf("want PASSKEY_GCID_REQUIRED, got %s", w.Body.String())
	}
}

func TestPasskey_Register_CredentialIDRequired_400(t *testing.T) {
	t.Parallel()
	f := newRegisterFixture(t)
	w := postRegister(t, f.handler, map[string]any{"challenge_id": "c", "gcid": f.gcid})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status=%d want 400; body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "PASSKEY_CREDENTIAL_ID_REQUIRED") {
		t.Fatalf("want PASSKEY_CREDENTIAL_ID_REQUIRED, got %s", w.Body.String())
	}
}

func TestPasskey_Register_AttestationRequired_400(t *testing.T) {
	t.Parallel()
	f := newRegisterFixture(t)
	w := postRegister(t, f.handler, map[string]any{
		"challenge_id":  "c",
		"gcid":          f.gcid,
		"credential_id": "ZGVhZGJlZWY=",
	})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status=%d want 400; body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "PASSKEY_ATTESTATION_REQUIRED") {
		t.Fatalf("want PASSKEY_ATTESTATION_REQUIRED, got %s", w.Body.String())
	}
}

func TestPasskey_Register_InvalidCredentialIDBase64_400(t *testing.T) {
	t.Parallel()
	f := newRegisterFixture(t)
	chID, chB64 := mintRegChallenge(t, f.handler)
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cose := ec2COSE(pad32(priv.PublicKey.X.Bytes()), pad32(priv.PublicKey.Y.Bytes()))
	credID := []byte("bad-b64-cred")
	body := registerBody(f, chID, chB64, base64.StdEncoding.EncodeToString(credID),
		attObjBytes("none", regAuthData("chora.site", 0, credID, cose)))
	body["credential_id"] = "###not-base64###"

	w := postRegister(t, f.handler, body)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status=%d want 400; body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "PASSKEY_INVALID_CREDENTIAL_ID") {
		t.Fatalf("want PASSKEY_INVALID_CREDENTIAL_ID, got %s", w.Body.String())
	}
}

func TestPasskey_Register_InvalidClientDataBase64_400(t *testing.T) {
	t.Parallel()
	f := newRegisterFixture(t)
	chID, chB64 := mintRegChallenge(t, f.handler)
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cose := ec2COSE(pad32(priv.PublicKey.X.Bytes()), pad32(priv.PublicKey.Y.Bytes()))
	credID := []byte("bad-cd-cred")
	body := registerBody(f, chID, chB64, base64.StdEncoding.EncodeToString(credID),
		attObjBytes("none", regAuthData("chora.site", 0, credID, cose)))
	body["client_data_json"] = "###not-base64###"

	w := postRegister(t, f.handler, body)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status=%d want 400; body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "PASSKEY_INVALID_CLIENT_DATA") {
		t.Fatalf("want PASSKEY_INVALID_CLIENT_DATA, got %s", w.Body.String())
	}
}

func TestPasskey_Register_InvalidAttestationBase64_400(t *testing.T) {
	t.Parallel()
	f := newRegisterFixture(t)
	chID, chB64 := mintRegChallenge(t, f.handler)
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cose := ec2COSE(pad32(priv.PublicKey.X.Bytes()), pad32(priv.PublicKey.Y.Bytes()))
	credID := []byte("bad-att-cred")
	body := registerBody(f, chID, chB64, base64.StdEncoding.EncodeToString(credID),
		attObjBytes("none", regAuthData("chora.site", 0, credID, cose)))
	body["attestation_object"] = "###not-base64###"

	w := postRegister(t, f.handler, body)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status=%d want 400; body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "PASSKEY_INVALID_ATTESTATION") {
		t.Fatalf("want PASSKEY_INVALID_ATTESTATION, got %s", w.Body.String())
	}
}

func TestPasskey_Register_ClientDataNotJSON_400(t *testing.T) {
	t.Parallel()
	f := newRegisterFixture(t)
	chID, chB64 := mintRegChallenge(t, f.handler)
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cose := ec2COSE(pad32(priv.PublicKey.X.Bytes()), pad32(priv.PublicKey.Y.Bytes()))
	credID := []byte("not-json-cred")
	body := registerBody(f, chID, chB64, base64.StdEncoding.EncodeToString(credID),
		attObjBytes("none", regAuthData("chora.site", 0, credID, cose)))
	body["client_data_json"] = base64.StdEncoding.EncodeToString([]byte("not-json")) // decodes, but is not JSON

	w := postRegister(t, f.handler, body)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status=%d want 400; body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "PASSKEY_INVALID_CLIENT_DATA") {
		t.Fatalf("want PASSKEY_INVALID_CLIENT_DATA, got %s", w.Body.String())
	}
}

func TestPasskey_Register_MalformedAttestationObject_400(t *testing.T) {
	t.Parallel()
	f := newRegisterFixture(t)
	chID, chB64 := mintRegChallenge(t, f.handler)
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cose := ec2COSE(pad32(priv.PublicKey.X.Bytes()), pad32(priv.PublicKey.Y.Bytes()))
	credID := []byte("garbage-att-cred")
	body := registerBody(f, chID, chB64, base64.StdEncoding.EncodeToString(credID),
		attObjBytes("none", regAuthData("chora.site", 0, credID, cose)))
	body["attestation_object"] = base64.StdEncoding.EncodeToString([]byte("garbage-cbor")) // not CBOR

	w := postRegister(t, f.handler, body)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status=%d want 400; body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "PASSKEY_INVALID_ATTESTATION") {
		t.Fatalf("want PASSKEY_INVALID_ATTESTATION, got %s", w.Body.String())
	}
}

func TestPasskey_Register_UserLookupError_500(t *testing.T) {
	t.Parallel()
	f := pkxNewFixture(t)
	chID, chB64 := mintChallenge(t, f.handler)
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cose := ec2COSE(pad32(priv.PublicKey.X.Bytes()), pad32(priv.PublicKey.Y.Bytes()))
	credID := []byte("pkx-reg-user-err")
	body := pkxRegisterBody(f.gcid, chID, chB64, base64.StdEncoding.EncodeToString(credID),
		attObjBytes("none", regAuthData("chora.site", 0, credID, cose)))

	f.users.getErr = errors.New("pgx: connection refused")
	w := postRegister(t, f.handler, body)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d want 500; body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "PASSKEY_REPO_ERROR") {
		t.Fatalf("want PASSKEY_REPO_ERROR, got %s", w.Body.String())
	}
}

func TestPasskey_Register_UserNotActive_403(t *testing.T) {
	t.Parallel()
	f := newRegisterFixture(t)
	// Overwrite the fixture's active user with a suspended one (same gcid).
	_ = f.users.Save(context.Background(), &identity.User{
		Gcid:               f.gcid,
		Email:              "register@chora.dev",
		IdentityProvider:   identity.ProviderOIDC,
		FederatedSubject:   "fed-sub-register",
		Status:             identity.UserStatusSuspended,
		VerificationStatus: identity.VerificationStatusUnverified,
	})
	chID, chB64 := mintRegChallenge(t, f.handler)
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cose := ec2COSE(pad32(priv.PublicKey.X.Bytes()), pad32(priv.PublicKey.Y.Bytes()))
	credID := []byte("suspended-user-cred")

	w := postRegister(t, f.handler, registerBody(f, chID, chB64,
		base64.StdEncoding.EncodeToString(credID),
		attObjBytes("none", regAuthData("chora.site", 0, credID, cose))))
	if w.Code != http.StatusForbidden {
		t.Fatalf("status=%d want 403; body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "PASSKEY_USER_NOT_ACTIVE") {
		t.Fatalf("want PASSKEY_USER_NOT_ACTIVE, got %s", w.Body.String())
	}
}

func TestPasskey_Register_CredentialLookupError_500(t *testing.T) {
	t.Parallel()
	f := pkxNewFixture(t)
	chID, chB64 := mintChallenge(t, f.handler)
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cose := ec2COSE(pad32(priv.PublicKey.X.Bytes()), pad32(priv.PublicKey.Y.Bytes()))
	credID := []byte("pkx-reg-cred-err")
	body := pkxRegisterBody(f.gcid, chID, chB64, base64.StdEncoding.EncodeToString(credID),
		attObjBytes("none", regAuthData("chora.site", 0, credID, cose)))

	// Uniqueness check (GetByCredentialID) blows up with a non-not-found error.
	f.credentials.getErr = errors.New("pgx: connection refused")
	w := postRegister(t, f.handler, body)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d want 500; body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "PASSKEY_REPO_ERROR") {
		t.Fatalf("want PASSKEY_REPO_ERROR, got %s", w.Body.String())
	}
}

func TestPasskey_Register_CredentialSaveError_500(t *testing.T) {
	t.Parallel()
	f := pkxNewFixture(t)
	chID, chB64 := mintChallenge(t, f.handler)
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cose := ec2COSE(pad32(priv.PublicKey.X.Bytes()), pad32(priv.PublicKey.Y.Bytes()))
	credID := []byte("pkx-reg-save-err")
	body := pkxRegisterBody(f.gcid, chID, chB64, base64.StdEncoding.EncodeToString(credID),
		attObjBytes("none", regAuthData("chora.site", 0, credID, cose)))

	// Challenge consumption succeeds, then the credential persist fails.
	f.credentials.saveErr = errors.New("pgx: connection refused")
	w := postRegister(t, f.handler, body)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d want 500; body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "PASSKEY_REPO_ERROR") {
		t.Fatalf("want PASSKEY_REPO_ERROR, got %s", w.Body.String())
	}
}

func TestPasskey_Register_ChallengeSaveConsumedError_401(t *testing.T) {
	t.Parallel()
	f := pkxNewFixture(t)
	chID, chB64 := mintChallenge(t, f.handler)
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cose := ec2COSE(pad32(priv.PublicKey.X.Bytes()), pad32(priv.PublicKey.Y.Bytes()))
	credID := []byte("pkx-reg-consume-err")
	body := pkxRegisterBody(f.gcid, chID, chB64, base64.StdEncoding.EncodeToString(credID),
		attObjBytes("none", regAuthData("chora.site", 0, credID, cose)))

	// The consume save loses the First-Save-Wins race (a concurrent pod won).
	f.challenges.saveErr = identity.ErrPasskeyChallengeConsumed
	w := postRegister(t, f.handler, body)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d want 401; body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "PASSKEY_CHALLENGE_CONSUMED") {
		t.Fatalf("want PASSKEY_CHALLENGE_CONSUMED, got %s", w.Body.String())
	}
}

func TestPasskey_Register_DEKIssueFailure_NonFatal(t *testing.T) {
	t.Parallel()
	users := inmem.NewUserRepository()
	challenges := inmem.NewPasskeyChallengeRepository()
	credentials := inmem.NewPasskeyCredentialRepository()
	ctx := context.Background()

	gcid := "01970000-0000-7000-8000-0000000000e2"
	_ = users.Save(ctx, &identity.User{
		Gcid:               gcid,
		Email:              "dek-fail@chora.dev",
		IdentityProvider:   identity.ProviderOIDC,
		FederatedSubject:   "fed-sub-dek-fail",
		Status:             identity.UserStatusActive,
		VerificationStatus: identity.VerificationStatusUnverified,
	})

	h := httpadapter.NewPasskeyHandlerWithDEK(users, challenges, credentials,
		pkxFailingKeyManager{},
		httpadapter.PasskeyHandlerConfig{RPID: "chora.site", ChallengeTTLSeconds: 300})

	chID, chB64 := mintChallenge(t, h)
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cose := ec2COSE(pad32(priv.PublicKey.X.Bytes()), pad32(priv.PublicKey.Y.Bytes()))
	credID := []byte("dek-fail-cred")
	body := pkxRegisterBody(gcid, chID, chB64, base64.StdEncoding.EncodeToString(credID),
		attObjBytes("none", regAuthData("chora.site", 0, credID, cose)))

	// DEK issuance failure must NOT fail the ceremony (log-and-continue).
	w := postRegister(t, h, body)
	if w.Code != http.StatusCreated {
		t.Fatalf("status=%d want 201 (DEK failure is non-fatal); body=%s", w.Code, w.Body.String())
	}
}

// -----------------------------------------------------------------------------
// POST /v1/auth/passkey/verify — error branches
// -----------------------------------------------------------------------------

func TestPasskey_Verify_RejectsGet_405(t *testing.T) {
	t.Parallel()
	h, _, _, _ := buildPasskeyHandler(t)
	r := httptest.NewRequest(http.MethodGet, "/v1/auth/passkey/verify", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status=%d want 405; body=%s", w.Code, w.Body.String())
	}
}

func TestPasskey_Verify_MalformedBody_400(t *testing.T) {
	t.Parallel()
	h, _, _, _ := buildPasskeyHandler(t)
	r := httptest.NewRequest(http.MethodPost, "/v1/auth/passkey/verify",
		bytes.NewBufferString(`{"challenge_id":`))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status=%d want 400; body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "PASSKEY_INVALID_BODY") {
		t.Fatalf("want PASSKEY_INVALID_BODY, got %s", w.Body.String())
	}
}

func TestPasskey_Verify_CredentialIDRequired_400(t *testing.T) {
	t.Parallel()
	h, _, _, _ := buildPasskeyHandler(t)
	r := httptest.NewRequest(http.MethodPost, "/v1/auth/passkey/verify",
		bytes.NewBufferString(`{"challenge_id":"some-challenge"}`))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status=%d want 400; body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "PASSKEY_CREDENTIAL_ID_REQUIRED") {
		t.Fatalf("want PASSKEY_CREDENTIAL_ID_REQUIRED, got %s", w.Body.String())
	}
}

func TestPasskey_Verify_InvalidCredentialIDBase64_400(t *testing.T) {
	t.Parallel()
	h, _, _, _ := buildPasskeyHandler(t)
	r := httptest.NewRequest(http.MethodPost, "/v1/auth/passkey/verify",
		bytes.NewBufferString(`{"challenge_id":"c","credential_id":"###not-base64###"}`))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status=%d want 400; body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "PASSKEY_INVALID_CREDENTIAL_ID") {
		t.Fatalf("want PASSKEY_INVALID_CREDENTIAL_ID, got %s", w.Body.String())
	}
}

func TestPasskey_Verify_ChallengeLookupError_500(t *testing.T) {
	t.Parallel()
	f := pkxNewFixture(t)
	f.challenges.getErr = errors.New("pgx: connection refused")

	w := pkxPostVerify(t, f.handler, map[string]any{
		"challenge_id":  "whatever",
		"credential_id": base64.StdEncoding.EncodeToString([]byte("deadbeef")),
	})
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d want 500; body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "PASSKEY_REPO_ERROR") {
		t.Fatalf("want PASSKEY_REPO_ERROR, got %s", w.Body.String())
	}
}

func TestPasskey_Verify_CredentialLookupError_500(t *testing.T) {
	t.Parallel()
	f := pkxNewFixture(t)
	chID, _ := mintChallenge(t, f.handler)
	f.credentials.getErr = errors.New("pgx: connection refused")

	w := pkxPostVerify(t, f.handler, map[string]any{
		"challenge_id":  chID,
		"credential_id": base64.StdEncoding.EncodeToString(f.credID),
	})
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d want 500; body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "PASSKEY_REPO_ERROR") {
		t.Fatalf("want PASSKEY_REPO_ERROR, got %s", w.Body.String())
	}
}

func TestPasskey_Verify_InvalidClientDataBase64_400(t *testing.T) {
	t.Parallel()
	f := pkxNewFixture(t)
	chID, chB64 := mintChallenge(t, f.handler)
	authData := loginAuthData("chora.site", 1)
	clientData := loginClientData(chB64)
	sig := signES256ForTest(t, f.priv, authData, clientData)

	body := pkxVerifyBody(f, chID, chB64, authData, clientData, sig, nil)
	body["client_data_json"] = "###not-base64###"

	w := pkxPostVerify(t, f.handler, body)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status=%d want 400; body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "PASSKEY_INVALID_CLIENT_DATA") {
		t.Fatalf("want PASSKEY_INVALID_CLIENT_DATA, got %s", w.Body.String())
	}
}

func TestPasskey_Verify_InvalidAuthDataBase64_400(t *testing.T) {
	t.Parallel()
	f := pkxNewFixture(t)
	chID, chB64 := mintChallenge(t, f.handler)
	authData := loginAuthData("chora.site", 1)
	clientData := loginClientData(chB64)
	sig := signES256ForTest(t, f.priv, authData, clientData)

	body := pkxVerifyBody(f, chID, chB64, authData, clientData, sig, nil)
	body["authenticator_data"] = "###not-base64###"

	w := pkxPostVerify(t, f.handler, body)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status=%d want 400; body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "PASSKEY_INVALID_AUTH_DATA") {
		t.Fatalf("want PASSKEY_INVALID_AUTH_DATA, got %s", w.Body.String())
	}
}

func TestPasskey_Verify_InvalidSignatureBase64_400(t *testing.T) {
	t.Parallel()
	f := pkxNewFixture(t)
	chID, chB64 := mintChallenge(t, f.handler)
	authData := loginAuthData("chora.site", 1)
	clientData := loginClientData(chB64)
	sig := signES256ForTest(t, f.priv, authData, clientData)

	body := pkxVerifyBody(f, chID, chB64, authData, clientData, sig, nil)
	body["signature"] = "###not-base64###"

	w := pkxPostVerify(t, f.handler, body)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status=%d want 400; body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "PASSKEY_INVALID_SIGNATURE") {
		t.Fatalf("want PASSKEY_INVALID_SIGNATURE, got %s", w.Body.String())
	}
}

func TestPasskey_Verify_MalformedClientDataJSON_400(t *testing.T) {
	t.Parallel()
	f := pkxNewFixture(t)
	chID, chB64 := mintChallenge(t, f.handler)
	authData := loginAuthData("chora.site", 1)
	clientData := loginClientData(chB64)
	sig := signES256ForTest(t, f.priv, authData, clientData)

	// clientDataJSON is valid base64 but not JSON → ErrMalformedClientData.
	body := pkxVerifyBody(f, chID, chB64, authData, clientData, sig, map[string]any{
		"client_data_json": base64.StdEncoding.EncodeToString([]byte("not-json")),
	})

	w := pkxPostVerify(t, f.handler, body)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status=%d want 400; body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "PASSKEY_INVALID_CLIENT_DATA") {
		t.Fatalf("want PASSKEY_INVALID_CLIENT_DATA, got %s", w.Body.String())
	}
}

func TestPasskey_Verify_KeyMaterialInvalid_500(t *testing.T) {
	t.Parallel()
	f := pkxNewFixture(t)
	// A second credential whose COSE key is garbage → ErrMalformedCOSEKey.
	badCredID := []byte("pkx-garbage-key-cred")
	badCred, err := identity.NewPasskeyCredential(identity.NewPasskeyCredentialParams{
		Gcid:          f.gcid,
		CredentialID:  badCredID,
		PublicKeyCOSE: []byte("not-a-real-cose-key"),
		RPID:          "chora.site",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.credentials.Save(context.Background(), badCred); err != nil {
		t.Fatal(err)
	}

	chID, chB64 := mintChallenge(t, f.handler)
	authData := loginAuthData("chora.site", 1)
	clientData := loginClientData(chB64)
	body := map[string]any{
		"challenge_id":       chID,
		"credential_id":      base64.StdEncoding.EncodeToString(badCredID),
		"sign_count":         1,
		"client_data_json":   base64.StdEncoding.EncodeToString(clientData),
		"authenticator_data": base64.StdEncoding.EncodeToString(authData),
		"signature":          base64.StdEncoding.EncodeToString([]byte("deadbeef")),
	}

	w := pkxPostVerify(t, f.handler, body)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d want 500; body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "PASSKEY_KEY_MATERIAL_INVALID") {
		t.Fatalf("want PASSKEY_KEY_MATERIAL_INVALID, got %s", w.Body.String())
	}
}

func TestPasskey_Verify_RevokedCredential_401(t *testing.T) {
	t.Parallel()
	f := pkxNewFixture(t)
	// A second credential that is already revoked.
	revokedCredID := []byte("pkx-revoked-cred")
	revokedCred, err := identity.NewPasskeyCredential(identity.NewPasskeyCredentialParams{
		Gcid:          f.gcid,
		CredentialID:  revokedCredID,
		PublicKeyCOSE: ec2COSE(pad32(f.priv.PublicKey.X.Bytes()), pad32(f.priv.PublicKey.Y.Bytes())),
		RPID:          "chora.site",
	})
	if err != nil {
		t.Fatal(err)
	}
	revokedCred.Revoke()
	if err := f.credentials.Save(context.Background(), revokedCred); err != nil {
		t.Fatal(err)
	}

	chID, chB64 := mintChallenge(t, f.handler)
	authData := loginAuthData("chora.site", 1)
	clientData := loginClientData(chB64)
	sig := signES256ForTest(t, f.priv, authData, clientData)

	body := map[string]any{
		"challenge_id":       chID,
		"credential_id":      base64.StdEncoding.EncodeToString(revokedCredID),
		"sign_count":         1,
		"client_data_json":   base64.StdEncoding.EncodeToString(clientData),
		"authenticator_data": base64.StdEncoding.EncodeToString(authData),
		"signature":          base64.StdEncoding.EncodeToString(sig),
	}

	w := pkxPostVerify(t, f.handler, body)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d want 401; body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "PASSKEY_CREDENTIAL_REVOKED") {
		t.Fatalf("want PASSKEY_CREDENTIAL_REVOKED, got %s", w.Body.String())
	}
}

func TestPasskey_Verify_UserLookupFailed_500(t *testing.T) {
	t.Parallel()
	f := pkxNewFixture(t)
	// A credential bound to a gcid with NO user row → final user lookup fails.
	orphanGcid := "01970000-0000-7000-8000-0000000000c2"
	orphanCredID := []byte("pkx-orphan-cred")
	orphanCred, err := identity.NewPasskeyCredential(identity.NewPasskeyCredentialParams{
		Gcid:          orphanGcid,
		CredentialID:  orphanCredID,
		PublicKeyCOSE: ec2COSE(pad32(f.priv.PublicKey.X.Bytes()), pad32(f.priv.PublicKey.Y.Bytes())),
		RPID:          "chora.site",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.credentials.Save(context.Background(), orphanCred); err != nil {
		t.Fatal(err)
	}

	chID, chB64 := mintChallenge(t, f.handler)
	authData := loginAuthData("chora.site", 1)
	clientData := loginClientData(chB64)
	sig := signES256ForTest(t, f.priv, authData, clientData)

	body := map[string]any{
		"challenge_id":       chID,
		"credential_id":      base64.StdEncoding.EncodeToString(orphanCredID),
		"sign_count":         1,
		"client_data_json":   base64.StdEncoding.EncodeToString(clientData),
		"authenticator_data": base64.StdEncoding.EncodeToString(authData),
		"signature":          base64.StdEncoding.EncodeToString(sig),
	}

	w := pkxPostVerify(t, f.handler, body)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d want 500; body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "PASSKEY_USER_LOOKUP_FAILED") {
		t.Fatalf("want PASSKEY_USER_LOOKUP_FAILED, got %s", w.Body.String())
	}
}

func TestPasskey_Verify_CredentialSaveError_500(t *testing.T) {
	t.Parallel()
	f := pkxNewFixture(t)
	chID, chB64 := mintChallenge(t, f.handler)
	authData := loginAuthData("chora.site", 1)
	clientData := loginClientData(chB64)
	sig := signES256ForTest(t, f.priv, authData, clientData)
	body := pkxVerifyBody(f, chID, chB64, authData, clientData, sig, nil)

	// Challenge consumption succeeds; persisting the advanced sign-count fails.
	f.credentials.saveErr = errors.New("pgx: connection refused")
	w := pkxPostVerify(t, f.handler, body)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d want 500; body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "PASSKEY_REPO_ERROR") {
		t.Fatalf("want PASSKEY_REPO_ERROR, got %s", w.Body.String())
	}
}

func TestPasskey_Verify_ChallengeSaveConsumed_401(t *testing.T) {
	t.Parallel()
	f := pkxNewFixture(t)
	chID, chB64 := mintChallenge(t, f.handler)
	authData := loginAuthData("chora.site", 1)
	clientData := loginClientData(chB64)
	sig := signES256ForTest(t, f.priv, authData, clientData)
	body := pkxVerifyBody(f, chID, chB64, authData, clientData, sig, nil)

	// The consume save loses the First-Save-Wins race (a concurrent pod won).
	f.challenges.saveErr = identity.ErrPasskeyChallengeConsumed
	w := pkxPostVerify(t, f.handler, body)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d want 401; body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "PASSKEY_CHALLENGE_CONSUMED") {
		t.Fatalf("want PASSKEY_CHALLENGE_CONSUMED, got %s", w.Body.String())
	}
}

func TestPasskey_Verify_ChallengeSaveError_500(t *testing.T) {
	t.Parallel()
	f := pkxNewFixture(t)
	chID, chB64 := mintChallenge(t, f.handler)
	authData := loginAuthData("chora.site", 1)
	clientData := loginClientData(chB64)
	sig := signES256ForTest(t, f.priv, authData, clientData)
	body := pkxVerifyBody(f, chID, chB64, authData, clientData, sig, nil)

	f.challenges.saveErr = errors.New("pgx: connection refused")
	w := pkxPostVerify(t, f.handler, body)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d want 500; body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "PASSKEY_REPO_ERROR") {
		t.Fatalf("want PASSKEY_REPO_ERROR, got %s", w.Body.String())
	}
}

// -----------------------------------------------------------------------------
// Challenge state machine edge cases (loadUsableChallenge / consumeChallenge)
// -----------------------------------------------------------------------------

// TestPasskey_Verify_ChallengeExpiredStatus_401 drives the Status==Expired
// branch of loadUsableChallenge (distinct from the time-based expiry).
func TestPasskey_Verify_ChallengeExpiredStatus_401(t *testing.T) {
	t.Parallel()
	f := pkxNewFixture(t)
	// Status already terminal-expired, ExpiresAt still in the FUTURE so only
	// the status switch can reject it.
	f.challenges.seedChallenge(pkxSeedChallenge("pkx-status-expired",
		identity.PasskeyChallengeStatusExpired, "", time.Now().UTC().Add(time.Hour)))

	w := pkxPostVerify(t, f.handler, map[string]any{
		"challenge_id":  "pkx-status-expired",
		"credential_id": base64.StdEncoding.EncodeToString([]byte("deadbeef")),
	})
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d want 401; body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "PASSKEY_CHALLENGE_EXPIRED") {
		t.Fatalf("want PASSKEY_CHALLENGE_EXPIRED, got %s", w.Body.String())
	}
}

// TestPasskey_Verify_ChallengeTimeExpired_401 drives the time-based
// ch.Expired(now) branch deterministically. (The existing TTL=1ns test is
// clock-resolution dependent on coarse Windows timers — we force a past
// ExpiresAt so the branch fires unconditionally.)
func TestPasskey_Verify_ChallengeTimeExpired_401(t *testing.T) {
	t.Parallel()
	f := pkxNewFixture(t)
	f.challenges.seedChallenge(pkxSeedChallenge("pkx-time-expired",
		identity.PasskeyChallengeStatusPending, "", time.Now().UTC().Add(-time.Minute)))

	w := pkxPostVerify(t, f.handler, map[string]any{
		"challenge_id":  "pkx-time-expired",
		"credential_id": base64.StdEncoding.EncodeToString([]byte("deadbeef")),
	})
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d want 401; body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "PASSKEY_CHALLENGE_EXPIRED") {
		t.Fatalf("want PASSKEY_CHALLENGE_EXPIRED, got %s", w.Body.String())
	}
}

// TestPasskey_Verify_ChallengeVerifiedForOtherUser_401 drives the
// MarkVerified rejection inside consumeChallenge: the challenge is already
// Verified but bound to a DIFFERENT gcid.
func TestPasskey_Verify_ChallengeVerifiedForOtherUser_401(t *testing.T) {
	t.Parallel()
	f := pkxNewFixture(t)
	ch := pkxSeedChallenge("pkx-verified-other",
		identity.PasskeyChallengeStatusVerified, "01970000-0000-7000-8000-00000000beef",
		time.Now().UTC().Add(time.Hour))
	f.challenges.seedChallenge(ch)

	// The client must echo the seeded challenge bytes in clientDataJSON.
	chB64 := base64.RawURLEncoding.EncodeToString(ch.ChallengeBytes)
	authData := loginAuthData("chora.site", 1)
	clientData := []byte(`{"type":"webauthn.get","challenge":"` + chB64 + `"}`)
	sig := signES256ForTest(t, f.priv, authData, clientData)
	body := pkxVerifyBody(f, ch.ChallengeID, chB64, authData, clientData, sig, nil)

	w := pkxPostVerify(t, f.handler, body)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d want 401; body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "PASSKEY_VERIFY_REJECTED") {
		t.Fatalf("want PASSKEY_VERIFY_REJECTED, got %s", w.Body.String())
	}
}
