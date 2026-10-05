// Tests for the DEK provisioning hook on passkey credential REGISTRATION.
//
// Per audit-identity-fillgaps.md §3.1 risk R-DEK + Tier 3 D11:
//
//	Passkey registration → Issue a per-user DEK (idempotent per gcid) so
//	subsequent INSERTs into PII columns can wrap with the user's DEK.
//	Crypto-shred is the inverse: closure subscriber deletes the DEK.
//
// Phase A4 (CHO-1718): user creation no longer happens on the passkey path
// (registration binds to an EXISTING gcid; users are created by the resolve
// flow), so the DEK hook moved from "first-time verify" to /register.
//
// The DEK adapter is `internal/domain/crypto`; production swaps in CMEK
// (chora_keys keyring) per ADR / Tier 3 D11.
package httpadapter_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	httpadapter "github.com/apollo-chora/chora-identity/internal/adapter/http"
	"github.com/apollo-chora/chora-identity/internal/adapter/inmem"
	"github.com/apollo-chora/chora-identity/internal/domain/crypto"
	"github.com/apollo-chora/chora-identity/internal/domain/identity"
)

func TestPasskeyRegister_IssuesDEKForOwner(t *testing.T) {
	users := inmem.NewUserRepository()
	challenges := inmem.NewPasskeyChallengeRepository()
	credentials := inmem.NewPasskeyCredentialRepository()
	ctx := context.Background()

	km := crypto.NewInMemoryKeyManager([]byte("test-master-32-bytes-padding-12345"))

	gcid := "01970000-0000-7000-8000-0000000000e1"
	u := &identity.User{
		Gcid:               gcid,
		Email:              "dek-owner@chora.dev",
		IdentityProvider:   identity.ProviderOIDC,
		FederatedSubject:   "fed-sub-dek",
		Status:             identity.UserStatusActive,
		VerificationStatus: identity.VerificationStatusUnverified,
	}
	_ = users.Save(ctx, u)

	h := httpadapter.NewPasskeyHandlerWithDEK(users, challenges, credentials, km,
		httpadapter.PasskeyHandlerConfig{RPID: "chora.site", ChallengeTTLSeconds: 300})

	// Mint a challenge.
	chReq := httptest.NewRequest(http.MethodPost, "/v1/auth/passkey/challenge", nil)
	chRec := httptest.NewRecorder()
	h.ServeHTTP(chRec, chReq)
	if chRec.Code != http.StatusOK {
		t.Fatalf("challenge: %d", chRec.Code)
	}
	var chResp struct {
		ChallengeID string `json:"challenge_id"`
		Challenge   string `json:"challenge"`
	}
	_ = json.Unmarshal(chRec.Body.Bytes(), &chResp)

	// Register a real ES256 credential.
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	cose := ec2COSE(pad32(priv.PublicKey.X.Bytes()), pad32(priv.PublicKey.Y.Bytes()))
	credID := []byte("dek-cred-id")
	regBody, _ := json.Marshal(map[string]any{
		"challenge_id":  chResp.ChallengeID,
		"gcid":          gcid,
		"credential_id": base64.StdEncoding.EncodeToString(credID),
		"client_data_json": base64.StdEncoding.EncodeToString(
			[]byte(`{"type":"webauthn.create","challenge":"` + chResp.Challenge + `"}`)),
		"attestation_object": base64.StdEncoding.EncodeToString(
			attObjBytes("none", regAuthData("chora.site", 0, credID, cose))),
	})
	rReq := httptest.NewRequest(http.MethodPost, "/v1/auth/passkey/register", bytes.NewReader(regBody))
	rReq.Header.Set("Content-Type", "application/json")
	rRec := httptest.NewRecorder()
	h.ServeHTTP(rRec, rReq)
	if rRec.Code != http.StatusCreated {
		t.Fatalf("register: %d body=%s", rRec.Code, rRec.Body.String())
	}

	// Confirm a DEK was issued for the gcid. The proof: Encrypt+Decrypt
	// round-trips for that gcid.
	ct, err := km.Encrypt(gcid, []byte("phyllis-name-PII"))
	if err != nil {
		t.Fatalf("Encrypt failed — DEK was not issued at registration: %v", err)
	}
	pt, err := km.Decrypt(gcid, ct)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if string(pt) != "phyllis-name-PII" {
		t.Fatalf("plaintext mismatch: %q", pt)
	}

	// Shred + decrypt: the same ciphertext now fails with ErrDEKShredded.
	if err := km.ShredDEK(gcid); err != nil {
		t.Fatal(err)
	}
	if _, err := km.Decrypt(gcid, ct); !errors.Is(err, crypto.ErrDEKShredded) {
		t.Fatalf("expected ErrDEKShredded; got %v", err)
	}
}

func TestPasskeyVerify_ExistingUser_DoesNotReIssueDEK(t *testing.T) {
	users := inmem.NewUserRepository()
	challenges := inmem.NewPasskeyChallengeRepository()
	credentials := inmem.NewPasskeyCredentialRepository()
	ctx := context.Background()

	km := crypto.NewInMemoryKeyManager([]byte("test-master-32-bytes-padding-12345"))

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

	// Production hardening: seed an existing credential with a REAL ES256
	// COSE_Key + sign the verify body for real. The dev shortcut is gone.
	priv, cose := newES256COSEPair(t)
	credID := []byte("known-cred-id-bytes")
	cred, _ := identity.NewPasskeyCredential(identity.NewPasskeyCredentialParams{
		Gcid:          gcid,
		CredentialID:  credID,
		PublicKeyCOSE: cose,
		RPID:          "chora.site",
	})
	_ = credentials.Save(ctx, cred)

	// Pre-issue DEK so we can test idempotency on the verify path.
	handle, err := km.IssueDEK(gcid)
	if err != nil {
		t.Fatal(err)
	}

	h := httpadapter.NewPasskeyHandlerWithDEK(users, challenges, credentials, km,
		httpadapter.PasskeyHandlerConfig{RPID: "chora.site", ChallengeTTLSeconds: 300})

	// Challenge.
	chReq := httptest.NewRequest(http.MethodPost, "/v1/auth/passkey/challenge", nil)
	chRec := httptest.NewRecorder()
	h.ServeHTTP(chRec, chReq)
	var chResp struct {
		ChallengeID string `json:"challenge_id"`
		Challenge   string `json:"challenge"`
	}
	_ = json.Unmarshal(chRec.Body.Bytes(), &chResp)

	// Sign + verify. The clientDataJSON.challenge must echo the issued one (D9).
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
	vReq := httptest.NewRequest(http.MethodPost, "/v1/auth/passkey/verify", bytes.NewBuffer(body))
	vReq.Header.Set("Content-Type", "application/json")
	vRec := httptest.NewRecorder()
	h.ServeHTTP(vRec, vReq)
	if vRec.Code != http.StatusOK {
		t.Fatalf("verify: %d body=%s", vRec.Code, vRec.Body.String())
	}

	// DEK handle must be unchanged for the existing user.
	handle2, _ := km.IssueDEK(gcid) // Idempotent — same handle.
	if handle != handle2 {
		t.Fatalf("DEK handle must be idempotent for existing user: %q vs %q", handle, handle2)
	}
}

// (DEK shred wiring on closure subscriber lives in events/closure_dek_test.go.)
