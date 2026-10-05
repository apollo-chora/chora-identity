// passkey_dev_shortcut_removal_test.go — RED-phase TDD specs for the
// production WebAuthn refactor (Wave A 2C).
//
// Per the agent brief: "replace `attestation_dev=true` shortcut with full
// CBOR + COSE EC2/RSA1 signature verification". The shortcut is removed
// outright — the only verify path for an existing credential is the W3C
// WebAuthn Level 3 §7.2 signature ceremony.
//
// These tests pin the post-removal behaviour. The legacy tests in
// passkey_handler_test.go that consumed the shortcut are migrated to
// "fresh-credential registration" semantics (no signature required for a
// brand-new credential — the challenge_id replay protection suffices) or
// deleted in favour of the real-signature coverage in passkey_signature_test.go.
package httpadapter_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	httpadapter "github.com/apollo-chora/chora-identity/internal/adapter/http"
	"github.com/apollo-chora/chora-identity/internal/adapter/inmem"
	"github.com/apollo-chora/chora-identity/internal/domain/identity"
)

// TestPasskey_Verify_AttestationDev_FieldIgnoredOnExistingCredential asserts
// that even if a client sends `attestation_dev: true`, the handler does NOT
// bypass signature verification when an existing credential is present.
// Production hardening: the only verify path for an existing credential is
// the W3C WebAuthn Level 3 §7.2 signature ceremony.
//
// We send the legacy shortcut field with NO real signature against an
// existing credential. The handler must respond with 400
// PASSKEY_SIGNATURE_REQUIRED — proving the dev bypass is gone.
func TestPasskey_Verify_AttestationDev_FieldIgnoredOnExistingCredential(t *testing.T) {
	t.Parallel()

	users := inmem.NewUserRepository()
	challenges := inmem.NewPasskeyChallengeRepository()
	credentials := inmem.NewPasskeyCredentialRepository()

	// Seed an existing credential. PublicKeyCOSE is intentionally garbage
	// so the signature verifier would fail anyway — but we never reach it
	// because the missing-signature check fires first.
	gcid := "01970000-0000-7000-8000-000000000ad0"
	credID := []byte("existing-cred-for-shortcut-removal")
	u := &identity.User{
		Gcid:               gcid,
		Email:              "shortcut-removal@chora.dev",
		IdentityProvider:   identity.ProviderWebAuthn,
		FederatedSubject:   "webauthn|" + gcid,
		Status:             identity.UserStatusActive,
		VerificationStatus: identity.VerificationStatusUnverified,
	}
	_ = users.Save(context.Background(), u)
	cred, _ := identity.NewPasskeyCredential(identity.NewPasskeyCredentialParams{
		Gcid:          gcid,
		CredentialID:  credID,
		PublicKeyCOSE: []byte("not-a-real-cose-key"),
		RPID:          "chora.site",
	})
	_ = credentials.Save(context.Background(), cred)

	cfg := httpadapter.PasskeyHandlerConfig{
		RPID:                "chora.site",
		ChallengeTTLSeconds: 300,
	}
	h := httpadapter.NewPasskeyHandler(users, challenges, credentials, cfg)

	// Mint challenge.
	chReq := httptest.NewRequest(http.MethodPost, "/v1/auth/passkey/challenge", nil)
	chRec := httptest.NewRecorder()
	h.ServeHTTP(chRec, chReq)
	var chResp struct {
		ChallengeID string `json:"challenge_id"`
	}
	_ = json.Unmarshal(chRec.Body.Bytes(), &chResp)

	// Send `attestation_dev: true` (legacy shortcut) with NO real signature.
	// Production behaviour: rejected with PASSKEY_SIGNATURE_REQUIRED.
	verifyBody := map[string]any{
		"challenge_id":    chResp.ChallengeID,
		"credential_id":   base64.StdEncoding.EncodeToString(credID),
		"sign_count":      1,
		"attestation_dev": true, // ignored under production hardening
	}
	body, _ := json.Marshal(verifyBody)
	r := httptest.NewRequest(http.MethodPost, "/v1/auth/passkey/verify", bytes.NewBuffer(body))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 PASSKEY_SIGNATURE_REQUIRED with no real signature; got %d body=%s",
			w.Code, w.Body.String())
	}
}
