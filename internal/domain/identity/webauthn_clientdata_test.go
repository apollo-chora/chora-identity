// webauthn_clientdata_test.go — RED-phase TDD specs for clientDataJSON
// ceremony binding (auth-hardening Phase A debt pass D9, CHO-1790).
//
// The LOGIN (assertion) path historically verified only the WebAuthn signature
// — it never bound the SIGNED clientDataJSON.challenge to the server-issued
// challenge, nor asserted clientDataJSON.type == "webauthn.get". That left a
// replay window for counter-less authenticators: a captured
// (authData, clientDataJSON, signature) triple verifies against ANY fresh
// ceremony because the signature only covers the OLD clientDataJSON, and the
// sign-count clone check is a no-op when both counters are 0.
//
// VerifyClientData closes that window (W3C WebAuthn Level 3 §7.2 steps 11+13 /
// §7.1 steps 8+9 for registration symmetry). These specs pin:
//
//  1. matching challenge + correct type  → nil
//  2. challenge mismatch (replay/reuse)  → ErrChallengeMismatch
//  3. wrong ceremony type                → ErrUnexpectedClientDataType
//  4. malformed clientDataJSON           → ErrMalformedClientData
//  5. challenge field not base64         → ErrChallengeMismatch (cannot bind)
//  6. base64url no-pad encoding (browser real-world) accepted
package identity_test

import (
	"encoding/base64"
	"errors"
	"fmt"
	"testing"

	"github.com/apollo-chora/chora-identity/internal/domain/identity"
)

func clientDataJSON(typ, challengeB64 string) []byte {
	return []byte(fmt.Sprintf(`{"type":%q,"challenge":%q,"origin":"https://chora.site"}`, typ, challengeB64))
}

func TestVerifyClientData_MatchingChallengeAndType_OK(t *testing.T) {
	t.Parallel()
	challenge := []byte("the-server-issued-challenge-bytes")
	cd := clientDataJSON(identity.ClientDataTypeGet, base64.RawURLEncoding.EncodeToString(challenge))
	if err := identity.VerifyClientData(cd, challenge, identity.ClientDataTypeGet); err != nil {
		t.Fatalf("VerifyClientData = %v, want nil", err)
	}
}

func TestVerifyClientData_ChallengeMismatch_Rejected(t *testing.T) {
	t.Parallel()
	issued := []byte("ceremony-2-fresh-challenge-bytes")
	// The signed clientDataJSON references a DIFFERENT (older / captured)
	// challenge — the assertion-replay scenario.
	captured := []byte("ceremony-1-captured-challenge!!!")
	cd := clientDataJSON(identity.ClientDataTypeGet, base64.RawURLEncoding.EncodeToString(captured))
	if err := identity.VerifyClientData(cd, issued, identity.ClientDataTypeGet); !errors.Is(err, identity.ErrChallengeMismatch) {
		t.Fatalf("VerifyClientData = %v, want ErrChallengeMismatch", err)
	}
}

func TestVerifyClientData_WrongType_Rejected(t *testing.T) {
	t.Parallel()
	challenge := []byte("the-server-issued-challenge-bytes")
	// A "webauthn.create" clientDataJSON replayed at the login endpoint.
	cd := clientDataJSON(identity.ClientDataTypeCreate, base64.RawURLEncoding.EncodeToString(challenge))
	if err := identity.VerifyClientData(cd, challenge, identity.ClientDataTypeGet); !errors.Is(err, identity.ErrUnexpectedClientDataType) {
		t.Fatalf("VerifyClientData = %v, want ErrUnexpectedClientDataType", err)
	}
}

func TestVerifyClientData_MalformedJSON_Rejected(t *testing.T) {
	t.Parallel()
	challenge := []byte("the-server-issued-challenge-bytes")
	if err := identity.VerifyClientData([]byte("not-json"), challenge, identity.ClientDataTypeGet); !errors.Is(err, identity.ErrMalformedClientData) {
		t.Fatalf("VerifyClientData = %v, want ErrMalformedClientData", err)
	}
	if err := identity.VerifyClientData(nil, challenge, identity.ClientDataTypeGet); !errors.Is(err, identity.ErrMalformedClientData) {
		t.Fatalf("VerifyClientData(nil) = %v, want ErrMalformedClientData", err)
	}
}

func TestVerifyClientData_ChallengeNotBase64_Rejected(t *testing.T) {
	t.Parallel()
	challenge := []byte("the-server-issued-challenge-bytes")
	// "!!!" can never decode to the issued challenge bytes — a non-decodable
	// challenge MUST fail the bind, never silently pass.
	cd := clientDataJSON(identity.ClientDataTypeGet, "!!!not-base64!!!")
	if err := identity.VerifyClientData(cd, challenge, identity.ClientDataTypeGet); !errors.Is(err, identity.ErrChallengeMismatch) {
		t.Fatalf("VerifyClientData = %v, want ErrChallengeMismatch", err)
	}
}

func TestVerifyClientData_AcceptsPaddedAndRawEncodings(t *testing.T) {
	t.Parallel()
	challenge := []byte{0xff, 0xfe, 0xfd, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}
	for name, enc := range map[string]*base64.Encoding{
		"rawurl": base64.RawURLEncoding,
		"url":    base64.URLEncoding,
		"std":    base64.StdEncoding,
		"rawstd": base64.RawStdEncoding,
	} {
		cd := clientDataJSON(identity.ClientDataTypeGet, enc.EncodeToString(challenge))
		if err := identity.VerifyClientData(cd, challenge, identity.ClientDataTypeGet); err != nil {
			t.Errorf("encoding %s: VerifyClientData = %v, want nil", name, err)
		}
	}
}

func TestVerifyClientData_EmptyExpectedType_Rejected(t *testing.T) {
	t.Parallel()
	// A caller must always pass an expected ceremony type; an empty expected
	// type must never accept (defense-in-depth against a mis-wired caller).
	challenge := []byte("the-server-issued-challenge-bytes")
	cd := clientDataJSON("", base64.RawURLEncoding.EncodeToString(challenge))
	if err := identity.VerifyClientData(cd, challenge, ""); !errors.Is(err, identity.ErrUnexpectedClientDataType) {
		t.Fatalf("VerifyClientData = %v, want ErrUnexpectedClientDataType", err)
	}
}
