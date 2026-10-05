// passkey_register_attestation_test.go — ADR-187 sub-phase 4 handler wiring:
// attestation verification + policy applied at registration. Reuses the
// register harness (newRegisterFixture / postRegister / regAuthData / attObjBytes
// / ec2COSE / pad32) from passkey_register_test.go (same httpadapter_test pkg).
package httpadapter_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/apollo-chora/chora-identity/internal/domain/identity"
)

// coldResolver always reports "can't evaluate" (cold trust store) — exercises
// the can't-evaluate path (A3). A `none` attestation never consults it but the
// wiring still records unverified provenance.
type coldResolver struct{}

func (coldResolver) ResolveAAGUID([]byte) (identity.AAGUIDMetadata, bool, error) {
	return identity.AAGUIDMetadata{}, false, errors.New("cold trust store")
}

func doRegisterNone(t *testing.T, f *registerFixture, credIDStr string) (credID []byte, code int, body string) {
	t.Helper()
	chID, chB64 := mintRegChallenge(t, f.handler)
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	cose := ec2COSE(pad32(priv.PublicKey.X.Bytes()), pad32(priv.PublicKey.Y.Bytes()))
	credID = []byte(credIDStr)
	attObj := attObjBytes("none", regAuthData("chora.site", 1, credID, cose))
	w := postRegister(t, f.handler, registerBody(f, chID, chB64,
		base64.StdEncoding.EncodeToString(credID), attObj))
	return credID, w.Code, w.Body.String()
}

func TestPasskey_Register_AttestationRecord_PersistsUnverifiedProvenance(t *testing.T) {
	f := newRegisterFixture(t)
	f.handler.EnableAttestation(coldResolver{},
		identity.AttestationPolicy{Mode: identity.AttestationModeRecord}, nil)

	credID, code, body := doRegisterNone(t, f, "att-record-cred")
	if code != http.StatusCreated {
		t.Fatalf("record mode must NEVER block: %d %s", code, body)
	}
	stored, err := f.credentials.GetByCredentialID(context.Background(), credID)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if stored.AttestationVerified {
		t.Error("A1: none attestation must persist AttestationVerified=false")
	}
	if len(stored.AttestationObject) == 0 {
		t.Error("A4: raw attestationObject must be persisted for offline re-evaluation")
	}
	if stored.AttestationType != "none" {
		t.Errorf("format = %q want none", stored.AttestationType)
	}
}

func TestPasskey_Register_AttestationEnforce_DeniesUnverified(t *testing.T) {
	f := newRegisterFixture(t)
	f.handler.EnableAttestation(coldResolver{},
		identity.AttestationPolicy{Mode: identity.AttestationModeEnforce, FailMode: identity.AttestationFailClosed}, nil)

	_, code, body := doRegisterNone(t, f, "att-enforce-cred")
	if code != http.StatusForbidden {
		t.Fatalf("enforce must DENY an unverified credential, got %d %s", code, body)
	}
	if !strings.Contains(body, "PASSKEY_ATTESTATION_REJECTED") {
		t.Errorf("expected PASSKEY_ATTESTATION_REJECTED, got %s", body)
	}
}

func TestPasskey_Register_OffMode_StillPersistsRawAttestationObject(t *testing.T) {
	f := newRegisterFixture(t) // default fixture: attestation disabled (off)
	credID, code, body := doRegisterNone(t, f, "att-off-cred")
	if code != http.StatusCreated {
		t.Fatalf("off mode register: %d %s", code, body)
	}
	stored, err := f.credentials.GetByCredentialID(context.Background(), credID)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(stored.AttestationObject) == 0 {
		t.Error("A4: raw attestationObject must persist even when verification is off")
	}
	if stored.AttestationVerified {
		t.Error("off mode must leave AttestationVerified=false")
	}
}
