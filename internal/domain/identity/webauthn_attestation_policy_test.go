// webauthn_attestation_policy_test.go — RED-phase TDD specs for ADR-187
// sub-phase 2: the attestation POLICY layer (off / record / enforce, with the
// can't-evaluate fail-mode of amendment A3). Evaluate() is the single
// allow/deny decision point — VerifyAttestationStatement never blocks.
package identity_test

import (
	"testing"

	"github.com/apollo-chora/chora-identity/internal/domain/identity"
)

func res(verified, evaluable bool, aaguidByte byte, certLevel string) *identity.AttestationResult {
	return &identity.AttestationResult{
		Format:             "packed",
		Verified:           verified,
		Evaluable:          evaluable,
		AAGUID:             aaguid16(aaguidByte),
		CertificationLevel: certLevel,
	}
}

func TestPolicy_Off_AlwaysAllows(t *testing.T) {
	p := identity.AttestationPolicy{Mode: identity.AttestationModeOff}
	if allow, _ := p.Evaluate(res(false, true, 0x01, "")); !allow {
		t.Fatal("off mode must allow")
	}
}

func TestPolicy_Record_AllowsVerifiedAndUnverified(t *testing.T) {
	p := identity.AttestationPolicy{Mode: identity.AttestationModeRecord}
	for _, verified := range []bool{true, false} {
		if allow, _ := p.Evaluate(res(verified, true, 0x01, "")); !allow {
			t.Fatalf("record mode must allow (verified=%v)", verified)
		}
	}
}

func TestPolicy_Enforce_AllowsVerifiedOnAllowList(t *testing.T) {
	p := identity.AttestationPolicy{
		Mode:           identity.AttestationModeEnforce,
		AllowedAAGUIDs: map[string]bool{identity.AAGUIDHex(aaguid16(0x05)): true},
	}
	if allow, _ := p.Evaluate(res(true, true, 0x05, "L1")); !allow {
		t.Fatal("enforce must allow a verified credential on the allow-list")
	}
}

func TestPolicy_Enforce_DeniesVerifiedOffAllowList(t *testing.T) {
	p := identity.AttestationPolicy{
		Mode:           identity.AttestationModeEnforce,
		AllowedAAGUIDs: map[string]bool{identity.AAGUIDHex(aaguid16(0x05)): true},
	}
	if allow, reason := p.Evaluate(res(true, true, 0x06, "L1")); allow {
		t.Fatalf("enforce must deny a verified credential NOT on the allow-list (reason=%q)", reason)
	}
}

func TestPolicy_Enforce_DeniesUnverified(t *testing.T) {
	p := identity.AttestationPolicy{Mode: identity.AttestationModeEnforce}
	if allow, _ := p.Evaluate(res(false, true, 0x05, "")); allow {
		t.Fatal("enforce must deny an unverified (untrusted) credential")
	}
}

func TestPolicy_Enforce_EmptyAllowList_AllowsAnyVerified(t *testing.T) {
	// No allow-list + no cert-level bar ⇒ "any MDS-trusted authenticator".
	p := identity.AttestationPolicy{Mode: identity.AttestationModeEnforce}
	if allow, _ := p.Evaluate(res(true, true, 0x07, "L1")); !allow {
		t.Fatal("enforce with no allow-list must allow any verified credential")
	}
}

func TestPolicy_Enforce_CertLevelThreshold(t *testing.T) {
	p := identity.AttestationPolicy{Mode: identity.AttestationModeEnforce, MinCertificationLevel: "L2"}
	if allow, _ := p.Evaluate(res(true, true, 0x08, "L1")); allow {
		t.Fatal("L1 below the L2 bar must be denied")
	}
	if allow, _ := p.Evaluate(res(true, true, 0x08, "L3")); !allow {
		t.Fatal("L3 at/above the L2 bar must be allowed")
	}
}

func TestPolicy_Enforce_CantEvaluate_FailClosed_Denies(t *testing.T) {
	p := identity.AttestationPolicy{Mode: identity.AttestationModeEnforce, FailMode: identity.AttestationFailClosed}
	if allow, _ := p.Evaluate(res(false, false, 0x09, "")); allow {
		t.Fatal("A3: can't-evaluate under fail_closed must deny")
	}
}

func TestPolicy_Enforce_CantEvaluate_FailOpenRecord_Allows(t *testing.T) {
	p := identity.AttestationPolicy{Mode: identity.AttestationModeEnforce, FailMode: identity.AttestationFailOpenRecord}
	if allow, _ := p.Evaluate(res(false, false, 0x09, "")); !allow {
		t.Fatal("A3: can't-evaluate under fail_open_record must allow (and record unverified)")
	}
}

func TestParseAttestationMode_AndFailMode(t *testing.T) {
	if identity.ParseAttestationMode("enforce") != identity.AttestationModeEnforce {
		t.Fatal("parse enforce")
	}
	if identity.ParseAttestationMode("") != identity.AttestationModeRecord {
		t.Fatal("empty must default to record (the safe new default)")
	}
	if identity.ParseAttestationMode("bogus") != identity.AttestationModeRecord {
		t.Fatal("unknown must default to record")
	}
	if identity.ParseAttestationFailMode("fail_open_record") != identity.AttestationFailOpenRecord {
		t.Fatal("parse fail_open_record")
	}
	if identity.ParseAttestationFailMode("") != identity.AttestationFailClosed {
		t.Fatal("empty fail-mode must default to fail_closed")
	}
}
