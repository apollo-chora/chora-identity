// webauthn_attestation_policy.go — the attestation policy layer (ADR-187 §D1).
// VerifyAttestationStatement never blocks registration; Evaluate is the SINGLE
// allow/deny decision point. Modes: off / record (safe default) / enforce.
package identity

import (
	"strconv"
	"strings"
)

// AttestationMode governs whether attestation provenance is recorded and/or
// enforced at registration.
type AttestationMode int

const (
	// AttestationModeOff — no attestation verification (parity with the
	// pre-ADR-187 self-attestation posture). Rollback target.
	AttestationModeOff AttestationMode = iota
	// AttestationModeRecord — verify+record provenance when present; NEVER
	// blocks. The safe new default (ADR-187 §D1).
	AttestationModeRecord
	// AttestationModeEnforce — record + reject when provenance does not meet
	// the configured bar. Per-tenant opt-in.
	AttestationModeEnforce
)

// AttestationFailMode decides what enforce does when the trust store could not
// be consulted (Evaluable=false) — amendment A3. "can't-evaluate" ≠ untrusted.
type AttestationFailMode int

const (
	// AttestationFailClosed — deny on can't-evaluate (default; safest for a
	// tenant that opted into enforce).
	AttestationFailClosed AttestationFailMode = iota
	// AttestationFailOpenRecord — allow on can't-evaluate, recording unverified.
	AttestationFailOpenRecord
)

// ParseAttestationMode maps an env/config string to a mode. Empty/unknown →
// record (the safe default — never silently `off`, never silently `enforce`).
func ParseAttestationMode(s string) AttestationMode {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "off":
		return AttestationModeOff
	case "enforce":
		return AttestationModeEnforce
	default:
		return AttestationModeRecord
	}
}

// ParseAttestationFailMode maps an env/config string to a fail mode. Empty/
// unknown → fail_closed (the conservative default for enforce).
func ParseAttestationFailMode(s string) AttestationFailMode {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "fail_open_record", "fail-open-record", "open", "fail_open":
		return AttestationFailOpenRecord
	default:
		return AttestationFailClosed
	}
}

// AttestationPolicy is the per-request (per-tenant-resolved) policy.
type AttestationPolicy struct {
	Mode AttestationMode
	// AllowedAAGUIDs (keyed by AAGUIDHex). Empty ⇒ any MDS-verified authenticator.
	AllowedAAGUIDs map[string]bool
	// MinCertificationLevel ("L1".."L3"; "" ⇒ no bar).
	MinCertificationLevel string
	FailMode              AttestationFailMode
}

// Evaluate decides allow/deny for a verified attestation result. It is the only
// place a registration is blocked on attestation grounds.
func (p AttestationPolicy) Evaluate(r *AttestationResult) (allow bool, reason string) {
	switch p.Mode {
	case AttestationModeOff:
		return true, "attestation policy off"
	case AttestationModeRecord:
		return true, "record mode — never blocks"
	case AttestationModeEnforce:
		if !r.Evaluable {
			if p.FailMode == AttestationFailOpenRecord {
				return true, "enforce: trust store unavailable — fail-open-record"
			}
			return false, "enforce: trust store unavailable — fail-closed"
		}
		if !r.Verified {
			return false, "enforce: attestation not verified to a trusted MDS root"
		}
		if len(p.AllowedAAGUIDs) > 0 && !p.AllowedAAGUIDs[AAGUIDHex(r.AAGUID)] {
			return false, "enforce: AAGUID not on the tenant allow-list"
		}
		if p.MinCertificationLevel != "" && !certLevelMeets(r.CertificationLevel, p.MinCertificationLevel) {
			return false, "enforce: certification level below the configured bar"
		}
		return true, "enforce: verified + meets policy"
	default:
		return false, "unknown attestation mode"
	}
}

// certLevelMeets reports whether have ≥ bar, comparing FIDO "L<n>" levels. An
// unparseable level ranks 0 (below any bar) — fail-safe.
func certLevelMeets(have, bar string) bool {
	return certLevelRank(have) >= certLevelRank(bar)
}

func certLevelRank(s string) int {
	s = strings.ToUpper(strings.TrimSpace(s))
	s = strings.TrimPrefix(s, "L")
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0
	}
	return n
}
