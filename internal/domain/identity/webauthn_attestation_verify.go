// webauthn_attestation_verify.go — registration attestation-STATEMENT
// verification (W3C WebAuthn L3 §8), ADR-187 sub-phase 2.
//
// Scope: the `none` and `packed` (full + self) formats, plus the strict
// provenance contract and the MetadataResolver port. The FIDO MDS3 trust-store
// adapter that IMPLEMENTS MetadataResolver, and the `apple`/`tpm`/`fido-u2f`/
// `android-*` verifiers, are later sub-phases — until then those formats record
// Verified=false (record-safe), never an error.
//
// STRICT "Verified" semantics (ADR-187 amendment A1): Verified=true iff the
// x5c chain validated to a trusted MDS attestation root AND the attestation
// signature verified AND the leaf's AAGUID extension matched authData.aaguid
// AND the AAGUID is not revoked. Self-attestation, `none`, anonymized-without-
// a-chain, unknown AAGUID, bad chain, and a cold trust store all record
// Verified=false. Verification content failures are NEVER returned as a Go
// error — the policy layer (webauthn_attestation_policy.go) is the single
// allow/deny decision point (amendment A3). A Go error means programmer misuse
// (nil arguments) only.
package identity

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

// Attestation statement formats (W3C WebAuthn L3 §8).
const (
	AttestationFormatNone   = "none"
	AttestationFormatPacked = "packed"
)

// fidoAAGUIDCertExtOID is id-fido-gen-ce-aaguid (1.3.6.1.4.1.45724.1.1.4) —
// when present in the attestation leaf cert its value (an OCTET STRING wrapping
// the 16-byte AAGUID) MUST equal authData.aaguid (W3C §8.2.1 verification 2.c).
var fidoAAGUIDCertExtOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 45724, 1, 1, 4}

// ErrNilAttestationInput is returned only for programmer misuse (nil args) —
// never for an attestation that merely fails to verify.
var ErrNilAttestationInput = errors.New("webauthn: nil attestation input")

// AAGUIDMetadata is what the trust store (FIDO MDS) knows about one AAGUID.
type AAGUIDMetadata struct {
	// Roots are the attestation root certificates the leaf chain must validate
	// to (FIDO MDS metadataStatement.attestationRootCertificates).
	Roots []*x509.Certificate
	// AuthenticatorDescription is the human-readable model name (MDS).
	AuthenticatorDescription string
	// CertificationLevel is the FIDO certification level ("L1".."L3"; "" unknown).
	CertificationLevel string
	// Revoked is true when a disqualifying MDS statusReport applies.
	Revoked bool
}

// MetadataResolver resolves an AAGUID against the FIDO Metadata trust store.
// found=false is a DEFINITE verdict (AAGUID is not in MDS). A non-nil error is
// "can't evaluate" (cold/unreachable cache) — distinct from untrusted (A3).
type MetadataResolver interface {
	ResolveAAGUID(aaguid []byte) (meta AAGUIDMetadata, found bool, err error)
}

// AttestationResult is the outcome of verifying a registration attestation
// statement. It never blocks; the policy layer consumes it.
type AttestationResult struct {
	Format    string
	Verified  bool   // STRICT provenance (amendment A1)
	Evaluable bool   // false ⇒ trust store could not be consulted (A3)
	AAGUID    []byte // from authData
	// Provenance, populated when resolved (regardless of Verified).
	AuthenticatorDescription string
	CertificationLevel       string
	// Reason explains the verdict (observability; not security-bearing).
	Reason string
}

// AAGUIDHex is the canonical lowercase-hex key for an AAGUID (allow-lists, logs).
func AAGUIDHex(aaguid []byte) string { return hex.EncodeToString(aaguid) }

// VerifyAttestationStatement verifies the attestation statement of a parsed
// registration attestationObject. now is injected for deterministic cert
// validity (amendment A5).
func VerifyAttestationStatement(att *AttestedCredential, clientDataHash []byte, resolver MetadataResolver, now time.Time) (*AttestationResult, error) {
	if att == nil || resolver == nil {
		return nil, ErrNilAttestationInput
	}
	res := &AttestationResult{Format: att.Format, AAGUID: att.AAGUID, Evaluable: true}

	switch att.Format {
	case AttestationFormatNone:
		res.Reason = "none attestation — no provenance"
		return res, nil
	case AttestationFormatPacked:
		verifyPacked(att, clientDataHash, resolver, now, res)
		return res, nil
	default:
		// apple / tpm / fido-u2f / android-* — verifier not in this sub-phase.
		res.Reason = fmt.Sprintf("attestation format %q not yet verifiable", att.Format)
		return res, nil
	}
}

func verifyPacked(att *AttestedCredential, clientDataHash []byte, resolver MetadataResolver, now time.Time, res *AttestationResult) {
	alg, sig, x5c, err := parsePackedAttStmt(att.AttStmtCBOR)
	if err != nil {
		res.Reason = "malformed packed attStmt"
		return
	}
	// Verification data = authenticatorData ‖ clientDataHash (W3C §8.2).
	signed := make([]byte, 0, len(att.AuthDataRaw)+len(clientDataHash))
	signed = append(signed, att.AuthDataRaw...)
	signed = append(signed, clientDataHash...)

	if len(x5c) == 0 {
		// Self-attestation: a valid sig proves only that the credential signed
		// its own attestation — NOT provenance. Always unverified (A1).
		res.Reason = "packed self-attestation — no provenance"
		return
	}

	// --- full (x5c) attestation ---
	leaf, err := x509.ParseCertificate(x5c[0])
	if err != nil {
		res.Reason = "packed x5c leaf did not parse"
		return
	}
	if !verifyAttestationSig(leaf.PublicKey, alg, signed, sig) {
		res.Reason = "packed attestation signature did not verify"
		return
	}
	if certAAGUID, ok := aaguidFromCert(leaf); ok && !bytes.Equal(certAAGUID, att.AAGUID) {
		res.Reason = "packed leaf AAGUID extension does not match authData.aaguid"
		return
	}

	meta, found, err := resolver.ResolveAAGUID(att.AAGUID)
	if err != nil {
		// Can't evaluate (cold/unreachable trust store) — NOT untrusted (A3).
		res.Evaluable = false
		res.Reason = "trust store unavailable"
		return
	}
	if !found {
		res.Reason = "AAGUID not present in FIDO MDS"
		return
	}
	res.AuthenticatorDescription = meta.AuthenticatorDescription
	res.CertificationLevel = meta.CertificationLevel
	if meta.Revoked {
		res.Reason = "AAGUID revoked by MDS status report"
		return
	}
	if err := verifyX5CChain(leaf, x5c[1:], meta.Roots, now); err != nil {
		res.Reason = "x5c chain did not validate to a trusted MDS root"
		return
	}

	res.Verified = true
	res.Reason = "verified: chain to trusted MDS root"
}

// verifyAttestationSig verifies sig over msg using the leaf cert's public key
// and the attStmt alg. Returns false (never panics) on any mismatch.
func verifyAttestationSig(pub any, alg int64, msg, sig []byte) bool {
	h := sha256.Sum256(msg)
	switch alg {
	case coseAlgES256:
		ec, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return false
		}
		return ecdsa.VerifyASN1(ec, h[:], sig)
	case coseAlgRS256:
		rk, ok := pub.(*rsa.PublicKey)
		if !ok {
			return false
		}
		return rsa.VerifyPKCS1v15(rk, crypto.SHA256, h[:], sig) == nil
	default:
		return false
	}
}

// verifyX5CChain builds leaf → intermediates → roots and validates the path at
// time now. Intermediates come from the attStmt x5c[1:]; roots from MDS.
func verifyX5CChain(leaf *x509.Certificate, intermediateDER [][]byte, roots []*x509.Certificate, now time.Time) error {
	if len(roots) == 0 {
		return errors.New("no trusted roots")
	}
	rootPool := x509.NewCertPool()
	for _, r := range roots {
		rootPool.AddCert(r)
	}
	interPool := x509.NewCertPool()
	for _, der := range intermediateDER {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return fmt.Errorf("intermediate parse: %w", err)
		}
		interPool.AddCert(c)
	}
	_, err := leaf.Verify(x509.VerifyOptions{
		Roots:         rootPool,
		Intermediates: interPool,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	return err
}

// aaguidFromCert extracts the AAGUID from the FIDO cert extension, if present.
func aaguidFromCert(cert *x509.Certificate) (aaguid []byte, ok bool) {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(fidoAAGUIDCertExtOID) {
			var raw []byte
			if _, err := asn1.Unmarshal(ext.Value, &raw); err != nil {
				return nil, false
			}
			return raw, true
		}
	}
	return nil, false
}

// parsePackedAttStmt decodes the packed attStmt CBOR map { alg, sig, x5c? }
// using the package's hand-rolled minimal-CBOR primitives.
func parsePackedAttStmt(b []byte) (alg int64, sig []byte, x5c [][]byte, err error) {
	major, pairs, off, e := decodeCBORHead(b)
	if e != nil || major != 5 {
		return 0, nil, nil, fmt.Errorf("%w: attStmt is not a CBOR map", ErrMalformedAttestation)
	}
	pos := off
	var haveAlg, haveSig bool
	for i := uint64(0); i < pairs; i++ {
		kMajor, kLen, kOff, e := decodeCBORHead(b[pos:])
		if e != nil || kMajor != 3 {
			return 0, nil, nil, fmt.Errorf("%w: attStmt non-text key", ErrMalformedAttestation)
		}
		kEnd := pos + kOff + int(kLen)
		if kLen > uint64(len(b)) || kEnd > len(b) {
			return 0, nil, nil, fmt.Errorf("%w: attStmt truncated key", ErrMalformedAttestation)
		}
		key := string(b[pos+kOff : kEnd])
		pos = kEnd

		switch key {
		case "alg":
			m, a, n, e := decodeCBORHead(b[pos:])
			if e != nil || (m != 0 && m != 1) {
				return 0, nil, nil, fmt.Errorf("%w: attStmt alg not an int", ErrMalformedAttestation)
			}
			if m == 0 {
				alg = int64(a)
			} else {
				alg = -1 - int64(a)
			}
			haveAlg = true
			pos += n
		case "sig":
			m, l, o, e := decodeCBORHead(b[pos:])
			if e != nil || m != 2 {
				return 0, nil, nil, fmt.Errorf("%w: attStmt sig not a byte string", ErrMalformedAttestation)
			}
			end := pos + o + int(l)
			if l > uint64(len(b)) || end > len(b) {
				return 0, nil, nil, fmt.Errorf("%w: attStmt sig truncated", ErrMalformedAttestation)
			}
			sig = append([]byte(nil), b[pos+o:end]...)
			haveSig = true
			pos = end
		case "x5c":
			m, cnt, o, e := decodeCBORHead(b[pos:])
			if e != nil || m != 4 {
				return 0, nil, nil, fmt.Errorf("%w: attStmt x5c not an array", ErrMalformedAttestation)
			}
			pos += o
			for j := uint64(0); j < cnt; j++ {
				cm, cl, co, ce := decodeCBORHead(b[pos:])
				if ce != nil || cm != 2 {
					return 0, nil, nil, fmt.Errorf("%w: attStmt x5c element not a byte string", ErrMalformedAttestation)
				}
				end := pos + co + int(cl)
				if cl > uint64(len(b)) || end > len(b) {
					return 0, nil, nil, fmt.Errorf("%w: attStmt x5c element truncated", ErrMalformedAttestation)
				}
				x5c = append(x5c, append([]byte(nil), b[pos+co:end]...))
				pos = end
			}
		default:
			n, e := cborSkipValue(b[pos:])
			if e != nil {
				return 0, nil, nil, fmt.Errorf("%w: attStmt unskippable value for %q", ErrMalformedAttestation, key)
			}
			pos += n
		}
	}
	if !haveAlg || !haveSig {
		return 0, nil, nil, fmt.Errorf("%w: attStmt missing alg or sig", ErrMalformedAttestation)
	}
	return alg, sig, x5c, nil
}
