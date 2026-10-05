// webauthn_verify.go — production-ready WebAuthn assertion signature
// verification per W3C WebAuthn Level 3 §7.2 (authentication ceremony).
//
// This file replaces the `attestation_dev=true` shortcut at the passkey
// verify HTTP handler. The handler now requires the SPA to provide the full
// authenticatorData + clientDataJSON + signature triple from
// navigator.credentials.get() and we verify against the credential's stored
// COSE_Key public key.
//
// Algorithm coverage (the two algs Identity Platform / Apple / Android emit):
//
//   - ES256 (kty=EC2/2, alg=-7, crv=P-256/1) — ECDSA over SHA-256
//   - RS256 (kty=RSA/3, alg=-257)            — RSA-PKCS1v15 over SHA-256
//
// Hexagonal: this is DOMAIN. No I/O, no http, no env. Pure crypto +
// minimal-CBOR. The HTTP adapter calls VerifyAssertion with the bytes
// extracted from the JSON request.
package identity

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
)

// -----------------------------------------------------------------------------
// Sentinel errors
// -----------------------------------------------------------------------------

var (
	// ErrInvalidSignature — signature did not verify against the COSE public
	// key. Either tampered authenticatorData / clientDataJSON / signature, or
	// the wrong credential.
	ErrInvalidSignature = errors.New("webauthn: invalid signature")

	// ErrUnsupportedCOSEAlg — the COSE alg field is not one we support
	// (only ES256 / RS256 today).
	ErrUnsupportedCOSEAlg = errors.New("webauthn: unsupported COSE alg")

	// ErrMalformedCOSEKey — the stored COSE_Key bytes do not parse to a CBOR
	// map with the required parameters.
	ErrMalformedCOSEKey = errors.New("webauthn: malformed COSE_Key")

	// ErrMalformedAttestation — the registration attestationObject (or its
	// embedded authenticator data) does not parse to the W3C WebAuthn L3
	// §6.5 shape. Auth-hardening Phase A4 (ADR-181 D2).
	ErrMalformedAttestation = errors.New("webauthn: malformed attestationObject")

	// ErrMalformedClientData — clientDataJSON does not parse to the W3C
	// WebAuthn L3 §5.8.1 CollectedClientData JSON shape. Auth-hardening Phase A
	// debt pass D9 (CHO-1790).
	ErrMalformedClientData = errors.New("webauthn: malformed clientDataJSON")

	// ErrUnexpectedClientDataType — clientDataJSON.type is not the ceremony
	// type the caller expected ("webauthn.get" for an authentication assertion,
	// "webauthn.create" for registration). D9.
	ErrUnexpectedClientDataType = errors.New("webauthn: unexpected clientDataJSON type")

	// ErrChallengeMismatch — the challenge embedded in (and signed over via)
	// clientDataJSON does not equal the server-issued, single-use challenge for
	// THIS ceremony. On the login path this is the assertion-replay guard:
	// without it a captured (authData, clientDataJSON, signature) triple
	// verifies against any fresh challenge because the signature only covers
	// the OLD clientDataJSON. D9.
	ErrChallengeMismatch = errors.New("webauthn: clientDataJSON challenge mismatch")
)

// CollectedClientData ceremony type discriminators (W3C WebAuthn L3 §5.8.1).
const (
	// ClientDataTypeGet is clientDataJSON.type for an authentication (login)
	// assertion produced by navigator.credentials.get().
	ClientDataTypeGet = "webauthn.get"
	// ClientDataTypeCreate is clientDataJSON.type for a registration ceremony
	// produced by navigator.credentials.create().
	ClientDataTypeCreate = "webauthn.create"
)

// -----------------------------------------------------------------------------
// Public API
// -----------------------------------------------------------------------------

// VerifyAssertion verifies a WebAuthn assertion. Returns nil on success,
// ErrInvalidSignature on a verifiable-but-rejected signature, and
// ErrUnsupportedCOSEAlg / ErrMalformedCOSEKey for parse-time failures.
//
// Per W3C WebAuthn Level 3 §7.2 step 19, the signed bytes are:
//
//	signing_input = authData || sha256(clientDataJSON)
//
// and the signature is interpreted per the COSE alg.
func VerifyAssertion(coseKey, authData, clientDataJSON, signature []byte) error {
	if len(coseKey) == 0 {
		return fmt.Errorf("%w: empty key", ErrMalformedCOSEKey)
	}
	pk, alg, err := parseCOSEKey(coseKey)
	if err != nil {
		return err
	}

	cdh := sha256.Sum256(clientDataJSON)
	signing := make([]byte, 0, len(authData)+len(cdh))
	signing = append(signing, authData...)
	signing = append(signing, cdh[:]...)
	hashed := sha256.Sum256(signing)

	switch alg {
	case coseAlgES256:
		ek, ok := pk.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("%w: ES256 needs ECDSA key", ErrInvalidSignature)
		}
		// WebAuthn signatures are ASN.1 DER (r, s) per §6.5.6.
		var pair struct{ R, S *big.Int }
		if _, err := asn1.Unmarshal(signature, &pair); err != nil || pair.R == nil || pair.S == nil {
			return fmt.Errorf("%w: ASN.1 decode: %v", ErrInvalidSignature, err)
		}
		if !ecdsa.Verify(ek, hashed[:], pair.R, pair.S) {
			return ErrInvalidSignature
		}
		return nil
	case coseAlgRS256:
		rk, ok := pk.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("%w: RS256 needs RSA key", ErrInvalidSignature)
		}
		if err := rsa.VerifyPKCS1v15(rk, crypto.SHA256, hashed[:], signature); err != nil {
			return fmt.Errorf("%w: %v", ErrInvalidSignature, err)
		}
		return nil
	default:
		return fmt.Errorf("%w: alg=%d", ErrUnsupportedCOSEAlg, alg)
	}
}

// collectedClientData is the subset of W3C WebAuthn L3 §5.8.1
// CollectedClientData we bind on. Additional fields (origin, crossOrigin,
// tokenBinding, …) are ignored by encoding/json — we only enforce the two
// ceremony-binding invariants here.
type collectedClientData struct {
	Type      string `json:"type"`
	Challenge string `json:"challenge"`
}

// VerifyClientData binds a WebAuthn clientDataJSON to the ceremony it claims to
// belong to. It enforces two invariants (W3C WebAuthn L3 §7.1 steps 8-9 for
// registration / §7.2 steps 11+13 for authentication):
//
//  1. clientDataJSON.type == expectedType ("webauthn.get" login /
//     "webauthn.create" registration).
//  2. base64url(clientDataJSON.challenge) decodes to exactly expectedChallenge
//     — the server-issued, single-use nonce for THIS ceremony.
//
// On the LOGIN path this is the assertion-replay guard: the WebAuthn signature
// only covers (authData || sha256(clientDataJSON)), so a captured triple
// re-verifies against any fresh challenge UNLESS the server also checks that
// the signed clientDataJSON.challenge equals the challenge it just minted.
// Counter-less authenticators (sign-count stays 0) make the clone-detection
// check a no-op, so this binding is the only thing closing the replay window.
//
// The challenge comparison is constant-time and accepts any of the four
// base64 alphabets (the browser emits base64url-no-pad, but we stay lenient at
// the decode boundary to mirror the transport-layer decode used elsewhere).
// A challenge that cannot be base64-decoded can never equal the issued bytes,
// so it fails closed as a mismatch.
//
// Pure domain: no I/O, no env. errors are sentinels callers map to HTTP codes.
func VerifyClientData(clientDataJSON, expectedChallenge []byte, expectedType string) error {
	var cd collectedClientData
	if err := json.Unmarshal(clientDataJSON, &cd); err != nil {
		return fmt.Errorf("%w: %v", ErrMalformedClientData, err)
	}
	// An empty expectedType would otherwise accept a clientDataJSON whose own
	// type was tampered to "" — reject a mis-wired caller defensively.
	if expectedType == "" || cd.Type != expectedType {
		return fmt.Errorf("%w: type=%q want %q", ErrUnexpectedClientDataType, cd.Type, expectedType)
	}
	sent, ok := decodeChallengeB64(cd.Challenge)
	if !ok {
		return fmt.Errorf("%w: challenge not base64-decodable", ErrChallengeMismatch)
	}
	if subtle.ConstantTimeCompare(sent, expectedChallenge) != 1 {
		return ErrChallengeMismatch
	}
	return nil
}

// decodeChallengeB64 decodes a WebAuthn clientDataJSON.challenge string. The
// spec mandates base64url-no-pad, but real-world transport (and our test
// fixtures) occasionally emit standard / padded variants — try each and
// require an EXACT full-string decode (no trailing garbage). Returns ok=false
// when no alphabet decodes the whole string.
func decodeChallengeB64(s string) ([]byte, bool) {
	for _, enc := range []*base64.Encoding{
		base64.RawURLEncoding,
		base64.URLEncoding,
		base64.StdEncoding,
		base64.RawStdEncoding,
	} {
		if b, err := enc.DecodeString(s); err == nil {
			return b, true
		}
	}
	return nil, false
}

// -----------------------------------------------------------------------------
// COSE algorithm constants (RFC 8152 §16)
// -----------------------------------------------------------------------------

const (
	coseAlgES256 = -7
	coseAlgRS256 = -257
	coseAlgEdDSA = -8 // not supported
)

// COSE map key identifiers (RFC 8152 §7.1)
const (
	coseKeyKty = 1 // 1=OKP, 2=EC2, 3=RSA, 4=Symmetric
	coseKeyAlg = 3
	// EC2-specific (negative)
	coseKeyEC2Crv = -1
	coseKeyEC2X   = -2
	coseKeyEC2Y   = -3
	// RSA-specific (negative)
	coseKeyRSAN = -1
	coseKeyRSAE = -2
)

const (
	coseKtyOKP = 1
	coseKtyEC2 = 2
	coseKtyRSA = 3
)

const coseCrvP256 = 1

// -----------------------------------------------------------------------------
// Tiny CBOR decoder (subset sufficient for COSE_Key maps)
// -----------------------------------------------------------------------------
//
// Supports only what COSE_Key requires: small unsigned ints, small negative
// ints, byte strings, and a single top-level map. Anything else returns
// ErrMalformedCOSEKey. We deliberately keep this minimal — it is NOT a
// full CBOR decoder; for the rest of the WebAuthn handshake (authData parsing,
// attestation statement) production wires github.com/fxamacker/cbor.

type cborValue struct {
	major byte
	uval  uint64 // unsigned magnitude (for ints)
	bytes []byte // for byte strings
	neg   bool   // true if originally negative int
}

// decodeCBORHead consumes the type+length prefix and returns the major type,
// the argument, and the bytes consumed. It does NOT consume the body of byte
// strings / arrays / maps.
func decodeCBORHead(b []byte) (major byte, arg uint64, n int, err error) {
	if len(b) == 0 {
		return 0, 0, 0, ErrMalformedCOSEKey
	}
	major = b[0] >> 5
	short := b[0] & 0x1f
	if short < 24 {
		return major, uint64(short), 1, nil
	}
	switch short {
	case 24:
		if len(b) < 2 {
			return 0, 0, 0, ErrMalformedCOSEKey
		}
		return major, uint64(b[1]), 2, nil
	case 25:
		if len(b) < 3 {
			return 0, 0, 0, ErrMalformedCOSEKey
		}
		return major, uint64(b[1])<<8 | uint64(b[2]), 3, nil
	case 26:
		if len(b) < 5 {
			return 0, 0, 0, ErrMalformedCOSEKey
		}
		return major, uint64(b[1])<<24 | uint64(b[2])<<16 | uint64(b[3])<<8 | uint64(b[4]), 5, nil
	case 27:
		if len(b) < 9 {
			return 0, 0, 0, ErrMalformedCOSEKey
		}
		return major, uint64(b[1])<<56 | uint64(b[2])<<48 | uint64(b[3])<<40 | uint64(b[4])<<32 | uint64(b[5])<<24 | uint64(b[6])<<16 | uint64(b[7])<<8 | uint64(b[8]), 9, nil
	default:
		return 0, 0, 0, ErrMalformedCOSEKey
	}
}

// decodeCBORValue decodes a single value (uint, negative-int, byte string).
// Used for both COSE_Key keys (the field identifiers) and values (concrete
// values). Returns the decoded value + how many bytes were consumed.
func decodeCBORValue(b []byte) (cborValue, int, error) {
	major, arg, n, err := decodeCBORHead(b)
	if err != nil {
		return cborValue{}, 0, err
	}
	switch major {
	case 0: // unsigned int
		return cborValue{major: 0, uval: arg}, n, nil
	case 1: // negative int — the value is -1 - arg
		return cborValue{major: 1, uval: arg, neg: true}, n, nil
	case 2: // byte string
		end := n + int(arg)
		if end > len(b) {
			return cborValue{}, 0, ErrMalformedCOSEKey
		}
		body := make([]byte, arg)
		copy(body, b[n:end])
		return cborValue{major: 2, bytes: body}, end, nil
	default:
		return cborValue{}, 0, ErrMalformedCOSEKey
	}
}

// asInt returns the decoded value as an int64 (positive or negative).
func (v cborValue) asInt() (int64, bool) {
	if v.major == 0 {
		return int64(v.uval), true
	}
	if v.major == 1 {
		return -1 - int64(v.uval), true
	}
	return 0, false
}

// parseCOSEKey decodes a COSE_Key map and returns either *ecdsa.PublicKey or
// *rsa.PublicKey along with the COSE alg field.
func parseCOSEKey(b []byte) (any, int64, error) {
	major, n, off, err := decodeCBORHead(b)
	if err != nil {
		return nil, 0, err
	}
	if major != 5 { // map
		return nil, 0, fmt.Errorf("%w: top is not a map", ErrMalformedCOSEKey)
	}
	pairs := int(n)
	pos := off

	var (
		gotKty int64
		gotAlg int64
		ec2X   []byte
		ec2Y   []byte
		ec2Crv int64
		rsaN   []byte
		rsaE   []byte
	)
	hasKty := false
	hasAlg := false

	for i := 0; i < pairs; i++ {
		k, kn, err := decodeCBORValue(b[pos:])
		if err != nil {
			return nil, 0, err
		}
		pos += kn
		v, vn, err := decodeCBORValue(b[pos:])
		if err != nil {
			return nil, 0, err
		}
		pos += vn

		ki, ok := k.asInt()
		if !ok {
			return nil, 0, fmt.Errorf("%w: non-int map key", ErrMalformedCOSEKey)
		}
		switch ki {
		case coseKeyKty:
			gotKty, ok = v.asInt()
			if !ok {
				return nil, 0, fmt.Errorf("%w: kty not int", ErrMalformedCOSEKey)
			}
			hasKty = true
		case coseKeyAlg:
			gotAlg, ok = v.asInt()
			if !ok {
				return nil, 0, fmt.Errorf("%w: alg not int", ErrMalformedCOSEKey)
			}
			hasAlg = true
		case coseKeyEC2Crv:
			// EC2 crv OR RSA n (same field id; disambiguated by kty).
			if v.major == 2 {
				rsaN = v.bytes
			} else {
				ec2Crv, _ = v.asInt()
			}
		case coseKeyEC2X:
			// EC2 x OR RSA e.
			if v.major == 2 {
				if hasKty && gotKty == coseKtyRSA {
					rsaE = v.bytes
				} else {
					ec2X = v.bytes
				}
			}
		case coseKeyEC2Y:
			ec2Y = v.bytes
		}
	}

	if !hasKty || !hasAlg {
		return nil, 0, fmt.Errorf("%w: missing kty or alg", ErrMalformedCOSEKey)
	}

	switch gotAlg {
	case coseAlgES256:
		if gotKty != coseKtyEC2 || ec2Crv != coseCrvP256 || len(ec2X) == 0 || len(ec2Y) == 0 {
			return nil, gotAlg, fmt.Errorf("%w: ES256 fields missing", ErrMalformedCOSEKey)
		}
		return &ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     new(big.Int).SetBytes(ec2X),
			Y:     new(big.Int).SetBytes(ec2Y),
		}, gotAlg, nil
	case coseAlgRS256:
		if gotKty != coseKtyRSA || len(rsaN) == 0 || len(rsaE) == 0 {
			return nil, gotAlg, fmt.Errorf("%w: RSA fields missing", ErrMalformedCOSEKey)
		}
		e := 0
		for _, byt := range rsaE {
			e = e<<8 | int(byt)
		}
		return &rsa.PublicKey{
			N: new(big.Int).SetBytes(rsaN),
			E: e,
		}, gotAlg, nil
	default:
		return nil, gotAlg, fmt.Errorf("%w: alg=%d (only ES256/RS256 supported)", ErrUnsupportedCOSEAlg, gotAlg)
	}
}

// -----------------------------------------------------------------------------
// Registration-time attestationObject parsing (W3C WebAuthn L3 §7.1)
// -----------------------------------------------------------------------------
//
// Auth-hardening Phase A4 (ADR-181 D2, CHO-1718): the registration ceremony
// must persist the REAL COSE public key extracted from the authenticator's
// attestationObject — the "dev-mode-public-key-placeholder" path is dead.
//
// attestationObject = CBOR map { "fmt": tstr, "attStmt": map, "authData": bstr }
// authData          = rpIdHash(32) || flags(1) || signCount(4 BE) ||
//                     [attestedCredentialData when flags&AT:
//                        aaguid(16) || credIdLen(2 BE) || credentialId ||
//                        credentialPublicKey(COSE_Key CBOR)]
//
// Same hand-rolled minimal-CBOR discipline as parseCOSEKey above — NO
// heavyweight CBOR dependency.
//
// SECURITY POSTURE (D9, CHO-1790) — attestation statement (incl. x5c) is
// PARSED-PAST, NOT VALIDATED. The whole attStmt map (alg / sig / x5c cert
// chain) is skipped by cborSkipValue; every attestation format ("none",
// "packed", "tpm", "apple", …) is accepted and treated as SELF-ATTESTATION.
// We bind the credential to this RP via authData.rpIdHash and persist the
// authenticator-reported COSE public key, but we do NOT cryptographically
// verify the attestation signature, nor build/validate the x5c certificate
// chain to a trusted root, nor match the AAGUID against authenticator
// metadata.
//
// Why this is an accepted posture (not a half-measure): real x5c chain
// validation requires a maintained trust-anchor store (FIDO Metadata Service
// blob ingestion + refresh), full X.509 path building + revocation, and
// per-format attestation-signature verification (packed/tpm/android-key/…).
// That is a standalone capability, not a few lines here, and attempting a
// partial chain check would give a FALSE sense of attestation assurance.
// Chora's threat model accepts self-attestation: passkey registration already
// binds to an authenticated Chora session for the target gcid (handler step
// 6), challenge single-use + RP-id binding hold, and we do not gate any
// entitlement on attested authenticator provenance. Full attestation chain
// validation is tracked as a FOLLOW-UP (needs the FIDO MDS trust store +
// its own ADR/story). The self-attestation behaviour is pinned by
// TestParseAttestationObject_X5cChain_SelfAttestationPosture_D9.

// authData flag bits (W3C WebAuthn L3 §6.1).
const (
	authDataFlagUP = 0x01 // user present
	authDataFlagAT = 0x40 // attested credential data included
)

// AttestedCredential is the parse result of a registration attestationObject.
type AttestedCredential struct {
	// Format is the attestation statement format ("none", "packed", ...).
	Format string
	// RPIDHash is sha256(rpId) as reported by the authenticator — callers
	// MUST compare against sha256 of their configured RP_ID.
	RPIDHash []byte
	// Flags is the raw authData flags byte.
	Flags byte
	// SignCount is the authenticator's initial signature counter.
	SignCount uint32
	// AAGUID identifies the authenticator model (16 bytes; zero for "none").
	AAGUID []byte
	// CredentialID is the authenticator-issued credential identifier.
	CredentialID []byte
	// PublicKeyCOSE is the raw COSE_Key CBOR bytes — ALREADY validated to be
	// a well-formed ES256 (-7) or RS256 (-257) key. These are the bytes to
	// persist on PasskeyCredential.PublicKeyCOSE.
	PublicKeyCOSE []byte
	// AttStmtCBOR is the raw CBOR bytes of the attStmt map (ADR-187) — the
	// input to attestation-statement verification (VerifyAttestationStatement).
	// nil/empty when the attestationObject carried no attStmt.
	AttStmtCBOR []byte
	// AuthDataRaw is the raw authenticatorData bytes (ADR-187) — one half of
	// the attestation verification data (authData ‖ clientDataHash).
	AuthDataRaw []byte
}

// ParseAttestationObject decodes a registration attestationObject and
// extracts the attested credential (credentialId + COSE public key).
//
// Errors:
//   - ErrMalformedAttestation — structural CBOR/authData violations
//   - ErrMalformedCOSEKey     — the embedded COSE_Key does not parse
//   - ErrUnsupportedCOSEAlg   — key alg is not ES256/RS256
func ParseAttestationObject(b []byte) (*AttestedCredential, error) {
	major, pairs, off, err := decodeCBORHead(b)
	if err != nil || major != 5 {
		return nil, fmt.Errorf("%w: top-level is not a CBOR map", ErrMalformedAttestation)
	}

	var (
		format      string
		authData    []byte
		attStmtCBOR []byte
	)
	pos := off
	for i := uint64(0); i < pairs; i++ {
		// Map keys are text strings ("fmt" / "attStmt" / "authData").
		kMajor, kLen, kOff, err := decodeCBORHead(b[pos:])
		if err != nil || kMajor != 3 {
			return nil, fmt.Errorf("%w: non-text map key", ErrMalformedAttestation)
		}
		keyEnd := pos + kOff + int(kLen)
		if kLen > uint64(len(b)) || keyEnd > len(b) {
			return nil, fmt.Errorf("%w: truncated map key", ErrMalformedAttestation)
		}
		key := string(b[pos+kOff : keyEnd])
		pos = keyEnd

		switch key {
		case "fmt":
			vMajor, vLen, vOff, err := decodeCBORHead(b[pos:])
			if err != nil || vMajor != 3 {
				return nil, fmt.Errorf("%w: fmt is not a text string", ErrMalformedAttestation)
			}
			end := pos + vOff + int(vLen)
			if vLen > uint64(len(b)) || end > len(b) {
				return nil, fmt.Errorf("%w: truncated fmt", ErrMalformedAttestation)
			}
			format = string(b[pos+vOff : end])
			pos = end
		case "authData":
			vMajor, vLen, vOff, err := decodeCBORHead(b[pos:])
			if err != nil || vMajor != 2 {
				return nil, fmt.Errorf("%w: authData is not a byte string", ErrMalformedAttestation)
			}
			end := pos + vOff + int(vLen)
			if vLen > uint64(len(b)) || end > len(b) {
				return nil, fmt.Errorf("%w: truncated authData", ErrMalformedAttestation)
			}
			authData = append([]byte(nil), b[pos+vOff:end]...)
			pos = end
		default: // attStmt + any future keys — measure the whole value.
			n, err := cborSkipValue(b[pos:])
			if err != nil {
				return nil, fmt.Errorf("%w: unskippable value for key %q", ErrMalformedAttestation, key)
			}
			if key == "attStmt" {
				// Capture the raw attStmt CBOR (ADR-187) instead of only
				// skipping it — the input to attestation verification.
				attStmtCBOR = append([]byte(nil), b[pos:pos+n]...)
			}
			pos += n
		}
	}
	if len(authData) == 0 {
		return nil, fmt.Errorf("%w: missing authData", ErrMalformedAttestation)
	}
	if format == "" {
		format = "none"
	}

	// --- authData walk -----------------------------------------------------
	if len(authData) < 37 {
		return nil, fmt.Errorf("%w: authData shorter than 37 bytes", ErrMalformedAttestation)
	}
	rpidHash := append([]byte(nil), authData[:32]...)
	flags := authData[32]
	signCount := uint32(authData[33])<<24 | uint32(authData[34])<<16 |
		uint32(authData[35])<<8 | uint32(authData[36])
	if flags&authDataFlagAT == 0 {
		return nil, fmt.Errorf("%w: AT flag absent — no attested credential data", ErrMalformedAttestation)
	}
	rest := authData[37:]
	if len(rest) < 18 {
		return nil, fmt.Errorf("%w: attestedCredentialData truncated", ErrMalformedAttestation)
	}
	aaguid := append([]byte(nil), rest[:16]...)
	credLen := int(rest[16])<<8 | int(rest[17])
	if credLen == 0 || len(rest) < 18+credLen {
		return nil, fmt.Errorf("%w: credentialId truncated (len=%d have=%d)",
			ErrMalformedAttestation, credLen, len(rest)-18)
	}
	credID := append([]byte(nil), rest[18:18+credLen]...)

	// The COSE_Key occupies the next complete CBOR value; measure it so we
	// can slice the exact raw bytes for persistence.
	coseRegion := rest[18+credLen:]
	coseLen, err := cborSkipValue(coseRegion)
	if err != nil {
		return nil, fmt.Errorf("%w: credentialPublicKey: %v", ErrMalformedCOSEKey, err)
	}
	coseKey := append([]byte(nil), coseRegion[:coseLen]...)

	// Validate the key now — registration MUST reject unsupported algs
	// cleanly rather than persisting an unusable key.
	if _, _, err := parseCOSEKey(coseKey); err != nil {
		return nil, err
	}

	return &AttestedCredential{
		Format:        format,
		RPIDHash:      rpidHash,
		Flags:         flags,
		SignCount:     signCount,
		AAGUID:        aaguid,
		CredentialID:  credID,
		PublicKeyCOSE: coseKey,
		AttStmtCBOR:   attStmtCBOR,
		AuthDataRaw:   authData,
	}, nil
}

// SignCountFromAuthenticatorData extracts the 32-bit big-endian signature
// counter at authData[33:37] (W3C WebAuthn L3 §6.1). Used by the assertion
// path so the persisted replay counter comes from the SIGNED authenticator
// data, not a client-supplied side-channel field.
func SignCountFromAuthenticatorData(authData []byte) (uint32, error) {
	if len(authData) < 37 {
		return 0, fmt.Errorf("%w: authenticator data shorter than 37 bytes", ErrMalformedAttestation)
	}
	return uint32(authData[33])<<24 | uint32(authData[34])<<16 |
		uint32(authData[35])<<8 | uint32(authData[36]), nil
}

// cborSkipValue returns the number of bytes occupied by the complete CBOR
// value at the start of b. Handles uint / nint / byte string / text string /
// array / map / tag / simple+float. Indefinite-length items are rejected
// (decodeCBORHead already errors on additional-info 28-31), which is fine —
// CTAP2 mandates canonical (definite-length) CBOR.
func cborSkipValue(b []byte) (int, error) {
	major, arg, n, err := decodeCBORHead(b)
	if err != nil {
		return 0, err
	}
	switch major {
	case 0, 1: // ints — fully consumed by the head
		return n, nil
	case 2, 3: // byte / text string — head + payload
		if arg > uint64(len(b)) || n+int(arg) > len(b) {
			return 0, ErrMalformedAttestation
		}
		return n + int(arg), nil
	case 4: // array — arg elements
		pos := n
		for i := uint64(0); i < arg; i++ {
			s, err := cborSkipValue(b[pos:])
			if err != nil {
				return 0, err
			}
			pos += s
		}
		return pos, nil
	case 5: // map — arg key/value pairs
		pos := n
		for i := uint64(0); i < arg*2; i++ {
			s, err := cborSkipValue(b[pos:])
			if err != nil {
				return 0, err
			}
			pos += s
		}
		return pos, nil
	case 6: // tag — skip the tagged value
		s, err := cborSkipValue(b[n:])
		if err != nil {
			return 0, err
		}
		return n + s, nil
	case 7: // simple values + floats — fully consumed by the head
		return n, nil
	}
	return 0, ErrMalformedAttestation
}
