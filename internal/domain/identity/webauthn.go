// WebAuthn / Passkey domain primitives — challenges + credentials.
//
// Per Phyllis MVP §3 Step 1 + audit-identity-fillgaps.md §3.1 (P0):
//
//	POST /v1/auth/passkey/challenge   → mints a PasskeyChallenge (this domain)
//	POST /v1/auth/passkey/verify      → verifies + binds to PasskeyCredential
//
// The chora-identity service holds the canonical Challenge + Credential state
// even when Identity Platform is the front-end IdP — chora-identity owns
// authoritative GCID issuance + replay-protection counters per WebAuthn spec.
//
// Hexagonal: this is DOMAIN. Infrastructure (HTTP, IdP gateways, KMS) lives in
// adapters. The WebAuthn library calls (CBOR decode, COSE verify) happen at
// the adapter boundary; this domain holds aggregate invariants only.
//
// Reference:
//   - Phyllis MVP §3 Step 1 — passkey is the Phyllis demo entry point
//   - audit-identity-fillgaps.md §3.1 — P0 priority
//   - W3C WebAuthn Level 3 §7.1 (registration) + §7.2 (authentication)
package identity

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// -----------------------------------------------------------------------------
// Sentinel errors
// -----------------------------------------------------------------------------

var (
	// ErrPasskeyChallengeExpired — the challenge TTL has lapsed.
	ErrPasskeyChallengeExpired = errors.New("passkey challenge expired")

	// ErrPasskeyChallengeConsumed — the challenge has already been consumed
	// (replay-protection: a challenge is single-use).
	ErrPasskeyChallengeConsumed = errors.New("passkey challenge already consumed")

	// ErrPasskeyCredentialReplay — sign-count went backwards = potential
	// cloned-authenticator attack per WebAuthn §6.1.1.
	ErrPasskeyCredentialReplay = errors.New("passkey credential replay detected")

	// ErrPasskeyCredentialRevoked — the credential has been revoked and may
	// no longer be used for authentication.
	ErrPasskeyCredentialRevoked = errors.New("passkey credential revoked")
)

// -----------------------------------------------------------------------------
// PasskeyChallenge — short-lived nonce minted on /challenge, consumed on /verify.
// -----------------------------------------------------------------------------

// PasskeyChallengeStatus tracks the lifecycle of a challenge.
type PasskeyChallengeStatus string

const (
	// PasskeyChallengeStatusPending — minted but not yet verified or consumed.
	PasskeyChallengeStatusPending PasskeyChallengeStatus = "pending"
	// PasskeyChallengeStatusVerified — challenge presented + signature checked,
	// but the bind-to-user side-effect has not yet committed.
	PasskeyChallengeStatusVerified PasskeyChallengeStatus = "verified"
	// PasskeyChallengeStatusConsumed — terminal: the challenge is no longer
	// valid for any further verification (single-use guarantee).
	PasskeyChallengeStatusConsumed PasskeyChallengeStatus = "consumed"
	// PasskeyChallengeStatusExpired — TTL lapsed; the verification path will
	// reject this challenge.
	PasskeyChallengeStatusExpired PasskeyChallengeStatus = "expired"
)

// PasskeyChallenge is the one-shot nonce + binding metadata that the verifier
// needs to safely accept a WebAuthn assertion. The bytes themselves are never
// reused (single-use replay protection per WebAuthn §6.1.2).
type PasskeyChallenge struct {
	ChallengeID    string                 `json:"challenge_id"`
	ChallengeBytes []byte                 `json:"challenge_bytes"`
	RPID           string                 `json:"rp_id"`
	UserHandle     string                 `json:"user_handle,omitempty"`
	Status         PasskeyChallengeStatus `json:"status"`
	VerifiedGCID   string                 `json:"verified_gcid,omitempty"`
	CreatedAt      time.Time              `json:"created_at"`
	ExpiresAt      time.Time              `json:"expires_at"`
}

// NewPasskeyChallengeParams is the constructor input.
type NewPasskeyChallengeParams struct {
	// ChallengeBytes is the random nonce. Caller is responsible for sourcing
	// it from a CSPRNG. Must be ≥ 16 bytes per WebAuthn §13.4.3 minimum.
	ChallengeBytes []byte
	// RPID is the WebAuthn relying-party ID — must match the SPA origin's
	// effective domain, e.g. "chora.site". Read from RP_ID env var by the
	// adapter caller (no inline config).
	RPID string
	// UserHandle is the opaque pre-login identifier (typically email). Used to
	// hint user verification at the authenticator. Optional.
	UserHandle string
	// TTL is the challenge lifetime. Typical: 5 minutes. Must be > 0.
	TTL time.Duration
}

// NewPasskeyChallenge constructs a fresh challenge with the supplied nonce +
// metadata. Returns an error if invariants are violated.
func NewPasskeyChallenge(p NewPasskeyChallengeParams) (*PasskeyChallenge, error) {
	if len(p.ChallengeBytes) < 16 {
		return nil, fmt.Errorf("passkey: challenge_bytes must be ≥ 16; got %d", len(p.ChallengeBytes))
	}
	rpID := strings.TrimSpace(p.RPID)
	if rpID == "" {
		return nil, errors.New("passkey: rp_id is required")
	}
	if p.TTL <= 0 {
		return nil, errors.New("passkey: ttl must be > 0")
	}
	id, err := uuid.NewV7()
	if err != nil {
		return nil, fmt.Errorf("passkey: uuidv7: %w", err)
	}
	now := time.Now().UTC()
	return &PasskeyChallenge{
		ChallengeID:    id.String(),
		ChallengeBytes: append([]byte(nil), p.ChallengeBytes...),
		RPID:           rpID,
		UserHandle:     strings.TrimSpace(p.UserHandle),
		Status:         PasskeyChallengeStatusPending,
		CreatedAt:      now,
		ExpiresAt:      now.Add(p.TTL),
	}, nil
}

// Expired reports whether at is past ExpiresAt.
func (c *PasskeyChallenge) Expired(at time.Time) bool {
	return !at.UTC().Before(c.ExpiresAt)
}

// MarkVerified flips the status to Verified and binds the supplied gcid as
// the resolved identity. Idempotent on the same gcid; rejects mismatching
// gcid or AGID-shaped IDs (per ddd-enforcement aggregate invariant #10).
func (c *PasskeyChallenge) MarkVerified(gcid string) error {
	gcid = strings.TrimSpace(gcid)
	if gcid == "" {
		return errors.New("passkey: gcid is required")
	}
	if IsAGID(gcid) {
		return errors.New("passkey: AGID cannot verify a passkey challenge")
	}
	switch c.Status {
	case PasskeyChallengeStatusConsumed:
		return ErrPasskeyChallengeConsumed
	case PasskeyChallengeStatusExpired:
		return ErrPasskeyChallengeExpired
	}
	if c.Expired(time.Now().UTC()) {
		c.Status = PasskeyChallengeStatusExpired
		return ErrPasskeyChallengeExpired
	}
	if c.Status == PasskeyChallengeStatusVerified && c.VerifiedGCID != gcid {
		return errors.New("passkey: challenge already verified for a different gcid")
	}
	c.Status = PasskeyChallengeStatusVerified
	c.VerifiedGCID = gcid
	return nil
}

// MarkConsumed terminates the challenge — no further use is permitted.
func (c *PasskeyChallenge) MarkConsumed() error {
	if c.Status == PasskeyChallengeStatusConsumed {
		return nil
	}
	c.Status = PasskeyChallengeStatusConsumed
	return nil
}

// -----------------------------------------------------------------------------
// PasskeyCredential — long-lived (gcid, credential_id) bind row.
// -----------------------------------------------------------------------------

// PasskeyCredentialStatus tracks the lifecycle of a stored credential.
type PasskeyCredentialStatus string

const (
	PasskeyCredentialStatusActive  PasskeyCredentialStatus = "active"
	PasskeyCredentialStatusRevoked PasskeyCredentialStatus = "revoked"
)

// PasskeyCredential is the persisted WebAuthn credential bound to a GCID.
// Production wiring stores the Public Key in COSE format (CBOR-encoded);
// this domain treats it as opaque bytes.
type PasskeyCredential struct {
	CredentialUUID  string                  `json:"credential_uuid"`
	Gcid            string                  `json:"gcid"`
	CredentialID    []byte                  `json:"credential_id"`
	PublicKeyCOSE   []byte                  `json:"public_key_cose"`
	AttestationType string                  `json:"attestation_type"`
	RPID            string                  `json:"rp_id"`
	SignCount       uint32                  `json:"sign_count"`
	Status          PasskeyCredentialStatus `json:"status"`
	CreatedAt       time.Time               `json:"created_at"`
	LastUsedAt      *time.Time              `json:"last_used_at,omitempty"`

	// Attestation provenance (ADR-187). AttestationType holds the format
	// ("none"/"packed"/...). AttestationVerified is STRICT (A1): true only when
	// the x5c chain validated to a trusted FIDO MDS root. AttestationObject is
	// the raw registration object, retained so provenance can be re-evaluated
	// offline when the trust store refreshes or a new verifier ships (A4).
	AAGUID                   []byte `json:"aaguid,omitempty"`
	AttestationVerified      bool   `json:"attestation_verified"`
	AuthenticatorDescription string `json:"authenticator_description,omitempty"`
	MDSCertificationLevel    string `json:"mds_certification_level,omitempty"`
	AttestationObject        []byte `json:"attestation_object,omitempty"`
}

// NewPasskeyCredentialParams is the constructor input.
type NewPasskeyCredentialParams struct {
	Gcid            string
	CredentialID    []byte
	PublicKeyCOSE   []byte
	AttestationType string // "none" | "direct" | "indirect" | "enterprise"
	RPID            string
	// InitialSignCount seeds the replay counter from the registration-time
	// authenticator data (W3C WebAuthn L3 §7.1 step 26). Zero for
	// authenticators that do not implement counters.
	InitialSignCount uint32
	// Attestation provenance (ADR-187) — optional; zero values record an
	// unverified credential (the default `record`-mode outcome for none/self).
	AAGUID                   []byte
	AttestationVerified      bool
	AuthenticatorDescription string
	MDSCertificationLevel    string
	AttestationObject        []byte
}

// NewPasskeyCredential constructs a fresh credential aggregate. Returns an
// error if invariants are violated.
func NewPasskeyCredential(p NewPasskeyCredentialParams) (*PasskeyCredential, error) {
	gcid := strings.TrimSpace(p.Gcid)
	if gcid == "" {
		return nil, errors.New("passkey: gcid is required")
	}
	if IsAGID(gcid) {
		return nil, errors.New("passkey: AGID cannot hold a passkey credential")
	}
	if len(p.CredentialID) == 0 {
		return nil, errors.New("passkey: credential_id required")
	}
	if len(p.PublicKeyCOSE) == 0 {
		return nil, errors.New("passkey: public_key_cose required")
	}
	rpID := strings.TrimSpace(p.RPID)
	if rpID == "" {
		return nil, errors.New("passkey: rp_id required")
	}
	id, err := uuid.NewV7()
	if err != nil {
		return nil, fmt.Errorf("passkey: uuidv7: %w", err)
	}
	att := strings.TrimSpace(p.AttestationType)
	if att == "" {
		att = "none"
	}
	return &PasskeyCredential{
		CredentialUUID:           id.String(),
		Gcid:                     gcid,
		CredentialID:             append([]byte(nil), p.CredentialID...),
		PublicKeyCOSE:            append([]byte(nil), p.PublicKeyCOSE...),
		AttestationType:          att,
		RPID:                     rpID,
		SignCount:                p.InitialSignCount,
		Status:                   PasskeyCredentialStatusActive,
		CreatedAt:                time.Now().UTC(),
		AAGUID:                   append([]byte(nil), p.AAGUID...),
		AttestationVerified:      p.AttestationVerified,
		AuthenticatorDescription: p.AuthenticatorDescription,
		MDSCertificationLevel:    p.MDSCertificationLevel,
		AttestationObject:        append([]byte(nil), p.AttestationObject...),
	}, nil
}

// RecordUse increments the sign-count to the new authenticator-reported value.
// Per WebAuthn §6.1.1, sign-count MUST monotonically increase between uses;
// any regression signals a cloned authenticator and MUST be treated as an
// attack (we return ErrPasskeyCredentialReplay).
//
// Calling RecordUse on a revoked credential returns ErrPasskeyCredentialRevoked.
func (c *PasskeyCredential) RecordUse(newSignCount uint32) error {
	if c.Status == PasskeyCredentialStatusRevoked {
		return ErrPasskeyCredentialRevoked
	}
	// Note: WebAuthn allows newSignCount == 0 only if BOTH old and new are 0
	// (some authenticators don't emit sign-counts at all). Otherwise it must
	// strictly increase.
	if newSignCount == 0 && c.SignCount == 0 {
		now := time.Now().UTC()
		c.LastUsedAt = &now
		return nil
	}
	if newSignCount <= c.SignCount {
		return ErrPasskeyCredentialReplay
	}
	c.SignCount = newSignCount
	now := time.Now().UTC()
	c.LastUsedAt = &now
	return nil
}

// Revoke marks the credential revoked. Idempotent.
func (c *PasskeyCredential) Revoke() {
	if c.Status == PasskeyCredentialStatusRevoked {
		return
	}
	c.Status = PasskeyCredentialStatusRevoked
}
