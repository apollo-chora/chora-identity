// /v1/auth/passkey/{challenge,register,verify} handlers.
//
// Auth-hardening Phase A4 (ADR-181 D2, CHO-1718) — the passkey backend is now
// a REAL three-route ceremony surface consumed by chora-gateway's
// /api/v1/auth/webauthn/* BFF routes:
//
//	POST /v1/auth/passkey/challenge
//	  body  { user_handle?: string }
//	  reply 200 { challenge_id, challenge: base64url, rp_id, expires_at, ... }
//	  Serves BOTH the registration (§7.1) and login (§7.2) ceremonies.
//
//	POST /v1/auth/passkey/register          ← NEW (registration finish)
//	  body  { challenge_id, gcid, credential_id: base64,
//	          client_data_json: base64, attestation_object: base64 }
//	  reply 201 { credential_id: base64url, gcid, created_at }
//	  Parses the attestationObject (CBOR → authData → attestedCredentialData)
//	  via domain ParseAttestationObject and persists the REAL COSE public key.
//	  The legacy "dev-mode-public-key-placeholder" path is DEAD. Registration
//	  binds to an EXISTING user (gcid) — chora-gateway enforces that the
//	  caller holds an authenticated Chora session for that gcid.
//
//	POST /v1/auth/passkey/verify            (login finish — LOGIN ONLY now)
//	  body  { challenge_id, credential_id: base64, client_data_json: base64,
//	          authenticator_data: base64, signature: base64, ... }
//	  reply 200 { gcid, email, credential_id }
//	  W3C WebAuthn Level 3 §7.2 signature ceremony against the stored COSE
//	  key. An unknown credential is REJECTED (401) — the Phyllis-era
//	  register-through-verify auto-provisioning is removed. The handler no
//	  longer mints any JWT: chora-gateway composes the standard session-mint
//	  pipeline (resolve → roles → HS256 session JWT) from the returned
//	  gcid+email, so passkey logins carry tenant_id + roles like every other
//	  login (ADR-181 §A4 — the dev HS256 path is dead).
//
// Replay/consistency machinery preserved: challenge single-use
// (First-Save-Wins on Pending→Consumed), sign-count monotonicity
// (ErrPasskeyCredentialReplay), revocation. The persisted sign-count on
// login is taken from the SIGNED authenticator data when parseable
// (≥37 bytes) — the client-supplied sign_count field is legacy fallback only.
//
// Hexagonal: this is an HTTP ADAPTER. Domain logic (challenge state machine,
// credential aggregate, signature verification, attestation parsing) lives in
// domain/identity/.
package httpadapter

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/apollo-chora/chora-identity/internal/domain/crypto"
	"github.com/apollo-chora/chora-identity/internal/domain/identity"
)

// -----------------------------------------------------------------------------
// PasskeyHandlerConfig — env-driven config (per secrets-and-env skill).
// -----------------------------------------------------------------------------

// PasskeyHandlerConfig is the env-derived configuration. All fields are
// expected to be sourced from env vars at the wiring layer:
//
//	RP_ID                       → e.g. "chora.site"
//	PASSKEY_CHALLENGE_TTL_SECS  → e.g. 300
//
// Per CLAUDE.md no-inline-config rule, the handler refuses to operate when
// RPID is empty (returns 500 with IDENTITY_PASSKEY_MISCONFIGURED).
//
// Phase A4 (CHO-1718): the JWTIssuer / JWTAudience / JWTSigningSecret fields
// are REMOVED together with the dev HS256 token mint — session JWTs are
// minted exclusively by chora-gateway's mint pipeline.
type PasskeyHandlerConfig struct {
	RPID                string
	ChallengeTTLSeconds int
}

// -----------------------------------------------------------------------------
// PasskeyHandler
// -----------------------------------------------------------------------------

// PasskeyHandler exposes /v1/auth/passkey/{challenge,register,verify}.
type PasskeyHandler struct {
	users       identity.UserRepository
	challenges  identity.PasskeyChallengeRepository
	credentials identity.PasskeyCredentialRepository
	dek         crypto.KeyManager // optional — when set, IssueDEK at credential registration
	cfg         PasskeyHandlerConfig

	// Attestation provenance (ADR-187). Disabled by default (policy zero value
	// = AttestationModeOff → registration verifies nothing, behaviour-neutral).
	// EnableAttestation wires the FIDO MDS resolver + policy.
	attestationResolver identity.MetadataResolver
	attestationPolicy   identity.AttestationPolicy
	nowFn               func() time.Time
}

// EnableAttestation turns on ADR-187 attestation verification at registration.
// resolver is the FIDO MDS trust store; policy governs record/enforce; now is
// injected for deterministic cert validity (defaults to time.Now).
func (h *PasskeyHandler) EnableAttestation(resolver identity.MetadataResolver, policy identity.AttestationPolicy, now func() time.Time) {
	if now == nil {
		now = time.Now
	}
	h.attestationResolver = resolver
	h.attestationPolicy = policy
	h.nowFn = now
}

// NewPasskeyHandler wires the dependencies (no DEK manager).
func NewPasskeyHandler(
	users identity.UserRepository,
	challenges identity.PasskeyChallengeRepository,
	credentials identity.PasskeyCredentialRepository,
	cfg PasskeyHandlerConfig,
) *PasskeyHandler {
	return NewPasskeyHandlerWithDEK(users, challenges, credentials, nil, cfg)
}

// NewPasskeyHandlerWithDEK wires the passkey handler + the DEK key manager.
//
// Per Tier 3 D11 + audit-identity-fillgaps.md §3.1 risk R-DEK: IssueDEK is
// idempotent per gcid, so calling it at passkey registration guarantees the
// owner has a DEK regardless of which sign-in path originally created the
// user row. The closure saga's terminal step deletes the DEK = crypto-shred.
func NewPasskeyHandlerWithDEK(
	users identity.UserRepository,
	challenges identity.PasskeyChallengeRepository,
	credentials identity.PasskeyCredentialRepository,
	dek crypto.KeyManager,
	cfg PasskeyHandlerConfig,
) *PasskeyHandler {
	if cfg.ChallengeTTLSeconds <= 0 {
		cfg.ChallengeTTLSeconds = 300 // 5 minutes default — overridden by env
	}
	return &PasskeyHandler{
		users:       users,
		challenges:  challenges,
		credentials: credentials,
		dek:         dek,
		cfg:         cfg,
	}
}

// ServeHTTP routes between /challenge, /register and /verify.
func (h *PasskeyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/v1/auth/passkey/challenge":
		h.handleChallenge(w, r)
	case "/v1/auth/passkey/register":
		h.handleRegister(w, r)
	case "/v1/auth/passkey/verify":
		h.handleVerify(w, r)
	default:
		writeError(w, http.StatusNotFound, "PASSKEY_NOT_FOUND", "unknown passkey route")
	}
}

// RegisterRoutes mounts the passkey routes on a mux.
func (h *PasskeyHandler) RegisterRoutes(mux *http.ServeMux) {
	mux.Handle("/v1/auth/passkey/challenge", h)
	mux.Handle("/v1/auth/passkey/register", h)
	mux.Handle("/v1/auth/passkey/verify", h)
}

// -----------------------------------------------------------------------------
// /v1/auth/passkey/challenge
// -----------------------------------------------------------------------------

type challengeRequest struct {
	UserHandle string `json:"user_handle,omitempty"`
}

type challengeResponse struct {
	ChallengeID string `json:"challenge_id"`
	Challenge   string `json:"challenge"`
	RPID        string `json:"rp_id"`
	UserHandle  string `json:"user_handle,omitempty"`
	ExpiresAt   string `json:"expires_at"`
}

func (h *PasskeyHandler) handleChallenge(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "POST only")
		return
	}
	if h.cfg.RPID == "" {
		writeError(w, http.StatusInternalServerError, "IDENTITY_PASSKEY_MISCONFIGURED",
			"RP_ID env var must be set")
		return
	}

	// Body is optional — discoverable credentials require no user_handle.
	var req challengeRequest
	if r.Body != nil && r.ContentLength > 0 {
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		if err := dec.Decode(&req); err != nil && err.Error() != "EOF" {
			writeError(w, http.StatusBadRequest, "PASSKEY_INVALID_BODY", err.Error())
			return
		}
	}

	// 32 bytes of CSPRNG entropy per WebAuthn §13.4.3.
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		writeError(w, http.StatusInternalServerError, "PASSKEY_RNG_ERROR", err.Error())
		return
	}

	c, err := identity.NewPasskeyChallenge(identity.NewPasskeyChallengeParams{
		ChallengeBytes: nonce,
		RPID:           h.cfg.RPID,
		UserHandle:     req.UserHandle,
		TTL:            time.Duration(h.cfg.ChallengeTTLSeconds) * time.Second,
	})
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, "PASSKEY_INVALID_CHALLENGE", err.Error())
		return
	}
	if err := h.challenges.Save(r.Context(), c); err != nil {
		log.Printf("passkey challenge save: %v", err)
		writeError(w, http.StatusInternalServerError, "PASSKEY_REPO_ERROR", "save failed")
		return
	}

	writeJSON(w, http.StatusOK, challengeResponse{
		ChallengeID: c.ChallengeID,
		Challenge:   base64.RawURLEncoding.EncodeToString(c.ChallengeBytes),
		RPID:        c.RPID,
		UserHandle:  c.UserHandle,
		ExpiresAt:   c.ExpiresAt.UTC().Format(time.RFC3339Nano),
	})
}

// -----------------------------------------------------------------------------
// /v1/auth/passkey/register — registration ceremony finish (W3C §7.1)
// -----------------------------------------------------------------------------

type registerRequest struct {
	ChallengeID       string `json:"challenge_id"`
	Gcid              string `json:"gcid"`
	CredentialID      string `json:"credential_id"`      // base64 rawId from the authenticator
	ClientDataJSON    string `json:"client_data_json"`   // base64
	AttestationObject string `json:"attestation_object"` // base64
}

type registerResponse struct {
	CredentialID string `json:"credential_id"` // base64url
	Gcid         string `json:"gcid"`
	CreatedAt    string `json:"created_at"`
}

// clientData is the parsed shape of clientDataJSON (W3C §5.8.1).
type clientData struct {
	Type      string `json:"type"`
	Challenge string `json:"challenge"`
	Origin    string `json:"origin"`
}

func (h *PasskeyHandler) handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "POST only")
		return
	}
	if h.cfg.RPID == "" {
		writeError(w, http.StatusInternalServerError, "IDENTITY_PASSKEY_MISCONFIGURED",
			"RP_ID env var must be set")
		return
	}

	var req registerRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "PASSKEY_INVALID_BODY", err.Error())
		return
	}
	if strings.TrimSpace(req.ChallengeID) == "" {
		writeError(w, http.StatusBadRequest, "PASSKEY_CHALLENGE_ID_REQUIRED", "challenge_id required")
		return
	}
	gcid := strings.TrimSpace(req.Gcid)
	if gcid == "" {
		writeError(w, http.StatusBadRequest, "PASSKEY_GCID_REQUIRED", "gcid required")
		return
	}
	if strings.TrimSpace(req.CredentialID) == "" {
		writeError(w, http.StatusBadRequest, "PASSKEY_CREDENTIAL_ID_REQUIRED", "credential_id required")
		return
	}
	if strings.TrimSpace(req.ClientDataJSON) == "" || strings.TrimSpace(req.AttestationObject) == "" {
		writeError(w, http.StatusBadRequest, "PASSKEY_ATTESTATION_REQUIRED",
			"client_data_json and attestation_object are required")
		return
	}
	claimedCredID, err := decodeAnyBase64(req.CredentialID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "PASSKEY_INVALID_CREDENTIAL_ID",
			"credential_id must be base64-encoded")
		return
	}
	clientDataRaw, err := decodeAnyBase64(req.ClientDataJSON)
	if err != nil {
		writeError(w, http.StatusBadRequest, "PASSKEY_INVALID_CLIENT_DATA",
			"client_data_json must be base64-encoded")
		return
	}
	attObjRaw, err := decodeAnyBase64(req.AttestationObject)
	if err != nil {
		writeError(w, http.StatusBadRequest, "PASSKEY_INVALID_ATTESTATION",
			"attestation_object must be base64-encoded")
		return
	}

	// 1. Fetch + validate the challenge (same machinery as login verify).
	ch, ok := h.loadUsableChallenge(w, r.Context(), req.ChallengeID)
	if !ok {
		return
	}

	// 2. clientDataJSON binding (W3C §7.1 steps 7-9): type must be
	//    webauthn.create and the signed challenge must be the minted one.
	var cd clientData
	if err := json.Unmarshal(clientDataRaw, &cd); err != nil {
		writeError(w, http.StatusBadRequest, "PASSKEY_INVALID_CLIENT_DATA",
			"client_data_json is not valid JSON")
		return
	}
	if cd.Type != "webauthn.create" {
		writeError(w, http.StatusBadRequest, "PASSKEY_CLIENT_DATA_TYPE",
			fmt.Sprintf("clientDataJSON.type = %q, want webauthn.create", cd.Type))
		return
	}
	sentChallenge, err := decodeAnyBase64(cd.Challenge)
	if err != nil || !bytes.Equal(sentChallenge, ch.ChallengeBytes) {
		writeError(w, http.StatusUnauthorized, "PASSKEY_CHALLENGE_MISMATCH",
			"clientDataJSON.challenge does not match the issued challenge")
		return
	}

	// 3. Parse the attestationObject → REAL credentialId + COSE public key.
	attested, err := identity.ParseAttestationObject(attObjRaw)
	if err != nil {
		switch {
		case errors.Is(err, identity.ErrUnsupportedCOSEAlg):
			writeError(w, http.StatusBadRequest, "PASSKEY_UNSUPPORTED_ALGORITHM",
				"credential public key algorithm not supported (ES256/RS256 only): "+err.Error())
		default:
			writeError(w, http.StatusBadRequest, "PASSKEY_INVALID_ATTESTATION", err.Error())
		}
		return
	}

	// 4. RP binding (W3C §7.1 step 13): authData.rpIdHash == sha256(RP_ID).
	wantRPHash := sha256.Sum256([]byte(h.cfg.RPID))
	if !bytes.Equal(attested.RPIDHash, wantRPHash[:]) {
		writeError(w, http.StatusBadRequest, "PASSKEY_RPID_MISMATCH",
			"attested rpIdHash does not match this relying party")
		return
	}

	// 5. The claimed rawId must equal the attested credentialId.
	if !bytes.Equal(claimedCredID, attested.CredentialID) {
		writeError(w, http.StatusBadRequest, "PASSKEY_CREDENTIAL_ID_MISMATCH",
			"credential_id does not match the attested credential")
		return
	}

	// 5b. Attestation provenance (ADR-187). Verify the attestation statement and
	//     apply the policy. Disabled by default (policy zero value = off) so
	//     existing registration flows are behaviour-neutral; under `record` it
	//     never blocks (records unverified), under `enforce` it may 403.
	var attResult *identity.AttestationResult
	if h.attestationResolver != nil && h.attestationPolicy.Mode != identity.AttestationModeOff {
		now := time.Now
		if h.nowFn != nil {
			now = h.nowFn
		}
		cdh := sha256.Sum256(clientDataRaw)
		res, verr := identity.VerifyAttestationStatement(attested, cdh[:], h.attestationResolver, now())
		if verr != nil {
			log.Printf("passkey attestation verify: %v", verr)
			writeError(w, http.StatusInternalServerError, "PASSKEY_ATTESTATION_ERROR",
				"attestation verification failed")
			return
		}
		attResult = res
		if allow, reason := h.attestationPolicy.Evaluate(res); !allow {
			writeError(w, http.StatusForbidden, "PASSKEY_ATTESTATION_REJECTED", reason)
			return
		}
	}

	// 6. Registration binds to an EXISTING user — chora-gateway has already
	//    verified the caller's session is for this gcid; re-check existence
	//    so a forged gcid cannot mint orphan credentials.
	u, err := h.users.GetByGcid(r.Context(), gcid)
	if err != nil {
		if errors.Is(err, identity.ErrUserNotFound) {
			writeError(w, http.StatusNotFound, "PASSKEY_USER_NOT_FOUND",
				"no user for the supplied gcid")
			return
		}
		log.Printf("passkey register user lookup: %v", err)
		writeError(w, http.StatusInternalServerError, "PASSKEY_REPO_ERROR", "user lookup failed")
		return
	}
	if u.Status != identity.UserStatusActive {
		writeError(w, http.StatusForbidden, "PASSKEY_USER_NOT_ACTIVE",
			"user account is not active")
		return
	}

	// 7. Credential uniqueness (W3C §7.1 step 22).
	if _, err := h.credentials.GetByCredentialID(r.Context(), attested.CredentialID); err == nil {
		writeError(w, http.StatusConflict, "PASSKEY_CREDENTIAL_EXISTS",
			"credential is already registered")
		return
	} else if !errors.Is(err, identity.ErrPasskeyCredentialNotFound) {
		log.Printf("passkey register credential lookup: %v", err)
		writeError(w, http.StatusInternalServerError, "PASSKEY_REPO_ERROR", "credential lookup failed")
		return
	}

	params := identity.NewPasskeyCredentialParams{
		Gcid:             gcid,
		CredentialID:     attested.CredentialID,
		PublicKeyCOSE:    attested.PublicKeyCOSE, // the REAL key — placeholder path is dead
		AttestationType:  attested.Format,
		RPID:             h.cfg.RPID,
		InitialSignCount: attested.SignCount,
		// Provenance (ADR-187). The raw object + AAGUID are stored regardless of
		// mode so a credential registered today can be re-evaluated later (A4).
		AAGUID:            attested.AAGUID,
		AttestationObject: attObjRaw,
	}
	if attResult != nil {
		params.AttestationVerified = attResult.Verified
		params.AuthenticatorDescription = attResult.AuthenticatorDescription
		params.MDSCertificationLevel = attResult.CertificationLevel
	}
	cred, err := identity.NewPasskeyCredential(params)
	if err != nil {
		writeError(w, http.StatusBadRequest, "PASSKEY_CREDENTIAL_INVALID", err.Error())
		return
	}

	// 8. Consume the challenge (single-use) BEFORE persisting the credential —
	//    First-Save-Wins on the Pending→Consumed transition guards the
	//    multi-pod race exactly like the login path.
	if !h.consumeChallenge(w, r.Context(), ch, gcid) {
		return
	}
	if err := h.credentials.Save(r.Context(), cred); err != nil {
		log.Printf("passkey credential save: %v", err)
		writeError(w, http.StatusInternalServerError, "PASSKEY_REPO_ERROR", "save failed")
		return
	}

	// 9. Guarantee the owner has a DEK before any PII write (Tier 3 D11 —
	//    idempotent per gcid; non-fatal on transient failure).
	if h.dek != nil {
		if _, err := h.dek.IssueDEK(gcid); err != nil {
			log.Printf("passkey: DEK issuance failed for gcid=%s: %v", gcid, err)
		}
	}

	writeJSON(w, http.StatusCreated, registerResponse{
		CredentialID: base64.RawURLEncoding.EncodeToString(cred.CredentialID),
		Gcid:         gcid,
		CreatedAt:    cred.CreatedAt.UTC().Format(time.RFC3339Nano),
	})
}

// -----------------------------------------------------------------------------
// /v1/auth/passkey/verify — login ceremony finish (W3C §7.2)
// -----------------------------------------------------------------------------

type verifyRequest struct {
	ChallengeID  string `json:"challenge_id"`
	CredentialID string `json:"credential_id"` // base64-encoded
	// SignCount is the LEGACY client-supplied counter. When the
	// authenticator_data parses (≥37 bytes) the SIGNED counter embedded in
	// it wins; this field is only honoured for legacy short fixtures.
	SignCount uint32 `json:"sign_count"`

	// W3C WebAuthn Level 3 §7.2 signature triple — REQUIRED for every
	// authentication ceremony (verify is login-only post-A4).
	ClientDataJSON    string `json:"client_data_json,omitempty"`   // base64
	AuthenticatorData string `json:"authenticator_data,omitempty"` // base64
	Signature         string `json:"signature,omitempty"`          // base64

	// Legacy dev-shortcut field. Retained on the wire for client-compatibility
	// but IGNORED — production hardening removed the bypass per Wave A 2C.
	AttestationDev bool `json:"attestation_dev,omitempty"`

	// Legacy registration-intent field — IGNORED (registration moved to
	// /v1/auth/passkey/register per Phase A4).
	UserHandle string `json:"user_handle,omitempty"`
}

// verifyResponse no longer carries a token: chora-gateway composes the
// standard session-mint pipeline from (gcid, email).
type verifyResponse struct {
	Gcid         string `json:"gcid"`
	Email        string `json:"email"`
	CredentialID string `json:"credential_id"` // base64url
}

func (h *PasskeyHandler) handleVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "POST only")
		return
	}

	var req verifyRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "PASSKEY_INVALID_BODY", err.Error())
		return
	}
	if strings.TrimSpace(req.ChallengeID) == "" {
		writeError(w, http.StatusBadRequest, "PASSKEY_CHALLENGE_ID_REQUIRED",
			"challenge_id required")
		return
	}
	if strings.TrimSpace(req.CredentialID) == "" {
		writeError(w, http.StatusBadRequest, "PASSKEY_CREDENTIAL_ID_REQUIRED",
			"credential_id required")
		return
	}
	credIDBytes, err := decodeAnyBase64(req.CredentialID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "PASSKEY_INVALID_CREDENTIAL_ID",
			"credential_id must be base64-encoded")
		return
	}

	// 1. Fetch + validate the challenge.
	ch, ok := h.loadUsableChallenge(w, r.Context(), req.ChallengeID)
	if !ok {
		return
	}

	// 2. Resolve the credential — login-only: unknown credentials are
	//    rejected (the Phyllis-era auto-provisioning path is dead, A4).
	cred, err := h.credentials.GetByCredentialID(r.Context(), credIDBytes)
	if err != nil {
		if errors.Is(err, identity.ErrPasskeyCredentialNotFound) {
			writeError(w, http.StatusUnauthorized, "PASSKEY_CREDENTIAL_UNKNOWN",
				"unknown credential — register a passkey first")
			return
		}
		log.Printf("passkey credential lookup: %v", err)
		writeError(w, http.StatusInternalServerError, "PASSKEY_REPO_ERROR", "lookup failed")
		return
	}

	// 2.5 Production WebAuthn signature verification (W3C WebAuthn Level 3
	// §7.2) against the stored COSE key — no dev shortcut exists.
	if req.ClientDataJSON == "" || req.AuthenticatorData == "" || req.Signature == "" {
		writeError(w, http.StatusBadRequest, "PASSKEY_SIGNATURE_REQUIRED",
			"client_data_json, authenticator_data, and signature are required")
		return
	}
	clientDataJSON, err := decodeAnyBase64(req.ClientDataJSON)
	if err != nil {
		writeError(w, http.StatusBadRequest, "PASSKEY_INVALID_CLIENT_DATA",
			"client_data_json must be base64-encoded")
		return
	}
	authData, err := decodeAnyBase64(req.AuthenticatorData)
	if err != nil {
		writeError(w, http.StatusBadRequest, "PASSKEY_INVALID_AUTH_DATA",
			"authenticator_data must be base64-encoded")
		return
	}
	sig, err := decodeAnyBase64(req.Signature)
	if err != nil {
		writeError(w, http.StatusBadRequest, "PASSKEY_INVALID_SIGNATURE",
			"signature must be base64-encoded")
		return
	}

	// 2.6 Bind the SIGNED clientDataJSON to THIS ceremony (W3C WebAuthn L3
	// §7.2 steps 11+13) BEFORE trusting the signature. type must be
	// "webauthn.get" and clientDataJSON.challenge must equal the
	// server-issued, single-use challenge. This is the assertion-replay guard
	// (D9, CHO-1790): the signature only covers authData || sha256(clientData),
	// so a captured triple re-verifies against any fresh challenge unless we
	// also pin the signed challenge — and counter-less authenticators make the
	// sign-count clone check a no-op. Mirrors the registration binding above.
	if err := identity.VerifyClientData(clientDataJSON, ch.ChallengeBytes, identity.ClientDataTypeGet); err != nil {
		switch {
		case errors.Is(err, identity.ErrUnexpectedClientDataType):
			writeError(w, http.StatusBadRequest, "PASSKEY_CLIENT_DATA_TYPE",
				"clientDataJSON.type must be webauthn.get for a login assertion")
		case errors.Is(err, identity.ErrChallengeMismatch):
			writeError(w, http.StatusUnauthorized, "PASSKEY_CHALLENGE_MISMATCH",
				"clientDataJSON.challenge does not match the issued challenge")
		default: // ErrMalformedClientData
			writeError(w, http.StatusBadRequest, "PASSKEY_INVALID_CLIENT_DATA",
				"client_data_json is not valid CollectedClientData JSON")
		}
		return
	}

	if err := identity.VerifyAssertion(cred.PublicKeyCOSE, authData, clientDataJSON, sig); err != nil {
		if errors.Is(err, identity.ErrInvalidSignature) {
			writeError(w, http.StatusUnauthorized, "PASSKEY_SIGNATURE_REJECTED",
				"WebAuthn signature did not verify")
			return
		}
		if errors.Is(err, identity.ErrUnsupportedCOSEAlg) || errors.Is(err, identity.ErrMalformedCOSEKey) {
			writeError(w, http.StatusInternalServerError, "PASSKEY_KEY_MATERIAL_INVALID",
				err.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, "PASSKEY_VERIFY_ERROR", err.Error())
		return
	}

	// 3. Replay protection on the credential's sign-count. The effective
	//    counter comes from the SIGNED authenticator data when it parses
	//    (real authenticators always emit ≥37 bytes); the client-supplied
	//    sign_count body field is legacy fallback only.
	effectiveSignCount := req.SignCount
	if sc, scErr := identity.SignCountFromAuthenticatorData(authData); scErr == nil {
		effectiveSignCount = sc
	}
	if err := cred.RecordUse(effectiveSignCount); err != nil {
		if errors.Is(err, identity.ErrPasskeyCredentialReplay) {
			writeError(w, http.StatusUnauthorized, "PASSKEY_REPLAY_DETECTED",
				"sign_count regression — possible cloned authenticator")
			return
		}
		if errors.Is(err, identity.ErrPasskeyCredentialRevoked) {
			writeError(w, http.StatusUnauthorized, "PASSKEY_CREDENTIAL_REVOKED",
				"credential has been revoked")
			return
		}
		writeError(w, http.StatusInternalServerError, "PASSKEY_RECORD_USE_ERROR", err.Error())
		return
	}

	// 4. Mark challenge verified+consumed (single-use).
	if !h.consumeChallenge(w, r.Context(), ch, cred.Gcid) {
		return
	}
	if err := h.credentials.Save(r.Context(), cred); err != nil {
		log.Printf("passkey credential save: %v", err)
		writeError(w, http.StatusInternalServerError, "PASSKEY_REPO_ERROR", "save failed")
		return
	}

	// 5. Surface the verified identity — chora-gateway composes the session
	//    mint (resolve → roles → JWT) from gcid+email. NO token minted here.
	u, err := h.users.GetByGcid(r.Context(), cred.Gcid)
	if err != nil {
		log.Printf("passkey verify user lookup (gcid=%s): %v", cred.Gcid, err)
		writeError(w, http.StatusInternalServerError, "PASSKEY_USER_LOOKUP_FAILED",
			"credential owner could not be loaded")
		return
	}

	writeJSON(w, http.StatusOK, verifyResponse{
		Gcid:         cred.Gcid,
		Email:        u.Email,
		CredentialID: base64.RawURLEncoding.EncodeToString(cred.CredentialID),
	})
}

// -----------------------------------------------------------------------------
// Shared challenge helpers
// -----------------------------------------------------------------------------

// loadUsableChallenge fetches the challenge and rejects consumed/expired/
// unknown ones, writing the error response itself. Returns (challenge, true)
// when the ceremony may proceed.
func (h *PasskeyHandler) loadUsableChallenge(w http.ResponseWriter, ctx context.Context, challengeID string) (*identity.PasskeyChallenge, bool) {
	ch, err := h.challenges.GetByID(ctx, challengeID)
	if err != nil {
		if errors.Is(err, identity.ErrPasskeyChallengeNotFound) {
			writeError(w, http.StatusUnauthorized, "PASSKEY_CHALLENGE_UNKNOWN",
				"unknown challenge_id")
			return nil, false
		}
		log.Printf("passkey challenge lookup: %v", err)
		writeError(w, http.StatusInternalServerError, "PASSKEY_REPO_ERROR", "lookup failed")
		return nil, false
	}
	switch ch.Status {
	case identity.PasskeyChallengeStatusConsumed:
		writeError(w, http.StatusUnauthorized, "PASSKEY_CHALLENGE_CONSUMED",
			"challenge already used")
		return nil, false
	case identity.PasskeyChallengeStatusExpired:
		writeError(w, http.StatusUnauthorized, "PASSKEY_CHALLENGE_EXPIRED", "challenge expired")
		return nil, false
	}
	if ch.Expired(time.Now().UTC()) {
		writeError(w, http.StatusUnauthorized, "PASSKEY_CHALLENGE_EXPIRED",
			"challenge expired")
		return nil, false
	}
	return ch, true
}

// consumeChallenge runs MarkVerified → MarkConsumed → Save with the
// First-Save-Wins concurrency contract (multi-pod single-use enforcement on
// the Pending → Consumed transition; per memory feedback_resilience_priority).
// Writes the error response itself; returns true on success.
func (h *PasskeyHandler) consumeChallenge(w http.ResponseWriter, ctx context.Context, ch *identity.PasskeyChallenge, gcid string) bool {
	if err := ch.MarkVerified(gcid); err != nil {
		writeError(w, http.StatusUnauthorized, "PASSKEY_VERIFY_REJECTED", err.Error())
		return false
	}
	if err := ch.MarkConsumed(); err != nil {
		writeError(w, http.StatusInternalServerError, "PASSKEY_CONSUME_ERROR", err.Error())
		return false
	}
	if err := h.challenges.Save(ctx, ch); err != nil {
		if errors.Is(err, identity.ErrPasskeyChallengeConsumed) {
			writeError(w, http.StatusUnauthorized, "PASSKEY_CHALLENGE_CONSUMED",
				"challenge already consumed by a concurrent verify")
			return false
		}
		log.Printf("passkey challenge save: %v", err)
		writeError(w, http.StatusInternalServerError, "PASSKEY_REPO_ERROR", "save failed")
		return false
	}
	return true
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

// decodeAnyBase64 accepts standard or URL-safe base64 (with or without padding).
// The WebAuthn API typically emits base64url; tests sometimes emit standard
// base64 — be lenient at the transport layer.
func decodeAnyBase64(s string) ([]byte, error) {
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding,
		base64.URLEncoding,
		base64.RawStdEncoding,
		base64.RawURLEncoding,
	} {
		if b, err := enc.DecodeString(s); err == nil {
			return b, nil
		}
	}
	return nil, fmt.Errorf("not a valid base64 string: %q", s)
}
