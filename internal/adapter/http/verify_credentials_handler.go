// verify_credentials_handler.go — POST /v1/auth/verify-credentials.
//
// This is the local username/password login endpoint that replaces the removed
// external identity provider. A sibling chora-gateway calls it during session
// mint and MUST trust the returned active tenant verbatim.
//
// FROZEN CONTRACT
//
//	Request:  {"username":"<string>","password":"<string>"}
//	200:      {"gcid","email","active_tenant_id","active_tenant_roles","memberships"}
//	401:      {"error":{"code":"INVALID_CREDENTIALS","message":"..."}}
//	403:      {"error":{"code":"ACCOUNT_DISABLED","message":"..."}}
//
// Semantics:
//   - Username is globally unique (normalised case).
//   - active_tenant_id / active_tenant_roles are AUTHORITATIVE.
//   - Zero active memberships → 401 (never mint a tenant-less principal).
//   - More than one active tenant → resolved deterministically by
//     authn.ResolveActiveTenant.
//   - A non-active user → 403.
//   - Password length is capped at authn.MaxPasswordBytes (1024).
//
// Request-shape problems (missing fields, malformed JSON, oversized password)
// all fail closed as 401 INVALID_CREDENTIALS so the endpoint's status set stays
// exactly {200,401,403} as the contract requires.
package httpadapter

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"log"
	"net/http"
	"strings"

	"github.com/apollo-chora/chora-identity/internal/domain/authn"
	"github.com/apollo-chora/chora-identity/internal/domain/identity"
)

// VerifyCredentialsConfig wires the handler dependencies.
type VerifyCredentialsConfig struct {
	// Credentials resolves the Argon2id credential by normalised username.
	Credentials authn.CredentialsRepository
	// Users loads the user aggregate by GCID (for status + email).
	Users identity.UserRepository
	// Memberships loads the GCID's ACTIVE memberships across tenants.
	Memberships authn.MembershipRepository
}

// VerifyCredentialsMembership is one tenant's role set in the response.
type VerifyCredentialsMembership struct {
	TenantID string   `json:"tenant_id"`
	Roles    []string `json:"roles"`
}

// VerifyCredentialsResponse is the canonical 200-OK body.
type VerifyCredentialsResponse struct {
	GCID              string                        `json:"gcid"`
	Email             string                        `json:"email"`
	ActiveTenantID    string                        `json:"active_tenant_id"`
	ActiveTenantRoles []string                      `json:"active_tenant_roles"`
	Memberships       []VerifyCredentialsMembership `json:"memberships"`
}

// VerifyCredentialsError is the nested error envelope for this endpoint.
type VerifyCredentialsError struct {
	Error VerifyCredentialsErrorBody `json:"error"`
}

// VerifyCredentialsErrorBody carries the code + human message.
type VerifyCredentialsErrorBody struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// VerifyCredentialsHandler implements POST /v1/auth/verify-credentials.
type VerifyCredentialsHandler struct {
	cfg VerifyCredentialsConfig
	// dummyPHC is a valid hash for a random password, verified against when no
	// credential matches so a lookup miss costs the same Argon2 work as a
	// wrong-password miss (no username-enumeration timing oracle).
	dummyPHC string
}

// NewVerifyCredentialsHandler constructs the handler.
func NewVerifyCredentialsHandler(cfg VerifyCredentialsConfig) *VerifyCredentialsHandler {
	h := &VerifyCredentialsHandler{cfg: cfg}
	// Best-effort timing-equalisation hash. A generation failure leaves
	// dummyPHC empty; the handler then skips the dummy verify (still correct,
	// just without the timing defence).
	if phc, err := authn.HashPassword(randomSecret()); err == nil {
		h.dummyPHC = phc
	}
	return h
}

// RegisterRoutes mounts the endpoint on the supplied mux.
func (h *VerifyCredentialsHandler) RegisterRoutes(mux *http.ServeMux) {
	mux.Handle("/v1/auth/verify-credentials", h)
}

type verifyCredentialsRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (h *VerifyCredentialsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		h.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "POST required")
		return
	}
	if h.cfg.Credentials == nil || h.cfg.Users == nil || h.cfg.Memberships == nil {
		// Misconfiguration is an internal error, not a credential verdict.
		h.writeError(w, http.StatusInternalServerError, "INTERNAL", "authentication is not configured")
		return
	}

	var req verifyCredentialsRequest
	if err := decodeJSON(r, &req); err != nil {
		h.invalidCredentials(w, "invalid request body")
		return
	}
	usernameNorm := authn.NormalizeUsername(req.Username)
	if usernameNorm == "" || req.Password == "" {
		h.invalidCredentials(w, "username and password are required")
		return
	}
	if len(req.Password) > authn.MaxPasswordBytes {
		// Never run Argon2 over an unbounded input (memory-amplification DoS).
		h.invalidCredentials(w, "invalid credentials")
		return
	}

	ctx := r.Context()
	cred, err := h.cfg.Credentials.GetByUsernameNorm(ctx, usernameNorm)
	if err != nil {
		if !errors.Is(err, authn.ErrCredentialsNotFound) {
			log.Printf("identity: verify-credentials credential lookup failed: %v", err)
		}
		// Equalise timing with the wrong-password path before failing closed.
		h.dummyVerify(req.Password)
		h.invalidCredentials(w, "invalid username or password")
		return
	}

	ok, verr := authn.VerifyPassword(req.Password, cred.PasswordHash)
	if verr != nil {
		log.Printf("identity: verify-credentials stored hash unreadable for gcid=%s: %v", cred.Gcid, verr)
		h.invalidCredentials(w, "invalid username or password")
		return
	}
	if !ok {
		h.invalidCredentials(w, "invalid username or password")
		return
	}

	user, err := h.cfg.Users.GetByGcid(ctx, cred.Gcid)
	if err != nil {
		if !errors.Is(err, identity.ErrUserNotFound) {
			log.Printf("identity: verify-credentials user lookup failed for gcid=%s: %v", cred.Gcid, err)
		}
		h.invalidCredentials(w, "invalid username or password")
		return
	}
	if user.Status != identity.UserStatusActive {
		h.writeError(w, http.StatusForbidden, "ACCOUNT_DISABLED", "account is not active")
		return
	}

	memberships, err := h.cfg.Memberships.ListActiveByGCID(ctx, user.Gcid)
	if err != nil {
		log.Printf("identity: verify-credentials membership lookup failed for gcid=%s: %v", user.Gcid, err)
		h.writeError(w, http.StatusInternalServerError, "INTERNAL", "membership lookup failed")
		return
	}
	groups := authn.GroupByTenant(memberships)
	activeTenant, activeRoles := authn.ResolveActiveTenant(memberships, groups)
	if activeTenant == "" {
		// Never mint a tenant-less principal.
		h.invalidCredentials(w, "no active tenant membership")
		return
	}

	resp := VerifyCredentialsResponse{
		GCID:              user.Gcid,
		Email:             user.Email,
		ActiveTenantID:    activeTenant,
		ActiveTenantRoles: activeRoles,
		Memberships:       make([]VerifyCredentialsMembership, 0, len(groups)),
	}
	for _, g := range groups {
		resp.Memberships = append(resp.Memberships, VerifyCredentialsMembership{
			TenantID: g.TenantID,
			Roles:    g.Roles,
		})
	}
	writeJSON(w, http.StatusOK, resp)
}

func (h *VerifyCredentialsHandler) invalidCredentials(w http.ResponseWriter, msg string) {
	h.writeError(w, http.StatusUnauthorized, "INVALID_CREDENTIALS", msg)
}

func (h *VerifyCredentialsHandler) writeError(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, VerifyCredentialsError{
		Error: VerifyCredentialsErrorBody{Code: code, Message: msg},
	})
}

// dummyVerify runs an Argon2 verification against a throwaway hash so a lookup
// miss is not observably faster than a wrong password.
func (h *VerifyCredentialsHandler) dummyVerify(password string) {
	if h.dummyPHC == "" {
		return
	}
	_, _ = authn.VerifyPassword(password, h.dummyPHC)
}

// randomSecret returns a base64 random string used only to seed dummyPHC.
func randomSecret() string {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return strings.Repeat("x", 24)
	}
	return base64.RawStdEncoding.EncodeToString(b)
}
