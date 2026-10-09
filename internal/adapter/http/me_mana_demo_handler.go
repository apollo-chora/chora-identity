// POST /api/v1/me/mana/demo-grant — the demo-mode free mana top-up.
//
// Demo mode exists so a demo never has to run a real payment/top-up flow: the
// seeded accounts start with a large balance (cmd/seed) and this endpoint tops
// one up for free. It is a DEDICATED demo operation, NOT a repurposing of the
// retired Stripe /me/mana/topup route, and it is ledger-backed under its own
// `demo_grant` reason so free demo mana is never misreported as a paid top-up.
//
// HARD GATING — default OFF. The endpoint is available ONLY when BOTH
// CHORA_DEMO_MANA_TOPUP_ENABLED=true AND CHORA_DEMO_MODE=true are set, and it
// refuses outright when CHORA_ENV is prod/production. CHORA_ENV alone is never
// sufficient to turn it on.
//
// ACCOUNT ALLOWLIST. Even when enabled, the endpoint grants ONLY to GCIDs
// listed in CHORA_DEMO_MANA_ALLOWED_GCIDS — the designated demo accounts.
// Anyone else gets 403 DEMO_ACCOUNT_NOT_ALLOWED. The allowlist is parsed and
// validated at startup (an enabled endpoint without a usable allowlist refuses
// to boot) and checked in the identity service itself, not at the gateway or in
// the frontend.
//
// The grant amount is FIXED server-side (configurable, never from the request
// body) and the GCID comes ONLY from the validated server-side session context
// — never from a request parameter.
//
// CAPS ARE ENFORCED IN THE DATABASE TRANSACTION. The handler deliberately does
// no idempotency/cap/budget decision of its own: those checks run inside the
// same transaction that credits the wallet and appends the ledger row, under a
// transaction-scoped GCID lock plus row locks on the shared demo-grant budget
// counters. Anything checked outside that transaction is a check two concurrent
// requests can both pass.
package httpadapter

import (
	"context"
	"errors"
	"log"
	"net/http"
	"strings"

	"github.com/google/uuid"

	"github.com/apollo-chora/chora-common/auth/chorasession"
	"github.com/apollo-chora/chora-identity/internal/domain/identity"
	mana "github.com/apollo-chora/chora-identity/internal/domain/user_mana"
)

// DemoManaConfig is the env-driven configuration for the demo mana grant.
// All fields are sourced from env vars at the wiring layer (cmd/server/main.go)
// per the no-inline-config rule.
//
// The zero value keeps the endpoint DISABLED: Enabled defaults to false and
// every guard below treats its zero value as "no grants".
type DemoManaConfig struct {
	// Enabled reports whether the demo grant is available at all.
	Enabled bool

	// GrantUnits is the fixed per-grant amount. NEVER read from the request.
	GrantUnits int64

	// MaxPerGcid is the number of INTERACTIVE demo grants one GCID may claim.
	// 0 means uncapped. The one-time seed grant is account provisioning and is
	// NOT counted against it.
	MaxPerGcid int64

	// TotalBudgetUnits is the platform-wide budget for INTERACTIVE demo grants.
	// 0 means uncapped. The seed grant does not consume it.
	TotalBudgetUnits int64

	// AllowedGcids is the immutable allowlist of canonical (lowercase,
	// hyphenated) UUID strings permitted to claim a demo grant — the designated
	// demo accounts. It is REQUIRED whenever Enabled is true: the composition
	// root refuses to start an enabled endpoint without one. FAIL CLOSED — an
	// empty set allows nobody, so a missing allowlist can never open the
	// endpoint to every authenticated account.
	AllowedGcids map[string]struct{}
}

// ParseDemoManaAllowedGcids parses the comma-separated
// CHORA_DEMO_MANA_ALLOWED_GCIDS value into an immutable set of canonical UUID
// strings. It returns the set plus the entries it rejected, split by reason:
//
//   - malformed: present but not a GCID (UUID) — an account the operator never
//     meant to allow;
//   - empty: a blank slot in the comma-separated list (a trailing comma, or
//     ", ," between entries).
//
// Both are reported rather than skipped so the composition root can refuse to
// start on an allowlist it cannot honour exactly. Silently dropping an empty
// slot is how "gcid-a, gcid-b," (trailing comma) becomes a two-account list
// the operator never wrote.
func ParseDemoManaAllowedGcids(raw string) (allowed map[string]struct{}, malformed, empty []string) {
	allowed = make(map[string]struct{})
	for _, part := range strings.Split(raw, ",") {
		entry := strings.TrimSpace(part)
		if entry == "" {
			empty = append(empty, entry)
			continue
		}
		canonical, err := canonicalGcid(entry)
		if err != nil {
			malformed = append(malformed, entry)
			continue
		}
		allowed[canonical] = struct{}{}
	}
	return allowed, malformed, empty
}

// canonicalGcid returns the canonical (lowercase, hyphenated) form of a GCID.
func canonicalGcid(gcid string) (string, error) {
	parsed, err := uuid.Parse(strings.TrimSpace(gcid))
	if err != nil {
		return "", err
	}
	return parsed.String(), nil
}

// AllowsGcid reports whether the authenticated GCID may claim a demo grant.
//
// FAIL CLOSED: an empty allowlist, an empty GCID or an unparseable GCID all
// deny. The caller must pass the GCID from the validated server-side session
// context — never one taken from the request body, query or an unrelated
// header, which are attacker-controlled.
func (c DemoManaConfig) AllowsGcid(gcid string) bool {
	if len(c.AllowedGcids) == 0 {
		return false
	}
	canonical, err := canonicalGcid(gcid)
	if err != nil {
		return false
	}
	_, ok := c.AllowedGcids[canonical]
	return ok
}

// DemoManaHandler exposes POST /api/v1/me/mana/demo-grant.
type DemoManaHandler struct {
	users     identity.UserRepository
	manaStore mana.Store
	cfg       DemoManaConfig
	// session validates the Chora session JWT that authenticates the caller.
	// Endpoint-scoped: no other identity route is changed by it.
	session *chorasession.Validator
}

// NewDemoManaHandler wires the demo mana grant handler. session may be nil only
// while the endpoint is disabled — an enabled endpoint without a session
// validator is refused at boot (see demoSessionValidatorFromEnv), because a
// demo grant that cannot authenticate its caller must not be served at all.
func NewDemoManaHandler(
	users identity.UserRepository,
	manaStore mana.Store,
	cfg DemoManaConfig,
	session *chorasession.Validator,
) *DemoManaHandler {
	return &DemoManaHandler{users: users, manaStore: manaStore, cfg: cfg, session: session}
}

// RegisterRoutes mounts the demo grant route.
func (h *DemoManaHandler) RegisterRoutes(mux *http.ServeMux) {
	mux.Handle("/api/v1/me/mana/demo-grant", h.requireSessionJWT(http.HandlerFunc(h.demoGrant)))
}

// demoSessionClaimsCtxKey carries the VALIDATED chorasession.Claims on the
// request context. Distinct from ctxKeyGcid, which tenantContext fills from
// unauthenticated headers — the two must never be conflated.
type demoSessionClaimsCtxKey struct{}

// demoSessionClaimsFromContext returns the validated session claims, or
// (nil, false) when the request never passed requireSessionJWT.
func demoSessionClaimsFromContext(ctx context.Context) (*chorasession.Claims, bool) {
	c, ok := ctx.Value(demoSessionClaimsCtxKey{}).(*chorasession.Claims)
	return c, ok && c != nil
}

// requireSessionJWT is the authentication boundary for the demo grant.
//
// It REPLACES bearerAuth for this one route. bearerAuth resolves the caller
// from `chora-gcid` / `gcid` headers or a raw-GCID Bearer token and then only
// checks that the GCID EXISTS in the user repository — existence checking, not
// authentication. Any container on the Docker network that can name an
// allowlisted GCID therefore obtained that account's authority over a free
// mana grant.
//
// This middleware instead requires a Chora session JWT and verifies it with the
// SAME chorasession.Validator chora-gateway uses at its /api/* trust boundary
// (chora-common/auth/chorasession) — signature, issuer, audience, expiry and
// the gcid claim. The GCID is then read from the VALIDATED claims, so:
//
//   - chora-gcid / gcid / X-Gcid / X-Chora-GCID and every other client-supplied
//     GCID are ignored for authorization on this endpoint;
//   - a raw-GCID Bearer token is not a JWT and fails validation (401);
//   - an unverified payload is never compared against a header — the signature
//     is verified BEFORE any claim is trusted.
//
// On any rejection it writes 401 + the canonical error envelope and
// short-circuits. The specific validator error is logged, not returned, so the
// response does not disclose which check failed.
func (h *DemoManaHandler) requireSessionJWT(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Enabled check FIRST, before authentication. A disabled demo must read
		// as 404 DEMO_UNAVAILABLE (learner-economy.yaml grantDemoManaToSelf — an
		// unavailable demo is not a permission the caller could ever be
		// granted). Checking the session first made a DISABLED deployment answer
		// 401 DEMO_SESSION_UNAVAILABLE, because the composition root builds no
		// validator when the feature is off.
		if !h.cfg.Enabled {
			writeError(w, http.StatusNotFound, "DEMO_UNAVAILABLE",
				"demo mana grant is not available (set CHORA_DEMO_MANA_TOPUP_ENABLED=true and CHORA_DEMO_MODE=true, and never in prod)")
			return
		}
		if h.session == nil {
			// Fail closed. Unreachable when the composition root honours the
			// enabled-without-validator boot gate.
			writeError(w, http.StatusUnauthorized, "DEMO_SESSION_UNAVAILABLE",
				"demo mana grant session validation is not configured")
			return
		}
		token, ok := extractBearer(r.Header.Get("Authorization"))
		if !ok {
			writeError(w, http.StatusUnauthorized, "DEMO_SESSION_REQUIRED",
				"Authorization: Bearer <Chora session JWT> is required")
			return
		}
		claims, err := h.session.Validate(token)
		if err != nil {
			log.Printf("demoGrant: session rejected: %v", err)
			writeError(w, http.StatusUnauthorized, "DEMO_SESSION_INVALID",
				"a valid Chora session JWT is required")
			return
		}
		if strings.TrimSpace(claims.GCID) == "" {
			writeError(w, http.StatusUnauthorized, "DEMO_SESSION_INVALID",
				"session JWT carries no gcid claim")
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), demoSessionClaimsCtxKey{}, claims)))
	})
}

// demoGrant applies one fixed demo mana grant to the authenticated caller.
func (h *DemoManaHandler) demoGrant(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "POST only")
		return
	}
	if !h.cfg.Enabled {
		// 404, not 403: an unavailable demo feature is not a permission the
		// caller could ever be granted.
		writeError(w, http.StatusNotFound, "DEMO_UNAVAILABLE",
			"demo mana grant is not available (set CHORA_DEMO_MANA_TOPUP_ENABLED=true and CHORA_DEMO_MODE=true, and never in prod)")
		return
	}

	ctx := r.Context()
	// GCID comes ONLY from the VALIDATED session claims. Nothing in the request
	// body, query string or headers is consulted for identity: the
	// authenticated caller wins. gcidFromContext (tenantContext) is filled from
	// unauthenticated headers and is deliberately NOT read here.
	claims, ok := demoSessionClaimsFromContext(ctx)
	if !ok {
		// Defensive: requireSessionJWT always stamps the claims. Refuse loud
		// rather than fall back to any other identity source.
		writeError(w, http.StatusUnauthorized, "DEMO_SESSION_INVALID",
			"a valid Chora session JWT is required")
		return
	}
	gcid := claims.GCID

	// TENANT CONSISTENCY. The session carries the caller's active tenant; the
	// request's tenant context (X-Tenant-Id, which the gateway stamps from that
	// same session) must agree with it. A mismatch means the request is
	// assembled from a session and a tenant that do not belong together, so it
	// is refused rather than honoured under whichever tenant the header names.
	// When the request carries no tenant context there is nothing to be
	// inconsistent with, so the check is not applicable.
	if reqTenant := tenantFromContext(ctx); reqTenant != "" && reqTenant != claims.TenantID {
		writeError(w, http.StatusUnauthorized, "DEMO_SESSION_TENANT_MISMATCH",
			"session tenant does not match the request tenant context")
		return
	}

	// Defence in depth: the JWT was minted for a real account, but an account
	// closed or deleted after minting must not be able to claim free mana.
	if _, err := h.users.GetByGcid(ctx, gcid); err != nil {
		if errors.Is(err, identity.ErrUserNotFound) {
			writeError(w, http.StatusUnauthorized, "IDENTITY_UNKNOWN_GCID", "unknown session gcid")
			return
		}
		log.Printf("demoGrant: user lookup error: %v", err)
		writeError(w, http.StatusInternalServerError, "IDENTITY_REPO_ERROR", "internal error")
		return
	}

	// ALLOWLIST GATE — the demo grant is restricted to designated demo
	// accounts. Identity is settled FIRST: a caller who is not on the list is
	// refused whatever the rest of the request looks like, and the decision is
	// keyed on the authenticated GCID alone, so a caller can neither grant to
	// an account they are not nor name an allowed account in the request.
	if !h.cfg.AllowsGcid(gcid) {
		writeError(w, http.StatusForbidden, "DEMO_ACCOUNT_NOT_ALLOWED",
			"demo mana grants are restricted")
		return
	}

	// The idempotency key is REQUIRED — the client must supply it so a retry
	// cannot double-grant. Unlike purchaseSubscription, we never mint one.
	key := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	if key == "" {
		writeError(w, http.StatusBadRequest, "IDEMPOTENCY_KEY_REQUIRED",
			"Idempotency-Key header is required")
		return
	}

	// ONE transactional call enforces both caps and applies the grant. The caps
	// are checked AFTER the per-GCID and budget row locks are taken and BEFORE
	// anything is written, so two concurrent requests can neither exceed the
	// platform-wide budget nor the per-GCID cap; and because the idempotency
	// re-check happens in the same transaction, a repeated key replays the
	// original grant (Replayed=true) without re-checking the caps or crediting
	// again. Nothing here is decided outside the transaction — a check outside
	// it is a check two concurrent requests can both pass.
	res, err := h.manaStore.CreditWallet(ctx, mana.CreditWalletInput{
		Gcid:           gcid,
		Units:          h.cfg.GrantUnits,
		Direction:      mana.DirectionMint,
		Reason:         mana.ReasonDemoGrant,
		IdempotencyKey: key,
		DemoGrantCaps: &mana.DemoGrantCaps{
			MaxPerGcid:  h.cfg.MaxPerGcid,
			BudgetUnits: h.cfg.TotalBudgetUnits,
		},
	})
	switch {
	case errors.Is(err, mana.ErrDemoGrantLimitReached):
		writeError(w, http.StatusTooManyRequests, "DEMO_GRANT_LIMIT_REACHED",
			"demo mana grant limit reached for this account")
		return
	case errors.Is(err, mana.ErrDemoGrantBudgetExhausted):
		writeError(w, http.StatusTooManyRequests, "DEMO_GRANT_BUDGET_EXHAUSTED",
			"demo mana grant budget exhausted")
		return
	case errors.Is(err, mana.ErrIdempotencyConflict):
		// The same key was already used for a DIFFERENT operation. Reporting a
		// replay here would silently accept the mismatch.
		writeError(w, http.StatusConflict, "IDEMPOTENCY_KEY_CONFLICT",
			"Idempotency-Key was already used for a different operation")
		return
	case err != nil:
		log.Printf("demoGrant: credit for gcid=%s: %v", gcid, err)
		writeError(w, http.StatusInternalServerError, "DEMO_REPO_ERROR", "demo grant failed")
		return
	}

	h.audit(gcid, key, res.Entry.Units, res.Replayed, res.BalanceAfterUnits)
	writeJSON(w, http.StatusOK, demoGrantResponse{
		GrantedUnits: res.Entry.Units,
		BalanceUnits: res.BalanceAfterUnits,
		Replayed:     res.Replayed,
		Reason:       string(res.Entry.Reason),
	})
}

// demoGrantResponse is the FE response shape.
type demoGrantResponse struct {
	GrantedUnits int64  `json:"granted_units"`
	BalanceUnits int64  `json:"balance_units"`
	Replayed     bool   `json:"replayed"`
	Reason       string `json:"reason"`
}

// audit records every demo grant. It logs the GCID, the fixed amount, the
// idempotency key and the resulting balance — NEVER a token, a password or any
// other credential.
func (h *DemoManaHandler) audit(gcid, idempotencyKey string, units int64, replayed bool, balance int64) {
	log.Printf("identity: demo mana grant gcid=%s units=%d idempotency_key=%s replayed=%t balance_units=%d",
		gcid, units, idempotencyKey, replayed, balance)
}
