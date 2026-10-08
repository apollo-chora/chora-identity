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
	"errors"
	"log"
	"net/http"
	"strings"

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
}

// DemoManaHandler exposes POST /api/v1/me/mana/demo-grant.
type DemoManaHandler struct {
	users     identity.UserRepository
	manaStore mana.Store
	cfg       DemoManaConfig
}

// NewDemoManaHandler wires the demo mana grant handler.
func NewDemoManaHandler(users identity.UserRepository, manaStore mana.Store, cfg DemoManaConfig) *DemoManaHandler {
	return &DemoManaHandler{users: users, manaStore: manaStore, cfg: cfg}
}

// RegisterRoutes mounts the demo grant route.
func (h *DemoManaHandler) RegisterRoutes(mux *http.ServeMux) {
	mux.Handle("/api/v1/me/mana/demo-grant", bearerAuth(h.users, http.HandlerFunc(h.demoGrant)))
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

	// The idempotency key is REQUIRED — the client must supply it so a retry
	// cannot double-grant. Unlike purchaseSubscription, we never mint one.
	key := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	if key == "" {
		writeError(w, http.StatusBadRequest, "IDEMPOTENCY_KEY_REQUIRED",
			"Idempotency-Key header is required")
		return
	}

	ctx := r.Context()
	// GCID comes ONLY from the validated server-side session context.
	gcid := gcidFromContext(ctx)

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

