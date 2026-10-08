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
package httpadapter

import (
	"context"
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

	// MaxPerGcid is the number of demo grants one GCID may claim.
	MaxPerGcid int64

	// TotalBudgetUnits is the platform-wide demo grant budget.
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

	// Idempotent replay short-circuit: a repeated key returns the original
	// grant WITHOUT re-checking the caps (a replay must not start failing once
	// the cap is reached) and without crediting again. The balance reported is
	// the caller's CURRENT balance, not the one stamped on the original row.
	if existing, err := h.manaStore.FindLedgerByIdempotencyKey(ctx, gcid, key); err == nil && len(existing) > 0 {
		bal, berr := h.currentBalance(ctx, gcid)
		if berr != nil {
			log.Printf("demoGrant: balance read for gcid=%s: %v", gcid, berr)
			writeError(w, http.StatusInternalServerError, "DEMO_REPO_ERROR", "demo grant failed")
			return
		}
		h.audit(gcid, key, existing[0].Units, true, bal)
		writeJSON(w, http.StatusOK, demoGrantResponse{
			GrantedUnits: existing[0].Units,
			BalanceUnits: bal,
			Replayed:     true,
			Reason:       string(existing[0].Reason),
		})
		return
	}

	// Per-GCID cap.
	reason := mana.ReasonDemoGrant
	used, err := h.manaStore.ListLedger(ctx, mana.LedgerFilter{Gcid: gcid, Reason: &reason})
	if err != nil {
		log.Printf("demoGrant: list ledger for gcid=%s: %v", gcid, err)
		writeError(w, http.StatusInternalServerError, "DEMO_REPO_ERROR", "demo grant failed")
		return
	}
	if h.cfg.MaxPerGcid > 0 && int64(len(used)) >= h.cfg.MaxPerGcid {
		writeError(w, http.StatusTooManyRequests, "DEMO_GRANT_LIMIT_REACHED",
			"demo mana grant limit reached for this account")
		return
	}

	// Platform-wide budget. Read through the SECURITY DEFINER helper (migration
	// 0043) because the caller's own RLS scope cannot see other GCIDs' grants.
	spent, err := h.manaStore.SumLedgerUnitsByReason(ctx, mana.ReasonDemoGrant)
	if err != nil {
		log.Printf("demoGrant: budget read for gcid=%s: %v", gcid, err)
		writeError(w, http.StatusInternalServerError, "DEMO_REPO_ERROR", "demo grant failed")
		return
	}
	if h.cfg.TotalBudgetUnits > 0 && spent+h.cfg.GrantUnits > h.cfg.TotalBudgetUnits {
		writeError(w, http.StatusTooManyRequests, "DEMO_GRANT_BUDGET_EXHAUSTED",
			"demo mana grant budget exhausted")
		return
	}

	res, err := h.manaStore.CreditWallet(ctx, mana.CreditWalletInput{
		Gcid:           gcid,
		Units:          h.cfg.GrantUnits,
		Direction:      mana.DirectionMint,
		Reason:         mana.ReasonDemoGrant,
		IdempotencyKey: key,
	})
	if err != nil {
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

// currentBalance returns the caller's current spendable balance (subsidy slices
// + personal), mirroring GET /api/v1/me/mana.
func (h *DemoManaHandler) currentBalance(ctx context.Context, gcid string) (int64, error) {
	wallet, err := h.manaStore.GetMana(ctx, gcid)
	if err != nil {
		return 0, err
	}
	bal := int64(0)
	if wallet != nil {
		bal = wallet.BalanceUnits
	}
	allocs, err := h.manaStore.ListAllocations(ctx, gcid)
	if err != nil {
		return 0, err
	}
	for _, a := range allocs {
		bal += a.RemainingUnits
	}
	return bal, nil
}

// audit records every demo grant. It logs the GCID, the fixed amount, the
// idempotency key and the resulting balance — NEVER a token, a password or any
// other credential.
func (h *DemoManaHandler) audit(gcid, idempotencyKey string, units int64, replayed bool, balance int64) {
	log.Printf("identity: demo mana grant gcid=%s units=%d idempotency_key=%s replayed=%t balance_units=%d",
		gcid, units, idempotencyKey, replayed, balance)
}

