// /api/v1/me/* economy handlers — per-user subscription, mana wallet,
// top-ups, KYC, and the Familiar plan catalog. (BE-USR-1, ADR-142.)
//
// 12 endpoints per chora-contracts/openapi/learner-economy.yaml:
//
//	GET   /api/v1/me/subscriptions
//	POST  /api/v1/me/subscriptions
//	GET   /api/v1/me/subscriptions/{id}
//	PATCH /api/v1/me/subscriptions/{id}
//	DELETE /api/v1/me/subscriptions/{id}
//	GET   /api/v1/me/mana
//	GET   /api/v1/me/mana/ledger
//	POST  /api/v1/me/mana/topup
//	GET   /api/v1/me/kyc/status
//	POST  /api/v1/me/kyc/singpass:initiate
//	POST  /api/v1/me/kyc/manual
//	GET   /api/v1/me/marketplace/familiar-plans
//
// Auth: bearer GCID (same convention as /me + /me/roles). All routes require
// the bearer token; only marketplace + healthz are unauth-friendly.
package httpadapter

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/apollo-chora/chora-identity/internal/adapter/events"
	"github.com/apollo-chora/chora-identity/internal/adapter/payments"
	"github.com/apollo-chora/chora-identity/internal/domain/identity"
	"github.com/apollo-chora/chora-identity/internal/domain/kyc"
	mana "github.com/apollo-chora/chora-identity/internal/domain/user_mana"
	usersub "github.com/apollo-chora/chora-identity/internal/domain/user_subscription"
)

// PaymentsSubscriptionCreator is the chora-payments client port that
// EconomyHandler depends on for CreateSubscription. Implemented by
// payments.Client; tests inject a fake.
//
// Per ADR-164 Wave 1 Stage E: chora-identity does not hold a Stripe SDK;
// the Stripe-correlation half (Stripe Subscription + Customer + Invoice)
// is owned by chora-payments. chora-identity calls CreateSubscription
// synchronously to mint a Checkout Session URL; the actual mana entitlement
// activation happens asynchronously via the chora.payments.user_subscription.*.v1
// Pub/Sub subscribers (see internal/adapter/events/payments_subscriber.go).
type PaymentsSubscriptionCreator interface {
	CreateSubscription(ctx context.Context, in payments.CreateSubscriptionInput) (payments.CreateSubscriptionOutput, error)
}

// EconomyHandlerOptions captures the env-driven configuration. All fields
// are sourced from env vars at the wiring layer per CLAUDE.md
// no-inline-config rule:
//
//	SINGPASS_AUTHORIZATION_URL    → e.g. "https://stg-id.singpass.gov.sg/auth"
//	                                production: "https://id.singpass.gov.sg/auth"
//	CHORA_PAYMENTS_GRPC_ADDR      → chora-payments gRPC target (mesh-internal)
//	STRIPE_SUBSCRIPTION_SUCCESS_URL → FE landing URL after Stripe Checkout success
//	STRIPE_SUBSCRIPTION_CANCEL_URL  → FE landing URL after Stripe Checkout cancel
//
// New options append-only — existing call sites use NewEconomyHandler and
// keep working.
type EconomyHandlerOptions struct {
	// SingpassAuthURL is the full /authorize endpoint URL of the configured
	// Singpass NDI issuer. Required for /api/v1/me/kyc/singpass:initiate.
	SingpassAuthURL string

	// SubscriptionSuccessURL + SubscriptionCancelURL are forwarded to
	// chora-payments as Stripe Checkout `success_url` / `cancel_url`. When
	// empty, chora-payments falls back to its own STRIPE_DEFAULT_*_URL envs.
	SubscriptionSuccessURL string
	SubscriptionCancelURL  string
}

// EconomyHandler exposes the /api/v1/me/* economy routes.
//
// Stripe SDK is no longer held by chora-identity (ADR-164 Wave 1 Stage E).
// The PaymentsClient calls chora-payments for CreateSubscription; the
// resulting Stripe Checkout URL is returned to the FE for redirect. Payment
// outcomes flow back asynchronously via the chora.payments.user_subscription.*.v1
// Pub/Sub subscriber (PaymentsSubscriber in events package).
type EconomyHandler struct {
	users     identity.UserRepository
	subs      usersub.Repository
	manaStore mana.Store
	manaQ     *mana.Quoter
	kycRepo   kyc.Repository
	payments  PaymentsSubscriptionCreator
	publisher *events.EconomyPublisher
	opts      EconomyHandlerOptions
}

// NewEconomyHandler wires the dependencies. Backwards-compatible — does not
// require new config; the Singpass URL falls back to the legacy stg URL only
// if the caller does not supply EconomyHandlerOptions.SingpassAuthURL.
func NewEconomyHandler(
	users identity.UserRepository,
	subs usersub.Repository,
	manaStore mana.Store,
	kycRepo kyc.Repository,
	payments PaymentsSubscriptionCreator,
	publisher *events.EconomyPublisher,
) *EconomyHandler {
	return NewEconomyHandlerWithOptions(users, subs, manaStore, kycRepo, payments, publisher, EconomyHandlerOptions{})
}

// NewEconomyHandlerWithOptions wires the dependencies + the env-driven config.
func NewEconomyHandlerWithOptions(
	users identity.UserRepository,
	subs usersub.Repository,
	manaStore mana.Store,
	kycRepo kyc.Repository,
	payments PaymentsSubscriptionCreator,
	publisher *events.EconomyPublisher,
	opts EconomyHandlerOptions,
) *EconomyHandler {
	return &EconomyHandler{
		users:     users,
		subs:      subs,
		manaStore: manaStore,
		manaQ:     mana.NewQuoter(manaStore),
		kycRepo:   kycRepo,
		payments:  payments,
		publisher: publisher,
		opts:      opts,
	}
}

// RegisterRoutes mounts the economy routes on a mux.
//
// Per ADR-164 Wave 1 Stage E:
//   - /v1/me/billing/stripe-customer is RETIRED — Stripe customer lifecycle
//     is now owned entirely by chora-payments at first Checkout Session.
//   - /api/v1/me/mana/topup is RETIRED — direct per-user Stripe charges are
//     replaced by the subscription mana-drip flow.
func (h *EconomyHandler) RegisterRoutes(mux *http.ServeMux) {
	mux.Handle("/api/v1/me/subscriptions", bearerAuth(h.users, http.HandlerFunc(h.subscriptionsCollection)))
	mux.Handle("/api/v1/me/subscriptions/", bearerAuth(h.users, http.HandlerFunc(h.subscriptionsItem)))
	mux.Handle("/api/v1/me/mana", bearerAuth(h.users, http.HandlerFunc(h.getMana)))
	mux.Handle("/api/v1/me/mana/ledger", bearerAuth(h.users, http.HandlerFunc(h.listManaLedger)))
	mux.Handle("/api/v1/me/mana/ledger/export", bearerAuth(h.users, http.HandlerFunc(h.exportManaLedger)))
	mux.Handle("/api/v1/me/kyc/status", bearerAuth(h.users, http.HandlerFunc(h.getKycStatus)))
	mux.Handle("/api/v1/me/kyc/singpass:initiate", bearerAuth(h.users, http.HandlerFunc(h.initiateSingpass)))
	// POST /api/v1/me/kyc/manual is owned by the dedicated KycHandler
	// (single source of truth for the fee-gated manual-doc flow per
	// ADR-164 Stage A.5). The legacy EconomyHandler.submitManualKyc — which
	// recorded the verification without collecting the $9.99 fee — has been
	// removed.
	mux.Handle("/api/v1/me/marketplace/familiar-plans", bearerAuth(h.users, http.HandlerFunc(h.listFamiliarPlans)))
}

// -----------------------------------------------------------------------------
// /api/v1/me/subscriptions
// -----------------------------------------------------------------------------

func (h *EconomyHandler) subscriptionsCollection(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.listSubscriptions(w, r)
	case http.MethodPost:
		h.purchaseSubscription(w, r)
	default:
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "GET or POST only")
	}
}

func (h *EconomyHandler) subscriptionsItem(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/me/subscriptions/")
	id = strings.TrimSuffix(id, "/")
	if id == "" {
		writeError(w, http.StatusNotFound, "ECONOMY_NOT_FOUND", "subscription_id required")
		return
	}
	switch r.Method {
	case http.MethodGet:
		h.getSubscription(w, r, id)
	case http.MethodPatch:
		h.changeSubscriptionPlan(w, r, id)
	case http.MethodDelete:
		h.cancelSubscription(w, r, id)
	default:
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED",
			"GET, PATCH, DELETE only on /me/subscriptions/{id}")
	}
}

type listSubsResponse struct {
	Items []map[string]any `json:"items"`
}

func (h *EconomyHandler) listSubscriptions(w http.ResponseWriter, r *http.Request) {
	gcid := gcidFromContext(r.Context())
	items, err := h.subs.ListByGcid(r.Context(), gcid)
	if err != nil {
		log.Printf("listSubscriptions: %v", err)
		writeError(w, http.StatusInternalServerError, "ECONOMY_REPO_ERROR", "list failed")
		return
	}
	out := make([]map[string]any, 0, len(items))
	for _, s := range items {
		out = append(out, subscriptionResponse(s))
	}
	writeJSON(w, http.StatusOK, listSubsResponse{Items: out})
}

type purchaseSubReq struct {
	PlanCode      string `json:"plan_code"`
	BillingPeriod string `json:"billing_period"`
	// PaymentMethodID is no longer accepted: the FE redirects to Stripe
	// Checkout via the returned stripe_checkout_url and the customer
	// supplies the payment method there.
	PromoCode string `json:"promo_code,omitempty"`
}

// purchaseSubscriptionResp is the FE response shape. Includes the Stripe
// Checkout URL the FE must redirect to. The subscription lives in
// pending_activation state until chora-payments fires
// chora.payments.user_subscription.payment_captured.v1.
type purchaseSubscriptionResp struct {
	SubscriptionID    string `json:"subscription_id"`
	PurchaseID        string `json:"purchase_id"`
	Status            string `json:"status"`
	StripeCheckoutURL string `json:"stripe_checkout_url"`
	StripeSessionID   string `json:"stripe_session_id"`
	PlanCode          string `json:"plan_code"`
	BillingPeriod     string `json:"billing_period"`
}

// planPricingForBillingPeriod returns the per-period charge in cents for
// the given plan + period.
func planPricingForBillingPeriod(planCode, billingPeriod string) (int64, error) {
	switch planCode {
	case "familiar_basic":
		if billingPeriod == "annually" {
			return 4999, nil
		}
		return 499, nil
	case "familiar_standard":
		if billingPeriod == "annually" {
			return 14999, nil
		}
		return 1499, nil
	case "familiar_premium":
		if billingPeriod == "annually" {
			return 39999, nil
		}
		return 3999, nil
	}
	return 0, errors.New("unknown plan_code")
}

// purchaseSubscription mints a chora-payments CreateSubscription RPC,
// persists a chora-identity-owned UserSubscription in pending_activation
// state, and returns the Stripe Checkout URL to the FE.
//
// Per ADR-164 Wave 1 Stage E: the Stripe Subscription handle + actual
// payment capture are owned by chora-payments. chora-identity activates the
// subscription via the chora.payments.user_subscription.payment_captured.v1
// subscriber (see internal/adapter/events/payments_subscriber.go).
func (h *EconomyHandler) purchaseSubscription(w http.ResponseWriter, r *http.Request) {
	gcid := gcidFromContext(r.Context())
	tenantID := tenantFromContext(r.Context())

	if h.payments == nil {
		writeError(w, http.StatusServiceUnavailable, "ECONOMY_PAYMENTS_UNCONFIGURED",
			"chora-payments client not wired (CHORA_PAYMENTS_GRPC_ADDR required)")
		return
	}

	var req purchaseSubReq
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "ECONOMY_INVALID_BODY", err.Error())
		return
	}
	tier, units, bonus, err := tierForPlan(req.PlanCode)
	if err != nil {
		writeError(w, http.StatusBadRequest, "ECONOMY_UNKNOWN_PLAN", err.Error())
		return
	}
	billing := strings.TrimSpace(req.BillingPeriod)
	if billing == "" {
		billing = "monthly"
	}
	if billing != "monthly" && billing != "annually" {
		writeError(w, http.StatusBadRequest, "ECONOMY_INVALID_BILLING_PERIOD",
			"billing_period must be 'monthly' or 'annually'")
		return
	}
	amountCents, err := planPricingForBillingPeriod(req.PlanCode, billing)
	if err != nil {
		writeError(w, http.StatusBadRequest, "ECONOMY_UNKNOWN_PLAN", err.Error())
		return
	}

	idempotencyKey := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	if idempotencyKey == "" {
		if v, err := uuid.NewV7(); err == nil {
			idempotencyKey = v.String()
		} else {
			writeError(w, http.StatusInternalServerError, "ECONOMY_IDEMPOTENCY_KEY", err.Error())
			return
		}
	}

	planSKU := "subscription." + req.PlanCode + "." + billing + ".v1"
	out, err := h.payments.CreateSubscription(r.Context(), payments.CreateSubscriptionInput{
		IdempotencyKey: idempotencyKey,
		TenantID:       tenantID,
		LearnerGcid:    gcid,
		PlanSku:        planSKU,
		BillingPeriod:  billing,
		AmountCents:    amountCents,
		Currency:       "USD",
		SuccessURL:     h.opts.SubscriptionSuccessURL,
		CancelURL:      h.opts.SubscriptionCancelURL,
	})
	if err != nil {
		if errors.Is(err, payments.ErrPaymentsUnavailable) {
			writeError(w, http.StatusBadGateway, "ECONOMY_PAYMENTS_UNAVAILABLE", err.Error())
			return
		}
		if errors.Is(err, payments.ErrInvalidInput) {
			writeError(w, http.StatusBadRequest, "ECONOMY_PAYMENTS_INVALID", err.Error())
			return
		}
		writeError(w, http.StatusBadGateway, "ECONOMY_PAYMENTS_FAILURE", err.Error())
		return
	}

	// The Stripe Subscription handle does NOT yet exist at Checkout Session
	// creation time — chora-payments fills it in on `customer.subscription.created`.
	// We persist a pending_activation UserSubscription so the subsequent
	// payment_captured.v1 subscriber can find it via the
	// (stripe_subscription_id, gcid) lookup once chora-payments populates it.
	//
	// Period boundaries are seeded as a 30-day placeholder window; the
	// payment_captured subscriber overrides them with Stripe's authoritative
	// period_start / period_end from the invoice line item.
	now := time.Now().UTC()
	periodPlaceholderEnd := now.AddDate(0, 1, 0)
	if billing == "annually" {
		periodPlaceholderEnd = now.AddDate(1, 0, 0)
	}
	s, err := usersub.NewSubscription(usersub.NewParams{
		Gcid:                 gcid,
		TenantID:             tenantID,
		PlanCode:             req.PlanCode,
		Tier:                 tier,
		BillingPeriod:        usersub.BillingPeriod(billing),
		ManaMonthlyUnits:     units,
		OnboardingBonusUnits: bonus,
		// StripeSubscriptionID is intentionally empty here — populated by
		// chora-payments once Stripe creates the Subscription object server-side.
		// Until then the subscription is resolved by purchase_id.
		StripeSubscriptionID: "",
		PeriodStart:          now,
		PeriodEnd:            periodPlaceholderEnd,
	})
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, "ECONOMY_INVALID_SUBSCRIPTION", err.Error())
		return
	}
	// Subscription stays in pending_activation until chora-payments fires
	// payment_captured.v1 (see PaymentsSubscriber.HandlePaymentCaptured).

	if err := h.subs.Save(r.Context(), s); err != nil {
		writeError(w, http.StatusInternalServerError, "ECONOMY_REPO_ERROR", err.Error())
		return
	}

	if h.publisher != nil {
		env := events.NewEnvelope(tenantID, gcid, r.Header.Get("traceparent"), r.Header.Get("tracestate"))
		_ = h.publisher.PublishSubscriptionCreated(env, s)
	}
	log.Printf("identity: created pending UserSubscription %s for gcid=%s plan=%s (payments purchase_id=%s)",
		s.SubscriptionID, gcid, req.PlanCode, out.PurchaseID)

	writeJSON(w, http.StatusCreated, purchaseSubscriptionResp{
		SubscriptionID:    s.SubscriptionID,
		PurchaseID:        out.PurchaseID,
		Status:            "pending_activation",
		StripeCheckoutURL: out.StripeCheckoutURL,
		StripeSessionID:   out.StripeSessionID,
		PlanCode:          req.PlanCode,
		BillingPeriod:     billing,
	})
}

func (h *EconomyHandler) getSubscription(w http.ResponseWriter, r *http.Request, id string) {
	s, err := h.subs.GetByID(r.Context(), id)
	if err != nil {
		if errors.Is(err, usersub.ErrNotFound) {
			writeError(w, http.StatusNotFound, "ECONOMY_NOT_FOUND", "subscription not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "ECONOMY_REPO_ERROR", err.Error())
		return
	}
	gcid := gcidFromContext(r.Context())
	if s.Gcid != gcid {
		writeError(w, http.StatusNotFound, "ECONOMY_NOT_FOUND", "subscription not found")
		return
	}
	writeJSON(w, http.StatusOK, subscriptionResponse(s))
}

type changePlanReq struct {
	TargetPlanCode      string `json:"target_plan_code"`
	TargetBillingPeriod string `json:"target_billing_period,omitempty"`
	ProrationMode       string `json:"proration_mode"`
	EffectiveAt         string `json:"effective_at,omitempty"`
}

func (h *EconomyHandler) changeSubscriptionPlan(w http.ResponseWriter, r *http.Request, id string) {
	var req changePlanReq
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "ECONOMY_INVALID_BODY", err.Error())
		return
	}
	s, err := h.subs.GetByID(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, "ECONOMY_NOT_FOUND", "subscription not found")
		return
	}
	gcid := gcidFromContext(r.Context())
	if s.Gcid != gcid {
		writeError(w, http.StatusNotFound, "ECONOMY_NOT_FOUND", "subscription not found")
		return
	}
	tier, units, _, err := tierForPlan(req.TargetPlanCode)
	if err != nil {
		writeError(w, http.StatusBadRequest, "ECONOMY_UNKNOWN_PLAN", err.Error())
		return
	}
	billing := usersub.BillingPeriod(req.TargetBillingPeriod)
	if billing == "" {
		billing = s.BillingPeriod
	}
	effectiveAt := time.Now().UTC()
	if req.EffectiveAt != "" {
		if t, err := time.Parse(time.RFC3339, req.EffectiveAt); err == nil {
			effectiveAt = t
		}
	}
	from := s.PlanCode
	if err := s.ChangePlan(usersub.ChangePlanParams{
		ToPlanCode: req.TargetPlanCode, ToTier: tier, ToBillingPeriod: billing,
		EffectiveAt: effectiveAt, RequestedByGcid: gcid, ManaMonthlyUnits: units,
	}); err != nil {
		writeError(w, http.StatusUnprocessableEntity, "ECONOMY_INVALID_TRANSITION", err.Error())
		return
	}
	if err := h.subs.Save(r.Context(), s); err != nil {
		writeError(w, http.StatusInternalServerError, "ECONOMY_REPO_ERROR", err.Error())
		return
	}
	resp := map[string]any{
		"subscription_id":     s.SubscriptionID,
		"from_plan_code":      from,
		"to_plan_code":        s.PlanCode,
		"billing_delta_cents": 0,
		"effective_at":        effectiveAt.Format(time.RFC3339),
	}
	writeJSON(w, http.StatusOK, resp)
}

type cancelSubReq struct {
	Reason      string `json:"reason"`
	EffectiveAt string `json:"effective_at,omitempty"`
}

// cancelSubscription transitions the chora-identity-owned UserSubscription
// to cancelled. The Stripe-side cancellation is owned by chora-payments —
// the FE must invoke chora-payments' admin RefundPurchase RPC (or a future
// CancelSubscription RPC) separately when an actual Stripe-side cancel is
// required. For ADR-164 Stage E this handler only flips the local FSM.
func (h *EconomyHandler) cancelSubscription(w http.ResponseWriter, r *http.Request, id string) {
	var req cancelSubReq
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "ECONOMY_INVALID_BODY", err.Error())
		return
	}
	s, err := h.subs.GetByID(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, "ECONOMY_NOT_FOUND", "subscription not found")
		return
	}
	gcid := gcidFromContext(r.Context())
	if s.Gcid != gcid {
		writeError(w, http.StatusNotFound, "ECONOMY_NOT_FOUND", "subscription not found")
		return
	}
	effectiveAt := s.CurrentPeriodEnd
	if req.EffectiveAt != "" {
		if t, err := time.Parse(time.RFC3339, req.EffectiveAt); err == nil {
			effectiveAt = t
		}
	}
	if err := s.Cancel(req.Reason, gcid, effectiveAt); err != nil {
		writeError(w, http.StatusConflict, "ECONOMY_INVALID_TRANSITION", err.Error())
		return
	}
	if err := h.subs.Save(r.Context(), s); err != nil {
		writeError(w, http.StatusInternalServerError, "ECONOMY_REPO_ERROR", err.Error())
		return
	}
	if h.publisher != nil {
		env := events.NewEnvelope(tenantFromContext(r.Context()), gcid, r.Header.Get("traceparent"), r.Header.Get("tracestate"))
		_ = h.publisher.PublishSubscriptionCancelled(env, s)
	}
	writeJSON(w, http.StatusOK, subscriptionResponse(s))
}

// -----------------------------------------------------------------------------
// /api/v1/me/mana[/ledger][/topup]
// -----------------------------------------------------------------------------

func (h *EconomyHandler) getMana(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "GET only")
		return
	}
	gcid := gcidFromContext(r.Context())
	bal, slices, err := h.manaQ.Breakdown(r.Context(), gcid)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "ECONOMY_REPO_ERROR", err.Error())
		return
	}
	wallet, _ := h.manaStore.GetMana(r.Context(), gcid)
	if wallet == nil {
		wallet = mana.NewUserMana(gcid)
	}
	out := map[string]any{
		"gcid":            gcid,
		"balance_units":   bal,
		"lifetime_earned": wallet.LifetimeEarned,
		"lifetime_spent":  wallet.LifetimeSpent,
	}
	if wallet.LastCreditedAt != nil {
		out["last_credited_at"] = wallet.LastCreditedAt.Format(time.RFC3339)
	}
	breakdown := make([]map[string]any, 0, len(slices))
	for _, s := range slices {
		row := map[string]any{
			"units":  s.Units,
			"source": string(s.Source),
		}
		if s.TenantID != "" {
			row["tenant_id"] = s.TenantID
		}
		if s.ExpiresAt != nil {
			row["expires_at"] = s.ExpiresAt.Format(time.RFC3339)
		}
		breakdown = append(breakdown, row)
	}
	out["subsidy_breakdown"] = breakdown
	writeJSON(w, http.StatusOK, out)
}

func (h *EconomyHandler) listManaLedger(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "GET only")
		return
	}
	gcid := gcidFromContext(r.Context())
	filter, pageSize, ok := parseLedgerFilter(r, gcid)
	if !ok {
		writeError(w, http.StatusBadRequest, "ECONOMY_BAD_CURSOR", "invalid cursor")
		return
	}
	// Fetch one extra row to detect whether another page exists (CHO-1883).
	filter.PageSize = pageSize + 1
	entries, err := h.manaStore.ListLedger(r.Context(), filter)
	if err != nil {
		if errors.Is(err, mana.ErrInvalidFilter) {
			writeError(w, http.StatusBadRequest, "ECONOMY_BAD_CURSOR", "invalid cursor")
			return
		}
		writeError(w, http.StatusInternalServerError, "ECONOMY_REPO_ERROR", err.Error())
		return
	}
	hasMore := len(entries) > pageSize
	var nextCursor string
	if hasMore {
		entries = entries[:pageSize]
		nextCursor = mana.EncodeLedgerCursor(entries[len(entries)-1])
	}
	items := make([]map[string]any, 0, len(entries))
	for _, e := range entries {
		items = append(items, ledgerEntryResponse(e))
	}
	resp := map[string]any{"items": items, "has_more": hasMore}
	if nextCursor != "" {
		resp["next_cursor"] = nextCursor
	}
	writeJSON(w, http.StatusOK, resp)
}

// exportManaLedger streams the caller's FULL filtered ledger as a CSV or NDJSON
// download (CHO-1883). RLS-scoped to the JWT gcid; honours the same
// direction/from/to/reason filters as the list view but ignores pagination —
// a learner's own history is bounded. Mirrors the H+ payments export so the FE
// download UX is consistent.
func (h *EconomyHandler) exportManaLedger(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "GET only")
		return
	}
	gcid := gcidFromContext(r.Context())
	filter, _, ok := parseLedgerFilter(r, gcid)
	if !ok {
		writeError(w, http.StatusBadRequest, "ECONOMY_BAD_CURSOR", "invalid cursor")
		return
	}
	filter.Cursor = ""  // export streams the full filtered set, not a page
	filter.PageSize = 0 // no LIMIT
	entries, err := h.manaStore.ListLedger(r.Context(), filter)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "ECONOMY_REPO_ERROR", err.Error())
		return
	}
	stamp := time.Now().UTC().Format("20060102-150405")
	if r.URL.Query().Get("format") == "json" {
		w.Header().Set("Content-Type", "application/x-ndjson; charset=utf-8")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="mana-ledger-%s.ndjson"`, stamp))
		w.WriteHeader(http.StatusOK)
		enc := json.NewEncoder(w)
		for _, e := range entries {
			_ = enc.Encode(ledgerEntryResponse(e))
		}
		return
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="mana-ledger-%s.csv"`, stamp))
	w.WriteHeader(http.StatusOK)
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"recorded_at", "direction", "units", "reason", "source_action_id", "balance_after_units"})
	for _, e := range entries {
		_ = cw.Write([]string{
			e.RecordedAt.UTC().Format(time.RFC3339),
			string(e.Direction),
			strconv.FormatInt(e.Units, 10),
			string(e.Reason),
			e.SourceActionID,
			strconv.FormatInt(e.BalanceAfterUnits, 10),
		})
	}
	cw.Flush()
}

// parseLedgerFilter builds the ledger query from the request, returning the
// requested page size (default 25, capped 100) separately from the filter so
// the handler can over-fetch by one for has_more detection. ok=false only when
// the cursor is structurally invalid (→ 400). Accepts ?cursor= or the H+
// ?page_token= alias (CHO-1883).
func parseLedgerFilter(r *http.Request, gcid string) (mana.LedgerFilter, int, bool) {
	q := r.URL.Query()
	filter := mana.LedgerFilter{Gcid: gcid}
	if v := q.Get("from"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			filter.From = &t
		}
	}
	if v := q.Get("to"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			filter.To = &t
		}
	}
	if v := q.Get("direction"); v != "" {
		d := mana.Direction(v)
		filter.Direction = &d
	}
	if v := q.Get("reason"); v != "" {
		rs := mana.Reason(v)
		filter.Reason = &rs
	}
	cursor := q.Get("cursor")
	if cursor == "" {
		cursor = q.Get("page_token")
	}
	filter.Cursor = cursor
	if _, _, err := mana.DecodeLedgerCursor(cursor); err != nil {
		return filter, 0, false
	}
	pageSize := 25
	if v := q.Get("page_size"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			pageSize = n
		}
	}
	if pageSize > 100 {
		pageSize = 100
	}
	return filter, pageSize, true
}

// /api/v1/me/mana/topup is RETIRED per ADR-164 Wave 1 Stage E. The
// per-user direct Stripe charge flow was a chora-identity-owned inline
// Stripe path. With Stripe SDK now consolidated into chora-payments and
// the supported user-mana flows being subscription-drip + tenant-subsidy
// (chora.tenancy.tenant_mana_allocation.granted.v1 → TenantManaSubscriber
// already wired), there is no chora-payments aggregate for per-user
// mana top-up. The route is intentionally NOT mounted in RegisterRoutes.

// -----------------------------------------------------------------------------
// /api/v1/me/kyc/*
// -----------------------------------------------------------------------------

func (h *EconomyHandler) getKycStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "GET only")
		return
	}
	gcid := gcidFromContext(r.Context())
	v, err := h.kycRepo.GetLatestByGcid(r.Context(), gcid)
	if err != nil {
		if errors.Is(err, kyc.ErrNotFound) {
			writeError(w, http.StatusNotFound, "KYC_NOT_FOUND", "no kyc verification on file")
			return
		}
		writeError(w, http.StatusInternalServerError, "KYC_REPO_ERROR", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, kycResponse(v))
}

type initiateSingpassReq struct {
	ReturnURL                string `json:"return_url,omitempty"`
	RequestSkillsfutureScope bool   `json:"request_skillsfuture_scope,omitempty"`
}

func (h *EconomyHandler) initiateSingpass(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "POST only")
		return
	}
	// Per CLAUDE.md no-inline-config rule (feedback_no_inline_config): the
	// Singpass authorize URL must come from env (SINGPASS_AUTHORIZATION_URL).
	// Audit-identity-fillgaps.md §3.7 + §3.8 explicitly flagged the previous
	// inline value here.
	if strings.TrimSpace(h.opts.SingpassAuthURL) == "" {
		writeError(w, http.StatusInternalServerError, "IDENTITY_KYC_MISCONFIGURED",
			"SINGPASS_AUTHORIZATION_URL env var must be set")
		return
	}

	var req initiateSingpassReq
	_ = decodeJSON(r, &req) // optional body
	gcid := gcidFromContext(r.Context())

	v, err := kyc.NewVerification(kyc.NewParams{
		Gcid: gcid, Method: kyc.MethodSingpass, Provider: "ndi",
	})
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, "KYC_INVALID", err.Error())
		return
	}
	if err := h.kycRepo.Save(r.Context(), v); err != nil {
		writeError(w, http.StatusInternalServerError, "KYC_REPO_ERROR", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"redirect_url":    h.opts.SingpassAuthURL + "?state=" + v.VerificationID,
		"state":           v.VerificationID,
		"verification_id": v.VerificationID,
	})
}

// /v1/me/billing/stripe-customer is RETIRED per ADR-164 Wave 1 Stage E.
// The Stripe Customer lifecycle is owned entirely by chora-payments —
// the Customer is provisioned lazily during the first Checkout Session
// (chora-payments handles Customer.search-or-create on the Stripe API
// keyed by metadata={gcid}).

// NOTE: the manual-doc KYC path (POST /api/v1/me/kyc/manual) is owned by the
// dedicated KycHandler (kyc_handler.go) per ADR-164 Stage A.5. The legacy
// EconomyHandler.submitManualKyc was removed: it recorded the verification
// without collecting the $9.99 fee (a documented Stage-E debt). KycHandler
// now charges via chora-payments Stripe Checkout and gates review-queue
// entry on payment capture.

// -----------------------------------------------------------------------------
// /api/v1/me/marketplace/familiar-plans
// -----------------------------------------------------------------------------

func (h *EconomyHandler) listFamiliarPlans(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "GET only")
		return
	}
	plans := []map[string]any{
		{
			"plan_code":              "familiar_basic",
			"tier":                   string(usersub.TierBasic),
			"display_name":           "Familiar Basic",
			"monthly_price_cents":    499,
			"annual_price_cents":     4999,
			"currency":               "USD",
			"mana_monthly_units":     500,
			"onboarding_bonus_units": 500,
		},
		{
			"plan_code":              "familiar_standard",
			"tier":                   string(usersub.TierStandard),
			"display_name":           "Familiar Standard",
			"monthly_price_cents":    1499,
			"annual_price_cents":     14999,
			"currency":               "USD",
			"mana_monthly_units":     2500,
			"onboarding_bonus_units": 2500,
		},
		{
			"plan_code":              "familiar_premium",
			"tier":                   string(usersub.TierPremium),
			"display_name":           "Familiar Premium",
			"monthly_price_cents":    3999,
			"annual_price_cents":     39999,
			"currency":               "USD",
			"mana_monthly_units":     10000,
			"onboarding_bonus_units": 10000,
			"cosmetic_skin_codes":    []string{"premium_aura", "premium_halo"},
		},
	}
	pricing := []map[string]any{
		{"method": "singpass", "fee_cents": 0, "currency": "USD", "eligibility_note": "SG residents"},
		{"method": "skillsfuture", "fee_cents": 0, "currency": "USD", "eligibility_note": "SG residents"},
		{"method": "manual_doc", "fee_cents": 999, "currency": "USD", "eligibility_note": "non-SG / fallback"},
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"plans":       plans,
		"kyc_pricing": pricing,
	})
}

// -----------------------------------------------------------------------------
// Catalog + response helpers
// -----------------------------------------------------------------------------

func tierForPlan(planCode string) (usersub.Tier, int64, int64, error) {
	switch planCode {
	case "familiar_basic":
		return usersub.TierBasic, 500, 500, nil
	case "familiar_standard":
		return usersub.TierStandard, 2500, 2500, nil
	case "familiar_premium":
		return usersub.TierPremium, 10000, 10000, nil
	}
	return "", 0, 0, errors.New("unknown plan_code")
}

func subscriptionResponse(s *usersub.Subscription) map[string]any {
	out := map[string]any{
		"subscription_id":        s.SubscriptionID,
		"gcid":                   s.Gcid,
		"tenant_id":              s.TenantID,
		"plan_code":              s.PlanCode,
		"tier":                   string(s.Tier),
		"status":                 string(s.Status),
		"billing_period":         string(s.BillingPeriod),
		"current_period_start":   s.CurrentPeriodStart.Format(time.RFC3339),
		"current_period_end":     s.CurrentPeriodEnd.Format(time.RFC3339),
		"stripe_subscription_id": s.StripeSubscriptionID,
		"created_at":             s.CreatedAt.Format(time.RFC3339),
	}
	if s.CancelledAt != nil {
		out["cancelled_at"] = s.CancelledAt.Format(time.RFC3339)
	}
	return out
}

func ledgerEntryResponse(e *mana.LedgerEntry) map[string]any {
	out := map[string]any{
		"entry_id":            e.EntryID,
		"gcid":                e.Gcid,
		"direction":           string(e.Direction),
		"units":               e.Units,
		"reason":              string(e.Reason),
		"balance_after_units": e.BalanceAfterUnits,
		"recorded_at":         e.RecordedAt.Format(time.RFC3339),
	}
	if e.SourceSubscriptionID != "" {
		out["source_subscription_id"] = e.SourceSubscriptionID
	}
	if e.SourceTopupID != "" {
		out["source_topup_id"] = e.SourceTopupID
	}
	if e.SourceAllocationID != "" {
		out["source_allocation_id"] = e.SourceAllocationID
	}
	if e.SourceActionID != "" {
		out["source_action_id"] = e.SourceActionID
	}
	return out
}

func kycResponse(v *kyc.Verification) map[string]any {
	out := map[string]any{
		"verification_id": v.VerificationID,
		"gcid":            v.Gcid,
		"method":          string(v.Method),
		"status":          string(v.Status),
		"provider":        v.Provider,
	}
	if v.DocumentURI != "" {
		out["document_uri"] = v.DocumentURI
	}
	if v.VerifiedAt != nil {
		out["verified_at"] = v.VerifiedAt.Format(time.RFC3339)
	}
	if v.RejectionCode != "" {
		out["rejected_reason"] = v.RejectionCode
	}
	if v.FeeChargedCents > 0 {
		out["fee_charged_cents"] = v.FeeChargedCents
		if v.Currency != "" {
			out["currency"] = v.Currency
		}
	}
	if len(v.AuditLog) > 0 {
		audit := make([]map[string]any, 0, len(v.AuditLog))
		for _, a := range v.AuditLog {
			row := map[string]any{
				"event":       a.Event,
				"occurred_at": a.OccurredAt.Format(time.RFC3339),
			}
			if a.ActorGcid != "" {
				row["actor_gcid"] = a.ActorGcid
			}
			if a.Notes != "" {
				row["notes"] = a.Notes
			}
			audit = append(audit, row)
		}
		out["audit_log"] = audit
	}
	return out
}

// keep json import used (some compilers warn on unused).
var _ = json.RawMessage{}
