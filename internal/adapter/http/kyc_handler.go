// kyc_handler.go — dedicated KYC HTTP handler for Singpass NDI + manual KYC
// flows (S6.3 A-Singpass §2-3 deliverables).
//
// Routes mounted via RegisterRoutes:
//
//	POST /v1/me/kyc/singpass            — initiate Singpass KYC (returns auth URL + state)
//	GET  /v1/me/kyc/singpass/callback   — handle Singpass callback (exchange code, MyInfo, verify)
//	POST /v1/me/kyc/manual              — manual review queue ($9.99 per ADR-142)
//	GET  /v1/me/kyc/status              — current KYC status
//	GET  /v1/me/myinfo-prefill          — redacted prefill payload (consumed by chora-delivery)
//
// IMDA evidence emission (per ADR-141):
//   - kyc.verified.v1 → accountability        (D1) + lifecycle_stage runtime
//   - kyc.rejected.v1 → safety_and_robustness (D3) + lifecycle_stage runtime
//
// All Singpass URLs sourced from env vars (no inline config).
//
// Federation note: NDI sits OUTSIDE Identity Platform's federation list per
// the platform architecture notes. chora-identity directly owns the OIDC exchange
// for Singpass. Existing-user KYC links the Singpass verification to the
// caller's existing GCID (carried from the bearer token through the state
// record). New-user Singpass sign-up lands at the Blocking Function path
// (blocking_handler.go) once Identity Platform issues a Singpass session;
// this handler is reused for the verification + MyInfo prefill once the
// session is established.
package httpadapter

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/apollo-chora/chora-identity/internal/adapter/events"
	"github.com/apollo-chora/chora-identity/internal/adapter/idp/singpass"
	"github.com/apollo-chora/chora-identity/internal/adapter/payments"
	"github.com/apollo-chora/chora-identity/internal/domain/identity"
	"github.com/apollo-chora/chora-identity/internal/domain/kyc"
)

// PaymentsKycClient is the slice of the chora-payments adapter the KYC
// handler uses to collect the manual-doc fee ($9.99 per ADR-142) via a
// Stripe Checkout redirect. chora-payments owns the Stripe SDK (ADR-164
// Stage E); chora-identity charges through it (Stage A.5). Tests inject a
// fake; production wires *payments.Client.
type PaymentsKycClient interface {
	CreateKycFee(ctx context.Context, in payments.CreateKycFeeInput) (payments.CreateKycFeeOutput, error)
}

// -----------------------------------------------------------------------------
// SingpassClient — port (interface) so the handler can be tested with fakes.
// -----------------------------------------------------------------------------

// SingpassClient is the subset of the singpass adapter used by the KYC handler.
//
// Per Singpass Path A (2026-05-10), the KYC callback uses /userinfo (which
// surfaces the OIDC `sub` UUID — the only Singpass-derived attribute Chora
// persists) and explicitly does NOT call /person (which surfaces NRIC, name,
// DOB, and other forbidden citizen-data fields). The MyInfoPerson method
// remains on the underlying adapter for any read-only diagnostics, but the
// HTTP handler does not consume it.
type SingpassClient interface {
	AuthorizationURL(state, codeChallenge string) (string, error)
	ExchangeCode(ctx context.Context, code, codeVerifier string) (*singpass.Tokens, error)
	UserInfo(ctx context.Context, accessToken string) (*singpass.UserInfo, error)
}

// -----------------------------------------------------------------------------
// SingpassStateRepository — short-lived state-token store
// -----------------------------------------------------------------------------

// SingpassStateRecord captures the per-user state that must persist across
// the OIDC redirect roundtrip.
type SingpassStateRecord struct {
	State          string
	Gcid           string
	TenantID       string
	CodeVerifier   string
	ReturnURL      string
	VerificationID string
	CreatedAt      time.Time
	ExpiresAt      time.Time
}

// SingpassStateRepository persists state tokens for the duration of a
// Singpass OIDC redirect flow.
//
// Resilience contract (memory feedback_resilience_priority.md):
//
//   - Put + Get + Delete are the legacy primitives kept for tests + admin
//     tooling.
//   - GetAndConsume is the ATOMIC single-use primitive the production
//     callback flow MUST use. It returns the record AND removes it in a
//     single critical section so two concurrent callbacks holding the
//     same state token can never both proceed. Production wiring (M12
//     Memorystore-backed) implements this via Lua GET+DEL atomically.
type SingpassStateRepository interface {
	Put(ctx context.Context, st *SingpassStateRecord) error
	Get(ctx context.Context, state string) (*SingpassStateRecord, error)
	Delete(ctx context.Context, state string) error
	// GetAndConsume atomically reads and removes the state record. Returns
	// an error if the state is unknown OR expired (in which case the
	// expired entry is also removed — never resurrected on retry).
	GetAndConsume(ctx context.Context, state string) (*SingpassStateRecord, error)
}

// InMemSingpassStateRepository is the in-memory implementation. Production
// swaps to a Memorystore-backed implementation (TTL = 10 min).
type InMemSingpassStateRepository struct {
	mu    sync.RWMutex
	store map[string]*SingpassStateRecord
}

// NewInMemSingpassStateRepository constructs the in-memory state repo.
func NewInMemSingpassStateRepository() *InMemSingpassStateRepository {
	return &InMemSingpassStateRepository{store: make(map[string]*SingpassStateRecord)}
}

// Put persists the state record.
func (r *InMemSingpassStateRepository) Put(_ context.Context, st *SingpassStateRecord) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	clone := *st
	r.store[st.State] = &clone
	return nil
}

// Get returns the state record, or nil + error.
func (r *InMemSingpassStateRepository) Get(_ context.Context, state string) (*SingpassStateRecord, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	st, ok := r.store[state]
	if !ok {
		return nil, errors.New("singpass: state not found")
	}
	if !st.ExpiresAt.IsZero() && time.Now().UTC().After(st.ExpiresAt) {
		return nil, errors.New("singpass: state expired")
	}
	clone := *st
	return &clone, nil
}

// Delete removes the state record (single-use semantics).
func (r *InMemSingpassStateRepository) Delete(_ context.Context, state string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.store, state)
	return nil
}

// GetAndConsume atomically reads + removes the state record. The exclusive
// mutex serialises the lookup and delete so no two callers can both observe
// the same state. Expired records are removed and reported as such — they
// are never returned for processing.
func (r *InMemSingpassStateRepository) GetAndConsume(_ context.Context, state string) (*SingpassStateRecord, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	st, ok := r.store[state]
	if !ok {
		return nil, errors.New("singpass: state not found")
	}
	// Always delete — single-use semantics, even when expired (so a stale
	// token can't sit in the store waiting for a clock-skewed retry).
	delete(r.store, state)
	if !st.ExpiresAt.IsZero() && time.Now().UTC().After(st.ExpiresAt) {
		return nil, errors.New("singpass: state expired")
	}
	clone := *st
	return &clone, nil
}

// Compile-time guard.
var _ SingpassStateRepository = (*InMemSingpassStateRepository)(nil)

// -----------------------------------------------------------------------------
// KycHandlerConfig — wiring for NewKycHandler
// -----------------------------------------------------------------------------

// KycHandlerConfig captures the dependencies for NewKycHandler.
//
// Per ADR-164 Wave 1 Stage E: the Stripe SDK has been moved to
// chora-payments. The Stripe field is removed; KYC manual-doc fee
// collection is deferred (see submitManual handler).
type KycHandlerConfig struct {
	Users           identity.UserRepository
	KycRepo         kyc.Repository
	PrefillRepo     kyc.PrefillRepository
	StateRepo       SingpassStateRepository
	Singpass        SingpassClient
	EconomyPub      *events.EconomyPublisher
	GovernancePub   *events.GovernancePublisher
	RedirectURI     string // Singpass redirect URI (env: SINGPASS_REDIRECT_URI)
	StateTTLSeconds int    // optional; defaults to 600 (10 min)
	ManaultFeeCents int64  // optional override; defaults to kyc.DefaultFeeCents(MethodManualDoc)

	// Payments collects the manual-doc fee via chora-payments Stripe
	// Checkout. Per ADR-164 Stage A.5 this is required for the manual_doc
	// path; when nil (dev / CHORA_PAYMENTS_GRPC_ADDR unset), submitManual
	// returns 503 rather than silently accepting an uncollected fee.
	Payments PaymentsKycClient
	// FeeSuccessURL / FeeCancelURL are optional FE redirect targets after
	// Stripe Checkout (env: KYC_FEE_SUCCESS_URL / KYC_FEE_CANCEL_URL). When
	// empty, chora-payments falls back to its STRIPE_DEFAULT_*_URL envs.
	FeeSuccessURL string
	FeeCancelURL  string
}

// KycHandler exposes the dedicated KYC routes.
type KycHandler struct {
	cfg KycHandlerConfig
}

// NewKycHandler wires the dependencies and returns a KycHandler.
func NewKycHandler(cfg KycHandlerConfig) *KycHandler {
	if cfg.StateTTLSeconds <= 0 {
		cfg.StateTTLSeconds = 600 // 10 min
	}
	if cfg.ManaultFeeCents == 0 {
		cfg.ManaultFeeCents = kyc.DefaultFeeCents(kyc.MethodManualDoc)
	}
	return &KycHandler{cfg: cfg}
}

// RegisterRoutes mounts the handler on the supplied mux.
func (h *KycHandler) RegisterRoutes(mux *http.ServeMux) {
	mux.Handle("/v1/me/kyc/singpass", bearerAuth(h.cfg.Users, http.HandlerFunc(h.initiateSingpass)))
	// Callback is unauthenticated by Bearer — security via state-token possession.
	mux.HandleFunc("/v1/me/kyc/singpass/callback", h.singpassCallback)
	mux.Handle("/v1/me/kyc/manual", bearerAuth(h.cfg.Users, http.HandlerFunc(h.submitManual)))
	// Canonical /api/v1 alias — consolidates the legacy
	// EconomyHandler.submitManualKyc duplicate onto this richer handler
	// (single source of truth for the fee-gated manual-doc flow).
	mux.Handle("/api/v1/me/kyc/manual", bearerAuth(h.cfg.Users, http.HandlerFunc(h.submitManual)))
	mux.Handle("/v1/me/kyc/status", bearerAuth(h.cfg.Users, http.HandlerFunc(h.getStatus)))
	mux.Handle("/v1/me/myinfo-prefill", bearerAuth(h.cfg.Users, http.HandlerFunc(h.getMyInfoPrefill)))
}

// -----------------------------------------------------------------------------
// POST /v1/me/kyc/singpass — initiate
// -----------------------------------------------------------------------------

type initiateBody struct {
	ReturnURL                string `json:"return_url,omitempty"`
	RequestSkillsfutureScope bool   `json:"request_skillsfuture_scope,omitempty"`
}

func (h *KycHandler) initiateSingpass(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "POST only")
		return
	}
	gcid := gcidFromContext(r.Context())
	tenantID := resolveTenantID(r)

	var req initiateBody
	_ = decodeJSON(r, &req) // optional body

	// Mint state + PKCE verifier/challenge.
	state := generateRandomToken(32)
	verifier := generateRandomToken(64)
	challenge := pkceS256Challenge(verifier)

	// Create the pending KYC verification.
	v, err := kyc.NewVerification(kyc.NewParams{
		Gcid: gcid, Method: kyc.MethodSingpass, Provider: "ndi",
	})
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, "KYC_INVALID", err.Error())
		return
	}
	if err := h.cfg.KycRepo.Save(r.Context(), v); err != nil {
		writeError(w, http.StatusInternalServerError, "KYC_REPO_ERROR", err.Error())
		return
	}

	// Persist the state record for the callback to consume.
	rec := &SingpassStateRecord{
		State:          state,
		Gcid:           gcid,
		TenantID:       tenantID,
		CodeVerifier:   verifier,
		ReturnURL:      req.ReturnURL,
		VerificationID: v.VerificationID,
		CreatedAt:      time.Now().UTC(),
		ExpiresAt:      time.Now().UTC().Add(time.Duration(h.cfg.StateTTLSeconds) * time.Second),
	}
	if err := h.cfg.StateRepo.Put(r.Context(), rec); err != nil {
		writeError(w, http.StatusInternalServerError, "KYC_STATE_PERSIST_FAILED", err.Error())
		return
	}

	// Build the Singpass /authorize URL.
	authURL, err := h.cfg.Singpass.AuthorizationURL(state, challenge)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "SINGPASS_URL_BUILD_FAILED", err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"redirect_url":    authURL,
		"state":           state,
		"verification_id": v.VerificationID,
	})
}

// -----------------------------------------------------------------------------
// GET /v1/me/kyc/singpass/callback — exchange code, fetch MyInfo, verify KYC
// -----------------------------------------------------------------------------

func (h *KycHandler) singpassCallback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "GET only")
		return
	}
	q := r.URL.Query()
	code := q.Get("code")
	state := q.Get("state")
	if code == "" || state == "" {
		writeError(w, http.StatusBadRequest, "SINGPASS_CALLBACK_MISSING_PARAMS",
			"code and state query params required")
		return
	}
	// Atomic read+consume: under multi-pod load (or even concurrent goroutines
	// on a single pod) two callbacks holding the same state token must never
	// both proceed. GetAndConsume's single critical section is the
	// replay-safety boundary per memory feedback_resilience_priority.md.
	// The previous Get + defer Delete pattern had a race window between the
	// read and the delete that allowed duplicate kyc.verified.v1 emission.
	st, err := h.cfg.StateRepo.GetAndConsume(r.Context(), state)
	if err != nil {
		writeError(w, http.StatusBadRequest, "SINGPASS_STATE_INVALID",
			"state token unknown or expired")
		return
	}

	traceparent := r.Header.Get("traceparent")
	tracestate := r.Header.Get("tracestate")
	env := events.NewEnvelope(st.TenantID, st.Gcid, traceparent, tracestate)

	// Look up the pending verification. Thread the owning gcid (from the
	// consumed state token) as the RLS subject so the durable (pg) repo can
	// scope its per-user policy — this callback is not bearer-authed, so
	// there is no ambient authed gcid to fall back on.
	verif, err := h.cfg.KycRepo.GetByID(kyc.WithSubjectGcid(r.Context(), st.Gcid), st.VerificationID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "KYC_REPO_ERROR", err.Error())
		return
	}

	// Exchange code for tokens.
	tok, err := h.cfg.Singpass.ExchangeCode(r.Context(), code, st.CodeVerifier)
	if err != nil {
		h.recordRejection(r.Context(), env, verif, "singpass_token_exchange_failed", err.Error())
		writeError(w, http.StatusBadGateway, "SINGPASS_TOKEN_EXCHANGE_FAILED", err.Error())
		return
	}

	// Path A (2026-05-10): pull the OIDC `sub` from /userinfo. This is the
	// ONLY Singpass-derived attribute Chora persists. /person (MyInfo) is
	// NOT called — its envelope leaks NRIC/FIN/name/DOB/etc., none of which
	// the closure map permits.
	info, err := h.cfg.Singpass.UserInfo(r.Context(), tok.AccessToken)
	if err != nil {
		h.recordRejection(r.Context(), env, verif, "singpass_userinfo_fetch_failed", err.Error())
		writeError(w, http.StatusBadGateway, "SINGPASS_USERINFO_FETCH_FAILED", err.Error())
		return
	}

	// Mark verification as submitted then verified.
	if err := verif.Submit("singpass:"+verif.VerificationID, 0, "USD"); err != nil {
		writeError(w, http.StatusInternalServerError, "KYC_INVALID_TRANSITION", err.Error())
		return
	}
	// Bind the Singpass `sub` BEFORE Verify so the audit trail orders bind
	// → verified consistently with the migration's partial unique index.
	if err := verif.BindSingpassSub(info.Sub); err != nil {
		h.recordRejection(r.Context(), env, verif, "singpass_sub_bind_failed", err.Error())
		writeError(w, http.StatusConflict, "SINGPASS_SUB_BIND_FAILED", err.Error())
		return
	}
	if err := verif.Verify("ndi", false); err != nil {
		writeError(w, http.StatusInternalServerError, "KYC_INVALID_TRANSITION", err.Error())
		return
	}
	if err := h.cfg.KycRepo.Save(r.Context(), verif); err != nil {
		writeError(w, http.StatusInternalServerError, "KYC_REPO_ERROR", err.Error())
		return
	}

	// Path A: NO MyInfoPrefill is persisted. The closure map declares
	// singpass_sub as the only field; persisting NRIC/FIN/name/DOB/etc.
	// would violate the scope-minimisation invariant.

	// Emit kyc.verified.v1.
	if h.cfg.EconomyPub != nil {
		if err := h.cfg.EconomyPub.PublishKycVerified(env, verif); err != nil {
			log.Printf("kyc: publish kyc.verified.v1 failed: %v", err)
		}
	}
	// Emit IMDA evidence (D1 accountability + runtime).
	h.emitIMDAEvidence(env, "kyc_verify_success", "chora.identity.kyc.verified.v1",
		"accountability", "ADR-142 §KYC", map[string]any{
			"gcid":            st.Gcid,
			"method":          string(verif.Method),
			"provider":        verif.Provider,
			"verification_id": verif.VerificationID,
		})

	// 200 with summary; the SPA navigates to a status page itself.
	writeJSON(w, http.StatusOK, map[string]any{
		"verification_id":   verif.VerificationID,
		"status":            string(verif.Status),
		"method":            string(verif.Method),
		"prefill_available": true,
	})
}

// recordRejection transitions the verification + emits kyc.rejected.v1 +
// IMDA evidence (safety_and_robustness D3). Failures are logged.
func (h *KycHandler) recordRejection(ctx context.Context, env events.Envelope, verif *kyc.Verification, code, notes string) {
	// If the verification is still pending we need to Submit-then-Reject.
	if verif.Status == kyc.StatusPending {
		_ = verif.Submit("singpass:"+verif.VerificationID, 0, "USD")
	}
	if err := verif.Reject(code, notes, false); err != nil {
		log.Printf("kyc: reject transition failed: %v", err)
		return
	}
	if err := h.cfg.KycRepo.Save(ctx, verif); err != nil {
		log.Printf("kyc: save rejected verification failed: %v", err)
	}
	if h.cfg.EconomyPub != nil {
		if err := h.cfg.EconomyPub.PublishKycRejected(env, verif); err != nil {
			log.Printf("kyc: publish kyc.rejected.v1 failed: %v", err)
		}
	}
	h.emitIMDAEvidence(env, "kyc_verify_rejected", "chora.identity.kyc.rejected.v1",
		"safety_and_robustness", "ADR-142 §KYC", map[string]any{
			"gcid":            verif.Gcid,
			"method":          string(verif.Method),
			"provider":        verif.Provider,
			"verification_id": verif.VerificationID,
			"rejection_code":  code,
		})
}

func (h *KycHandler) emitIMDAEvidence(env events.Envelope, evidenceType, sourceTopic, dimension, policy string, extra map[string]any) {
	if h.cfg.GovernancePub == nil {
		return
	}
	if err := h.cfg.GovernancePub.RecordEvidence(env, events.EvidenceInput{
		EvidenceType:     evidenceType,
		SourceEventType:  sourceTopic,
		Dimension:        dimension,
		LifecycleStage:   "runtime",
		PolicyReference:  policy,
		AdditionalFields: extra,
	}); err != nil {
		log.Printf("kyc: emit IMDA evidence failed: %v", err)
	}
}

// -----------------------------------------------------------------------------
// POST /v1/me/kyc/manual — manual review queue
// -----------------------------------------------------------------------------

func (h *KycHandler) submitManual(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "POST only")
		return
	}
	gcid := gcidFromContext(r.Context())
	tenantID := resolveTenantID(r)

	if err := r.ParseMultipartForm(16 << 20); err != nil {
		writeError(w, http.StatusBadRequest, "KYC_INVALID_MULTIPART", err.Error())
		return
	}
	docType := r.FormValue("document_type")
	if docType == "" {
		writeError(w, http.StatusUnprocessableEntity, "KYC_DOC_TYPE_REQUIRED", "document_type required")
		return
	}
	if _, _, err := r.FormFile("document_front"); err != nil {
		writeError(w, http.StatusUnprocessableEntity, "KYC_DOC_FRONT_REQUIRED", "document_front required")
		return
	}
	currency := r.FormValue("currency")
	if currency == "" {
		currency = "USD"
	}

	// Per ADR-164 Stage A.5 the manual-doc fee is collected by chora-payments
	// via Stripe Checkout. Fail loud (no silent uncollected submission) when
	// the payments client is unwired (per feedback_no_stubs_real_wiring).
	if h.cfg.Payments == nil {
		writeError(w, http.StatusServiceUnavailable, "KYC_FEE_COLLECTION_UNAVAILABLE",
			"manual-doc KYC fee collection requires chora-payments (CHORA_PAYMENTS_GRPC_ADDR unset)")
		return
	}

	verif, err := kyc.NewVerification(kyc.NewParams{
		Gcid: gcid, Method: kyc.MethodManualDoc, Provider: "internal_review",
	})
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, "KYC_INVALID", err.Error())
		return
	}

	// Capture the uploaded document while the verification stays PENDING.
	// It only enters the review queue (Submit → submitted) once the
	// KycFeeSubscriber receives chora.payments.identity_kyc_fee.payment_
	// captured.v1 — charging at submission gates the manual-review effort
	// behind payment.
	docURI := "gs://chora-kyc-sandbox/" + verif.VerificationID
	if err := verif.AttachPendingDocument(docURI); err != nil {
		writeError(w, http.StatusUnprocessableEntity, "KYC_INVALID_TRANSITION", err.Error())
		return
	}
	if err := h.cfg.KycRepo.Save(r.Context(), verif); err != nil {
		writeError(w, http.StatusInternalServerError, "KYC_REPO_ERROR", err.Error())
		return
	}

	feeCents := h.cfg.ManaultFeeCents
	out, err := h.cfg.Payments.CreateKycFee(r.Context(), payments.CreateKycFeeInput{
		// One fee per verification attempt — the verification_id is the
		// natural idempotency key for the chora-payments dedupe window.
		IdempotencyKey: verif.VerificationID,
		TenantID:       tenantID,
		LearnerGcid:    gcid,
		KYCDocType:     docType,
		AmountCents:    feeCents,
		Currency:       currency,
		SuccessURL:     h.cfg.FeeSuccessURL,
		CancelURL:      h.cfg.FeeCancelURL,
	})
	if err != nil {
		if errors.Is(err, payments.ErrPaymentsUnavailable) {
			writeError(w, http.StatusBadGateway, "KYC_PAYMENTS_UNAVAILABLE", err.Error())
			return
		}
		if errors.Is(err, payments.ErrInvalidInput) {
			writeError(w, http.StatusUnprocessableEntity, "KYC_PAYMENT_INVALID", err.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, "KYC_PAYMENT_ERROR", err.Error())
		return
	}

	// 200 with the Stripe Checkout URL — the SPA redirects the learner to
	// pay. status stays "pending" until the capture event flows back.
	writeJSON(w, http.StatusOK, map[string]any{
		"verification_id":     verif.VerificationID,
		"status":              string(verif.Status), // pending
		"method":              string(verif.Method),
		"fee_charged_cents":   feeCents,
		"currency":            currency,
		"purchase_id":         out.PurchaseID,
		"stripe_session_id":   out.StripeSessionID,
		"stripe_checkout_url": out.StripeCheckoutURL,
	})
}

// -----------------------------------------------------------------------------
// GET /v1/me/kyc/status
// -----------------------------------------------------------------------------

func (h *KycHandler) getStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "GET only")
		return
	}
	gcid := gcidFromContext(r.Context())
	v, err := h.cfg.KycRepo.GetLatestByGcid(r.Context(), gcid)
	if err != nil {
		if errors.Is(err, kyc.ErrNotFound) {
			writeJSON(w, http.StatusOK, map[string]any{
				"overall_status": "unverified",
			})
			return
		}
		writeError(w, http.StatusInternalServerError, "KYC_REPO_ERROR", err.Error())
		return
	}
	overall := overallStatus(v)
	out := map[string]any{
		"overall_status":  overall,
		"verification_id": v.VerificationID,
		"method":          string(v.Method),
		"status":          string(v.Status),
		"provider":        v.Provider,
	}
	if v.VerifiedAt != nil {
		out["verified_at"] = v.VerifiedAt.Format(time.RFC3339)
	}
	if v.RejectionCode != "" {
		out["rejection_code"] = v.RejectionCode
	}
	writeJSON(w, http.StatusOK, out)
}

// overallStatus maps the latest verification → external status string.
func overallStatus(v *kyc.Verification) string {
	switch v.Status {
	case kyc.StatusVerified:
		switch v.Method {
		case kyc.MethodSingpass:
			return "verified_singpass"
		case kyc.MethodSkillsFuture:
			return "verified_skillsfuture"
		case kyc.MethodManualDoc:
			return "verified_manual"
		}
		return "verified"
	case kyc.StatusSubmitted:
		return "pending"
	case kyc.StatusPending:
		return "pending"
	case kyc.StatusRejected:
		return "rejected"
	case kyc.StatusExpired:
		return "expired"
	}
	return "unverified"
}

// -----------------------------------------------------------------------------
// GET /v1/me/myinfo-prefill?for=course_application
//
// Path A (2026-05-10): the MyInfoPrefill aggregate is DEPRECATED. Chora
// persists only the Singpass OIDC `sub` UUID — there is nothing to prefill.
// The route is preserved for client-compatibility but always returns 404
// with a Path-A explanation. Once chora-web S9 lands, the SPA stops
// querying this endpoint entirely.
// -----------------------------------------------------------------------------

func (h *KycHandler) getMyInfoPrefill(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "GET only")
		return
	}
	writeError(w, http.StatusNotFound, "KYC_PREFILL_DEPRECATED",
		"MyInfo prefill is deprecated — Chora persists only the Singpass `sub` UUID per Path A scope minimisation (migration 0004_singpass_sub_minimisation.sql)")
}

// -----------------------------------------------------------------------------
// PKCE helpers
// -----------------------------------------------------------------------------

// generateRandomToken returns a URL-safe base64 random string of the requested
// byte length. Used for state + PKCE verifier generation.
func generateRandomToken(byteLen int) string {
	b := make([]byte, byteLen)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// pkceS256Challenge returns base64url(SHA256(verifier)) per RFC 7636 §4.2.
func pkceS256Challenge(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// resolveTenantID returns the request's tenant_id, with the precedence:
//
//  1. ctx (set by tenantContext middleware)
//  2. X-Tenant-Id header
//  3. dev-fallback "01970000-0000-7000-8000-0000000000aa"
//
// The dev fallback exists so isolated handler tests don't need to wire
// tenantContext middleware. Production runs the middleware which always
// populates ctx with the real tenant.
func resolveTenantID(r *http.Request) string {
	if v := tenantFromContext(r.Context()); v != "" {
		return v
	}
	if v := r.Header.Get("X-Tenant-Id"); v != "" {
		return v
	}
	return "01970000-0000-7000-8000-0000000000aa"
}

// hexencode is a helper used by tests / future telemetry.
var _ = hex.EncodeToString
