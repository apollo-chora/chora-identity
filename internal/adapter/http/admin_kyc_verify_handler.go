// admin_kyc_verify_handler.go — staff-gated manual-doc KYC verify/reject
// (CHO-2103, W4 Exam BC follow-up).
//
// Routes (mounted as a subtree on the composed mux in cmd/server/main.go):
//
//	POST /api/v1/admin/kyc/{gcid}/verify   → submitted → verified; emits kyc.verified.v1
//	POST /api/v1/admin/kyc/{gcid}/reject   → submitted → rejected; emits kyc.rejected.v1
//
// WHY: KycFeeSubscriber promotes manual_doc pending→submitted on fee capture, but
// only the Singpass OIDC callback auto-verifies. manual_doc therefore sat at
// `submitted` with no action to reach `verified`, so the Exam BC admit gate
// (ADR-190 D2, GET /internal/v1/identity/verification-status) could never pass a
// manual-doc candidate. This is the missing staff review action.
//
// AUTHZ (fail-closed): adminGate — the mesh x-mesh-user-roles header must carry
// TRAINING_ADMIN / TENANT_ADMIN / ADMIN / OWNER AND a tenant context must be
// present. A non-staff caller gets 403 before any store read; a caller with no
// tenant context gets 401. Reachable only via the bearer-authed gateway/BFF
// admin surface (the sidecar default-deny + authz-allow-gateway.yaml keep
// learners out; the in-handler role gate is the second layer).
//
// RLS: person-scoped, NOT an admin bypass. Both GetLatestByGcid(gcid) and Save(v)
// self-scope the pg adapter's RunInUserTx to the SUBJECT gcid (the {gcid} path
// param / the aggregate's Gcid), so the kyc_verifications user_isolation policy
// passes on `gcid = current_setting('chora.user_gcid')`. The reviewing staff
// member's own gcid never widens scope — it is recorded only in the audit trail.
// No new migration, no new store — reuses the CHO-2100 durable pg repo.
//
// KNOWN SIMPLIFICATION (flagged, not hidden): a KYC claim is a property of the
// GCID (cross-tenant portable — carries no tenant), so today any tenant admin
// passing adminGate may action a submitted claim for any gcid. A dedicated
// compliance_reviewer capability is a future refinement (CHO-2103 note).
package httpadapter

import (
	"errors"
	"log"
	"net/http"
	"strings"

	"github.com/apollo-chora/chora-common/auth/servicemesh"
	"github.com/apollo-chora/chora-identity/internal/adapter/events"
	"github.com/apollo-chora/chora-identity/internal/domain/kyc"
)

const adminKycPathPrefix = "/api/v1/admin/kyc/"

// AdminKycVerifyHandler serves the staff verify/reject actions on the KYC
// aggregate. It depends only on the kyc.Repository port plus the (nil-tolerant)
// publishers — hexagonal, no infra.
type AdminKycVerifyHandler struct {
	kycRepo       kyc.Repository
	economyPub    *events.EconomyPublisher    // nil-tolerant (best-effort emit)
	governancePub *events.GovernancePublisher // nil-tolerant (best-effort IMDA evidence)
}

// NewAdminKycVerifyHandler wires the handler.
func NewAdminKycVerifyHandler(kycRepo kyc.Repository, economyPub *events.EconomyPublisher, governancePub *events.GovernancePublisher) *AdminKycVerifyHandler {
	return &AdminKycVerifyHandler{kycRepo: kycRepo, economyPub: economyPub, governancePub: governancePub}
}

// RegisterRoutes mounts the handler as a subtree (manual path-parse, matching the
// tenant_members_admin house pattern — avoids the Go-1.22 method-mux panic).
func (h *AdminKycVerifyHandler) RegisterRoutes(mux *http.ServeMux) {
	mux.Handle(adminKycPathPrefix, h)
}

// Compile-time guard.
var _ http.Handler = (*AdminKycVerifyHandler)(nil)

func (h *AdminKycVerifyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED",
			"POST only on /api/v1/admin/kyc/{gcid}/verify|reject")
		return
	}
	// Fail-closed authz FIRST — a non-staff caller never reaches the store.
	tenantID, ok := adminGate(w, r)
	if !ok {
		return
	}
	if h.kycRepo == nil {
		// Fail loud — a nil repo is a wiring bug, never a silent success.
		writeError(w, http.StatusInternalServerError, "KYC_REPO_UNAVAILABLE", "verification store not wired")
		return
	}

	// Parse {gcid}/{action} from the subtree remainder.
	rest := strings.Trim(strings.TrimPrefix(r.URL.Path, adminKycPathPrefix), "/")
	parts := strings.Split(rest, "/")
	if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" {
		writeError(w, http.StatusNotFound, "IDENTITY_NOT_FOUND",
			"path must be /api/v1/admin/kyc/{gcid}/verify or /reject")
		return
	}
	subjectGcid := strings.TrimSpace(parts[0])
	action := parts[1]
	if action != "verify" && action != "reject" {
		writeError(w, http.StatusNotFound, "IDENTITY_NOT_FOUND", "action must be verify or reject")
		return
	}

	// Read the latest verification for the subject (self-scopes RLS to the
	// subject gcid — see file header).
	verif, err := h.kycRepo.GetLatestByGcid(r.Context(), subjectGcid)
	if err != nil {
		if errors.Is(err, kyc.ErrNotFound) {
			writeError(w, http.StatusNotFound, "KYC_NOT_FOUND", "no verification on record for that gcid")
			return
		}
		writeError(w, http.StatusInternalServerError, "KYC_REPO_ERROR", err.Error())
		return
	}

	env := events.NewEnvelope(tenantID, subjectGcid,
		r.Header.Get("traceparent"), r.Header.Get("tracestate"))

	switch action {
	case "verify":
		h.verify(w, r, env, verif, strings.TrimSpace(r.Header.Get(servicemesh.HeaderGCID)))
	case "reject":
		h.reject(w, r, env, verif)
	}
}

// verify transitions submitted → verified, persists, emits kyc.verified.v1 +
// IMDA-D1 accountability evidence. Parity with the Singpass callback's verify.
func (h *AdminKycVerifyHandler) verify(w http.ResponseWriter, r *http.Request, env events.Envelope, verif *kyc.Verification, actorGcid string) {
	// skillsfutureScope stays false — the SkillsFuture grant is a Singpass /
	// SkillsFuture-method concern, not a manual-doc staff review.
	if err := verif.Verify(actorGcid, false); err != nil {
		writeError(w, http.StatusConflict, "KYC_INVALID_TRANSITION", err.Error())
		return
	}
	if err := h.kycRepo.Save(r.Context(), verif); err != nil {
		writeError(w, http.StatusInternalServerError, "KYC_REPO_ERROR", err.Error())
		return
	}
	// Best-effort emit — same semantics as the Singpass callback: the
	// RLS-enforced write is not rolled back over a publish hiccup, but the
	// failure is logged loudly.
	if h.economyPub != nil {
		if err := h.economyPub.PublishKycVerified(env, verif); err != nil {
			log.Printf("admin-kyc: publish kyc.verified.v1 failed (verify persisted): %v", err)
		}
	}
	h.emitEvidence(env, verif, "kyc_staff_verify_success", "chora.identity.kyc.verified.v1",
		"accountability", "ADR-142 §KYC / CHO-2103", actorGcid, "")

	writeJSON(w, http.StatusOK, map[string]any{
		"verification_id": verif.VerificationID,
		"gcid":            verif.Gcid,
		"status":          string(verif.Status),
		"method":          string(verif.Method),
	})
}

type adminKycRejectBody struct {
	Code         string `json:"code"`
	Notes        string `json:"notes"`
	RetryAllowed *bool  `json:"retry_allowed"` // pointer: omitted → retryable default
}

// reject transitions submitted → rejected, persists, emits kyc.rejected.v1 +
// IMDA-D3 safety evidence.
func (h *AdminKycVerifyHandler) reject(w http.ResponseWriter, r *http.Request, env events.Envelope, verif *kyc.Verification) {
	var body adminKycRejectBody
	_ = decodeJSON(r, &body) // body optional; sane defaults below
	code := strings.TrimSpace(body.Code)
	if code == "" {
		code = "staff_rejected"
	}
	// Manual-doc rejections are retryable by default (the learner may re-upload
	// a legible document); staff pin retry_allowed:false for a hard fail.
	retry := true
	if body.RetryAllowed != nil {
		retry = *body.RetryAllowed
	}
	if err := verif.Reject(code, strings.TrimSpace(body.Notes), retry); err != nil {
		writeError(w, http.StatusConflict, "KYC_INVALID_TRANSITION", err.Error())
		return
	}
	if err := h.kycRepo.Save(r.Context(), verif); err != nil {
		writeError(w, http.StatusInternalServerError, "KYC_REPO_ERROR", err.Error())
		return
	}
	if h.economyPub != nil {
		if err := h.economyPub.PublishKycRejected(env, verif); err != nil {
			log.Printf("admin-kyc: publish kyc.rejected.v1 failed (reject persisted): %v", err)
		}
	}
	h.emitEvidence(env, verif, "kyc_staff_verify_rejected", "chora.identity.kyc.rejected.v1",
		"safety_and_robustness", "ADR-142 §KYC / CHO-2103", "", code)

	writeJSON(w, http.StatusOK, map[string]any{
		"verification_id": verif.VerificationID,
		"gcid":            verif.Gcid,
		"status":          string(verif.Status),
		"method":          string(verif.Method),
		"rejection_code":  verif.RejectionCode,
		"retry_allowed":   verif.RetryAllowed,
	})
}

// emitEvidence records the IMDA evidence for a staff KYC action (best-effort,
// nil-tolerant). Mirrors KycHandler.emitIMDAEvidence for the Singpass path.
func (h *AdminKycVerifyHandler) emitEvidence(env events.Envelope, verif *kyc.Verification, evidenceType, sourceTopic, dimension, policy, verifiedBy, rejectionCode string) {
	if h.governancePub == nil {
		return
	}
	extra := map[string]any{
		"gcid":            verif.Gcid,
		"method":          string(verif.Method),
		"provider":        verif.Provider,
		"verification_id": verif.VerificationID,
	}
	if verifiedBy != "" {
		extra["verified_by"] = verifiedBy
	}
	if rejectionCode != "" {
		extra["rejection_code"] = rejectionCode
	}
	if err := h.governancePub.RecordEvidence(env, events.EvidenceInput{
		EvidenceType:     evidenceType,
		SourceEventType:  sourceTopic,
		Dimension:        dimension,
		LifecycleStage:   "runtime",
		PolicyReference:  policy,
		AdditionalFields: extra,
	}); err != nil {
		log.Printf("admin-kyc: emit IMDA evidence failed: %v", err)
	}
}
