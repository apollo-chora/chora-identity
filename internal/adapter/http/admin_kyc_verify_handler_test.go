// Package httpadapter_test — RED-phase TDD specs for the staff-gated manual-doc
// KYC verify/reject endpoint (CHO-2103, W4 Exam BC follow-up).
//
// Routes under test (admin_kyc_verify_handler.go):
//
//	POST /api/v1/admin/kyc/{gcid}/verify   — submitted → verified; emits kyc.verified.v1
//	POST /api/v1/admin/kyc/{gcid}/reject   — submitted → rejected; emits kyc.rejected.v1
//
// Completes the manual_doc lifecycle: KycFeeSubscriber promotes pending→submitted
// on fee capture, but only Singpass auto-verifies — manual_doc sat at `submitted`
// with no staff action to reach `verified`, so the Exam BC admit gate (ADR-190 D2)
// could never pass a manual-doc candidate.
//
// Authz is fail-closed via adminGate (mesh x-mesh-user-roles + tenant context).
package httpadapter_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/apollo-chora/chora-common/auth/servicemesh"
	"github.com/apollo-chora/chora-identity/internal/adapter/events"
	httpadapter "github.com/apollo-chora/chora-identity/internal/adapter/http"
	"github.com/apollo-chora/chora-identity/internal/adapter/repo"
	"github.com/apollo-chora/chora-identity/internal/domain/kyc"
)

// saveErrKycRepo wraps an InMemKycRepo but fails every Save — to prove the
// handler fails LOUD (500) rather than reporting a silent success when the
// durable write cannot land.
type saveErrKycRepo struct{ inner *repo.InMemKycRepo }

func (r *saveErrKycRepo) Save(context.Context, *kyc.Verification) error {
	return errors.New("pg: write timeout")
}
func (r *saveErrKycRepo) GetByID(ctx context.Context, id string) (*kyc.Verification, error) {
	return r.inner.GetByID(ctx, id)
}
func (r *saveErrKycRepo) GetLatestByGcid(ctx context.Context, gcid string) (*kyc.Verification, error) {
	return r.inner.GetLatestByGcid(ctx, gcid)
}

const (
	adminKycSubjectGcid = "01970000-0000-7000-8000-0000000ac103" // the manual-doc learner
	adminKycStaffGcid   = "01970000-0000-7000-8000-0000000ac1ad" // the reviewing staff member
	adminKycTenant      = "01970000-0000-7000-8000-0000000000aa"
)

// -----------------------------------------------------------------------------
// harness
// -----------------------------------------------------------------------------

type adminKycHarness struct {
	mux      *http.ServeMux
	recorder *events.Recorder
	kycRepo  *repo.InMemKycRepo
}

func newAdminKycHarness(t *testing.T) *adminKycHarness {
	t.Helper()
	kycRepo := repo.NewInMemKycRepo()
	rec := events.NewRecorder()
	economyPub := events.NewEconomyPublisher(rec)
	govPub := events.NewGovernancePublisher(rec)

	h := httpadapter.NewAdminKycVerifyHandler(kycRepo, economyPub, govPub)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	return &adminKycHarness{mux: mux, recorder: rec, kycRepo: kycRepo}
}

// seedManualDoc inserts a manual_doc verification in the given status for the
// subject gcid. It walks the real aggregate FSM so the audit trail is authentic.
func seedManualDoc(t *testing.T, r *repo.InMemKycRepo, gcid string, status kyc.Status) *kyc.Verification {
	t.Helper()
	v, err := kyc.NewVerification(kyc.NewParams{Gcid: gcid, Method: kyc.MethodManualDoc, Provider: "internal_review"})
	if err != nil {
		t.Fatalf("seed NewVerification: %v", err)
	}
	if err := v.AttachPendingDocument("gs://chora-kyc-sandbox/" + v.VerificationID); err != nil {
		t.Fatalf("seed AttachPendingDocument: %v", err)
	}
	if status == kyc.StatusSubmitted || status == kyc.StatusVerified || status == kyc.StatusRejected {
		if err := v.Submit("gs://chora-kyc-sandbox/"+v.VerificationID, 999, "USD"); err != nil {
			t.Fatalf("seed Submit: %v", err)
		}
	}
	if err := r.Save(context.Background(), v); err != nil {
		t.Fatalf("seed Save: %v", err)
	}
	return v
}

// adminKycReq builds a POST to the admin KYC endpoint with the given mesh headers.
// Empty roles/tenant/actor are omitted so the fail-closed gate can be exercised.
func adminKycReq(path string, body any, roles, tenant, actorGcid string) *http.Request {
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	r := httptest.NewRequest(http.MethodPost, path, &buf)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("traceparent", "00-aabbccddeeff00112233445566778899-0011223344556677-01")
	if roles != "" {
		r.Header.Set(servicemesh.HeaderUserRoles, roles)
	}
	if tenant != "" {
		r.Header.Set(servicemesh.HeaderTenantID, tenant)
	}
	if actorGcid != "" {
		r.Header.Set(servicemesh.HeaderGCID, actorGcid)
	}
	return r
}

func decodeAdminKycBody(t *testing.T, b *bytes.Buffer) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(b.Bytes(), &out); err != nil {
		t.Fatalf("invalid json body=%s: %v", b.String(), err)
	}
	return out
}

// -----------------------------------------------------------------------------
// AC: Staff verify — submitted → verified, persists, emits kyc.verified.v1
// -----------------------------------------------------------------------------

func TestAdminKyc_Verify_HappyPath(t *testing.T) {
	t.Parallel()
	h := newAdminKycHarness(t)
	seedManualDoc(t, h.kycRepo, adminKycSubjectGcid, kyc.StatusSubmitted)

	w := httptest.NewRecorder()
	h.mux.ServeHTTP(w, adminKycReq(
		"/api/v1/admin/kyc/"+adminKycSubjectGcid+"/verify", nil,
		"TENANT_ADMIN", adminKycTenant, adminKycStaffGcid))

	if w.Code != http.StatusOK {
		t.Fatalf("verify status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	out := decodeAdminKycBody(t, w.Body)
	if out["status"] != "verified" {
		t.Errorf("status = %v, want verified", out["status"])
	}

	// Persisted as verified.
	v, err := h.kycRepo.GetLatestByGcid(context.Background(), adminKycSubjectGcid)
	if err != nil {
		t.Fatalf("GetLatestByGcid: %v", err)
	}
	if v.Status != kyc.StatusVerified {
		t.Errorf("persisted status = %q, want verified", v.Status)
	}
	if v.VerifiedAt == nil {
		t.Error("VerifiedAt must be set after verify")
	}
	// Accountability: the audit trail records WHO verified.
	last := v.AuditLog[len(v.AuditLog)-1]
	if last.Event != "verified" || last.ActorGcid != adminKycStaffGcid {
		t.Errorf("audit tail = %+v, want event=verified actor=%s", last, adminKycStaffGcid)
	}

	// kyc.verified.v1 emitted.
	if got := len(h.recorder.RecordedByTopic("chora.identity.kyc.verified.v1")); got != 1 {
		t.Errorf("kyc.verified.v1 count = %d, want 1", got)
	}
}

// -----------------------------------------------------------------------------
// AC: Staff reject — submitted → rejected (retryable per policy)
// -----------------------------------------------------------------------------

func TestAdminKyc_Reject_HappyPath(t *testing.T) {
	t.Parallel()
	h := newAdminKycHarness(t)
	seedManualDoc(t, h.kycRepo, adminKycSubjectGcid, kyc.StatusSubmitted)

	w := httptest.NewRecorder()
	h.mux.ServeHTTP(w, adminKycReq(
		"/api/v1/admin/kyc/"+adminKycSubjectGcid+"/reject",
		map[string]any{"code": "doc_illegible", "notes": "blurry scan", "retry_allowed": true},
		"TENANT_ADMIN", adminKycTenant, adminKycStaffGcid))

	if w.Code != http.StatusOK {
		t.Fatalf("reject status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	out := decodeAdminKycBody(t, w.Body)
	if out["status"] != "rejected" {
		t.Errorf("status = %v, want rejected", out["status"])
	}

	v, err := h.kycRepo.GetLatestByGcid(context.Background(), adminKycSubjectGcid)
	if err != nil {
		t.Fatalf("GetLatestByGcid: %v", err)
	}
	if v.Status != kyc.StatusRejected {
		t.Errorf("persisted status = %q, want rejected", v.Status)
	}
	if v.RejectionCode != "doc_illegible" {
		t.Errorf("RejectionCode = %q, want doc_illegible", v.RejectionCode)
	}
	if !v.RetryAllowed {
		t.Error("RetryAllowed must be true when requested")
	}
	if got := len(h.recorder.RecordedByTopic("chora.identity.kyc.rejected.v1")); got != 1 {
		t.Errorf("kyc.rejected.v1 count = %d, want 1", got)
	}
}

// -----------------------------------------------------------------------------
// AC: Authz — non-staff caller → 403, fail-closed (no state change, no event)
// -----------------------------------------------------------------------------

func TestAdminKyc_NonStaff_Forbidden(t *testing.T) {
	t.Parallel()
	h := newAdminKycHarness(t)
	seedManualDoc(t, h.kycRepo, adminKycSubjectGcid, kyc.StatusSubmitted)

	w := httptest.NewRecorder()
	h.mux.ServeHTTP(w, adminKycReq(
		"/api/v1/admin/kyc/"+adminKycSubjectGcid+"/verify", nil,
		"LEARNER", adminKycTenant, adminKycSubjectGcid))

	if w.Code != http.StatusForbidden {
		t.Fatalf("non-staff verify status = %d, want 403; body=%s", w.Code, w.Body.String())
	}
	// Untouched: still submitted, nothing emitted.
	v, _ := h.kycRepo.GetLatestByGcid(context.Background(), adminKycSubjectGcid)
	if v.Status != kyc.StatusSubmitted {
		t.Errorf("status = %q after 403, want unchanged submitted", v.Status)
	}
	if got := len(h.recorder.RecordedByTopic("chora.identity.kyc.verified.v1")); got != 0 {
		t.Errorf("no event must be emitted on 403, got %d", got)
	}
}

// -----------------------------------------------------------------------------
// AC: Authz — missing tenant context → 401 (adminGate fail-closed)
// -----------------------------------------------------------------------------

func TestAdminKyc_MissingTenantContext_Unauthorized(t *testing.T) {
	t.Parallel()
	h := newAdminKycHarness(t)
	seedManualDoc(t, h.kycRepo, adminKycSubjectGcid, kyc.StatusSubmitted)

	w := httptest.NewRecorder()
	h.mux.ServeHTTP(w, adminKycReq(
		"/api/v1/admin/kyc/"+adminKycSubjectGcid+"/verify", nil,
		"TENANT_ADMIN", "", adminKycStaffGcid)) // no tenant header

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("missing-tenant status = %d, want 401; body=%s", w.Code, w.Body.String())
	}
}

// -----------------------------------------------------------------------------
// Wrong state — verify a pending (not submitted) claim → 409, no event
// -----------------------------------------------------------------------------

func TestAdminKyc_Verify_WrongState_Conflict(t *testing.T) {
	t.Parallel()
	h := newAdminKycHarness(t)
	seedManualDoc(t, h.kycRepo, adminKycSubjectGcid, kyc.StatusPending)

	w := httptest.NewRecorder()
	h.mux.ServeHTTP(w, adminKycReq(
		"/api/v1/admin/kyc/"+adminKycSubjectGcid+"/verify", nil,
		"TENANT_ADMIN", adminKycTenant, adminKycStaffGcid))

	if w.Code != http.StatusConflict {
		t.Fatalf("wrong-state verify status = %d, want 409; body=%s", w.Code, w.Body.String())
	}
	if got := len(h.recorder.RecordedByTopic("chora.identity.kyc.verified.v1")); got != 0 {
		t.Errorf("no event on invalid transition, got %d", got)
	}
}

// -----------------------------------------------------------------------------
// No claim on record → 404
// -----------------------------------------------------------------------------

func TestAdminKyc_NoClaim_NotFound(t *testing.T) {
	t.Parallel()
	h := newAdminKycHarness(t)
	// nothing seeded

	w := httptest.NewRecorder()
	h.mux.ServeHTTP(w, adminKycReq(
		"/api/v1/admin/kyc/"+adminKycSubjectGcid+"/verify", nil,
		"TENANT_ADMIN", adminKycTenant, adminKycStaffGcid))

	if w.Code != http.StatusNotFound {
		t.Fatalf("no-claim status = %d, want 404; body=%s", w.Code, w.Body.String())
	}
}

// -----------------------------------------------------------------------------
// Unknown action segment → 404
// -----------------------------------------------------------------------------

func TestAdminKyc_UnknownAction_NotFound(t *testing.T) {
	t.Parallel()
	h := newAdminKycHarness(t)
	seedManualDoc(t, h.kycRepo, adminKycSubjectGcid, kyc.StatusSubmitted)

	w := httptest.NewRecorder()
	h.mux.ServeHTTP(w, adminKycReq(
		"/api/v1/admin/kyc/"+adminKycSubjectGcid+"/frobnicate", nil,
		"TENANT_ADMIN", adminKycTenant, adminKycStaffGcid))

	if w.Code != http.StatusNotFound {
		t.Fatalf("unknown-action status = %d, want 404; body=%s", w.Code, w.Body.String())
	}
}

// -----------------------------------------------------------------------------
// Non-POST → 405
// -----------------------------------------------------------------------------

func TestAdminKyc_MethodNotAllowed(t *testing.T) {
	t.Parallel()
	h := newAdminKycHarness(t)
	seedManualDoc(t, h.kycRepo, adminKycSubjectGcid, kyc.StatusSubmitted)

	r := httptest.NewRequest(http.MethodGet, "/api/v1/admin/kyc/"+adminKycSubjectGcid+"/verify", nil)
	r.Header.Set(servicemesh.HeaderUserRoles, "TENANT_ADMIN")
	r.Header.Set(servicemesh.HeaderTenantID, adminKycTenant)
	w := httptest.NewRecorder()
	h.mux.ServeHTTP(w, r)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET status = %d, want 405; body=%s", w.Code, w.Body.String())
	}
}

// -----------------------------------------------------------------------------
// AC: Gate unblocked — after staff verify, the internal verification-status read
// (the exam admit gate's source of truth) reports verified:true for the subject.
// -----------------------------------------------------------------------------

func TestAdminKyc_Verify_UnblocksInternalGate(t *testing.T) {
	t.Parallel()
	h := newAdminKycHarness(t)
	seedManualDoc(t, h.kycRepo, adminKycSubjectGcid, kyc.StatusSubmitted)

	// Staff verify.
	w := httptest.NewRecorder()
	h.mux.ServeHTTP(w, adminKycReq(
		"/api/v1/admin/kyc/"+adminKycSubjectGcid+"/verify", nil,
		"TENANT_ADMIN", adminKycTenant, adminKycStaffGcid))
	if w.Code != http.StatusOK {
		t.Fatalf("verify status = %d, want 200; body=%s", w.Code, w.Body.String())
	}

	// The exam admit gate reads the SAME repo via the internal handler.
	internal := httpadapter.NewInternalVerificationHandler(h.kycRepo)
	gw := httptest.NewRecorder()
	internal.ServeHTTP(gw, httptest.NewRequest(http.MethodGet,
		"/internal/v1/identity/verification-status?gcid="+adminKycSubjectGcid, nil))
	if gw.Code != http.StatusOK {
		t.Fatalf("verification-status = %d, want 200; body=%s", gw.Code, gw.Body.String())
	}
	claim := decodeAdminKycBody(t, gw.Body)
	if claim["verified"] != true {
		t.Errorf("verified = %v, want true (admit gate must now pass)", claim["verified"])
	}
}

// -----------------------------------------------------------------------------
// Fail-loud — a durable-write failure must surface as 500, never a silent 200,
// and must NOT emit kyc.verified.v1 (the claim did not persist).
// -----------------------------------------------------------------------------

func TestAdminKyc_Verify_SaveError_FailsLoud(t *testing.T) {
	t.Parallel()
	inner := repo.NewInMemKycRepo()
	seedManualDoc(t, inner, adminKycSubjectGcid, kyc.StatusSubmitted)
	rec := events.NewRecorder()
	h := httpadapter.NewAdminKycVerifyHandler(&saveErrKycRepo{inner: inner},
		events.NewEconomyPublisher(rec), events.NewGovernancePublisher(rec))
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	w := httptest.NewRecorder()
	mux.ServeHTTP(w, adminKycReq(
		"/api/v1/admin/kyc/"+adminKycSubjectGcid+"/verify", nil,
		"TENANT_ADMIN", adminKycTenant, adminKycStaffGcid))

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("save-error status = %d, want 500; body=%s", w.Code, w.Body.String())
	}
	if got := len(rec.RecordedByTopic("chora.identity.kyc.verified.v1")); got != 0 {
		t.Errorf("no event must be emitted when the write fails, got %d", got)
	}
}

// -----------------------------------------------------------------------------
// Reject hard-fail — retry_allowed:false is honoured; omitted code defaults.
// -----------------------------------------------------------------------------

func TestAdminKyc_Reject_HardFail_NoRetry(t *testing.T) {
	t.Parallel()
	h := newAdminKycHarness(t)
	seedManualDoc(t, h.kycRepo, adminKycSubjectGcid, kyc.StatusSubmitted)

	no := false
	w := httptest.NewRecorder()
	h.mux.ServeHTTP(w, adminKycReq(
		"/api/v1/admin/kyc/"+adminKycSubjectGcid+"/reject",
		map[string]any{"retry_allowed": no}, // no code → server default
		"TENANT_ADMIN", adminKycTenant, adminKycStaffGcid))

	if w.Code != http.StatusOK {
		t.Fatalf("reject status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	v, _ := h.kycRepo.GetLatestByGcid(context.Background(), adminKycSubjectGcid)
	if v.RetryAllowed {
		t.Error("RetryAllowed must be false when retry_allowed:false")
	}
	if v.RejectionCode == "" {
		t.Error("RejectionCode must default when omitted (never blank)")
	}
}

// -----------------------------------------------------------------------------
// Best-effort emit — nil publishers must not block a persisted verify (the
// durable state write is the contract; the event is best-effort).
// -----------------------------------------------------------------------------

func TestAdminKyc_NilPublishers_StillVerifies(t *testing.T) {
	t.Parallel()
	kycRepo := repo.NewInMemKycRepo()
	seedManualDoc(t, kycRepo, adminKycSubjectGcid, kyc.StatusSubmitted)
	h := httpadapter.NewAdminKycVerifyHandler(kycRepo, nil, nil) // no publishers wired
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	w := httptest.NewRecorder()
	mux.ServeHTTP(w, adminKycReq(
		"/api/v1/admin/kyc/"+adminKycSubjectGcid+"/verify", nil,
		"TENANT_ADMIN", adminKycTenant, adminKycStaffGcid))

	if w.Code != http.StatusOK {
		t.Fatalf("nil-publisher verify status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	v, _ := kycRepo.GetLatestByGcid(context.Background(), adminKycSubjectGcid)
	if v.Status != kyc.StatusVerified {
		t.Errorf("status = %q, want verified (persist must not depend on publishers)", v.Status)
	}
}
