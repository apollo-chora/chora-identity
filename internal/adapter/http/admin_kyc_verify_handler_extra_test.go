// admin_kyc_verify_handler_extra_test.go — additional coverage for
// admin_kyc_verify_handler.go beyond admin_kyc_verify_handler_test.go:
//
//   - ServeHTTP: nil kycRepo → 500 KYC_REPO_UNAVAILABLE; a non-ErrNotFound
//     GetLatestByGcid failure → 500 KYC_REPO_ERROR.
//   - reject: invalid-transition 409, save-error 500, publish-error log-only.
//   - verify: publish-error log-only (still 200, state persisted).
//   - emitEvidence: RecordEvidence failure is logged loudly but the KYC
//     transition still returns 200.
//
// Reuses the harness + fakes from admin_kyc_verify_handler_test.go
// (newAdminKycHarness, seedManualDoc, saveErrKycRepo, adminKycReq,
// adminKyc* consts, decodeAdminKycBody); new identifiers carry the akx_ prefix.
package httpadapter_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/apollo-chora/chora-identity/internal/adapter/events"
	httpadapter "github.com/apollo-chora/chora-identity/internal/adapter/http"
	"github.com/apollo-chora/chora-identity/internal/adapter/repo"
	"github.com/apollo-chora/chora-identity/internal/domain/kyc"
)

// akxFailingPublisher implements events.Publisher and always fails — proves the
// best-effort kyc.*.v1 emits and the IMDA evidence emit cannot turn a persisted
// KYC transition into an error response.
type akxFailingPublisher struct{}

func (akxFailingPublisher) Publish(_ string, _ events.Envelope, _ map[string]any) error {
	return errors.New("akx: publish backend down")
}

// akxErringGetRepo wraps an in-memory KYC repo but fails GetLatestByGcid with a
// non-ErrNotFound error — exercises the KYC_REPO_ERROR 500 path in ServeHTTP.
type akxErringGetRepo struct {
	inner  *repo.InMemKycRepo
	getErr error
}

func (r *akxErringGetRepo) Save(ctx context.Context, v *kyc.Verification) error {
	return r.inner.Save(ctx, v)
}

func (r *akxErringGetRepo) GetByID(ctx context.Context, id string) (*kyc.Verification, error) {
	return r.inner.GetByID(ctx, id)
}

func (r *akxErringGetRepo) GetLatestByGcid(ctx context.Context, gcid string) (*kyc.Verification, error) {
	if r.getErr != nil {
		return nil, r.getErr
	}
	return r.inner.GetLatestByGcid(ctx, gcid)
}

// -----------------------------------------------------------------------------
// ServeHTTP — repo wiring/error branches
// -----------------------------------------------------------------------------

func TestAdminKyc_Extra_RepoGetError_500(t *testing.T) {
	t.Parallel()
	inner := repo.NewInMemKycRepo()
	seedManualDoc(t, inner, adminKycSubjectGcid, kyc.StatusSubmitted)
	h := httpadapter.NewAdminKycVerifyHandler(
		&akxErringGetRepo{inner: inner, getErr: errors.New("pg: connection refused")}, nil, nil)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	w := httptest.NewRecorder()
	mux.ServeHTTP(w, adminKycReq(
		"/api/v1/admin/kyc/"+adminKycSubjectGcid+"/verify", nil,
		"TENANT_ADMIN", adminKycTenant, adminKycStaffGcid))

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d want 500; body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "KYC_REPO_ERROR") {
		t.Errorf("body=%q want KYC_REPO_ERROR fragment", w.Body.String())
	}
}

func TestAdminKyc_Extra_NilRepo_500(t *testing.T) {
	t.Parallel()
	h := httpadapter.NewAdminKycVerifyHandler(nil, nil, nil) // wiring bug: repo not injected
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	w := httptest.NewRecorder()
	mux.ServeHTTP(w, adminKycReq(
		"/api/v1/admin/kyc/"+adminKycSubjectGcid+"/verify", nil,
		"TENANT_ADMIN", adminKycTenant, adminKycStaffGcid))

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d want 500; body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "KYC_REPO_UNAVAILABLE") {
		t.Errorf("body=%q want KYC_REPO_UNAVAILABLE fragment", w.Body.String())
	}
}

// -----------------------------------------------------------------------------
// reject — invalid transition / save failure / publish failure
// -----------------------------------------------------------------------------

func TestAdminKyc_Extra_Reject_WrongState_Conflict(t *testing.T) {
	t.Parallel()
	h := newAdminKycHarness(t)
	seedManualDoc(t, h.kycRepo, adminKycSubjectGcid, kyc.StatusPending) // never submitted

	w := httptest.NewRecorder()
	h.mux.ServeHTTP(w, adminKycReq(
		"/api/v1/admin/kyc/"+adminKycSubjectGcid+"/reject",
		map[string]any{"code": "doc_illegible"},
		"TENANT_ADMIN", adminKycTenant, adminKycStaffGcid))

	if w.Code != http.StatusConflict {
		t.Fatalf("status=%d want 409; body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "KYC_INVALID_TRANSITION") {
		t.Errorf("body=%q want KYC_INVALID_TRANSITION fragment", w.Body.String())
	}
	if got := len(h.recorder.RecordedByTopic("chora.identity.kyc.rejected.v1")); got != 0 {
		t.Errorf("no event on invalid transition, got %d", got)
	}
}

func TestAdminKyc_Extra_Reject_SaveError_500(t *testing.T) {
	t.Parallel()
	inner := repo.NewInMemKycRepo()
	seedManualDoc(t, inner, adminKycSubjectGcid, kyc.StatusSubmitted)
	h := httpadapter.NewAdminKycVerifyHandler(&saveErrKycRepo{inner: inner}, nil, nil)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	w := httptest.NewRecorder()
	mux.ServeHTTP(w, adminKycReq(
		"/api/v1/admin/kyc/"+adminKycSubjectGcid+"/reject",
		map[string]any{"code": "doc_illegible"},
		"TENANT_ADMIN", adminKycTenant, adminKycStaffGcid))

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d want 500; body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "KYC_REPO_ERROR") {
		t.Errorf("body=%q want KYC_REPO_ERROR fragment", w.Body.String())
	}
}

func TestAdminKyc_Extra_Reject_PublishError_Still200(t *testing.T) {
	t.Parallel()
	kycRepo := repo.NewInMemKycRepo()
	seedManualDoc(t, kycRepo, adminKycSubjectGcid, kyc.StatusSubmitted)
	rec := events.NewRecorder()
	h := httpadapter.NewAdminKycVerifyHandler(kycRepo,
		events.NewEconomyPublisher(akxFailingPublisher{}), // typed emit fails → log-only
		events.NewGovernancePublisher(rec))
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	w := httptest.NewRecorder()
	mux.ServeHTTP(w, adminKycReq(
		"/api/v1/admin/kyc/"+adminKycSubjectGcid+"/reject",
		map[string]any{"code": "doc_illegible"},
		"TENANT_ADMIN", adminKycTenant, adminKycStaffGcid))

	if w.Code != http.StatusOK {
		t.Fatalf("status=%d want 200; body=%s", w.Code, w.Body.String())
	}
	out := decodeAdminKycBody(t, w.Body)
	if out["status"] != "rejected" {
		t.Errorf("status=%v want rejected", out["status"])
	}
	v, err := kycRepo.GetLatestByGcid(context.Background(), adminKycSubjectGcid)
	if err != nil {
		t.Fatalf("GetLatestByGcid: %v", err)
	}
	if v.Status != kyc.StatusRejected {
		t.Errorf("persisted status=%q want rejected", v.Status)
	}
	// The governance evidence path must still have recorded (it uses the recorder).
	if got := len(rec.RecordedByTopic("chora.governance.evidence.recorded.v1")); got != 1 {
		t.Errorf("evidence count=%d want 1", got)
	}
}

// -----------------------------------------------------------------------------
// verify — publish failure is log-only
// -----------------------------------------------------------------------------

func TestAdminKyc_Extra_Verify_PublishError_Still200(t *testing.T) {
	t.Parallel()
	kycRepo := repo.NewInMemKycRepo()
	seedManualDoc(t, kycRepo, adminKycSubjectGcid, kyc.StatusSubmitted)
	rec := events.NewRecorder()
	h := httpadapter.NewAdminKycVerifyHandler(kycRepo,
		events.NewEconomyPublisher(akxFailingPublisher{}),
		events.NewGovernancePublisher(rec))
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	w := httptest.NewRecorder()
	mux.ServeHTTP(w, adminKycReq(
		"/api/v1/admin/kyc/"+adminKycSubjectGcid+"/verify", nil,
		"TENANT_ADMIN", adminKycTenant, adminKycStaffGcid))

	if w.Code != http.StatusOK {
		t.Fatalf("status=%d want 200; body=%s", w.Code, w.Body.String())
	}
	out := decodeAdminKycBody(t, w.Body)
	if out["status"] != "verified" {
		t.Errorf("status=%v want verified", out["status"])
	}
	v, err := kycRepo.GetLatestByGcid(context.Background(), adminKycSubjectGcid)
	if err != nil {
		t.Fatalf("GetLatestByGcid: %v", err)
	}
	if v.Status != kyc.StatusVerified {
		t.Errorf("persisted status=%q want verified", v.Status)
	}
}

// -----------------------------------------------------------------------------
// emitEvidence — RecordEvidence failure is logged loudly, response stays 200
// -----------------------------------------------------------------------------

func TestAdminKyc_Extra_EvidenceEmitError_Still200(t *testing.T) {
	t.Parallel()
	kycRepo := repo.NewInMemKycRepo()
	seedManualDoc(t, kycRepo, adminKycSubjectGcid, kyc.StatusSubmitted)
	rec := events.NewRecorder()
	h := httpadapter.NewAdminKycVerifyHandler(kycRepo,
		events.NewEconomyPublisher(rec),
		events.NewGovernancePublisher(akxFailingPublisher{})) // evidence emit fails → log-only
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	w := httptest.NewRecorder()
	mux.ServeHTTP(w, adminKycReq(
		"/api/v1/admin/kyc/"+adminKycSubjectGcid+"/verify", nil,
		"TENANT_ADMIN", adminKycTenant, adminKycStaffGcid))

	if w.Code != http.StatusOK {
		t.Fatalf("status=%d want 200; body=%s", w.Code, w.Body.String())
	}
	out := decodeAdminKycBody(t, w.Body)
	if out["status"] != "verified" {
		t.Errorf("status=%v want verified (evidence failure must not block verify)", out["status"])
	}
	// The typed kyc.verified.v1 emit (healthy recorder) must still be recorded.
	if got := len(rec.RecordedByTopic("chora.identity.kyc.verified.v1")); got != 1 {
		t.Errorf("kyc.verified.v1 count=%d want 1", got)
	}
	if got := len(rec.RecordedByTopic("chora.governance.evidence.recorded.v1")); got != 0 {
		t.Errorf("failed evidence must not be recorded, got %d", got)
	}
}

// -----------------------------------------------------------------------------
// ServeHTTP — {gcid}/{action} path-parse 404
// -----------------------------------------------------------------------------

func TestAdminKyc_Extra_BadPathShape_NotFound(t *testing.T) {
	t.Parallel()
	h := newAdminKycHarness(t)
	seedManualDoc(t, h.kycRepo, adminKycSubjectGcid, kyc.StatusSubmitted)

	// Case 1: subtree root with no {gcid}/{action} remainder at all.
	w1 := httptest.NewRecorder()
	h.mux.ServeHTTP(w1, adminKycReq(
		"/api/v1/admin/kyc/", nil,
		"TENANT_ADMIN", adminKycTenant, adminKycStaffGcid))
	if w1.Code != http.StatusNotFound {
		t.Fatalf("empty-rest status=%d want 404; body=%s", w1.Code, w1.Body.String())
	}
	if !strings.Contains(w1.Body.String(), "IDENTITY_NOT_FOUND") ||
		!strings.Contains(w1.Body.String(), "path must be") {
		t.Errorf("body=%q want IDENTITY_NOT_FOUND + path must be fragment", w1.Body.String())
	}

	// Case 2: extra trailing segment → 3 parts, also not {gcid}/verify|reject.
	w2 := httptest.NewRecorder()
	h.mux.ServeHTTP(w2, adminKycReq(
		"/api/v1/admin/kyc/"+adminKycSubjectGcid+"/verify/extra", nil,
		"TENANT_ADMIN", adminKycTenant, adminKycStaffGcid))
	if w2.Code != http.StatusNotFound {
		t.Fatalf("trailing-segment status=%d want 404; body=%s", w2.Code, w2.Body.String())
	}

	// No state change + no event on either parse failure.
	if got := len(h.recorder.RecordedByTopic("chora.identity.kyc.verified.v1")); got != 0 {
		t.Errorf("no event on path-parse 404, got %d", got)
	}
	v, _ := h.kycRepo.GetLatestByGcid(context.Background(), adminKycSubjectGcid)
	if v.Status != kyc.StatusSubmitted {
		t.Errorf("status=%q after 404, want unchanged submitted", v.Status)
	}
}
