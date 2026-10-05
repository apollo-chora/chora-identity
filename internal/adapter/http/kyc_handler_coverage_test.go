// kyc_handler_coverage_test.go — branch-completion specs for
// services/chora-identity/internal/adapter/http/kyc_handler.go.
//
// Extends the existing KYC specs (kyc_handler_test.go + extras) with the
// previously-uncovered branches:
//
//	InMemSingpassStateRepository.Get  missing-key + expired branches,
//	                                Delete (missing entirely)
//	initiateSingpass   state-repo Put failure, Singpass auth-URL failure,
//	                   resolveTenantID header + dev-fallback branches
//	singpassCallback   GetByID not-found, UserInfo failure, non-pending
//	                   Submit, SingpassSub re-bind conflict, verbatim
//	                   persist failure at the tail, and best-effort
//	                   emission with nil / failing publishers
//	recordRejection    non-pending (already submitted) branch + persist
//	                   failure still emitting the rejection event
//	emitIMDAEvidence   nil GovernancePublisher + RecordEvidence failure
//	submitManual       missing document_type (422), persist failure (500),
//	                   and the three chora-payments error shapes
//	getStatus          repository failure (500) + the remaining
//	overallStatus      submitted / pending / unknown-method / unknown-status
//	                   branches
//
// All helpers defined here are prefixed `kxc` so they can never collide with
// the existing suite's fakes and builders. No production code is touched.
package httpadapter_test

import (
	"bytes"
	"context"
	"errors"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/apollo-chora/chora-identity/internal/adapter/events"
	httpadapter "github.com/apollo-chora/chora-identity/internal/adapter/http"
	"github.com/apollo-chora/chora-identity/internal/adapter/idp/singpass"
	"github.com/apollo-chora/chora-identity/internal/adapter/inmem"
	"github.com/apollo-chora/chora-identity/internal/adapter/payments"
	"github.com/apollo-chora/chora-identity/internal/adapter/repo"
	"github.com/apollo-chora/chora-identity/internal/domain/identity"
	"github.com/apollo-chora/chora-identity/internal/domain/kyc"
)

// -----------------------------------------------------------------------------
// Shared scaffolding (kxc-prefixed so nothing collides with existing helpers)
// -----------------------------------------------------------------------------

// kxcLiveUsers returns a user repo seeded with the canonical kycTestGcid so
// the bearer-auth middleware accepts requests built by bearerKyc.
func kxcLiveUsers(t *testing.T) *inmem.UserRepository {
	t.Helper()
	users := inmem.NewUserRepository()
	u, err := identity.NewUser(identity.NewUserParams{
		Email: "kxc@chora.dev", IdentityProvider: identity.ProviderOIDC, FederatedSubject: "kxc-1",
	})
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}
	u.Gcid = kycTestGcid
	if err := users.Save(context.Background(), u); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	return users
}

// kxcBaseServer returns a fully-wired KycHandlerConfig built from the
// standard in-memory fakes + recorder, plus the concrete inner KYC repo (for
// seeding/assertions) and the shared singpass/payments fakes (for fault
// injection). Callers override the fields they need to reach a seam.
func kxcBaseServer(t *testing.T) (httpadapter.KycHandlerConfig, *events.Recorder, *repo.InMemKycRepo, *fakeSingpassClient, *fakeKycPayments) {
	t.Helper()
	inner := repo.NewInMemKycRepo()
	rec := events.NewRecorder()
	sing := &fakeSingpassClient{}
	pay := &fakeKycPayments{}
	cfg := httpadapter.KycHandlerConfig{
		Users:         kxcLiveUsers(t),
		KycRepo:       inner,
		PrefillRepo:   repo.NewInMemPrefillRepo(),
		StateRepo:     httpadapter.NewInMemSingpassStateRepository(),
		Singpass:      sing,
		EconomyPub:    events.NewEconomyPublisher(rec),
		GovernancePub: events.NewGovernancePublisher(rec),
		Payments:      pay,
	}
	return cfg, rec, inner, sing, pay
}

// kxcHandlerMux mounts a fully-built KycHandler onto a fresh mux.
func kxcHandlerMux(cfg httpadapter.KycHandlerConfig) *http.ServeMux {
	mux := http.NewServeMux()
	httpadapter.NewKycHandler(cfg).RegisterRoutes(mux)
	return mux
}

// kxcPutState seeds a short-lived Singpass state token pointing at the given
// verification id.
func kxcPutState(t *testing.T, r httpadapter.SingpassStateRepository, state, verifID string) {
	t.Helper()
	if err := r.Put(context.Background(), &httpadapter.SingpassStateRecord{
		State:          state,
		Gcid:           kycTestGcid,
		TenantID:       kycTestTenant,
		CodeVerifier:   "kxc-verifier",
		VerificationID: verifID,
		CreatedAt:      time.Now().UTC(),
		ExpiresAt:      time.Now().UTC().Add(10 * time.Minute),
	}); err != nil {
		t.Fatalf("seed state: %v", err)
	}
}

// kxcCallbackReq builds an unauthenticated Singpass callback request.
func kxcCallbackReq(state, code string) *http.Request {
	r := httptest.NewRequest(http.MethodGet,
		"/v1/me/kyc/singpass/callback?code="+code+"&state="+state, nil)
	r.Header.Set("traceparent", "00-aabbccddeeff00112233445566778899-0011223344556677-01")
	return r
}

// kxcInitiate runs POST /v1/me/kyc/singpass and returns the minted state.
func kxcInitiate(t *testing.T, mux *http.ServeMux) string {
	t.Helper()
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, bearerKyc(http.MethodPost, "/v1/me/kyc/singpass", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("initiate status=%d body=%s", w.Code, w.Body.String())
	}
	return mustJSONFromBody(t, w.Body)["state"].(string)
}

// kxcManualMultipart renders a manual-KYC multipart body. fields are written
// verbatim (e.g. document_type); withFront adds the document_front file part.
func kxcManualMultipart(t *testing.T, fields map[string]string, withFront bool) (*bytes.Buffer, string) {
	t.Helper()
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	for k, v := range fields {
		_ = mw.WriteField(k, v)
	}
	if withFront {
		fw, err := mw.CreateFormFile("document_front", "front.jpg")
		if err != nil {
			t.Fatalf("form file: %v", err)
		}
		_, _ = fw.Write([]byte("fake-jpeg"))
	}
	_ = mw.Close()
	return &body, mw.FormDataContentType()
}

// kxcManualRequest POSTs a multipart manual KYC submission with bearer auth.
func kxcManualRequest(mux *http.ServeMux, body *bytes.Buffer, contentType string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "/v1/me/kyc/manual", body)
	r.Header.Set("Authorization", "Bearer "+kycTestGcid)
	r.Header.Set("Content-Type", contentType)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	return w
}

// kxcSeedPendingVerification inserts a fresh singpass verification (pending).
func kxcSeedPendingVerification(t *testing.T, r *repo.InMemKycRepo, gcid string) *kyc.Verification {
	t.Helper()
	v, err := kyc.NewVerification(kyc.NewParams{Gcid: gcid, Method: kyc.MethodSingpass, Provider: "ndi"})
	if err != nil {
		t.Fatalf("seed new verification: %v", err)
	}
	if err := r.Save(context.Background(), v); err != nil {
		t.Fatalf("seed save verification: %v", err)
	}
	return v
}

// kxcSeedSubmittedVerification inserts a singpass verification that has
// already entered the review queue (submitted).
func kxcSeedSubmittedVerification(t *testing.T, r *repo.InMemKycRepo, gcid string) *kyc.Verification {
	t.Helper()
	v := kxcSeedPendingVerification(t, r, gcid)
	if err := v.Submit("singpass:"+v.VerificationID, 0, "USD"); err != nil {
		t.Fatalf("seed submit: %v", err)
	}
	if err := r.Save(context.Background(), v); err != nil {
		t.Fatalf("seed save submitted: %v", err)
	}
	return v
}

// -----------------------------------------------------------------------------
// Fault-injection fakes (all kxc-prefixed)
// -----------------------------------------------------------------------------

// kxcFailingStateRepo satisfies SingpassStateRepository but fails every Put —
// used to prove initiateSingpass fails loud (500) when the state token cannot
// be persisted.
type kxcFailingStateRepo struct{}

func (kxcFailingStateRepo) Put(context.Context, *httpadapter.SingpassStateRecord) error {
	return errors.New("redis: state put failed")
}
func (kxcFailingStateRepo) Get(context.Context, string) (*httpadapter.SingpassStateRecord, error) {
	return nil, errors.New("redis: state get failed")
}
func (kxcFailingStateRepo) Delete(context.Context, string) error { return nil }
func (kxcFailingStateRepo) GetAndConsume(context.Context, string) (*httpadapter.SingpassStateRecord, error) {
	return nil, errors.New("redis: state consume failed")
}

// kxcAuthErrSingpassClient satisfies SingpassClient but fails to build the
// /authorize URL — the last seam of initiateSingpass.
type kxcAuthErrSingpassClient struct{}

func (kxcAuthErrSingpassClient) AuthorizationURL(state, codeChallenge string) (string, error) {
	return "", errors.New("singpass: authorize endpoint unavailable")
}
func (kxcAuthErrSingpassClient) ExchangeCode(context.Context, string, string) (*singpass.Tokens, error) {
	return &singpass.Tokens{AccessToken: "at", IDToken: "id"}, nil
}
func (kxcAuthErrSingpassClient) UserInfo(context.Context, string) (*singpass.UserInfo, error) {
	return &singpass.UserInfo{Sub: "01970000-1111-7000-8000-0000000000a0"}, nil
}

// kxcLatestErrKycRepo wraps the in-memory repo but fails every
// GetLatestByGcid — reaches the 500 branch of getStatus.
type kxcLatestErrKycRepo struct {
	inner *repo.InMemKycRepo
}

func (r *kxcLatestErrKycRepo) Save(ctx context.Context, v *kyc.Verification) error {
	return r.inner.Save(ctx, v)
}
func (r *kxcLatestErrKycRepo) GetByID(ctx context.Context, id string) (*kyc.Verification, error) {
	return r.inner.GetByID(ctx, id)
}
func (*kxcLatestErrKycRepo) GetLatestByGcid(context.Context, string) (*kyc.Verification, error) {
	return nil, errors.New("pg: query failed")
}

// kxcFailingPub is an events.Publisher that always fails — proves the KYC
// handler treats emission as best-effort.
type kxcFailingPub struct{}

func (kxcFailingPub) Publish(string, events.Envelope, map[string]any) error {
	return errors.New("pubsub: publish failed")
}

// -----------------------------------------------------------------------------
// InMemSingpassStateRepository — Get missing/expired + Delete
// -----------------------------------------------------------------------------

func TestKycCoverage_InMemStateRepo_Delete_RemovesAndMissingIsHarmless(t *testing.T) {
	t.Parallel()
	repo := httpadapter.NewInMemSingpassStateRepository()
	ctx := context.Background()
	_ = repo.Put(ctx, &httpadapter.SingpassStateRecord{
		State: "kxc-st-delete", Gcid: "g", TenantID: "t",
		ExpiresAt: time.Now().UTC().Add(time.Minute),
	})
	if err := repo.Delete(ctx, "kxc-st-delete"); err != nil {
		t.Fatalf("delete existing: %v", err)
	}
	if _, err := repo.Get(ctx, "kxc-st-delete"); err == nil {
		t.Fatalf("Get after Delete must miss")
	}
	// Deleting a non-existent key is harmless (single-use semantics).
	if err := repo.Delete(ctx, "kxc-st-delete"); err != nil {
		t.Fatalf("delete missing: %v", err)
	}
}

func TestKycCoverage_InMemStateRepo_Get_MissingKey(t *testing.T) {
	t.Parallel()
	repo := httpadapter.NewInMemSingpassStateRepository()
	if _, err := repo.Get(context.Background(), "kxc-st-nope"); err == nil {
		t.Fatalf("Get must fail for unknown state")
	}
}

func TestKycCoverage_InMemStateRepo_Get_Expired(t *testing.T) {
	t.Parallel()
	repo := httpadapter.NewInMemSingpassStateRepository()
	_ = repo.Put(context.Background(), &httpadapter.SingpassStateRecord{
		State: "kxc-st-exp", Gcid: "g", TenantID: "t",
		ExpiresAt: time.Now().UTC().Add(-time.Minute), // already past
	})
	if _, err := repo.Get(context.Background(), "kxc-st-exp"); err == nil {
		t.Fatalf("Get must reject an expired record")
	}
}

// -----------------------------------------------------------------------------
// initiateSingpass — resolveTenantID header/fallback + persist/URL failures
// -----------------------------------------------------------------------------

func TestKycCoverage_InitiateSingpass_TenantFromHeader(t *testing.T) {
	t.Parallel()
	h := newKycServer(t)
	w := httptest.NewRecorder()
	r := bearerKyc(http.MethodPost, "/v1/me/kyc/singpass", nil)
	r.Header.Set("X-Tenant-Id", "01970000-0000-7000-8000-00000000ab12")
	h.mux.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	state := mustJSONFromBody(t, w.Body)["state"].(string)
	st, err := h.stateRepo.Get(context.Background(), state)
	if err != nil {
		t.Fatalf("state not persisted: %v", err)
	}
	if st.TenantID != "01970000-0000-7000-8000-00000000ab12" {
		t.Errorf("TenantID=%q want header value", st.TenantID)
	}
}

func TestKycCoverage_InitiateSingpass_TenantFallback(t *testing.T) {
	t.Parallel()
	h := newKycServer(t)
	w := httptest.NewRecorder()
	// No X-Tenant-Id header and no tenant context → dev fallback.
	h.mux.ServeHTTP(w, bearerKyc(http.MethodPost, "/v1/me/kyc/singpass", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	state := mustJSONFromBody(t, w.Body)["state"].(string)
	st, err := h.stateRepo.Get(context.Background(), state)
	if err != nil {
		t.Fatalf("state not persisted: %v", err)
	}
	if st.TenantID != kycTestTenant {
		t.Errorf("TenantID=%q want dev fallback %q", st.TenantID, kycTestTenant)
	}
}

func TestKycCoverage_InitiateSingpass_StatePersistFailure(t *testing.T) {
	t.Parallel()
	cfg, _, _, _, _ := kxcBaseServer(t)
	cfg.StateRepo = kxcFailingStateRepo{}
	w := httptest.NewRecorder()
	kxcHandlerMux(cfg).ServeHTTP(w, bearerKyc(http.MethodPost, "/v1/me/kyc/singpass", nil))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d want 500 body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "KYC_STATE_PERSIST_FAILED") {
		t.Errorf("body=%s want KYC_STATE_PERSIST_FAILED", w.Body.String())
	}
}

func TestKycCoverage_InitiateSingpass_VerificationPersistFailure(t *testing.T) {
	t.Parallel()
	cfg, _, inner, _, _ := kxcBaseServer(t)
	cfg.KycRepo = &saveErrKycRepo{inner: inner} // Save fails before the state token is minted
	w := httptest.NewRecorder()
	kxcHandlerMux(cfg).ServeHTTP(w, bearerKyc(http.MethodPost, "/v1/me/kyc/singpass", nil))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d want 500 body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "KYC_REPO_ERROR") {
		t.Errorf("body=%s want KYC_REPO_ERROR", w.Body.String())
	}
}

func TestKycCoverage_InitiateSingpass_AuthURLFailure(t *testing.T) {
	t.Parallel()
	cfg, _, _, _, _ := kxcBaseServer(t)
	cfg.Singpass = kxcAuthErrSingpassClient{}
	w := httptest.NewRecorder()
	kxcHandlerMux(cfg).ServeHTTP(w, bearerKyc(http.MethodPost, "/v1/me/kyc/singpass", nil))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d want 500 body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "SINGPASS_URL_BUILD_FAILED") {
		t.Errorf("body=%s want SINGPASS_URL_BUILD_FAILED", w.Body.String())
	}
}

// -----------------------------------------------------------------------------
// singpassCallback — repo/transition/persist failure branches
// -----------------------------------------------------------------------------

func TestKycCoverage_Callback_VerificationNotFound_Returns500(t *testing.T) {
	t.Parallel()
	h := newKycServer(t)
	// State token exists but its verification was never persisted.
	kxcPutState(t, h.stateRepo, "kxc-st-orphan", "01970000-0000-7000-8000-00000000dead")
	cw := httptest.NewRecorder()
	h.mux.ServeHTTP(cw, kxcCallbackReq("kxc-st-orphan", "AC-1"))
	if cw.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d want 500 body=%s", cw.Code, cw.Body.String())
	}
	if !strings.Contains(cw.Body.String(), "KYC_REPO_ERROR") {
		t.Errorf("body=%s want KYC_REPO_ERROR", cw.Body.String())
	}
}

func TestKycCoverage_Callback_UserInfoFailure_EmitsRejection(t *testing.T) {
	t.Parallel()
	h := newKycServer(t)
	h.singpass.userInfoErr = errors.New("userinfo exploded")
	state := kxcInitiate(t, h.mux)

	cw := httptest.NewRecorder()
	h.mux.ServeHTTP(cw, kxcCallbackReq(state, "AC-1"))
	if cw.Code != http.StatusBadGateway {
		t.Fatalf("status=%d want 502 body=%s", cw.Code, cw.Body.String())
	}
	if !strings.Contains(cw.Body.String(), "SINGPASS_USERINFO_FETCH_FAILED") {
		t.Errorf("body=%s want SINGPASS_USERINFO_FETCH_FAILED", cw.Body.String())
	}
	// Rejection emitted: kyc.rejected.v1 + IMDA safety_and_robustness (D3).
	if got := len(h.recorder.RecordedByTopic("chora.identity.kyc.rejected.v1")); got != 1 {
		t.Errorf("kyc.rejected.v1 count=%d want 1", got)
	}
	imda := h.recorder.RecordedByTopic(events.EvidenceTopic)
	if len(imda) == 0 || imda[0].Payload["chora_imda_dimension"] != "safety_and_robustness" {
		t.Errorf("IMDA rejection evidence missing, got %d records", len(imda))
	}
	// The pending verification was submitted then rejected.
	v, err := h.kycRepo.GetLatestByGcid(context.Background(), kycTestGcid)
	if err != nil {
		t.Fatalf("GetLatestByGcid: %v", err)
	}
	if v.Status != kyc.StatusRejected {
		t.Errorf("status=%q want rejected", v.Status)
	}
}

func TestKycCoverage_Callback_SubmitFailsOnNonPending_Returns500(t *testing.T) {
	t.Parallel()
	h := newKycServer(t)
	// A state token pointing at an already-submitted verification — the
	// callback's Submit transition must fail, not double-submit.
	v := kxcSeedSubmittedVerification(t, h.kycRepo, kycTestGcid)
	kxcPutState(t, h.stateRepo, "kxc-st-submitted", v.VerificationID)

	cw := httptest.NewRecorder()
	h.mux.ServeHTTP(cw, kxcCallbackReq("kxc-st-submitted", "AC-1"))
	if cw.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d want 500 body=%s", cw.Code, cw.Body.String())
	}
	if !strings.Contains(cw.Body.String(), "KYC_INVALID_TRANSITION") {
		t.Errorf("body=%s want KYC_INVALID_TRANSITION", cw.Body.String())
	}
}

func TestKycCoverage_Callback_BindSingpassSubConflict_EmitsRejection(t *testing.T) {
	t.Parallel()
	h := newKycServer(t)
	// The verification already carries a different Singpass `sub` — the
	// callback's bind is one-singpass-account-per-verification.
	v := kxcSeedPendingVerification(t, h.kycRepo, kycTestGcid)
	if err := v.BindSingpassSub("01970000-aaaa-7000-8000-0000000000aa"); err != nil {
		t.Fatalf("seed bind: %v", err)
	}
	if err := h.kycRepo.Save(context.Background(), v); err != nil {
		t.Fatalf("seed save: %v", err)
	}
	kxcPutState(t, h.stateRepo, "kxc-st-bindconflict", v.VerificationID)
	h.singpass.userInfo = &fakeUserInfo{Sub: "01970000-bbbb-7000-8000-0000000000bb"}

	cw := httptest.NewRecorder()
	h.mux.ServeHTTP(cw, kxcCallbackReq("kxc-st-bindconflict", "AC-1"))
	if cw.Code != http.StatusConflict {
		t.Fatalf("status=%d want 409 body=%s", cw.Code, cw.Body.String())
	}
	if !strings.Contains(cw.Body.String(), "SINGPASS_SUB_BIND_FAILED") {
		t.Errorf("body=%s want SINGPASS_SUB_BIND_FAILED", cw.Body.String())
	}
	// recordRejection ran on a NON-pending (already submitted) verification —
	// the Submit must be skipped, the reject still persisted + emitted.
	if got := len(h.recorder.RecordedByTopic("chora.identity.kyc.rejected.v1")); got != 1 {
		t.Errorf("kyc.rejected.v1 count=%d want 1", got)
	}
	v2, err := h.kycRepo.GetLatestByGcid(context.Background(), kycTestGcid)
	if err != nil {
		t.Fatalf("GetLatestByGcid: %v", err)
	}
	if v2.Status != kyc.StatusRejected {
		t.Errorf("status=%q want rejected", v2.Status)
	}
}

func TestKycCoverage_Callback_PersistFailureAtEnd_Returns500(t *testing.T) {
	t.Parallel()
	cfg, rec, inner, _, _ := kxcBaseServer(t)
	cfg.KycRepo = &saveErrKycRepo{inner: inner} // GetByID works, Save fails
	mux := kxcHandlerMux(cfg)
	v := kxcSeedPendingVerification(t, inner, kycTestGcid)
	kxcPutState(t, cfg.StateRepo, "kxc-st-savefail", v.VerificationID)

	cw := httptest.NewRecorder()
	mux.ServeHTTP(cw, kxcCallbackReq("kxc-st-savefail", "AC-1"))
	if cw.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d want 500 body=%s", cw.Code, cw.Body.String())
	}
	if !strings.Contains(cw.Body.String(), "KYC_REPO_ERROR") {
		t.Errorf("body=%s want KYC_REPO_ERROR", cw.Body.String())
	}
	// Fail loud: no kyc.verified.v1 may be emitted when the write did not land.
	if got := len(rec.RecordedByTopic("chora.identity.kyc.verified.v1")); got != 0 {
		t.Errorf("kyc.verified.v1 count=%d want 0", got)
	}
}

func TestKycCoverage_Callback_RejectionPersistFailure_StillEmits(t *testing.T) {
	t.Parallel()
	cfg, rec, inner, sing, _ := kxcBaseServer(t)
	cfg.KycRepo = &saveErrKycRepo{inner: inner}
	sing.exchangeErr = errors.New("invalid_grant")
	mux := kxcHandlerMux(cfg)
	v := kxcSeedPendingVerification(t, inner, kycTestGcid)
	kxcPutState(t, cfg.StateRepo, "kxc-st-rejsave", v.VerificationID)

	cw := httptest.NewRecorder()
	mux.ServeHTTP(cw, kxcCallbackReq("kxc-st-rejsave", "AC-1"))
	if cw.Code != http.StatusBadGateway {
		t.Fatalf("status=%d want 502 body=%s", cw.Code, cw.Body.String())
	}
	// recordRejection's own Save failure is logged; the rejection event is
	// still emitted best-effort.
	if got := len(rec.RecordedByTopic("chora.identity.kyc.rejected.v1")); got != 1 {
		t.Errorf("kyc.rejected.v1 count=%d want 1", got)
	}
}

func TestKycCoverage_Callback_RejectionOnTerminalVerification_BailsOut(t *testing.T) {
	t.Parallel()
	cfg, rec, inner, sing, _ := kxcBaseServer(t)
	// A verification already in a terminal state cannot be rejected — the
	// transition error is logged and recordRejection returns early.
	v, err := kyc.NewVerification(kyc.NewParams{Gcid: kycTestGcid, Method: kyc.MethodSingpass, Provider: "ndi"})
	if err != nil {
		t.Fatalf("seed new verification: %v", err)
	}
	if err := v.Submit("singpass:"+v.VerificationID, 0, "USD"); err != nil {
		t.Fatalf("seed submit: %v", err)
	}
	if err := v.Verify("ndi", false); err != nil {
		t.Fatalf("seed verify: %v", err)
	}
	if err := inner.Save(context.Background(), v); err != nil {
		t.Fatalf("seed save: %v", err)
	}
	sing.exchangeErr = errors.New("invalid_grant")
	mux := kxcHandlerMux(cfg)
	kxcPutState(t, cfg.StateRepo, "kxc-st-terminal", v.VerificationID)

	cw := httptest.NewRecorder()
	mux.ServeHTTP(cw, kxcCallbackReq("kxc-st-terminal", "AC-1"))
	if cw.Code != http.StatusBadGateway {
		t.Fatalf("status=%d want 502 body=%s", cw.Code, cw.Body.String())
	}
	if !strings.Contains(cw.Body.String(), "SINGPASS_TOKEN_EXCHANGE_FAILED") {
		t.Errorf("body=%s want SINGPASS_TOKEN_EXCHANGE_FAILED", cw.Body.String())
	}
	// Early return: NO rejection event and NO old rejection evidence.
	if got := len(rec.RecordedByTopic("chora.identity.kyc.rejected.v1")); got != 0 {
		t.Errorf("kyc.rejected.v1 count=%d want 0 (reject transition failed)", got)
	}
}

func TestKycCoverage_Callback_RejectionPublishFailure_StillEmitsEvidence(t *testing.T) {
	t.Parallel()
	cfg, rec, inner, sing, _ := kxcBaseServer(t)
	cfg.EconomyPub = events.NewEconomyPublisher(kxcFailingPub{}) // publish fails, evidence still emitted
	sing.exchangeErr = errors.New("invalid_grant")
	mux := kxcHandlerMux(cfg)
	v := kxcSeedPendingVerification(t, inner, kycTestGcid)
	kxcPutState(t, cfg.StateRepo, "kxc-st-rejpub", v.VerificationID)

	cw := httptest.NewRecorder()
	mux.ServeHTTP(cw, kxcCallbackReq("kxc-st-rejpub", "AC-1"))
	if cw.Code != http.StatusBadGateway {
		t.Fatalf("status=%d want 502 body=%s", cw.Code, cw.Body.String())
	}
	if got := len(rec.RecordedByTopic("chora.identity.kyc.rejected.v1")); got != 0 {
		t.Errorf("kyc.rejected.v1 count=%d want 0 (publisher injected failure)", got)
	}
	// IMDA evidence goes through the recorder-backed GovernancePublisher.
	imda := rec.RecordedByTopic(events.EvidenceTopic)
	if len(imda) == 0 || imda[0].Payload["chora_imda_dimension"] != "safety_and_robustness" {
		t.Errorf("IMDA rejection evidence missing, got %d records", len(imda))
	}
}

func TestKycCoverage_Callback_NilPublishers_BestEffortEmissionSkipped(t *testing.T) {
	t.Parallel()
	cfg, _, inner, sing, _ := kxcBaseServer(t)
	cfg.EconomyPub = nil
	cfg.GovernancePub = nil
	mux := kxcHandlerMux(cfg)

	// Verify path: no emission, still 200 + persisted verified.
	state := kxcInitiate(t, mux)
	cw := httptest.NewRecorder()
	mux.ServeHTTP(cw, kxcCallbackReq(state, "AC-1"))
	if cw.Code != http.StatusOK {
		t.Fatalf("callback status=%d body=%s", cw.Code, cw.Body.String())
	}
	v, err := inner.GetLatestByGcid(context.Background(), kycTestGcid)
	if err != nil {
		t.Fatalf("GetLatestByGcid: %v", err)
	}
	if v.Status != kyc.StatusVerified {
		t.Errorf("status=%q want verified", v.Status)
	}

	// Rejection path: recordRejection + emitIMDAEvidence tolerate nil pubs.
	sing.exchangeErr = errors.New("invalid_grant")
	v2 := kxcSeedPendingVerification(t, inner, kycTestGcid)
	kxcPutState(t, cfg.StateRepo, "kxc-st-nilpub-rej", v2.VerificationID)
	cw2 := httptest.NewRecorder()
	mux.ServeHTTP(cw2, kxcCallbackReq("kxc-st-nilpub-rej", "AC-2"))
	if cw2.Code != http.StatusBadGateway {
		t.Fatalf("rejection status=%d want 502 body=%s", cw2.Code, cw2.Body.String())
	}
}

func TestKycCoverage_Callback_PublishFailures_StillVerifies(t *testing.T) {
	t.Parallel()
	cfg, _, inner, _, _ := kxcBaseServer(t)
	cfg.EconomyPub = events.NewEconomyPublisher(kxcFailingPub{})
	cfg.GovernancePub = events.NewGovernancePublisher(kxcFailingPub{})
	mux := kxcHandlerMux(cfg)

	state := kxcInitiate(t, mux)
	cw := httptest.NewRecorder()
	mux.ServeHTTP(cw, kxcCallbackReq(state, "AC-1"))
	if cw.Code != http.StatusOK {
		t.Fatalf("callback status=%d body=%s", cw.Code, cw.Body.String())
	}
	// The durable state write is the contract; publish failures only log.
	v, err := inner.GetLatestByGcid(context.Background(), kycTestGcid)
	if err != nil {
		t.Fatalf("GetLatestByGcid: %v", err)
	}
	if v.Status != kyc.StatusVerified {
		t.Errorf("status=%q want verified", v.Status)
	}
}

// -----------------------------------------------------------------------------
// submitManual — validation + persist + chora-payments failure branches
// -----------------------------------------------------------------------------

func TestKycCoverage_ManualSubmit_MissingDocType_422(t *testing.T) {
	t.Parallel()
	h := newKycServer(t)
	body, ctype := kxcManualMultipart(t, nil, true) // document_front only
	w := kxcManualRequest(h.mux, body, ctype)
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status=%d want 422 body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "KYC_DOC_TYPE_REQUIRED") {
		t.Errorf("body=%s want KYC_DOC_TYPE_REQUIRED", w.Body.String())
	}
}

func TestKycCoverage_ManualSubmit_MissingDocFront_422(t *testing.T) {
	t.Parallel()
	h := newKycServer(t)
	// A well-formed multipart parse (document_type present) but no uploaded
	// file part — reaches the FormFile guard (the older spec only exercised
	// the malformed-multipart 400 path).
	body, ctype := kxcManualMultipart(t, map[string]string{"document_type": "manual_passport"}, false)
	w := kxcManualRequest(h.mux, body, ctype)
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status=%d want 422 body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "KYC_DOC_FRONT_REQUIRED") {
		t.Errorf("body=%s want KYC_DOC_FRONT_REQUIRED", w.Body.String())
	}
}

func TestKycCoverage_ManualSubmit_PersistFailure_500(t *testing.T) {
	t.Parallel()
	cfg, _, _, _, _ := kxcBaseServer(t)
	cfg.KycRepo = &saveErrKycRepo{inner: repo.NewInMemKycRepo()}
	mux := kxcHandlerMux(cfg)
	body, ctype := kxcManualMultipart(t, map[string]string{"document_type": "manual_passport"}, true)
	w := kxcManualRequest(mux, body, ctype)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d want 500 body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "KYC_REPO_ERROR") {
		t.Errorf("body=%s want KYC_REPO_ERROR", w.Body.String())
	}
}

func TestKycCoverage_ManualSubmit_PaymentsUnavailable_502(t *testing.T) {
	t.Parallel()
	h := newKycServer(t)
	h.payments.err = payments.ErrPaymentsUnavailable
	body, ctype := kxcManualMultipart(t, map[string]string{"document_type": "manual_passport"}, true)
	w := kxcManualRequest(h.mux, body, ctype)
	if w.Code != http.StatusBadGateway {
		t.Fatalf("status=%d want 502 body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "KYC_PAYMENTS_UNAVAILABLE") {
		t.Errorf("body=%s want KYC_PAYMENTS_UNAVAILABLE", w.Body.String())
	}
}

func TestKycCoverage_ManualSubmit_PaymentsInvalidInput_422(t *testing.T) {
	t.Parallel()
	h := newKycServer(t)
	h.payments.err = payments.ErrInvalidInput
	body, ctype := kxcManualMultipart(t, map[string]string{"document_type": "manual_passport"}, true)
	w := kxcManualRequest(h.mux, body, ctype)
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status=%d want 422 body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "KYC_PAYMENT_INVALID") {
		t.Errorf("body=%s want KYC_PAYMENT_INVALID", w.Body.String())
	}
}

func TestKycCoverage_ManualSubmit_PaymentsGenericError_500(t *testing.T) {
	t.Parallel()
	h := newKycServer(t)
	h.payments.err = errors.New("stripe: checkout declined")
	body, ctype := kxcManualMultipart(t, map[string]string{"document_type": "manual_passport"}, true)
	w := kxcManualRequest(h.mux, body, ctype)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d want 500 body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "KYC_PAYMENT_ERROR") {
		t.Errorf("body=%s want KYC_PAYMENT_ERROR", w.Body.String())
	}
}

// -----------------------------------------------------------------------------
// getStatus + overallStatus — repository failure and the remaining statuses
// -----------------------------------------------------------------------------

func TestKycCoverage_GetStatus_RepoError_500(t *testing.T) {
	t.Parallel()
	cfg, _, inner, _, _ := kxcBaseServer(t)
	cfg.KycRepo = &kxcLatestErrKycRepo{inner: inner}
	mux := kxcHandlerMux(cfg)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, bearerKyc(http.MethodGet, "/v1/me/kyc/status", nil))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d want 500 body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "KYC_REPO_ERROR") {
		t.Errorf("body=%s want KYC_REPO_ERROR", w.Body.String())
	}
}

func TestKycCoverage_GetStatus_Submitted_ReportsPending(t *testing.T) {
	t.Parallel()
	h := newKycServer(t)
	kxcSeedSubmittedVerification(t, h.kycRepo, kycTestGcid)
	sw := httptest.NewRecorder()
	h.mux.ServeHTTP(sw, bearerKyc(http.MethodGet, "/v1/me/kyc/status", nil))
	if sw.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", sw.Code, sw.Body.String())
	}
	if got := mustJSONFromBody(t, sw.Body)["overall_status"]; got != "pending" {
		t.Errorf("overall_status=%v want pending", got)
	}
}

func TestKycCoverage_GetStatus_Pending_ReportsPending(t *testing.T) {
	t.Parallel()
	h := newKycServer(t)
	kxcSeedPendingVerification(t, h.kycRepo, kycTestGcid)
	sw := httptest.NewRecorder()
	h.mux.ServeHTTP(sw, bearerKyc(http.MethodGet, "/v1/me/kyc/status", nil))
	if sw.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", sw.Code, sw.Body.String())
	}
	if got := mustJSONFromBody(t, sw.Body)["overall_status"]; got != "pending" {
		t.Errorf("overall_status=%v want pending", got)
	}
}

func TestKycCoverage_GetStatus_VerifiedUnknownMethod_ReportsVerified(t *testing.T) {
	t.Parallel()
	h := newKycServer(t)
	now := time.Now().UTC()
	// A verified verification whose method is outside the three known methods
	// falls through to the generic "verified" label.
	if err := h.kycRepo.Save(context.Background(), &kyc.Verification{
		VerificationID: "kxc-v-unknown-method",
		Gcid:           kycTestGcid,
		Method:         kyc.Method("corporate_doc"),
		Status:         kyc.StatusVerified,
		Provider:       "internal_review",
		CreatedAt:      now,
		UpdatedAt:      now,
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	sw := httptest.NewRecorder()
	h.mux.ServeHTTP(sw, bearerKyc(http.MethodGet, "/v1/me/kyc/status", nil))
	if sw.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", sw.Code, sw.Body.String())
	}
	if got := mustJSONFromBody(t, sw.Body)["overall_status"]; got != "verified" {
		t.Errorf("overall_status=%v want verified", got)
	}
}

func TestKycCoverage_GetStatus_UnknownStatus_ReportsUnverified(t *testing.T) {
	t.Parallel()
	h := newKycServer(t)
	now := time.Now().UTC()
	// A status outside the closed FSM vocabulary falls through to
	// "unverified" — the defensive default of overallStatus.
	if err := h.kycRepo.Save(context.Background(), &kyc.Verification{
		VerificationID: "kxc-v-unknown-status",
		Gcid:           kycTestGcid,
		Method:         kyc.MethodSingpass,
		Status:         kyc.Status(""),
		Provider:       "ndi",
		CreatedAt:      now,
		UpdatedAt:      now,
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	sw := httptest.NewRecorder()
	h.mux.ServeHTTP(sw, bearerKyc(http.MethodGet, "/v1/me/kyc/status", nil))
	if sw.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", sw.Code, sw.Body.String())
	}
	if got := mustJSONFromBody(t, sw.Body)["overall_status"]; got != "unverified" {
		t.Errorf("overall_status=%v want unverified", got)
	}
}
