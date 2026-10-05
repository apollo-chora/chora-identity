// Package httpadapter_test — RED-phase TDD specs for the dedicated KYC HTTP
// handler under chora-identity (S6.3 A-Singpass deliverable §2-3).
//
// Routes implemented in kyc_handler.go:
//
//	POST /v1/me/kyc/singpass            — initiate Singpass KYC; mints state token + auth URL
//	GET  /v1/me/kyc/singpass/callback   — handle Singpass callback; exchanges code, MyInfo, verifies
//	POST /v1/me/kyc/manual              — manual review queue ($9.99 charge per ADR-142)
//	GET  /v1/me/kyc/status              — current KYC status
//	GET  /v1/me/myinfo-prefill?for=course_application — redacted prefill payload
//
// All Singpass URLs sourced from env (no inline config). The handler depends
// on a singpass.SingpassClient interface (port) so tests can inject fakes.
//
// Per ADR-141 IMDA evidence emission:
//   - kyc.verified.v1   → accountability    (D1) + lifecycle_stage runtime
//   - kyc.rejected.v1   → safety_and_robustness (D3) + lifecycle_stage runtime
package httpadapter_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/apollo-chora/chora-identity/internal/adapter/events"
	httpadapter "github.com/apollo-chora/chora-identity/internal/adapter/http"
	"github.com/apollo-chora/chora-identity/internal/adapter/idp/singpass"
	"github.com/apollo-chora/chora-identity/internal/adapter/inmem"
	"github.com/apollo-chora/chora-identity/internal/adapter/payments"
	"github.com/apollo-chora/chora-identity/internal/adapter/repo"
	"github.com/apollo-chora/chora-identity/internal/domain/identity"
	"github.com/apollo-chora/chora-identity/internal/domain/kyc"
)

const kycTestGcid = "01970000-0000-7000-8000-00000000ec0a"
const kycTestTenant = "01970000-0000-7000-8000-0000000000aa"

// -----------------------------------------------------------------------------
// fakeSingpassClient implements httpadapter.SingpassClient for testing.
// -----------------------------------------------------------------------------

// fakeUserInfo is a Path A-style /userinfo response — it carries only the
// OIDC `sub` claim (UUID) plus optional `email` for non-PII envelopes. The
// Path A invariant forbids Chora from persisting anything except `sub`, so
// the test scaffolding only needs the `sub` field.
type fakeUserInfo struct {
	Sub   string
	Email string
	Name  string
}

type fakeSingpassClient struct {
	authURL         string
	exchangeTokens  *singpass.Tokens
	exchangeErr     error
	userInfo        *fakeUserInfo
	userInfoErr     error
	exchangeCalls   int
	userInfoCalls   int
	personCalls     int // pinned at 0 under Path A — drift signals regression.
	lastCode        string
	lastVerifier    string
	lastAccessToken string
}

func (f *fakeSingpassClient) AuthorizationURL(state, codeChallenge string) (string, error) {
	if f.authURL == "" {
		return "https://stg-id.singpass.gov.sg/auth?state=" + state + "&code_challenge=" + codeChallenge, nil
	}
	return f.authURL + "?state=" + state, nil
}

func (f *fakeSingpassClient) ExchangeCode(_ context.Context, code, verifier string) (*singpass.Tokens, error) {
	f.exchangeCalls++
	f.lastCode = code
	f.lastVerifier = verifier
	if f.exchangeErr != nil {
		return nil, f.exchangeErr
	}
	if f.exchangeTokens != nil {
		return f.exchangeTokens, nil
	}
	return &singpass.Tokens{AccessToken: "at-userinfo", IDToken: "id-tok"}, nil
}

func (f *fakeSingpassClient) UserInfo(_ context.Context, accessToken string) (*singpass.UserInfo, error) {
	f.userInfoCalls++
	f.lastAccessToken = accessToken
	if f.userInfoErr != nil {
		return nil, f.userInfoErr
	}
	if f.userInfo != nil {
		return &singpass.UserInfo{
			Sub:   f.userInfo.Sub,
			Name:  f.userInfo.Name,  // discarded by handler under Path A
			Email: f.userInfo.Email, // discarded by handler under Path A
		}, nil
	}
	return &singpass.UserInfo{
		Sub: "01970000-1111-7000-8000-0000000000a0",
	}, nil
}

// -----------------------------------------------------------------------------
// newKycServer wires the dedicated KYC handler. Returns the mux + the
// publishers + the in-memory state-token repo for assertions.
// -----------------------------------------------------------------------------

type kycServerHarness struct {
	mux         *http.ServeMux
	recorder    *events.Recorder
	stateRepo   httpadapter.SingpassStateRepository
	kycRepo     *repo.InMemKycRepo
	prefillRepo *repo.InMemPrefillRepo
	users       *inmem.UserRepository
	singpass    *fakeSingpassClient
	payments    *fakeKycPayments
}

// fakeKycPayments implements httpadapter.PaymentsKycClient — returns a
// deterministic Checkout Session unless an error is injected.
type fakeKycPayments struct {
	out  payments.CreateKycFeeOutput
	err  error
	last payments.CreateKycFeeInput
}

func (f *fakeKycPayments) CreateKycFee(_ context.Context, in payments.CreateKycFeeInput) (payments.CreateKycFeeOutput, error) {
	f.last = in
	if f.err != nil {
		return payments.CreateKycFeeOutput{}, f.err
	}
	if f.out.PurchaseID == "" && f.out.StripeCheckoutURL == "" {
		return payments.CreateKycFeeOutput{
			PurchaseID:        "01970000-0000-7000-8000-000000000777",
			StripeSessionID:   "cs_test_kyc",
			StripeCheckoutURL: "https://checkout.stripe.com/c/test_kyc",
			State:             "checkout_started",
		}, nil
	}
	return f.out, nil
}

func newKycServer(t *testing.T) *kycServerHarness {
	t.Helper()
	users := inmem.NewUserRepository()
	u, _ := identity.NewUser(identity.NewUserParams{
		Email: "kyc@chora.dev", IdentityProvider: identity.ProviderOIDC, FederatedSubject: "kyc-1",
	})
	u.Gcid = kycTestGcid
	if err := users.Save(context.Background(), u); err != nil {
		t.Fatalf("seed: %v", err)
	}

	kycRepo := repo.NewInMemKycRepo()
	prefillRepo := repo.NewInMemPrefillRepo()
	stateRepo := httpadapter.NewInMemSingpassStateRepository()

	rec := events.NewRecorder()
	economyPub := events.NewEconomyPublisher(rec)
	govPub := events.NewGovernancePublisher(rec)

	singClient := &fakeSingpassClient{}
	payClient := &fakeKycPayments{}

	h := httpadapter.NewKycHandler(httpadapter.KycHandlerConfig{
		Users:           users,
		KycRepo:         kycRepo,
		PrefillRepo:     prefillRepo,
		StateRepo:       stateRepo,
		Singpass:        singClient,
		EconomyPub:      economyPub,
		GovernancePub:   govPub,
		RedirectURI:     "https://chora.site/v1/me/kyc/singpass/callback",
		ManaultFeeCents: kyc.DefaultFeeCents(kyc.MethodManualDoc),
		Payments:        payClient,
	})

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	return &kycServerHarness{
		mux:         mux,
		recorder:    rec,
		stateRepo:   stateRepo,
		kycRepo:     kycRepo,
		prefillRepo: prefillRepo,
		users:       users,
		singpass:    singClient,
		payments:    payClient,
	}
}

func bearerKyc(method, path string, body any) *http.Request {
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	r := httptest.NewRequest(method, path, &buf)
	r.Header.Set("Authorization", "Bearer "+kycTestGcid)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("traceparent", "00-aabbccddeeff00112233445566778899-0011223344556677-01")
	return r
}

func mustJSONFromBody(t *testing.T, body *bytes.Buffer) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(body.Bytes(), &out); err != nil {
		t.Fatalf("invalid json: %v body=%s", err, body.String())
	}
	return out
}

// -----------------------------------------------------------------------------
// POST /v1/me/kyc/singpass — initiate
// -----------------------------------------------------------------------------

func TestKyc_InitiateSingpass_HappyPath(t *testing.T) {
	t.Parallel()
	h := newKycServer(t)
	w := httptest.NewRecorder()
	h.mux.ServeHTTP(w, bearerKyc(http.MethodPost, "/v1/me/kyc/singpass", map[string]any{
		"return_url": "https://app.chora.site/me/kyc",
	}))
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	got := mustJSONFromBody(t, w.Body)
	if got["redirect_url"] == nil {
		t.Errorf("redirect_url missing")
	}
	if !strings.Contains(got["redirect_url"].(string), "state=") {
		t.Errorf("redirect_url missing state param: %v", got["redirect_url"])
	}
	if got["state"] == nil {
		t.Errorf("state missing")
	}
	// State token persisted with PKCE verifier.
	st, err := h.stateRepo.Get(context.Background(), got["state"].(string))
	if err != nil || st == nil {
		t.Errorf("state not persisted: %v", err)
	}
	if st.Gcid != kycTestGcid {
		t.Errorf("state.Gcid=%q", st.Gcid)
	}
	if st.CodeVerifier == "" {
		t.Errorf("state.CodeVerifier empty")
	}
}

// -----------------------------------------------------------------------------
// GET /v1/me/kyc/singpass/callback — completes flow + emits IMDA evidence
// -----------------------------------------------------------------------------

// TestKyc_SingpassCallback_HappyPath_PathA verifies the Singpass callback
// happy path under Path A scope minimisation:
//   - SingpassSub bound on Verification
//   - status transitioned to verified
//   - kyc.verified.v1 + IMDA accountability evidence emitted
//   - NO MyInfoPrefill persisted (Path A drops that aggregate)
func TestKyc_SingpassCallback_HappyPath_PathA(t *testing.T) {
	t.Parallel()
	h := newKycServer(t)

	// Pre-stage state token via initiate.
	w := httptest.NewRecorder()
	h.mux.ServeHTTP(w, bearerKyc(http.MethodPost, "/v1/me/kyc/singpass", nil))
	got := mustJSONFromBody(t, w.Body)
	state := got["state"].(string)

	// Now hit the callback (which is unauthenticated by GCID — security
	// comes from state-token possession + PKCE verifier persistence).
	cw := httptest.NewRecorder()
	cr := httptest.NewRequest(http.MethodGet,
		"/v1/me/kyc/singpass/callback?code=AC-1&state="+state, nil)
	cr.Header.Set("traceparent", "00-aabbccddeeff00112233445566778899-0011223344556677-01")
	h.mux.ServeHTTP(cw, cr)
	if cw.Code != http.StatusOK && cw.Code != http.StatusFound {
		t.Fatalf("callback status=%d body=%s", cw.Code, cw.Body.String())
	}

	// Singpass /token + /userinfo exchanged. Per Path A, /person (MyInfo)
	// must NOT be called.
	if h.singpass.exchangeCalls != 1 || h.singpass.userInfoCalls != 1 {
		t.Errorf("exchangeCalls=%d userInfoCalls=%d", h.singpass.exchangeCalls, h.singpass.userInfoCalls)
	}
	if h.singpass.personCalls != 0 {
		t.Errorf("Path A: MyInfoPerson must NOT be called; got %d", h.singpass.personCalls)
	}
	if h.singpass.lastCode != "AC-1" {
		t.Errorf("lastCode=%q", h.singpass.lastCode)
	}

	// KYC verification persisted as verified_singpass with SingpassSub bound.
	v, err := h.kycRepo.GetLatestByGcid(context.Background(), kycTestGcid)
	if err != nil {
		t.Fatalf("GetLatestByGcid: %v", err)
	}
	if v.Status != kyc.StatusVerified {
		t.Errorf("status=%q want verified", v.Status)
	}
	if v.Method != kyc.MethodSingpass {
		t.Errorf("method=%q want singpass", v.Method)
	}
	if v.SingpassSub == "" {
		t.Errorf("SingpassSub should be bound from /userinfo response")
	}

	// Path A: NO MyInfoPrefill persisted.
	if h.prefillRepo.HasPrefill(kycTestGcid) {
		t.Errorf("Path A: MyInfoPrefill must NOT be persisted; closure map allows only singpass_sub")
	}

	// IMDA evidence emitted: accountability (D1) + lifecycle runtime.
	imdaRecs := h.recorder.RecordedByTopic(events.EvidenceTopic)
	if len(imdaRecs) == 0 {
		t.Fatalf("no IMDA evidence emitted")
	}
	rec := imdaRecs[0]
	if rec.Payload["chora_imda_dimension"] != "accountability" {
		t.Errorf("chora_imda_dimension=%v want accountability", rec.Payload["chora_imda_dimension"])
	}
	if rec.Payload["imda_lifecycle_stage"] != "runtime" {
		t.Errorf("imda_lifecycle_stage=%v want runtime", rec.Payload["imda_lifecycle_stage"])
	}

	// kyc.verified.v1 emitted.
	verifiedRecs := h.recorder.RecordedByTopic("chora.identity.kyc.verified.v1")
	if len(verifiedRecs) == 0 {
		t.Errorf("no kyc.verified.v1 emitted")
	}
}

func TestKyc_SingpassCallback_RejectsUnknownState(t *testing.T) {
	t.Parallel()
	h := newKycServer(t)
	cw := httptest.NewRecorder()
	cr := httptest.NewRequest(http.MethodGet,
		"/v1/me/kyc/singpass/callback?code=ANY&state=does-not-exist", nil)
	h.mux.ServeHTTP(cw, cr)
	if cw.Code != http.StatusBadRequest && cw.Code != http.StatusUnauthorized {
		t.Errorf("status=%d want 400/401 for unknown state", cw.Code)
	}
}

func TestKyc_SingpassCallback_TokenExchangeFailureEmitsRejection(t *testing.T) {
	t.Parallel()
	h := newKycServer(t)
	h.singpass.exchangeErr = errors.New("invalid_grant")
	// Set userInfo so the path through the callback at least has a non-nil
	// stub if it's somehow exercised; the exchange failure short-circuits
	// before /userinfo runs.
	h.singpass.userInfo = &fakeUserInfo{Sub: "01970000-9999-7000-8000-000000000099"}

	w := httptest.NewRecorder()
	h.mux.ServeHTTP(w, bearerKyc(http.MethodPost, "/v1/me/kyc/singpass", nil))
	got := mustJSONFromBody(t, w.Body)
	state := got["state"].(string)

	cw := httptest.NewRecorder()
	cr := httptest.NewRequest(http.MethodGet,
		"/v1/me/kyc/singpass/callback?code=AC-1&state="+state, nil)
	cr.Header.Set("traceparent", "00-aabbccddeeff00112233445566778899-0011223344556677-01")
	h.mux.ServeHTTP(cw, cr)
	if cw.Code < 400 {
		t.Fatalf("callback status=%d, expected error", cw.Code)
	}

	// IMDA evidence emitted: safety_and_robustness (D3) + lifecycle runtime.
	imdaRecs := h.recorder.RecordedByTopic(events.EvidenceTopic)
	if len(imdaRecs) == 0 {
		t.Fatalf("no IMDA rejection evidence emitted")
	}
	rec := imdaRecs[0]
	if rec.Payload["chora_imda_dimension"] != "safety_and_robustness" {
		t.Errorf("chora_imda_dimension=%v want safety_and_robustness", rec.Payload["chora_imda_dimension"])
	}
	// kyc.rejected.v1 emitted.
	rejRecs := h.recorder.RecordedByTopic("chora.identity.kyc.rejected.v1")
	if len(rejRecs) == 0 {
		t.Errorf("kyc.rejected.v1 missing")
	}
}

// -----------------------------------------------------------------------------
// POST /v1/me/kyc/manual — manual review queue ($9.99 charge per ADR-142)
// -----------------------------------------------------------------------------

// Manual-doc submission charges the $9.99 fee via chora-payments + returns
// a Stripe Checkout URL; the verification stays PENDING until the capture
// event flows back (ADR-142 + ADR-164 Stage A.5).
func TestKyc_ManualSubmit_CreatesCheckoutAndStaysPending(t *testing.T) {
	t.Parallel()
	h := newKycServer(t)

	// multipart body (no payment_method_id — Stripe Checkout collects card)
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	_ = mw.WriteField("document_type", "manual_passport")
	fw, _ := mw.CreateFormFile("document_front", "front.jpg")
	_, _ = fw.Write([]byte("fake-jpeg"))
	_ = mw.Close()

	r := httptest.NewRequest(http.MethodPost, "/v1/me/kyc/manual", &body)
	r.Header.Set("Authorization", "Bearer "+kycTestGcid)
	r.Header.Set("Content-Type", mw.FormDataContentType())
	r.Header.Set("traceparent", "00-aabbccddeeff00112233445566778899-0011223344556677-01")
	w := httptest.NewRecorder()
	h.mux.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	got := mustJSONFromBody(t, w.Body)
	if got["stripe_checkout_url"] != "https://checkout.stripe.com/c/test_kyc" {
		t.Errorf("stripe_checkout_url=%v", got["stripe_checkout_url"])
	}
	if got["status"] != "pending" {
		t.Errorf("status=%v want pending (review-queue entry is fee-gated)", got["status"])
	}
	if got["verification_id"] == nil {
		t.Errorf("verification_id missing")
	}
	// The fee request reached chora-payments with the right doc type + amount.
	if h.payments.last.KYCDocType != "manual_passport" {
		t.Errorf("kyc_doc_type forwarded=%q", h.payments.last.KYCDocType)
	}
	if h.payments.last.AmountCents != kyc.DefaultFeeCents(kyc.MethodManualDoc) {
		t.Errorf("amount_cents forwarded=%d", h.payments.last.AmountCents)
	}
	if h.payments.last.IdempotencyKey != got["verification_id"] {
		t.Errorf("idempotency_key %q != verification_id %v", h.payments.last.IdempotencyKey, got["verification_id"])
	}
}

// The /api/v1 alias resolves to the same consolidated handler.
func TestKyc_ManualSubmit_ApiV1AliasRoutesToSameHandler(t *testing.T) {
	t.Parallel()
	h := newKycServer(t)
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	_ = mw.WriteField("document_type", "manual_id_doc")
	fw, _ := mw.CreateFormFile("document_front", "front.jpg")
	_, _ = fw.Write([]byte("fake"))
	_ = mw.Close()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/me/kyc/manual", &body)
	r.Header.Set("Authorization", "Bearer "+kycTestGcid)
	r.Header.Set("Content-Type", mw.FormDataContentType())
	w := httptest.NewRecorder()
	h.mux.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("api/v1 alias status=%d body=%s", w.Code, w.Body.String())
	}
}

// When chora-payments is unwired, submitManual fails loud (503) rather than
// silently accepting an uncollected fee.
func TestKyc_ManualSubmit_NoPaymentsClient_FailsLoud(t *testing.T) {
	t.Parallel()
	users := inmem.NewUserRepository()
	u, _ := identity.NewUser(identity.NewUserParams{
		Email: "k2@chora.dev", IdentityProvider: identity.ProviderOIDC, FederatedSubject: "k2",
	})
	u.Gcid = kycTestGcid
	_ = users.Save(context.Background(), u)
	h := httpadapter.NewKycHandler(httpadapter.KycHandlerConfig{
		Users:    users,
		KycRepo:  repo.NewInMemKycRepo(),
		Singpass: &fakeSingpassClient{},
		// Payments deliberately nil.
	})
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	_ = mw.WriteField("document_type", "manual_passport")
	fw, _ := mw.CreateFormFile("document_front", "f.jpg")
	_, _ = fw.Write([]byte("x"))
	_ = mw.Close()
	r := httptest.NewRequest(http.MethodPost, "/v1/me/kyc/manual", &body)
	r.Header.Set("Authorization", "Bearer "+kycTestGcid)
	r.Header.Set("Content-Type", mw.FormDataContentType())
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d want 503 body=%s", w.Code, w.Body.String())
	}
}

// -----------------------------------------------------------------------------
// GET /v1/me/kyc/status
// -----------------------------------------------------------------------------

func TestKyc_GetStatus_AfterSingpassVerify_ReturnsVerifiedSingpass(t *testing.T) {
	t.Parallel()
	h := newKycServer(t)

	// Run the verify flow.
	w := httptest.NewRecorder()
	h.mux.ServeHTTP(w, bearerKyc(http.MethodPost, "/v1/me/kyc/singpass", nil))
	got := mustJSONFromBody(t, w.Body)
	state := got["state"].(string)
	cw := httptest.NewRecorder()
	cr := httptest.NewRequest(http.MethodGet,
		"/v1/me/kyc/singpass/callback?code=AC-1&state="+state, nil)
	cr.Header.Set("traceparent", "00-aabbccddeeff00112233445566778899-0011223344556677-01")
	h.mux.ServeHTTP(cw, cr)

	// GET /v1/me/kyc/status
	sw := httptest.NewRecorder()
	h.mux.ServeHTTP(sw, bearerKyc(http.MethodGet, "/v1/me/kyc/status", nil))
	if sw.Code != http.StatusOK {
		t.Fatalf("status fetch=%d body=%s", sw.Code, sw.Body.String())
	}
	got = mustJSONFromBody(t, sw.Body)
	if got["overall_status"] != "verified_singpass" {
		t.Errorf("overall_status=%v want verified_singpass", got["overall_status"])
	}
}

func TestKyc_GetStatus_NoVerification_ReturnsUnverified(t *testing.T) {
	t.Parallel()
	h := newKycServer(t)
	sw := httptest.NewRecorder()
	h.mux.ServeHTTP(sw, bearerKyc(http.MethodGet, "/v1/me/kyc/status", nil))
	if sw.Code != http.StatusOK {
		t.Fatalf("status=%d", sw.Code)
	}
	got := mustJSONFromBody(t, sw.Body)
	if got["overall_status"] != "unverified" {
		t.Errorf("overall_status=%v want unverified", got["overall_status"])
	}
}

// -----------------------------------------------------------------------------
// GET /v1/me/myinfo-prefill?for=course_application
// -----------------------------------------------------------------------------

// Path A: the MyInfoPrefill aggregate is deprecated. The route returns 404
// regardless of whether KYC has been verified. The deprecation reason is
// surfaced in the error code so SPA dev tools can detect drift.
func TestKyc_MyInfoPrefill_AfterVerify_DeprecatedUnderPathA(t *testing.T) {
	t.Parallel()
	h := newKycServer(t)

	// Run the verify flow.
	w := httptest.NewRecorder()
	h.mux.ServeHTTP(w, bearerKyc(http.MethodPost, "/v1/me/kyc/singpass", nil))
	got := mustJSONFromBody(t, w.Body)
	state := got["state"].(string)
	cw := httptest.NewRecorder()
	cr := httptest.NewRequest(http.MethodGet,
		"/v1/me/kyc/singpass/callback?code=AC-1&state="+state, nil)
	cr.Header.Set("traceparent", "00-aabbccddeeff00112233445566778899-0011223344556677-01")
	h.mux.ServeHTTP(cw, cr)

	// Path A: prefill is deprecated — always 404.
	pw := httptest.NewRecorder()
	h.mux.ServeHTTP(pw, bearerKyc(http.MethodGet, "/v1/me/myinfo-prefill?for=course_application", nil))
	if pw.Code != http.StatusNotFound {
		t.Fatalf("status=%d want 404 (Path A deprecation)", pw.Code)
	}
	body := pw.Body.String()
	if !strings.Contains(body, "KYC_PREFILL_DEPRECATED") {
		t.Errorf("body should mention KYC_PREFILL_DEPRECATED; got %s", body)
	}
}

func TestKyc_MyInfoPrefill_WithoutVerify_Returns404(t *testing.T) {
	t.Parallel()
	h := newKycServer(t)
	pw := httptest.NewRecorder()
	h.mux.ServeHTTP(pw, bearerKyc(http.MethodGet, "/v1/me/myinfo-prefill?for=course_application", nil))
	if pw.Code != http.StatusNotFound {
		t.Fatalf("status=%d want 404 (Path A deprecation)", pw.Code)
	}
}

// -----------------------------------------------------------------------------
// Auth — all routes (except callback) require Bearer.
// -----------------------------------------------------------------------------

func TestKycHandler_RoutesRequireBearer(t *testing.T) {
	t.Parallel()
	h := newKycServer(t)
	for _, p := range []string{
		"/v1/me/kyc/status",
		"/v1/me/myinfo-prefill?for=course_application",
	} {
		w := httptest.NewRecorder()
		h.mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, p, nil))
		if w.Code != http.StatusUnauthorized {
			t.Errorf("%s status=%d want 401", p, w.Code)
		}
	}
}
