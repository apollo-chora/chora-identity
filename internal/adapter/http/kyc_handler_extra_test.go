// Additional KYC handler specs for coverage parity (S6.3 §7).
package httpadapter_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/apollo-chora/chora-identity/internal/domain/kyc"
)

// overallStatus branch coverage — drives the verified_skillsfuture +
// verified_manual + rejected + expired branches via direct repo seed.

func TestKyc_GetStatus_VerifiedSkillsfuture(t *testing.T) {
	t.Parallel()
	h := newKycServer(t)
	v, _ := kyc.NewVerification(kyc.NewParams{Gcid: kycTestGcid, Method: kyc.MethodSkillsFuture, Provider: "ssg"})
	_ = v.Submit("u", 0, "USD")
	_ = v.Verify("admin", true)
	_ = h.kycRepo.Save(context.Background(), v)

	w := httptest.NewRecorder()
	h.mux.ServeHTTP(w, bearerKyc(http.MethodGet, "/v1/me/kyc/status", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d", w.Code)
	}
	got := mustJSONFromBody(t, w.Body)
	if got["overall_status"] != "verified_skillsfuture" {
		t.Errorf("overall_status=%v", got["overall_status"])
	}
}

func TestKyc_GetStatus_VerifiedManual(t *testing.T) {
	t.Parallel()
	h := newKycServer(t)
	v, _ := kyc.NewVerification(kyc.NewParams{Gcid: kycTestGcid, Method: kyc.MethodManualDoc, Provider: "internal_review"})
	_ = v.Submit("u", 999, "USD")
	_ = v.Verify("admin", false)
	_ = h.kycRepo.Save(context.Background(), v)

	w := httptest.NewRecorder()
	h.mux.ServeHTTP(w, bearerKyc(http.MethodGet, "/v1/me/kyc/status", nil))
	got := mustJSONFromBody(t, w.Body)
	if got["overall_status"] != "verified_manual" {
		t.Errorf("overall_status=%v", got["overall_status"])
	}
}

func TestKyc_GetStatus_Rejected(t *testing.T) {
	t.Parallel()
	h := newKycServer(t)
	v, _ := kyc.NewVerification(kyc.NewParams{Gcid: kycTestGcid, Method: kyc.MethodManualDoc, Provider: "internal_review"})
	_ = v.Submit("u", 999, "USD")
	_ = v.Reject("docs_unclear", "blurry", true)
	_ = h.kycRepo.Save(context.Background(), v)

	w := httptest.NewRecorder()
	h.mux.ServeHTTP(w, bearerKyc(http.MethodGet, "/v1/me/kyc/status", nil))
	got := mustJSONFromBody(t, w.Body)
	if got["overall_status"] != "rejected" {
		t.Errorf("overall_status=%v", got["overall_status"])
	}
	if got["rejection_code"] != "docs_unclear" {
		t.Errorf("rejection_code=%v", got["rejection_code"])
	}
}

func TestKyc_GetStatus_Expired(t *testing.T) {
	t.Parallel()
	h := newKycServer(t)
	v, _ := kyc.NewVerification(kyc.NewParams{Gcid: kycTestGcid, Method: kyc.MethodSingpass, Provider: "ndi"})
	_ = v.MarkExpired()
	_ = h.kycRepo.Save(context.Background(), v)

	w := httptest.NewRecorder()
	h.mux.ServeHTTP(w, bearerKyc(http.MethodGet, "/v1/me/kyc/status", nil))
	got := mustJSONFromBody(t, w.Body)
	if got["overall_status"] != "expired" {
		t.Errorf("overall_status=%v", got["overall_status"])
	}
}

func TestKyc_InitiateSingpass_RejectsWrongMethod(t *testing.T) {
	t.Parallel()
	h := newKycServer(t)
	w := httptest.NewRecorder()
	h.mux.ServeHTTP(w, bearerKyc(http.MethodGet, "/v1/me/kyc/singpass", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status=%d want 405", w.Code)
	}
}

func TestKyc_SingpassCallback_RejectsWrongMethod(t *testing.T) {
	t.Parallel()
	h := newKycServer(t)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/v1/me/kyc/singpass/callback?code=x&state=y", nil)
	h.mux.ServeHTTP(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status=%d want 405", w.Code)
	}
}

func TestKyc_SingpassCallback_MissingParams(t *testing.T) {
	t.Parallel()
	h := newKycServer(t)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/v1/me/kyc/singpass/callback", nil)
	h.mux.ServeHTTP(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status=%d want 400", w.Code)
	}
}

func TestKyc_ManualSubmit_RejectsMissingDocFront(t *testing.T) {
	t.Parallel()
	h := newKycServer(t)
	// Empty multipart — no doc front.
	r := httptest.NewRequest(http.MethodPost, "/v1/me/kyc/manual", nil)
	r.Header.Set("Authorization", "Bearer "+kycTestGcid)
	r.Header.Set("Content-Type", "multipart/form-data; boundary=xx")
	w := httptest.NewRecorder()
	h.mux.ServeHTTP(w, r)
	if w.Code < 400 {
		t.Errorf("status=%d want 4xx", w.Code)
	}
}

func TestKyc_ManualSubmit_RejectsWrongMethod(t *testing.T) {
	t.Parallel()
	h := newKycServer(t)
	w := httptest.NewRecorder()
	h.mux.ServeHTTP(w, bearerKyc(http.MethodGet, "/v1/me/kyc/manual", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status=%d want 405", w.Code)
	}
}

func TestKyc_GetStatus_RejectsWrongMethod(t *testing.T) {
	t.Parallel()
	h := newKycServer(t)
	w := httptest.NewRecorder()
	h.mux.ServeHTTP(w, bearerKyc(http.MethodPost, "/v1/me/kyc/status", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status=%d want 405", w.Code)
	}
}

func TestKyc_MyInfoPrefill_RejectsWrongMethod(t *testing.T) {
	t.Parallel()
	h := newKycServer(t)
	w := httptest.NewRecorder()
	h.mux.ServeHTTP(w, bearerKyc(http.MethodPost, "/v1/me/myinfo-prefill", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status=%d want 405", w.Code)
	}
}

// Path A: the prefill route returns 404 regardless of query params.
func TestKyc_MyInfoPrefill_DefaultForParam_DeprecatedUnderPathA(t *testing.T) {
	t.Parallel()
	h := newKycServer(t)

	// Verify flow first.
	w := httptest.NewRecorder()
	h.mux.ServeHTTP(w, bearerKyc(http.MethodPost, "/v1/me/kyc/singpass", nil))
	got := mustJSONFromBody(t, w.Body)
	state := got["state"].(string)
	cw := httptest.NewRecorder()
	cr := httptest.NewRequest(http.MethodGet,
		"/v1/me/kyc/singpass/callback?code=AC&state="+state, nil)
	cr.Header.Set("traceparent", "00-aabbccddeeff00112233445566778899-0011223344556677-01")
	h.mux.ServeHTTP(cw, cr)

	// Without ?for= param, route still 404s under Path A.
	pw := httptest.NewRecorder()
	h.mux.ServeHTTP(pw, bearerKyc(http.MethodGet, "/v1/me/myinfo-prefill", nil))
	if pw.Code != http.StatusNotFound {
		t.Fatalf("status=%d want 404 (Path A deprecation)", pw.Code)
	}
}
