// kyc_handler_path_a_test.go — RED-phase TDD specs for the Singpass Path A
// scope-minimisation refactor (SP-2).
//
// Path A invariants enforced here:
//  1. The Singpass callback persists ONLY the OIDC `sub` UUID against the
//     KYCVerification aggregate (Verification.SingpassSub). No NRIC/FIN,
//     name, DOB, address, employment, etc. are written.
//  2. The callback uses singpass.UserInfo (which surfaces the `sub` claim),
//     NOT singpass.MyInfoPerson (which surfaces the now-forbidden citizen
//     data envelope).
//  3. The PII_Closure_Map drops the field on closure — covered separately
//     in domain/kyc/singpass_sub_test.go via SoftDelete.
//  4. The /v1/me/myinfo-prefill route always returns 404 — the
//     MyInfoPrefill aggregate is deprecated under Path A.
//
// Companion: services/chora-identity/migrations/0004_singpass_sub_minimisation.sql
//
//	services/chora-identity/config/PII_Closure_Map.yaml
package httpadapter_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/apollo-chora/chora-identity/internal/domain/kyc"
)

// TestKyc_SingpassCallback_PathA_BindsSubOnly asserts the Path A invariant:
// the verification aggregate carries the OIDC `sub` (and NOTHING else) after
// a successful callback.
func TestKyc_SingpassCallback_PathA_BindsSubOnly(t *testing.T) {
	t.Parallel()
	h := newKycServer(t)
	// Pre-stage: the fake UserInfo returns a Path A-shaped UUID sub.
	h.singpass.userInfo = &fakeUserInfo{
		Sub: "01970000-cccc-7000-8000-000000000099",
	}

	// Run initiate → callback.
	w := httptest.NewRecorder()
	h.mux.ServeHTTP(w, bearerKyc(http.MethodPost, "/v1/me/kyc/singpass", nil))
	state := mustJSONFromBody(t, w.Body)["state"].(string)

	cw := httptest.NewRecorder()
	cr := httptest.NewRequest(http.MethodGet,
		"/v1/me/kyc/singpass/callback?code=AC-1&state="+state, nil)
	cr.Header.Set("traceparent", "00-aabbccddeeff00112233445566778899-0011223344556677-01")
	h.mux.ServeHTTP(cw, cr)
	if cw.Code != http.StatusOK {
		t.Fatalf("callback status=%d body=%s", cw.Code, cw.Body.String())
	}

	// Path A: SingpassSub set; no prefill persisted.
	v, err := h.kycRepo.GetLatestByGcid(context.Background(), kycTestGcid)
	if err != nil {
		t.Fatalf("GetLatestByGcid: %v", err)
	}
	if v.SingpassSub != "01970000-cccc-7000-8000-000000000099" {
		t.Errorf("SingpassSub=%q want UUID", v.SingpassSub)
	}
	if v.Status != kyc.StatusVerified {
		t.Errorf("status=%q want verified", v.Status)
	}
	// Per Path A no MyInfoPrefill is persisted.
	if h.prefillRepo.HasPrefill(kycTestGcid) {
		t.Errorf("Path A: MyInfoPrefill must NOT be persisted; closure map only allows singpass_sub")
	}
}

// TestKyc_SingpassCallback_PathA_UsesUserInfoNotMyInfoPerson asserts the
// adapter switches from /person (MyInfo) to /userinfo (OIDC `sub`).
func TestKyc_SingpassCallback_PathA_UsesUserInfoNotMyInfoPerson(t *testing.T) {
	t.Parallel()
	h := newKycServer(t)
	h.singpass.userInfo = &fakeUserInfo{Sub: "01970000-dddd-7000-8000-0000000000aa"}

	w := httptest.NewRecorder()
	h.mux.ServeHTTP(w, bearerKyc(http.MethodPost, "/v1/me/kyc/singpass", nil))
	state := mustJSONFromBody(t, w.Body)["state"].(string)

	cw := httptest.NewRecorder()
	cr := httptest.NewRequest(http.MethodGet,
		"/v1/me/kyc/singpass/callback?code=AC&state="+state, nil)
	h.mux.ServeHTTP(cw, cr)

	if h.singpass.userInfoCalls != 1 {
		t.Errorf("UserInfo not called: got %d", h.singpass.userInfoCalls)
	}
	if h.singpass.personCalls != 0 {
		t.Errorf("MyInfoPerson must NOT be called under Path A; got %d", h.singpass.personCalls)
	}
}

// TestKyc_MyInfoPrefill_Always404UnderPathA asserts the prefill route is
// always 404 (the MyInfoPrefill aggregate is deprecated).
func TestKyc_MyInfoPrefill_Always404UnderPathA(t *testing.T) {
	t.Parallel()
	h := newKycServer(t)
	h.singpass.userInfo = &fakeUserInfo{Sub: "01970000-eeee-7000-8000-0000000000ab"}

	// Run initiate → callback (verify completed)
	w := httptest.NewRecorder()
	h.mux.ServeHTTP(w, bearerKyc(http.MethodPost, "/v1/me/kyc/singpass", nil))
	state := mustJSONFromBody(t, w.Body)["state"].(string)
	cw := httptest.NewRecorder()
	cr := httptest.NewRequest(http.MethodGet,
		"/v1/me/kyc/singpass/callback?code=AC&state="+state, nil)
	h.mux.ServeHTTP(cw, cr)

	// Even after a successful KYC, the prefill route returns 404 because
	// Path A explicitly does NOT persist the MyInfoPrefill aggregate.
	pw := httptest.NewRecorder()
	h.mux.ServeHTTP(pw, bearerKyc(http.MethodGet, "/v1/me/myinfo-prefill?for=course_application", nil))
	if pw.Code != http.StatusNotFound {
		t.Errorf("status=%d want 404 (prefill aggregate is deprecated under Path A)", pw.Code)
	}
}

// TestKyc_SingpassCallback_PathA_BindIdempotent — re-running the callback
// for the same GCID + same sub does not error.
func TestKyc_SingpassCallback_PathA_BindIdempotent(t *testing.T) {
	t.Parallel()
	h := newKycServer(t)
	sub := "01970000-ffff-7000-8000-000000000fff"
	h.singpass.userInfo = &fakeUserInfo{Sub: sub}

	for i := 0; i < 2; i++ {
		w := httptest.NewRecorder()
		h.mux.ServeHTTP(w, bearerKyc(http.MethodPost, "/v1/me/kyc/singpass", nil))
		state := mustJSONFromBody(t, w.Body)["state"].(string)
		cw := httptest.NewRecorder()
		cr := httptest.NewRequest(http.MethodGet,
			"/v1/me/kyc/singpass/callback?code=AC&state="+state, nil)
		h.mux.ServeHTTP(cw, cr)
		// Either 200 (first time, transitions pending→submitted→verified)
		// or any 2xx response on idempotent re-bind. The hard requirement
		// is "no 5xx".
		if cw.Code >= 500 {
			t.Errorf("iteration %d: 5xx body=%s", i, cw.Body.String())
		}
	}
}
