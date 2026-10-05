// internal_verification_handler_test.go — tests for the INTERNAL
// service-to-service by-GCID verification-claim read (ADR-190 D2). Drives the
// handler through ServeHTTP with a real in-memory kyc.Repository seed.
package httpadapter_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	httpadapter "github.com/apollo-chora/chora-identity/internal/adapter/http"
	"github.com/apollo-chora/chora-identity/internal/adapter/repo"
	"github.com/apollo-chora/chora-identity/internal/domain/kyc"
)

// errKycRepo is a kyc.Repository whose reads fail with a non-ErrNotFound error,
// exercising the fail-loud 500 path.
type errKycRepo struct{}

func (errKycRepo) Save(context.Context, *kyc.Verification) error { return errors.New("boom") }
func (errKycRepo) GetByID(context.Context, string) (*kyc.Verification, error) {
	return nil, errors.New("boom")
}
func (errKycRepo) GetLatestByGcid(context.Context, string) (*kyc.Verification, error) {
	return nil, errors.New("boom")
}

// seedVerified saves a fully-VERIFIED singpass verification for gcid.
func seedVerified(t *testing.T, r kyc.Repository, gcid string) {
	t.Helper()
	v, err := kyc.NewVerification(kyc.NewParams{Gcid: gcid, Method: kyc.MethodSingpass, Provider: "ndi"})
	if err != nil {
		t.Fatalf("new verification: %v", err)
	}
	if err := v.Submit("singpass:"+v.VerificationID, 0, "USD"); err != nil {
		t.Fatalf("submit: %v", err)
	}
	if err := v.Verify("ndi", false); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if err := r.Save(context.Background(), v); err != nil {
		t.Fatalf("save: %v", err)
	}
}

// seedPending saves a still-PENDING verification for gcid (never verified).
func seedPending(t *testing.T, r kyc.Repository, gcid string) {
	t.Helper()
	v, err := kyc.NewVerification(kyc.NewParams{Gcid: gcid, Method: kyc.MethodManualDoc, Provider: "internal_review"})
	if err != nil {
		t.Fatalf("new verification: %v", err)
	}
	if err := r.Save(context.Background(), v); err != nil {
		t.Fatalf("save: %v", err)
	}
}

func doGet(t *testing.T, h http.Handler, target string) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, target, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var body map[string]any
	if rec.Body.Len() > 0 {
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("decode body %q: %v", rec.Body.String(), err)
		}
	}
	return rec.Code, body
}

func TestInternalVerification_VerifiedGCID_ReturnsTrue(t *testing.T) {
	kycRepo := repo.NewInMemKycRepo()
	seedVerified(t, kycRepo, "gcid-verified")
	h := httpadapter.NewInternalVerificationHandler(kycRepo)

	code, body := doGet(t, h, "/internal/v1/identity/verification-status?gcid=gcid-verified")
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}
	if body["verified"] != true {
		t.Errorf("verified = %v, want true", body["verified"])
	}
	if body["status"] != "verified" {
		t.Errorf("status = %v, want verified", body["status"])
	}
	if body["gcid"] != "gcid-verified" {
		t.Errorf("gcid = %v, want gcid-verified", body["gcid"])
	}
}

func TestInternalVerification_UnknownGCID_ReturnsFalse(t *testing.T) {
	kycRepo := repo.NewInMemKycRepo()
	h := httpadapter.NewInternalVerificationHandler(kycRepo)

	code, body := doGet(t, h, "/internal/v1/identity/verification-status?gcid=nobody")
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}
	if body["verified"] != false {
		t.Errorf("verified = %v, want false", body["verified"])
	}
	if body["status"] != "unverified" {
		t.Errorf("status = %v, want unverified", body["status"])
	}
}

func TestInternalVerification_PendingGCID_ReturnsFalse(t *testing.T) {
	kycRepo := repo.NewInMemKycRepo()
	seedPending(t, kycRepo, "gcid-pending")
	h := httpadapter.NewInternalVerificationHandler(kycRepo)

	code, body := doGet(t, h, "/internal/v1/identity/verification-status?gcid=gcid-pending")
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}
	if body["verified"] != false {
		t.Errorf("verified = %v, want false (pending claim is not VERIFIED)", body["verified"])
	}
	if body["status"] != "pending" {
		t.Errorf("status = %v, want pending", body["status"])
	}
}

func TestInternalVerification_MissingGCID_Returns400(t *testing.T) {
	kycRepo := repo.NewInMemKycRepo()
	h := httpadapter.NewInternalVerificationHandler(kycRepo)

	code, _ := doGet(t, h, "/internal/v1/identity/verification-status")
	if code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", code)
	}
}

func TestInternalVerification_WrongMethod_Returns405(t *testing.T) {
	kycRepo := repo.NewInMemKycRepo()
	h := httpadapter.NewInternalVerificationHandler(kycRepo)

	req := httptest.NewRequest(http.MethodPost, "/internal/v1/identity/verification-status?gcid=x", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", rec.Code)
	}
}

func TestInternalVerification_NilRepo_Returns500(t *testing.T) {
	h := httpadapter.NewInternalVerificationHandler(nil)
	code, _ := doGet(t, h, "/internal/v1/identity/verification-status?gcid=x")
	if code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 (nil repo must fail loud, never silent-false)", code)
	}
}

func TestInternalVerification_RepoError_Returns500(t *testing.T) {
	h := httpadapter.NewInternalVerificationHandler(errKycRepo{})
	code, _ := doGet(t, h, "/internal/v1/identity/verification-status?gcid=x")
	if code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 (infra error must fail loud)", code)
	}
}

func TestInternalVerification_RegisterRoutes_Mounts(t *testing.T) {
	kycRepo := repo.NewInMemKycRepo()
	seedVerified(t, kycRepo, "gcid-mounted")
	mux := http.NewServeMux()
	httpadapter.NewInternalVerificationHandler(kycRepo).RegisterRoutes(mux)

	code, body := doGet(t, mux, "/internal/v1/identity/verification-status?gcid=gcid-mounted")
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200 via RegisterRoutes mount", code)
	}
	if body["verified"] != true {
		t.Errorf("verified = %v, want true", body["verified"])
	}
}
