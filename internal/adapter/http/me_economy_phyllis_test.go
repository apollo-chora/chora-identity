// Phyllis MVP S2.1 deltas: Singpass redirect URL via env var (no inline
// config) per audit-identity-fillgaps.md §3.7 + §3.8.
//
// Per ADR-164 Wave 1 Stage E: the per-user Stripe-customer route
// (/v1/me/billing/stripe-customer) is RETIRED. Stripe Customer lifecycle is
// now owned by chora-payments at first Checkout Session.
package httpadapter_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	httpadapter "github.com/apollo-chora/chora-identity/internal/adapter/http"
	"github.com/apollo-chora/chora-identity/internal/adapter/inmem"
	"github.com/apollo-chora/chora-identity/internal/adapter/repo"
	"github.com/apollo-chora/chora-identity/internal/domain/identity"
)

// helper — build an EconomyHandler with explicit (env-driven) Singpass +
// chora-payments config. This forces wiring through the new options so we can
// assert env-driven values appear on the wire (no inline-config violation).
func newConfiguredEconomyServer(t *testing.T, opts httpadapter.EconomyHandlerOptions) http.Handler {
	t.Helper()
	users := inmem.NewUserRepository()
	u, _ := identity.NewUser(identity.NewUserParams{
		Email: "ec@chora.dev", IdentityProvider: identity.ProviderOIDC, FederatedSubject: "ec-1",
	})
	u.Gcid = economyTestGcid
	if err := users.Save(context.Background(), u); err != nil {
		t.Fatalf("seed: %v", err)
	}
	subs := repo.NewInMemUserSubscriptionRepo()
	manaStore := repo.NewInMemManaStore()
	kycRepo := repo.NewInMemKycRepo()

	mux := http.NewServeMux()
	h := httpadapter.NewEconomyHandlerWithOptions(users, subs, manaStore, kycRepo, defaultFakePayments(), nil, opts)
	h.RegisterRoutes(mux)
	return mux
}

// -----------------------------------------------------------------------------
// Singpass redirect URL — must come from env var, NOT inline.
// -----------------------------------------------------------------------------

func TestInitiateSingpass_RedirectURLFromEnv(t *testing.T) {
	t.Parallel()
	srv := newConfiguredEconomyServer(t, httpadapter.EconomyHandlerOptions{
		SingpassAuthURL: "https://stg-id.singpass.gov.sg/auth",
	})

	w := httptest.NewRecorder()
	srv.ServeHTTP(w, bearerJSON(http.MethodPost, "/api/v1/me/kyc/singpass:initiate", economyTestGcid, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	got := mustJSON(t, w.Body)
	url, _ := got["redirect_url"].(string)
	if !strings.HasPrefix(url, "https://stg-id.singpass.gov.sg/auth?state=") {
		t.Fatalf("expected env-driven URL prefix; got %q", url)
	}
}

func TestInitiateSingpass_RedirectURLProductionAware(t *testing.T) {
	t.Parallel()
	// Production NDI URL via env var — confirms the handler is NOT inlining
	// stg-id.* anywhere.
	srv := newConfiguredEconomyServer(t, httpadapter.EconomyHandlerOptions{
		SingpassAuthURL: "https://id.singpass.gov.sg/auth",
	})
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, bearerJSON(http.MethodPost, "/api/v1/me/kyc/singpass:initiate", economyTestGcid, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	got := mustJSON(t, w.Body)
	url, _ := got["redirect_url"].(string)
	if !strings.HasPrefix(url, "https://id.singpass.gov.sg/auth?state=") {
		t.Fatalf("expected prod URL prefix; got %q", url)
	}
}

func TestInitiateSingpass_MisconfiguredErrors(t *testing.T) {
	t.Parallel()
	// Empty SingpassAuthURL → 500 IDENTITY_PASSKEY_MISCONFIGURED-like error.
	srv := newConfiguredEconomyServer(t, httpadapter.EconomyHandlerOptions{
		SingpassAuthURL: "",
	})
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, bearerJSON(http.MethodPost, "/api/v1/me/kyc/singpass:initiate", economyTestGcid, nil))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 on missing config; got %d body=%s", w.Code, w.Body.String())
	}
	got := mustJSON(t, w.Body)
	if !strings.Contains(strings.ToLower(got["code"].(string)), "misconfigured") {
		t.Fatalf("expected misconfigured-flagged error; got %v", got["code"])
	}
}

// -----------------------------------------------------------------------------
// /v1/me/billing/stripe-customer is RETIRED per ADR-164 Wave 1 Stage E.
// Verify the route is NOT mounted (the Stripe Customer is now created
// lazily by chora-payments at first Checkout Session).
// -----------------------------------------------------------------------------

func TestStripeCustomerRoute_IsRetired(t *testing.T) {
	t.Parallel()
	srv := newConfiguredEconomyServer(t, httpadapter.EconomyHandlerOptions{
		SingpassAuthURL: "https://stg-id.singpass.gov.sg/auth",
	})

	w := httptest.NewRecorder()
	srv.ServeHTTP(w, bearerJSON(http.MethodPost, "/v1/me/billing/stripe-customer", economyTestGcid, map[string]any{
		"email": "phyllis@mightymind.sg",
	}))
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404 (route retired); got %d body=%s", w.Code, w.Body.String())
	}
}
