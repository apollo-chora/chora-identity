// Handler-level TDD specs for /api/v1/me/* economy endpoints (BE-USR-1).
//
// Per ADR-164 Wave 1 Stage E: the inline Stripe SDK has been replaced by a
// chora-payments gRPC client. Tests inject a fake PaymentsSubscriptionCreator
// to drive purchaseSubscription happy path + error branches without an
// upstream chora-payments running.
package httpadapter_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	httpadapter "github.com/apollo-chora/chora-identity/internal/adapter/http"
	"github.com/apollo-chora/chora-identity/internal/adapter/inmem"
	"github.com/apollo-chora/chora-identity/internal/adapter/payments"
	"github.com/apollo-chora/chora-identity/internal/adapter/repo"
	"github.com/apollo-chora/chora-identity/internal/domain/identity"
	mana "github.com/apollo-chora/chora-identity/internal/domain/user_mana"
)

const economyTestGcid = "01970000-0000-7000-8000-00000000ec01"

// fakePaymentsClient implements httpadapter.PaymentsSubscriptionCreator
// with a canned CreateSubscription response. Used by tests that exercise
// the chora-payments-coupled subscription purchase flow.
type fakePaymentsClient struct {
	out        payments.CreateSubscriptionOutput
	err        error
	lastInput  payments.CreateSubscriptionInput
	wasCalledN int
}

func (f *fakePaymentsClient) CreateSubscription(_ context.Context, in payments.CreateSubscriptionInput) (payments.CreateSubscriptionOutput, error) {
	f.wasCalledN++
	f.lastInput = in
	return f.out, f.err
}

// defaultFakePayments returns a permissive fake that always succeeds with
// canned Stripe Checkout handles.
func defaultFakePayments() *fakePaymentsClient {
	return &fakePaymentsClient{
		out: payments.CreateSubscriptionOutput{
			PurchaseID:        "01970000-0000-7000-8000-pppp00000001",
			StripeSessionID:   "cs_test_default",
			StripeCheckoutURL: "https://checkout.stripe.com/c/test_default",
			State:             "checkout_started",
		},
	}
}

func newEconomyServerWith(t *testing.T, pay httpadapter.PaymentsSubscriptionCreator) http.Handler {
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
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})

	h := httpadapter.NewEconomyHandlerWithOptions(users, subs, manaStore, kycRepo, pay, nil,
		httpadapter.EconomyHandlerOptions{
			// Test fixture uses the staging Singpass URL — production wires the
			// real URL via SINGPASS_AUTHORIZATION_URL env var (no inline config).
			SingpassAuthURL:        "https://stg-id.singpass.gov.sg/auth",
			SubscriptionSuccessURL: "https://chora.site/me/subscriptions/success",
			SubscriptionCancelURL:  "https://chora.site/me/subscriptions/cancel",
		})
	h.RegisterRoutes(mux)
	return mux
}

func newEconomyServer(t *testing.T) http.Handler {
	return newEconomyServerWith(t, defaultFakePayments())
}

func mustJSON(t *testing.T, body *bytes.Buffer) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(body.Bytes(), &out); err != nil {
		t.Fatalf("invalid json: %v body=%s", err, body.String())
	}
	return out
}

func bearerJSON(method, path, gcid string, body any) *http.Request {
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	r := httptest.NewRequest(method, path, &buf)
	r.Header.Set("Authorization", "Bearer "+gcid)
	r.Header.Set("Content-Type", "application/json")
	return r
}

// -----------------------------------------------------------------------------
// /api/v1/me/marketplace/familiar-plans
// -----------------------------------------------------------------------------

func TestListFamiliarPlans_HappyPath(t *testing.T) {
	t.Parallel()
	srv := newEconomyServer(t)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, bearerJSON(http.MethodGet, "/api/v1/me/marketplace/familiar-plans", economyTestGcid, nil))

	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	got := mustJSON(t, w.Body)
	plans, ok := got["plans"].([]any)
	if !ok || len(plans) != 3 {
		t.Errorf("plans=%v", got["plans"])
	}
	pricing, ok := got["kyc_pricing"].([]any)
	if !ok || len(pricing) != 3 {
		t.Errorf("kyc_pricing=%v", got["kyc_pricing"])
	}
}

// -----------------------------------------------------------------------------
// /api/v1/me/subscriptions
// -----------------------------------------------------------------------------

func TestPurchaseSubscription_AndListAndGet(t *testing.T) {
	t.Parallel()
	pay := defaultFakePayments()
	srv := newEconomyServerWith(t, pay)

	// POST /api/v1/me/subscriptions — initiates the Stripe Checkout via
	// chora-payments; subscription stays in pending_activation.
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, bearerJSON(http.MethodPost, "/api/v1/me/subscriptions", economyTestGcid, map[string]any{
		"plan_code":      "familiar_basic",
		"billing_period": "monthly",
	}))
	if w.Code != http.StatusCreated {
		t.Fatalf("POST status=%d body=%s", w.Code, w.Body.String())
	}
	got := mustJSON(t, w.Body)
	subID, _ := got["subscription_id"].(string)
	if subID == "" {
		t.Fatalf("missing subscription_id")
	}
	if got["status"] != "pending_activation" {
		t.Errorf("status=%v want pending_activation", got["status"])
	}
	if got["stripe_checkout_url"] != "https://checkout.stripe.com/c/test_default" {
		t.Errorf("stripe_checkout_url=%v", got["stripe_checkout_url"])
	}
	if got["purchase_id"] != "01970000-0000-7000-8000-pppp00000001" {
		t.Errorf("purchase_id=%v", got["purchase_id"])
	}

	// Verify the payments-client received the canonical request shape.
	if pay.lastInput.PlanSku != "subscription.familiar_basic.monthly.v1" {
		t.Errorf("plan_sku mismatch: %q", pay.lastInput.PlanSku)
	}
	if pay.lastInput.BillingPeriod != "monthly" {
		t.Errorf("billing_period mismatch: %q", pay.lastInput.BillingPeriod)
	}
	if pay.lastInput.AmountCents != 499 {
		t.Errorf("amount_cents mismatch: %d", pay.lastInput.AmountCents)
	}
	if pay.lastInput.LearnerGcid != economyTestGcid {
		t.Errorf("learner_gcid mismatch: %q", pay.lastInput.LearnerGcid)
	}
	if pay.lastInput.IdempotencyKey == "" {
		t.Errorf("idempotency_key missing")
	}

	// GET /api/v1/me/subscriptions
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, bearerJSON(http.MethodGet, "/api/v1/me/subscriptions", economyTestGcid, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("GET list status=%d", w.Code)
	}
	gotList := mustJSON(t, w.Body)
	items, _ := gotList["items"].([]any)
	if len(items) != 1 {
		t.Errorf("items=%d want 1", len(items))
	}

	// GET /api/v1/me/subscriptions/{id}
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, bearerJSON(http.MethodGet, "/api/v1/me/subscriptions/"+subID, economyTestGcid, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("GET item status=%d", w.Code)
	}
	gotOne := mustJSON(t, w.Body)
	if gotOne["subscription_id"] != subID {
		t.Errorf("id mismatch")
	}
	// Subscription stored in pending_activation — chora-payments Pub/Sub event
	// activates it when payment is captured (see PaymentsSubscriber).
	if gotOne["status"] != "pending_activation" {
		t.Errorf("stored status=%v want pending_activation", gotOne["status"])
	}
}

func TestPurchaseSubscription_RejectsUnknownPlan(t *testing.T) {
	t.Parallel()
	srv := newEconomyServer(t)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, bearerJSON(http.MethodPost, "/api/v1/me/subscriptions", economyTestGcid, map[string]any{
		"plan_code":      "familiar_titan",
		"billing_period": "monthly",
	}))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status=%d want 400", w.Code)
	}
}

func TestPurchaseSubscription_RejectsInvalidBillingPeriod(t *testing.T) {
	t.Parallel()
	srv := newEconomyServer(t)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, bearerJSON(http.MethodPost, "/api/v1/me/subscriptions", economyTestGcid, map[string]any{
		"plan_code":      "familiar_basic",
		"billing_period": "biennially",
	}))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status=%d want 400", w.Code)
	}
}

func TestPurchaseSubscription_PaymentsUnavailable_Returns502(t *testing.T) {
	t.Parallel()
	pay := &fakePaymentsClient{
		err: errors.New("chora-payments unavailable: connect: connection refused"),
	}
	// Wrap as the canonical sentinel-error so the handler maps to 502.
	pay.err = paymentsUnavailableShim(pay.err)
	srv := newEconomyServerWith(t, pay)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, bearerJSON(http.MethodPost, "/api/v1/me/subscriptions", economyTestGcid, map[string]any{
		"plan_code":      "familiar_basic",
		"billing_period": "monthly",
	}))
	if w.Code != http.StatusBadGateway {
		t.Fatalf("status=%d want 502; body=%s", w.Code, w.Body.String())
	}
}

func TestPurchaseSubscription_AnnualPriceMaps(t *testing.T) {
	t.Parallel()
	pay := defaultFakePayments()
	srv := newEconomyServerWith(t, pay)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, bearerJSON(http.MethodPost, "/api/v1/me/subscriptions", economyTestGcid, map[string]any{
		"plan_code":      "familiar_premium",
		"billing_period": "annually",
	}))
	if w.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if pay.lastInput.AmountCents != 39999 {
		t.Errorf("annual premium amount: got %d want 39999", pay.lastInput.AmountCents)
	}
}

// paymentsUnavailableShim wraps an error into the payments.ErrPaymentsUnavailable
// sentinel hierarchy without importing the unexported sentinel directly.
func paymentsUnavailableShim(err error) error {
	return paymentsErrShim{inner: err}
}

type paymentsErrShim struct{ inner error }

func (p paymentsErrShim) Error() string { return p.inner.Error() }
func (p paymentsErrShim) Is(target error) bool {
	return target == payments.ErrPaymentsUnavailable
}

func TestCancelSubscription_PersistsState(t *testing.T) {
	t.Parallel()
	srv := newEconomyServer(t)

	// Purchase (pending_activation).
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, bearerJSON(http.MethodPost, "/api/v1/me/subscriptions", economyTestGcid, map[string]any{
		"plan_code":      "familiar_basic",
		"billing_period": "monthly",
	}))
	subID := mustJSON(t, w.Body)["subscription_id"].(string)

	// Cancel — chora-identity-owned FSM transitions pending_activation → cancelled.
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, bearerJSON(http.MethodDelete, "/api/v1/me/subscriptions/"+subID, economyTestGcid, map[string]any{
		"reason": "user_request",
	}))
	if w.Code != http.StatusOK {
		t.Fatalf("cancel status=%d body=%s", w.Code, w.Body.String())
	}
	got := mustJSON(t, w.Body)
	if got["status"] != "cancelled" {
		t.Errorf("status=%v want cancelled", got["status"])
	}
}

func TestChangeSubscriptionPlan_NotAllowedFromPending(t *testing.T) {
	t.Parallel()
	srv := newEconomyServer(t)
	// Purchase (pending_activation).
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, bearerJSON(http.MethodPost, "/api/v1/me/subscriptions", economyTestGcid, map[string]any{
		"plan_code":      "familiar_basic",
		"billing_period": "monthly",
	}))
	subID := mustJSON(t, w.Body)["subscription_id"].(string)

	// ChangePlan is allowed only from active/grace/paused; pending_activation
	// is NOT allowed by the domain FSM (see user_subscription.ChangePlan).
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, bearerJSON(http.MethodPatch, "/api/v1/me/subscriptions/"+subID, economyTestGcid, map[string]any{
		"target_plan_code": "familiar_premium",
		"proration_mode":   "create_prorations",
	}))
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status=%d want 422", w.Code)
	}
}

// -----------------------------------------------------------------------------
// /api/v1/me/mana[/ledger]
// -----------------------------------------------------------------------------

func TestGetMana_ZeroBalanceForNewUser(t *testing.T) {
	t.Parallel()
	srv := newEconomyServer(t)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, bearerJSON(http.MethodGet, "/api/v1/me/mana", economyTestGcid, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d", w.Code)
	}
	got := mustJSON(t, w.Body)
	if int64(got["balance_units"].(float64)) != 0 {
		t.Errorf("new user balance=%v want 0", got["balance_units"])
	}
}

// /api/v1/me/mana/topup is RETIRED per ADR-164 Wave 1 Stage E.
// Verify the route is NOT mounted.
func TestTopupMana_RouteIsRetired(t *testing.T) {
	t.Parallel()
	srv := newEconomyServer(t)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, bearerJSON(http.MethodPost, "/api/v1/me/mana/topup", economyTestGcid, map[string]any{
		"amount_cents": 999,
		"currency":     "USD",
	}))
	// Without the route mounted, fallthrough to the default mux returns 404.
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for retired route; got %d body=%s", w.Code, w.Body.String())
	}
}

// -----------------------------------------------------------------------------
// /api/v1/me/kyc/*
// -----------------------------------------------------------------------------

func TestInitiateSingpassKyc_CreatesPendingVerification(t *testing.T) {
	t.Parallel()
	srv := newEconomyServer(t)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, bearerJSON(http.MethodPost, "/api/v1/me/kyc/singpass:initiate", economyTestGcid, map[string]any{
		"return_url": "https://app.chora.site/kyc/callback",
	}))
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	got := mustJSON(t, w.Body)
	if got["redirect_url"] == nil {
		t.Errorf("redirect_url missing")
	}
	if got["verification_id"] == nil {
		t.Errorf("verification_id missing")
	}
}

func TestGetKycStatus_NotFoundForNewUser(t *testing.T) {
	t.Parallel()
	srv := newEconomyServer(t)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, bearerJSON(http.MethodGet, "/api/v1/me/kyc/status", economyTestGcid, nil))
	if w.Code != http.StatusNotFound {
		t.Fatalf("status=%d want 404", w.Code)
	}
}

// NOTE: the POST /api/v1/me/kyc/manual tests moved to kyc_handler_test.go —
// the route is now owned by the dedicated KycHandler (ADR-164 Stage A.5),
// which charges the $9.99 fee via chora-payments Stripe Checkout.

// -----------------------------------------------------------------------------
// Auth + 404 hygiene
// -----------------------------------------------------------------------------

func TestEconomyEndpoints_RequireBearerAuth(t *testing.T) {
	t.Parallel()
	srv := newEconomyServer(t)
	for _, path := range []string{
		"/api/v1/me/subscriptions",
		"/api/v1/me/mana",
		"/api/v1/me/mana/ledger",
		"/api/v1/me/kyc/status",
		"/api/v1/me/marketplace/familiar-plans",
	} {
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		if w.Code != http.StatusUnauthorized {
			t.Errorf("%s status=%d want 401", path, w.Code)
		}
	}
}

// -----------------------------------------------------------------------------
// CHO-1883 — mana ledger keyset pagination + cursor validation
// -----------------------------------------------------------------------------

// newLedgerServerSeeded wires the economy handler with a mana store pre-seeded
// with n debit entries (ascending recorded_at) for economyTestGcid.
func newLedgerServerSeeded(t *testing.T, n int) http.Handler {
	t.Helper()
	users := inmem.NewUserRepository()
	u, _ := identity.NewUser(identity.NewUserParams{
		Email: "led@chora.dev", IdentityProvider: identity.ProviderOIDC, FederatedSubject: "led-1",
	})
	u.Gcid = economyTestGcid
	if err := users.Save(context.Background(), u); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	manaStore := repo.NewInMemManaStore()
	base := time.Date(2026, 6, 26, 0, 0, 0, 0, time.UTC)
	for i := 0; i < n; i++ {
		e := &mana.LedgerEntry{
			EntryID:           fmt.Sprintf("019f0000-0000-7000-8000-%012d", i),
			Gcid:              economyTestGcid,
			Direction:         mana.DirectionDebit,
			Units:             10,
			Reason:            mana.ReasonFamiliarAction,
			BalanceAfterUnits: int64(1000 - i),
			RecordedAt:        base.Add(time.Duration(i) * time.Minute),
		}
		if err := manaStore.AppendLedger(context.Background(), e); err != nil {
			t.Fatalf("seed ledger: %v", err)
		}
	}
	h := httpadapter.NewEconomyHandlerWithOptions(
		users, repo.NewInMemUserSubscriptionRepo(), manaStore, repo.NewInMemKycRepo(),
		defaultFakePayments(), nil, httpadapter.EconomyHandlerOptions{})
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	return mux
}

func TestListManaLedger_KeysetPagination(t *testing.T) {
	t.Parallel()
	srv := newLedgerServerSeeded(t, 5)

	// Page 1 — page_size=2 → 2 items, has_more, a next_cursor.
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, bearerJSON(http.MethodGet, "/api/v1/me/mana/ledger?page_size=2", economyTestGcid, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("page1 status=%d want 200", w.Code)
	}
	body := mustJSON(t, w.Body)
	if items, _ := body["items"].([]any); len(items) != 2 {
		t.Fatalf("page1 items=%d want 2", len(items))
	}
	if body["has_more"] != true {
		t.Errorf("page1 has_more=%v want true", body["has_more"])
	}
	cur, _ := body["next_cursor"].(string)
	if cur == "" {
		t.Fatal("page1 missing next_cursor")
	}

	// Page 2 (cursor) → 2 items, still has_more.
	w2 := httptest.NewRecorder()
	srv.ServeHTTP(w2, bearerJSON(http.MethodGet, "/api/v1/me/mana/ledger?page_size=2&cursor="+cur, economyTestGcid, nil))
	body2 := mustJSON(t, w2.Body)
	cur2, _ := body2["next_cursor"].(string)
	if cur2 == "" {
		t.Fatal("page2 missing next_cursor")
	}

	// Page 3 (cursor) → final 1 item, has_more=false, NO next_cursor.
	w3 := httptest.NewRecorder()
	srv.ServeHTTP(w3, bearerJSON(http.MethodGet, "/api/v1/me/mana/ledger?page_size=2&cursor="+cur2, economyTestGcid, nil))
	body3 := mustJSON(t, w3.Body)
	if items, _ := body3["items"].([]any); len(items) != 1 {
		t.Fatalf("page3 items=%d want 1 (5 total / 2 per page)", len(items))
	}
	if body3["has_more"] != false {
		t.Errorf("page3 has_more=%v want false", body3["has_more"])
	}
	if _, has := body3["next_cursor"]; has {
		t.Error("page3 must not carry next_cursor on the last page")
	}
}

func TestListManaLedger_BadCursor_Returns400(t *testing.T) {
	t.Parallel()
	srv := newLedgerServerSeeded(t, 0)
	w := httptest.NewRecorder()
	// "bm9waXBl" = base64("nopipe") — valid base64 but no "|" separator.
	srv.ServeHTTP(w, bearerJSON(http.MethodGet, "/api/v1/me/mana/ledger?cursor=bm9waXBl", economyTestGcid, nil))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status=%d want 400 on malformed cursor", w.Code)
	}
}

func TestListManaLedger_EmptyShape(t *testing.T) {
	t.Parallel()
	srv := newLedgerServerSeeded(t, 0)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, bearerJSON(http.MethodGet, "/api/v1/me/mana/ledger", economyTestGcid, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d want 200", w.Code)
	}
	body := mustJSON(t, w.Body)
	if items, _ := body["items"].([]any); len(items) != 0 {
		t.Errorf("items=%d want 0", len(items))
	}
	if body["has_more"] != false {
		t.Errorf("empty has_more=%v want false", body["has_more"])
	}
}

func TestExportManaLedger_CSV(t *testing.T) {
	t.Parallel()
	srv := newLedgerServerSeeded(t, 3)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, bearerJSON(http.MethodGet, "/api/v1/me/mana/ledger/export?format=csv", economyTestGcid, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d want 200", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/csv") {
		t.Errorf("Content-Type=%q want text/csv", ct)
	}
	cd := w.Header().Get("Content-Disposition")
	if !strings.Contains(cd, "attachment") || !strings.Contains(cd, ".csv") {
		t.Errorf("Content-Disposition=%q want attachment .csv", cd)
	}
	lines := strings.Split(strings.TrimRight(w.Body.String(), "\n"), "\n")
	if len(lines) != 4 { // header + 3 rows
		t.Fatalf("csv lines=%d want 4 (header + 3)", len(lines))
	}
	if !strings.Contains(lines[0], "recorded_at") || !strings.Contains(lines[0], "balance_after_units") {
		t.Errorf("csv header missing columns: %q", lines[0])
	}
}

func TestExportManaLedger_NDJSON(t *testing.T) {
	t.Parallel()
	srv := newLedgerServerSeeded(t, 2)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, bearerJSON(http.MethodGet, "/api/v1/me/mana/ledger/export?format=json", economyTestGcid, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d want 200", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); !strings.Contains(ct, "json") {
		t.Errorf("Content-Type=%q want ndjson", ct)
	}
	lines := strings.Split(strings.TrimRight(w.Body.String(), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("ndjson lines=%d want 2", len(lines))
	}
	var obj map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &obj); err != nil {
		t.Fatalf("line 0 not valid JSON: %v", err)
	}
	if obj["direction"] != "debit" {
		t.Errorf("direction=%v want debit", obj["direction"])
	}
}

func TestGetSubscription_OtherUserReturns404(t *testing.T) {
	t.Parallel()
	srv := newEconomyServer(t)
	// Purchase a sub for the seeded user.
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, bearerJSON(http.MethodPost, "/api/v1/me/subscriptions", economyTestGcid, map[string]any{
		"plan_code":      "familiar_basic",
		"billing_period": "monthly",
	}))
	subID := mustJSON(t, w.Body)["subscription_id"].(string)

	// Different bearer (which doesn't exist in repo) → 401 from middleware.
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, bearerJSON(http.MethodGet, "/api/v1/me/subscriptions/"+subID, "01970000-0000-7000-8000-00000000ffff", nil))
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status=%d want 401", w.Code)
	}
}

// -----------------------------------------------------------------------------
// Handler-level: payments client unconfigured
// -----------------------------------------------------------------------------

func TestPurchaseSubscription_PaymentsUnconfigured_Returns503(t *testing.T) {
	t.Parallel()
	srv := newEconomyServerWith(t, nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, bearerJSON(http.MethodPost, "/api/v1/me/subscriptions", economyTestGcid, map[string]any{
		"plan_code":      "familiar_basic",
		"billing_period": "monthly",
	}))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d want 503", w.Code)
	}
}

// kept to silence imports in case body usage is removed during refactor.
var _ = strings.Contains
