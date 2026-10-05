// Extra handler-level specs for /api/v1/me/* economy endpoints — fills the
// remaining branch gaps in me_economy_handlers.go (method guards, repo-error
// 500s, plan-price matrix, KYC-present mapping, publisher emission, ledger
// source fields) without touching any existing test file.
//
// All new helpers/fakes are prefixed mex_ to avoid clashing with the shared
// test helpers in me_economy_handlers_test.go / me_economy_phyllis_test.go.
package httpadapter_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/apollo-chora/chora-identity/internal/adapter/events"
	httpadapter "github.com/apollo-chora/chora-identity/internal/adapter/http"
	"github.com/apollo-chora/chora-identity/internal/adapter/inmem"
	"github.com/apollo-chora/chora-identity/internal/adapter/payments"
	"github.com/apollo-chora/chora-identity/internal/adapter/repo"
	"github.com/apollo-chora/chora-identity/internal/domain/identity"
	kyc "github.com/apollo-chora/chora-identity/internal/domain/kyc"
	mana "github.com/apollo-chora/chora-identity/internal/domain/user_mana"
	usersub "github.com/apollo-chora/chora-identity/internal/domain/user_subscription"
)

// -----------------------------------------------------------------------------
// mex_ helpers + fakes
// -----------------------------------------------------------------------------

// mex_recordingPublisher records every Publish call without envelope
// validation, so tests can assert the handler invokes the publisher with the
// canonical topic even though the bearer-only routes carry no tenant context
// (the domain Envelope validation requires a tenant_id).
type mex_recordingPublisher struct {
	calls     int
	lastTopic string
}

func (p *mex_recordingPublisher) Publish(topic string, _ events.Envelope, _ map[string]any) error {
	p.calls++
	p.lastTopic = topic
	return nil
}

// mex_economyMux wires an EconomyHandler from explicit repos/options and
// returns the fully-registered mux. Mirror of newEconomyServerWith with the
// repos left injectable so tests can seed or fail them.
func mex_economyMux(
	t *testing.T,
	users identity.UserRepository,
	subs usersub.Repository,
	manaStore mana.Store,
	kycRepo kyc.Repository,
	pay httpadapter.PaymentsSubscriptionCreator,
	pub *events.EconomyPublisher,
	opts httpadapter.EconomyHandlerOptions,
) http.Handler {
	t.Helper()
	h := httpadapter.NewEconomyHandlerWithOptions(users, subs, manaStore, kycRepo, pay, pub, opts)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	return mux
}

// mex_standardMux builds the default economy mux (one seeded user) from a
// custom subscriptions repo — the common shape for error-injection tests.
func mex_standardMux(t *testing.T, subs usersub.Repository) http.Handler {
	t.Helper()
	return mex_economyMux(t, mex_seededUsers(t, economyTestGcid), subs,
		repo.NewInMemManaStore(), repo.NewInMemKycRepo(), defaultFakePayments(), nil,
		httpadapter.EconomyHandlerOptions{SingpassAuthURL: "https://stg-id.singpass.gov.sg/auth"})
}

// mex_seededUsers returns a user repo with one user per gcid (FederatedSubject
// unique per gcid so NewUser never dedupes).
func mex_seededUsers(t *testing.T, gcids ...string) identity.UserRepository {
	t.Helper()
	users := inmem.NewUserRepository()
	for i, gcid := range gcids {
		u, err := identity.NewUser(identity.NewUserParams{
			Email:            fmt.Sprintf("mex%d@chora.dev", i),
			IdentityProvider: identity.ProviderOIDC,
			FederatedSubject: fmt.Sprintf("mex-sub-%d", i),
		})
		if err != nil {
			t.Fatalf("seed user: %v", err)
		}
		u.Gcid = gcid
		if err := users.Save(context.Background(), u); err != nil {
			t.Fatalf("seed user: %v", err)
		}
	}
	return users
}

// mex_rawBearer builds a bearer-authed request with a RAW body string so
// tests can drive decodeJSON's error branch with malformed JSON.
func mex_rawBearer(method, path, gcid, rawBody string) *http.Request {
	r := httptest.NewRequest(method, path, strings.NewReader(rawBody))
	r.Header.Set("Authorization", "Bearer "+gcid)
	r.Header.Set("Content-Type", "application/json")
	return r
}

// mex_purchaseSub POSTs a purchase and returns the minted subscription_id.
func mex_purchaseSub(t *testing.T, srv http.Handler, gcid, plan, billing string) string {
	t.Helper()
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, bearerJSON(http.MethodPost, "/api/v1/me/subscriptions", gcid, map[string]any{
		"plan_code":      plan,
		"billing_period": billing,
	}))
	if w.Code != http.StatusCreated {
		t.Fatalf("purchase status=%d body=%s", w.Code, w.Body.String())
	}
	id, _ := mustJSON(t, w.Body)["subscription_id"].(string)
	if id == "" {
		t.Fatal("purchase response missing subscription_id")
	}
	return id
}

// mex_newSub builds a usersub.Subscription directly (optionally activated) so
// tests can drive the active-state happy path of the PATCH/DELETE handlers.
func mex_newSub(t *testing.T, gcid, planCode string, bill usersub.BillingPeriod, activate bool) *usersub.Subscription {
	t.Helper()
	now := time.Now().UTC()
	var tier usersub.Tier
	var units int64
	switch planCode {
	case "familiar_basic":
		tier, units = usersub.TierBasic, 500
	case "familiar_standard":
		tier, units = usersub.TierStandard, 2500
	case "familiar_premium":
		tier, units = usersub.TierPremium, 10000
	default:
		t.Fatalf("unexpected plan %q", planCode)
	}
	s, err := usersub.NewSubscription(usersub.NewParams{
		Gcid:                 gcid,
		TenantID:             "01970000-0000-7000-8000-000000000001",
		PlanCode:             planCode,
		Tier:                 tier,
		BillingPeriod:        bill,
		ManaMonthlyUnits:     units,
		OnboardingBonusUnits: units,
		PeriodStart:          now,
		PeriodEnd:            now.AddDate(0, 1, 0),
	})
	if err != nil {
		t.Fatalf("new sub: %v", err)
	}
	if activate {
		if err := s.Activate(); err != nil {
			t.Fatalf("activate: %v", err)
		}
	}
	return s
}

// mex_subsFake is a usersub.Repository whose ListByGcid / GetByID / Save can
// be forced to fail. GetByID returns subs when set (ignoring id), else falls
// through to the embedded in-memory repo.
type mex_subsFake struct {
	*repo.InMemUserSubscriptionRepo
	subs    *usersub.Subscription
	listErr error
	getErr  error
	saveErr error
}

func (r *mex_subsFake) GetByID(ctx context.Context, id string) (*usersub.Subscription, error) {
	if r.getErr != nil {
		return nil, r.getErr
	}
	if r.subs != nil {
		clone := *r.subs
		return &clone, nil
	}
	return r.InMemUserSubscriptionRepo.GetByID(ctx, id)
}

func (r *mex_subsFake) ListByGcid(ctx context.Context, gcid string) ([]*usersub.Subscription, error) {
	if r.listErr != nil {
		return nil, r.listErr
	}
	return r.InMemUserSubscriptionRepo.ListByGcid(ctx, gcid)
}

func (r *mex_subsFake) Save(ctx context.Context, s *usersub.Subscription) error {
	if r.saveErr != nil {
		return r.saveErr
	}
	return r.InMemUserSubscriptionRepo.Save(ctx, s)
}

// mex_manaFake is a mana.Store whose GetMana / ListLedger can fail. Remaining
// methods delegate to the embedded domain in-memory store.
type mex_manaFake struct {
	*mana.InMemoryStore
	getManaErr    error
	listLedgerErr error
}

func (s *mex_manaFake) GetMana(ctx context.Context, gcid string) (*mana.UserMana, error) {
	if s.getManaErr != nil {
		return nil, s.getManaErr
	}
	return s.InMemoryStore.GetMana(ctx, gcid)
}

func (s *mex_manaFake) ListLedger(ctx context.Context, f mana.LedgerFilter) ([]*mana.LedgerEntry, error) {
	if s.listLedgerErr != nil {
		return nil, s.listLedgerErr
	}
	return s.InMemoryStore.ListLedger(ctx, f)
}

// mex_kycFake is a kyc.Repository whose GetLatestByGcid / Save can fail.
type mex_kycFake struct {
	*repo.InMemKycRepo
	getErr  error
	saveErr error
}

func (r *mex_kycFake) GetLatestByGcid(ctx context.Context, gcid string) (*kyc.Verification, error) {
	if r.getErr != nil {
		return nil, r.getErr
	}
	return r.InMemKycRepo.GetLatestByGcid(ctx, gcid)
}

func (r *mex_kycFake) Save(ctx context.Context, v *kyc.Verification) error {
	if r.saveErr != nil {
		return r.saveErr
	}
	return r.InMemKycRepo.Save(ctx, v)
}

// -----------------------------------------------------------------------------
// NewEconomyHandler (no-options constructor)
// -----------------------------------------------------------------------------

func TestNewEconomyHandler_NoOptions_ConstructsUsableHandler(t *testing.T) {
	t.Parallel()
	users := mex_seededUsers(t, economyTestGcid)
	h := httpadapter.NewEconomyHandler(users, repo.NewInMemUserSubscriptionRepo(),
		repo.NewInMemManaStore(), repo.NewInMemKycRepo(), defaultFakePayments(), nil)
	if h == nil {
		t.Fatal("NewEconomyHandler returned nil")
	}
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	// Marketplace catalog needs no env config — proves the plain constructor
	// yields a fully-wired handler.
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, bearerJSON(http.MethodGet, "/api/v1/me/marketplace/familiar-plans", economyTestGcid, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
}

// -----------------------------------------------------------------------------
// Method guards → 405 METHOD_NOT_ALLOWED (one per economy route)
// -----------------------------------------------------------------------------

func TestEconomyRoutes_MethodNotAllowed405(t *testing.T) {
	t.Parallel()
	srv := newEconomyServerWith(t, defaultFakePayments())
	cases := []struct {
		method string
		path   string
	}{
		{http.MethodPut, "/api/v1/me/subscriptions"},               // subscriptionsCollection default
		{http.MethodPost, "/api/v1/me/subscriptions/sub-1"},        // subscriptionsItem default
		{http.MethodPost, "/api/v1/me/mana"},                       // getMana guard
		{http.MethodPost, "/api/v1/me/mana/ledger"},                // listManaLedger guard
		{http.MethodPost, "/api/v1/me/mana/ledger/export"},         // exportManaLedger guard
		{http.MethodPost, "/api/v1/me/kyc/status"},                 // getKycStatus guard
		{http.MethodGet, "/api/v1/me/kyc/singpass:initiate"},       // initiateSingpass guard
		{http.MethodPost, "/api/v1/me/marketplace/familiar-plans"}, // listFamiliarPlans guard
	}
	for _, tc := range cases {
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, bearerJSON(tc.method, tc.path, economyTestGcid, nil))
		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s %s status=%d want 405 body=%s", tc.method, tc.path, w.Code, w.Body.String())
			continue
		}
		if got := mustJSON(t, w.Body)["code"]; got != "METHOD_NOT_ALLOWED" {
			t.Errorf("%s %s code=%v want METHOD_NOT_ALLOWED", tc.method, tc.path, got)
		}
	}
}

// -----------------------------------------------------------------------------
// /api/v1/me/subscriptions — list / item error branches
// -----------------------------------------------------------------------------

func TestListSubscriptions_RepoError_Returns500(t *testing.T) {
	t.Parallel()
	subs := &mex_subsFake{InMemUserSubscriptionRepo: repo.NewInMemUserSubscriptionRepo(), listErr: errors.New("db down")}
	srv := mex_standardMux(t, subs)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, bearerJSON(http.MethodGet, "/api/v1/me/subscriptions", economyTestGcid, nil))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d want 500 body=%s", w.Code, w.Body.String())
	}
	if got := mustJSON(t, w.Body)["code"]; got != "ECONOMY_REPO_ERROR" {
		t.Errorf("code=%v want ECONOMY_REPO_ERROR", got)
	}
}

func TestGetSubscription_UnknownID_Returns404(t *testing.T) {
	t.Parallel()
	srv := newEconomyServer(t)
	// Unknown subscription id → ErrNotFound → 404.
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, bearerJSON(http.MethodGet, "/api/v1/me/subscriptions/019f0000-0000-7000-8000-00000000dead", economyTestGcid, nil))
	if w.Code != http.StatusNotFound {
		t.Fatalf("status=%d want 404 body=%s", w.Code, w.Body.String())
	}
	if got := mustJSON(t, w.Body)["code"]; got != "ECONOMY_NOT_FOUND" {
		t.Errorf("code=%v want ECONOMY_NOT_FOUND", got)
	}
	// Bare item path (no id) → 404 "subscription_id required".
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, bearerJSON(http.MethodGet, "/api/v1/me/subscriptions/", economyTestGcid, nil))
	if w.Code != http.StatusNotFound {
		t.Fatalf("bare path status=%d want 404 body=%s", w.Code, w.Body.String())
	}
}

func TestGetSubscription_OtherUser_Returns404(t *testing.T) {
	t.Parallel()
	users := mex_seededUsers(t, economyTestGcid, gcidA)
	subs := repo.NewInMemUserSubscriptionRepo()
	srv := mex_economyMux(t, users, subs, repo.NewInMemManaStore(), repo.NewInMemKycRepo(),
		defaultFakePayments(), nil, httpadapter.EconomyHandlerOptions{})
	subID := mex_purchaseSub(t, srv, economyTestGcid, "familiar_basic", "monthly")

	// Same sub, different (valid) bearer → gcid mismatch → 404.
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, bearerJSON(http.MethodGet, "/api/v1/me/subscriptions/"+subID, gcidA, nil))
	if w.Code != http.StatusNotFound {
		t.Fatalf("status=%d want 404 body=%s", w.Code, w.Body.String())
	}
}

func TestGetSubscription_RepoError_Returns500(t *testing.T) {
	t.Parallel()
	subs := &mex_subsFake{InMemUserSubscriptionRepo: repo.NewInMemUserSubscriptionRepo(),
		getErr: errors.New("pg unavailable")}
	srv := mex_standardMux(t, subs)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, bearerJSON(http.MethodGet, "/api/v1/me/subscriptions/any-id", economyTestGcid, nil))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d want 500 body=%s", w.Code, w.Body.String())
	}
	if got := mustJSON(t, w.Body)["code"]; got != "ECONOMY_REPO_ERROR" {
		t.Errorf("code=%v want ECONOMY_REPO_ERROR", got)
	}
}

// -----------------------------------------------------------------------------
// Pricing matrix — planPricingForBillingPeriod + tierForPlan remaining branches
// -----------------------------------------------------------------------------

func TestPurchaseSubscription_PriceMatrix(t *testing.T) {
	t.Parallel()
	combos := []struct {
		plan    string
		billing string
		cents   int64
	}{
		{"familiar_basic", "annually", 4999},
		{"familiar_standard", "monthly", 1499},
		{"familiar_standard", "annually", 14999},
		{"familiar_premium", "monthly", 3999},
	}
	for _, tc := range combos {
		pay := defaultFakePayments()
		srv := newEconomyServerWith(t, pay)
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, bearerJSON(http.MethodPost, "/api/v1/me/subscriptions", economyTestGcid, map[string]any{
			"plan_code":      tc.plan,
			"billing_period": tc.billing,
		}))
		if w.Code != http.StatusCreated {
			t.Fatalf("%s %s status=%d body=%s", tc.plan, tc.billing, w.Code, w.Body.String())
		}
		if pay.lastInput.AmountCents != tc.cents {
			t.Errorf("%s %s amount_cents=%d want %d", tc.plan, tc.billing, pay.lastInput.AmountCents, tc.cents)
		}
	}
}

func TestPurchaseSubscription_DefaultBillingIsMonthly(t *testing.T) {
	t.Parallel()
	pay := defaultFakePayments()
	srv := newEconomyServerWith(t, pay)
	// No billing_period → defaults to monthly for the price computation.
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, bearerJSON(http.MethodPost, "/api/v1/me/subscriptions", economyTestGcid, map[string]any{
		"plan_code": "familiar_standard",
	}))
	if w.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if pay.lastInput.AmountCents != 1499 {
		t.Errorf("amount_cents=%d want 1499 (default monthly)", pay.lastInput.AmountCents)
	}
	if pay.lastInput.BillingPeriod != "monthly" {
		t.Errorf("billing_period=%q want monthly", pay.lastInput.BillingPeriod)
	}
}

// -----------------------------------------------------------------------------
// POST subscribe — remaining error branches + publisher emission
// -----------------------------------------------------------------------------

func TestPurchaseSubscription_InvalidBody_Returns400(t *testing.T) {
	t.Parallel()
	srv := newEconomyServer(t)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, mex_rawBearer(http.MethodPost, "/api/v1/me/subscriptions", economyTestGcid, "{not-json"))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status=%d want 400 body=%s", w.Code, w.Body.String())
	}
	if got := mustJSON(t, w.Body)["code"]; got != "ECONOMY_INVALID_BODY" {
		t.Errorf("code=%v want ECONOMY_INVALID_BODY", got)
	}
}

func TestPurchaseSubscription_PaymentsInvalidInput_Returns400(t *testing.T) {
	t.Parallel()
	pay := &fakePaymentsClient{err: payments.ErrInvalidInput}
	srv := newEconomyServerWith(t, pay)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, bearerJSON(http.MethodPost, "/api/v1/me/subscriptions", economyTestGcid, map[string]any{
		"plan_code":      "familiar_basic",
		"billing_period": "monthly",
	}))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status=%d want 400 body=%s", w.Code, w.Body.String())
	}
	if got := mustJSON(t, w.Body)["code"]; got != "ECONOMY_PAYMENTS_INVALID" {
		t.Errorf("code=%v want ECONOMY_PAYMENTS_INVALID", got)
	}
}

func TestPurchaseSubscription_PaymentsFailure_Returns502(t *testing.T) {
	t.Parallel()
	pay := &fakePaymentsClient{err: errors.New("upstream exploded")}
	srv := newEconomyServerWith(t, pay)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, bearerJSON(http.MethodPost, "/api/v1/me/subscriptions", economyTestGcid, map[string]any{
		"plan_code":      "familiar_basic",
		"billing_period": "monthly",
	}))
	if w.Code != http.StatusBadGateway {
		t.Fatalf("status=%d want 502 body=%s", w.Code, w.Body.String())
	}
	if got := mustJSON(t, w.Body)["code"]; got != "ECONOMY_PAYMENTS_FAILURE" {
		t.Errorf("code=%v want ECONOMY_PAYMENTS_FAILURE", got)
	}
}

func TestPurchaseSubscription_SaveError_Returns500(t *testing.T) {
	t.Parallel()
	subs := &mex_subsFake{InMemUserSubscriptionRepo: repo.NewInMemUserSubscriptionRepo(),
		saveErr: errors.New("write failed")}
	srv := mex_standardMux(t, subs)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, bearerJSON(http.MethodPost, "/api/v1/me/subscriptions", economyTestGcid, map[string]any{
		"plan_code":      "familiar_basic",
		"billing_period": "monthly",
	}))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d want 500 body=%s", w.Code, w.Body.String())
	}
	if got := mustJSON(t, w.Body)["code"]; got != "ECONOMY_REPO_ERROR" {
		t.Errorf("code=%v want ECONOMY_REPO_ERROR", got)
	}
}

func TestPurchaseSubscription_PublishesCreatedEvent(t *testing.T) {
	t.Parallel()
	rec := &mex_recordingPublisher{}
	pub := events.NewEconomyPublisher(rec)
	users := mex_seededUsers(t, economyTestGcid)
	srv := mex_economyMux(t, users, repo.NewInMemUserSubscriptionRepo(),
		repo.NewInMemManaStore(), repo.NewInMemKycRepo(), defaultFakePayments(), pub,
		httpadapter.EconomyHandlerOptions{})

	w := httptest.NewRecorder()
	srv.ServeHTTP(w, bearerJSON(http.MethodPost, "/api/v1/me/subscriptions", economyTestGcid, map[string]any{
		"plan_code":      "familiar_basic",
		"billing_period": "monthly",
	}))
	if w.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if rec.calls != 1 {
		t.Fatalf("publish calls=%d want 1", rec.calls)
	}
	if rec.lastTopic != usersub.TopicName(usersub.EventCreated) {
		t.Errorf("topic=%q want %q", rec.lastTopic, usersub.TopicName(usersub.EventCreated))
	}
}

// -----------------------------------------------------------------------------
// PATCH /api/v1/me/subscriptions/{id} — remaining branches
// -----------------------------------------------------------------------------

func TestChangeSubscriptionPlan_UnknownPlan_Returns400(t *testing.T) {
	t.Parallel()
	srv := newEconomyServer(t)
	subID := mex_purchaseSub(t, srv, economyTestGcid, "familiar_basic", "monthly")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, bearerJSON(http.MethodPatch, "/api/v1/me/subscriptions/"+subID, economyTestGcid, map[string]any{
		"target_plan_code": "familiar_titan",
		"proration_mode":   "create_prorations",
	}))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status=%d want 400 body=%s", w.Code, w.Body.String())
	}
	if got := mustJSON(t, w.Body)["code"]; got != "ECONOMY_UNKNOWN_PLAN" {
		t.Errorf("code=%v want ECONOMY_UNKNOWN_PLAN", got)
	}
}

func TestChangeSubscriptionPlan_UnknownSub_Returns404(t *testing.T) {
	t.Parallel()
	srv := newEconomyServer(t)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, bearerJSON(http.MethodPatch, "/api/v1/me/subscriptions/019f0000-0000-7000-8000-00000000dead",
		economyTestGcid, map[string]any{
			"target_plan_code": "familiar_premium",
			"proration_mode":   "create_prorations",
		}))
	if w.Code != http.StatusNotFound {
		t.Fatalf("status=%d want 404 body=%s", w.Code, w.Body.String())
	}
	if got := mustJSON(t, w.Body)["code"]; got != "ECONOMY_NOT_FOUND" {
		t.Errorf("code=%v want ECONOMY_NOT_FOUND", got)
	}
}

func TestChangeSubscriptionPlan_InvalidBody_Returns400(t *testing.T) {
	t.Parallel()
	srv := newEconomyServer(t)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, mex_rawBearer(http.MethodPatch, "/api/v1/me/subscriptions/some-id", economyTestGcid, "{bad"))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status=%d want 400 body=%s", w.Code, w.Body.String())
	}
}

func TestChangeSubscriptionPlan_HappyPath_ActiveSub(t *testing.T) {
	t.Parallel()
	users := mex_seededUsers(t, economyTestGcid)
	subs := repo.NewInMemUserSubscriptionRepo()
	srv := mex_economyMux(t, users, subs, repo.NewInMemManaStore(), repo.NewInMemKycRepo(),
		defaultFakePayments(), nil, httpadapter.EconomyHandlerOptions{})

	if err := subs.Save(context.Background(), mex_newSub(t, economyTestGcid, "familiar_basic", usersub.BillingMonthly, true)); err != nil {
		t.Fatalf("seed sub: %v", err)
	}

	// Find the seeded sub id via the list endpoint, then change plan.
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, bearerJSON(http.MethodGet, "/api/v1/me/subscriptions", economyTestGcid, nil))
	items, _ := mustJSON(t, w.Body)["items"].([]any)
	id := items[0].(map[string]any)["subscription_id"].(string)

	eff := time.Now().UTC().Add(2 * time.Hour).Format(time.RFC3339)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, bearerJSON(http.MethodPatch, "/api/v1/me/subscriptions/"+id, economyTestGcid, map[string]any{
		"target_plan_code":      "familiar_standard",
		"target_billing_period": "monthly",
		"proration_mode":        "create_prorations",
		"effective_at":          eff,
	}))
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	got := mustJSON(t, w.Body)
	if got["from_plan_code"] != "familiar_basic" || got["to_plan_code"] != "familiar_standard" {
		t.Errorf("plan transition=%v/%v", got["from_plan_code"], got["to_plan_code"])
	}
	if got["effective_at"] != eff {
		t.Errorf("effective_at=%v want %s", got["effective_at"], eff)
	}
	if got["billing_delta_cents"] != float64(0) {
		t.Errorf("billing_delta_cents=%v want 0", got["billing_delta_cents"])
	}
}

func TestChangeSubscriptionPlan_OtherUser_Returns404(t *testing.T) {
	t.Parallel()
	users := mex_seededUsers(t, economyTestGcid, gcidA)
	subs := repo.NewInMemUserSubscriptionRepo()
	srv := mex_economyMux(t, users, subs, repo.NewInMemManaStore(), repo.NewInMemKycRepo(),
		defaultFakePayments(), nil, httpadapter.EconomyHandlerOptions{})
	subID := mex_purchaseSub(t, srv, economyTestGcid, "familiar_basic", "monthly")

	w := httptest.NewRecorder()
	srv.ServeHTTP(w, bearerJSON(http.MethodPatch, "/api/v1/me/subscriptions/"+subID, gcidA, map[string]any{
		"target_plan_code": "familiar_premium",
		"proration_mode":   "create_prorations",
	}))
	if w.Code != http.StatusNotFound {
		t.Fatalf("status=%d want 404 body=%s", w.Code, w.Body.String())
	}
	if got := mustJSON(t, w.Body)["code"]; got != "ECONOMY_NOT_FOUND" {
		t.Errorf("code=%v want ECONOMY_NOT_FOUND", got)
	}
}

func TestChangeSubscriptionPlan_SaveError_Returns500(t *testing.T) {
	t.Parallel()
	subs := &mex_subsFake{
		InMemUserSubscriptionRepo: repo.NewInMemUserSubscriptionRepo(),
		subs:                      mex_newSub(t, economyTestGcid, "familiar_basic", usersub.BillingMonthly, true),
		saveErr:                   errors.New("write failed"),
	}
	srv := mex_standardMux(t, subs)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, bearerJSON(http.MethodPatch, "/api/v1/me/subscriptions/sub-1", economyTestGcid, map[string]any{
		"target_plan_code": "familiar_premium",
		"proration_mode":   "create_prorations",
	}))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d want 500 body=%s", w.Code, w.Body.String())
	}
	if got := mustJSON(t, w.Body)["code"]; got != "ECONOMY_REPO_ERROR" {
		t.Errorf("code=%v want ECONOMY_REPO_ERROR", got)
	}
}

// -----------------------------------------------------------------------------
// DELETE /api/v1/me/subscriptions/{id} — remaining branches
// -----------------------------------------------------------------------------

func TestCancelSubscription_UnknownSub_Returns404(t *testing.T) {
	t.Parallel()
	srv := newEconomyServer(t)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, bearerJSON(http.MethodDelete, "/api/v1/me/subscriptions/019f0000-0000-7000-8000-00000000dead",
		economyTestGcid, map[string]any{"reason": "user_request"}))
	if w.Code != http.StatusNotFound {
		t.Fatalf("status=%d want 404 body=%s", w.Code, w.Body.String())
	}
	if got := mustJSON(t, w.Body)["code"]; got != "ECONOMY_NOT_FOUND" {
		t.Errorf("code=%v want ECONOMY_NOT_FOUND", got)
	}
}

func TestCancelSubscription_OtherUser_Returns404(t *testing.T) {
	t.Parallel()
	users := mex_seededUsers(t, economyTestGcid, gcidA)
	subs := repo.NewInMemUserSubscriptionRepo()
	srv := mex_economyMux(t, users, subs, repo.NewInMemManaStore(), repo.NewInMemKycRepo(),
		defaultFakePayments(), nil, httpadapter.EconomyHandlerOptions{})
	subID := mex_purchaseSub(t, srv, economyTestGcid, "familiar_basic", "monthly")

	w := httptest.NewRecorder()
	srv.ServeHTTP(w, bearerJSON(http.MethodDelete, "/api/v1/me/subscriptions/"+subID, gcidA,
		map[string]any{"reason": "user_request"}))
	if w.Code != http.StatusNotFound {
		t.Fatalf("status=%d want 404 body=%s", w.Code, w.Body.String())
	}
	if got := mustJSON(t, w.Body)["code"]; got != "ECONOMY_NOT_FOUND" {
		t.Errorf("code=%v want ECONOMY_NOT_FOUND", got)
	}
}

func TestCancelSubscription_InvalidBody_Returns400(t *testing.T) {
	t.Parallel()
	srv := newEconomyServer(t)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, mex_rawBearer(http.MethodDelete, "/api/v1/me/subscriptions/some-id", economyTestGcid, "{"))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status=%d want 400 body=%s", w.Code, w.Body.String())
	}
	if got := mustJSON(t, w.Body)["code"]; got != "ECONOMY_INVALID_BODY" {
		t.Errorf("code=%v want ECONOMY_INVALID_BODY", got)
	}
}

func TestCancelSubscription_TerminalState_Returns409(t *testing.T) {
	t.Parallel()
	users := mex_seededUsers(t, economyTestGcid)
	subs := repo.NewInMemUserSubscriptionRepo()
	srv := mex_economyMux(t, users, subs, repo.NewInMemManaStore(), repo.NewInMemKycRepo(),
		defaultFakePayments(), nil, httpadapter.EconomyHandlerOptions{})

	expired := mex_newSub(t, economyTestGcid, "familiar_basic", usersub.BillingMonthly, false)
	if err := expired.MarkExpired(); err != nil {
		t.Fatalf("expire: %v", err)
	}
	if err := subs.Save(context.Background(), expired); err != nil {
		t.Fatalf("seed sub: %v", err)
	}
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, bearerJSON(http.MethodDelete, "/api/v1/me/subscriptions/"+expired.SubscriptionID,
		economyTestGcid, map[string]any{"reason": "user_request"}))
	if w.Code != http.StatusConflict {
		t.Fatalf("status=%d want 409 body=%s", w.Code, w.Body.String())
	}
	if got := mustJSON(t, w.Body)["code"]; got != "ECONOMY_INVALID_TRANSITION" {
		t.Errorf("code=%v want ECONOMY_INVALID_TRANSITION", got)
	}
}

func TestCancelSubscription_SaveError_Returns500(t *testing.T) {
	t.Parallel()
	subs := &mex_subsFake{
		InMemUserSubscriptionRepo: repo.NewInMemUserSubscriptionRepo(),
		subs:                      mex_newSub(t, economyTestGcid, "familiar_basic", usersub.BillingMonthly, true),
		saveErr:                   errors.New("write failed"),
	}
	srv := mex_standardMux(t, subs)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, bearerJSON(http.MethodDelete, "/api/v1/me/subscriptions/sub-1", economyTestGcid,
		map[string]any{"reason": "user_request"}))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d want 500 body=%s", w.Code, w.Body.String())
	}
	if got := mustJSON(t, w.Body)["code"]; got != "ECONOMY_REPO_ERROR" {
		t.Errorf("code=%v want ECONOMY_REPO_ERROR", got)
	}
}

func TestCancelSubscription_EffectiveAt_Variants(t *testing.T) {
	t.Parallel()
	users := mex_seededUsers(t, economyTestGcid)
	subs := repo.NewInMemUserSubscriptionRepo()
	srv := mex_economyMux(t, users, subs, repo.NewInMemManaStore(), repo.NewInMemKycRepo(),
		defaultFakePayments(), nil, httpadapter.EconomyHandlerOptions{})

	// Valid effective_at → honoured exactly.
	withEff := mex_newSub(t, economyTestGcid, "familiar_basic", usersub.BillingMonthly, true)
	if err := subs.Save(context.Background(), withEff); err != nil {
		t.Fatalf("seed sub: %v", err)
	}
	eff := "2026-12-01T00:00:00Z"
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, bearerJSON(http.MethodDelete, "/api/v1/me/subscriptions/"+withEff.SubscriptionID,
		economyTestGcid, map[string]any{"reason": "user_request", "effective_at": eff}))
	if w.Code != http.StatusOK {
		t.Fatalf("valid-eff status=%d body=%s", w.Code, w.Body.String())
	}
	if got := mustJSON(t, w.Body)["cancelled_at"]; got != eff {
		t.Errorf("cancelled_at=%v want %s", got, eff)
	}

	// Unparseable effective_at → falls back to current period end, still 200.
	badEff := mex_newSub(t, economyTestGcid, "familiar_basic", usersub.BillingMonthly, true)
	if err := subs.Save(context.Background(), badEff); err != nil {
		t.Fatalf("seed sub: %v", err)
	}
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, bearerJSON(http.MethodDelete, "/api/v1/me/subscriptions/"+badEff.SubscriptionID,
		economyTestGcid, map[string]any{"reason": "user_request", "effective_at": "not-a-time"}))
	if w.Code != http.StatusOK {
		t.Fatalf("bad-eff status=%d body=%s", w.Code, w.Body.String())
	}
	if got := mustJSON(t, w.Body)["status"]; got != "cancelled" {
		t.Errorf("status=%v want cancelled", got)
	}
}

func TestCancelSubscription_PublishesCancelledEvent(t *testing.T) {
	t.Parallel()
	rec := &mex_recordingPublisher{}
	pub := events.NewEconomyPublisher(rec)
	users := mex_seededUsers(t, economyTestGcid)
	subs := repo.NewInMemUserSubscriptionRepo()
	srv := mex_economyMux(t, users, subs, repo.NewInMemManaStore(), repo.NewInMemKycRepo(),
		defaultFakePayments(), pub, httpadapter.EconomyHandlerOptions{})
	sub := mex_newSub(t, economyTestGcid, "familiar_basic", usersub.BillingMonthly, true)
	if err := subs.Save(context.Background(), sub); err != nil {
		t.Fatalf("seed sub: %v", err)
	}

	w := httptest.NewRecorder()
	srv.ServeHTTP(w, bearerJSON(http.MethodDelete, "/api/v1/me/subscriptions/"+sub.SubscriptionID,
		economyTestGcid, map[string]any{"reason": "user_request"}))
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if rec.calls != 1 {
		t.Fatalf("publish calls=%d want 1", rec.calls)
	}
	if rec.lastTopic != usersub.TopicName(usersub.EventCancelled) {
		t.Errorf("topic=%q want %q", rec.lastTopic, usersub.TopicName(usersub.EventCancelled))
	}
}

// -----------------------------------------------------------------------------
// /api/v1/me/mana — rich wallet + repo errors
// -----------------------------------------------------------------------------

func TestGetMana_RichWalletAndBreakdown(t *testing.T) {
	t.Parallel()
	users := mex_seededUsers(t, economyTestGcid)
	manaStore := repo.NewInMemManaStore()
	srv := mex_economyMux(t, users, repo.NewInMemUserSubscriptionRepo(), manaStore,
		repo.NewInMemKycRepo(), defaultFakePayments(), nil, httpadapter.EconomyHandlerOptions{})

	ctx := context.Background()
	quoter := mana.NewQuoter(manaStore)
	exp := time.Now().UTC().Add(30 * 24 * time.Hour)
	if _, err := quoter.CreditMana(ctx, mana.CreditInput{
		Gcid: economyTestGcid, Source: mana.SourceTenantSubsidy, Units: 1200,
		Reason: mana.ReasonTenantSubsidy, IdempotencyKey: "mex-subsidy-1",
		TenantID: "01970000-0000-7000-8000-000000000001", ExpiresAt: &exp,
	}); err != nil {
		t.Fatalf("seed subsidy: %v", err)
	}
	if _, err := quoter.CreditMana(ctx, mana.CreditInput{
		Gcid: economyTestGcid, Source: mana.SourcePersonal, Units: 300,
		Reason: mana.ReasonTopup, IdempotencyKey: "mex-topup-1",
	}); err != nil {
		t.Fatalf("seed topup: %v", err)
	}

	w := httptest.NewRecorder()
	srv.ServeHTTP(w, bearerJSON(http.MethodGet, "/api/v1/me/mana", economyTestGcid, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	got := mustJSON(t, w.Body)
	if _, ok := got["last_credited_at"]; !ok {
		t.Errorf("last_credited_at missing: %v", got)
	}
	if got["balance_units"] != float64(1500) {
		t.Errorf("balance_units=%v want 1500", got["balance_units"])
	}
	rows, _ := got["subsidy_breakdown"].([]any)
	if len(rows) != 2 {
		t.Fatalf("subsidy_breakdown rows=%d want 2", len(rows))
	}
	var sawSubsidy, sawPersonal bool
	for _, r := range rows {
		row := r.(map[string]any)
		if row["source"] == "tenant_subsidy" {
			sawSubsidy = true
			if _, ok := row["tenant_id"]; !ok {
				t.Errorf("subsidy row missing tenant_id: %v", row)
			}
			if _, ok := row["expires_at"]; !ok {
				t.Errorf("subsidy row missing expires_at: %v", row)
			}
		}
		if row["source"] == "personal" {
			sawPersonal = true
		}
	}
	if !sawSubsidy || !sawPersonal {
		t.Errorf("breakdown sources missing: subsidy=%v personal=%v rows=%v", sawSubsidy, sawPersonal, rows)
	}
}

func TestGetMana_RepoError_Returns500(t *testing.T) {
	t.Parallel()
	manaStore := &mex_manaFake{InMemoryStore: mana.NewInMemoryStore(), getManaErr: errors.New("db down")}
	srv := mex_economyMux(t, mex_seededUsers(t, economyTestGcid), repo.NewInMemUserSubscriptionRepo(),
		manaStore, repo.NewInMemKycRepo(), defaultFakePayments(), nil, httpadapter.EconomyHandlerOptions{})
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, bearerJSON(http.MethodGet, "/api/v1/me/mana", economyTestGcid, nil))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d want 500 body=%s", w.Code, w.Body.String())
	}
	if got := mustJSON(t, w.Body)["code"]; got != "ECONOMY_REPO_ERROR" {
		t.Errorf("code=%v want ECONOMY_REPO_ERROR", got)
	}
}

// -----------------------------------------------------------------------------
// /api/v1/me/mana/ledger — filter/pagination branches + repo errors
// -----------------------------------------------------------------------------

func TestListManaLedger_RepoError_Returns500(t *testing.T) {
	t.Parallel()
	manaStore := &mex_manaFake{InMemoryStore: mana.NewInMemoryStore(), listLedgerErr: errors.New("db down")}
	srv := mex_economyMux(t, mex_seededUsers(t, economyTestGcid), repo.NewInMemUserSubscriptionRepo(),
		manaStore, repo.NewInMemKycRepo(), defaultFakePayments(), nil, httpadapter.EconomyHandlerOptions{})
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, bearerJSON(http.MethodGet, "/api/v1/me/mana/ledger", economyTestGcid, nil))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d want 500 body=%s", w.Code, w.Body.String())
	}
	if got := mustJSON(t, w.Body)["code"]; got != "ECONOMY_REPO_ERROR" {
		t.Errorf("code=%v want ECONOMY_REPO_ERROR", got)
	}
}

func TestListManaLedger_InvalidFilter_Returns400(t *testing.T) {
	t.Parallel()
	manaStore := &mex_manaFake{InMemoryStore: mana.NewInMemoryStore(), listLedgerErr: mana.ErrInvalidFilter}
	srv := mex_economyMux(t, mex_seededUsers(t, economyTestGcid), repo.NewInMemUserSubscriptionRepo(),
		manaStore, repo.NewInMemKycRepo(), defaultFakePayments(), nil, httpadapter.EconomyHandlerOptions{})
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, bearerJSON(http.MethodGet, "/api/v1/me/mana/ledger", economyTestGcid, nil))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status=%d want 400 body=%s", w.Code, w.Body.String())
	}
	if got := mustJSON(t, w.Body)["code"]; got != "ECONOMY_BAD_CURSOR" {
		t.Errorf("code=%v want ECONOMY_BAD_CURSOR", got)
	}
}

func TestListManaLedger_PageSizeDefaultsAndCap(t *testing.T) {
	t.Parallel()
	// Non-numeric page_size → silently falls back to the 25 default (200).
	srv := newLedgerServerSeeded(t, 5)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, bearerJSON(http.MethodGet, "/api/v1/me/mana/ledger?page_size=abc", economyTestGcid, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("non-numeric page_size status=%d", w.Code)
	}
	// page_size=1000 → capped at 100; 5 rows < 100 → no has_more.
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, bearerJSON(http.MethodGet, "/api/v1/me/mana/ledger?page_size=1000", economyTestGcid, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("capped page_size status=%d", w.Code)
	}
	if body := mustJSON(t, w.Body); body["has_more"] != false {
		t.Errorf("has_more=%v want false when rows < page cap", body["has_more"])
	}
}

func TestListManaLedger_FiltersApplied(t *testing.T) {
	t.Parallel()
	users := mex_seededUsers(t, economyTestGcid)
	manaStore := repo.NewInMemManaStore()
	base := time.Date(2026, 6, 26, 12, 0, 0, 0, time.UTC)
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		e := &mana.LedgerEntry{
			EntryID:           fmt.Sprintf("019f0000-0000-7000-8000-%012d", i),
			Gcid:              economyTestGcid,
			Direction:         mana.DirectionDebit,
			Units:             10,
			Reason:            mana.ReasonFamiliarAction,
			BalanceAfterUnits: int64(100 - i),
			RecordedAt:        base.Add(time.Duration(i) * time.Minute),
		}
		if err := manaStore.AppendLedger(ctx, e); err != nil {
			t.Fatalf("seed ledger: %v", err)
		}
	}
	srv := mex_economyMux(t, users, repo.NewInMemUserSubscriptionRepo(), manaStore,
		repo.NewInMemKycRepo(), defaultFakePayments(), nil, httpadapter.EconomyHandlerOptions{})

	q := fmt.Sprintf("/api/v1/me/mana/ledger?from=%s&to=%s&direction=debit&reason=familiar_action",
		base.Add(-time.Hour).Format(time.RFC3339), base.Add(2*time.Minute).Format(time.RFC3339))
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, bearerJSON(http.MethodGet, q, economyTestGcid, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	items, _ := mustJSON(t, w.Body)["items"].([]any)
	if len(items) != 2 { // rows at base and base+1m; base+2m excluded by to=
		t.Errorf("items=%d want 2 (from/to/direction/reason filter)", len(items))
	}
}

func TestListManaLedger_EntrySourceFields(t *testing.T) {
	t.Parallel()
	users := mex_seededUsers(t, economyTestGcid)
	manaStore := repo.NewInMemManaStore()
	e := &mana.LedgerEntry{
		EntryID:              "019f0000-0000-7000-8000-00000000led1",
		Gcid:                 economyTestGcid,
		Direction:            mana.DirectionDebit,
		Units:                10,
		Reason:               mana.ReasonSubscriptionGrant,
		BalanceAfterUnits:    90,
		RecordedAt:           time.Date(2026, 6, 26, 0, 0, 0, 0, time.UTC),
		SourceSubscriptionID: "019f0000-0000-7000-8000-00000000sub1",
		SourceTopupID:        "019f0000-0000-7000-8000-00000000top1",
		SourceAllocationID:   "019f0000-0000-7000-8000-00000000all1",
		SourceActionID:       "019f0000-0000-7000-8000-00000000act1",
	}
	if err := manaStore.AppendLedger(context.Background(), e); err != nil {
		t.Fatalf("seed ledger: %v", err)
	}
	srv := mex_economyMux(t, users, repo.NewInMemUserSubscriptionRepo(), manaStore,
		repo.NewInMemKycRepo(), defaultFakePayments(), nil, httpadapter.EconomyHandlerOptions{})

	w := httptest.NewRecorder()
	srv.ServeHTTP(w, bearerJSON(http.MethodGet, "/api/v1/me/mana/ledger", economyTestGcid, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	items, _ := mustJSON(t, w.Body)["items"].([]any)
	if len(items) != 1 {
		t.Fatalf("items=%d want 1", len(items))
	}
	row := items[0].(map[string]any)
	for _, k := range []string{"source_subscription_id", "source_topup_id", "source_allocation_id", "source_action_id"} {
		if _, ok := row[k]; !ok {
			t.Errorf("row missing %s: %v", k, row)
		}
	}
}

// -----------------------------------------------------------------------------
// /api/v1/me/mana/ledger/export — remaining branches
// -----------------------------------------------------------------------------

func TestExportManaLedger_BadCursor_Returns400(t *testing.T) {
	t.Parallel()
	srv := newLedgerServerSeeded(t, 0)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, bearerJSON(http.MethodGet, "/api/v1/me/mana/ledger/export?cursor=bm9waXBl", economyTestGcid, nil))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status=%d want 400 body=%s", w.Code, w.Body.String())
	}
	if got := mustJSON(t, w.Body)["code"]; got != "ECONOMY_BAD_CURSOR" {
		t.Errorf("code=%v want ECONOMY_BAD_CURSOR", got)
	}
}

func TestExportManaLedger_RepoError_Returns500(t *testing.T) {
	t.Parallel()
	manaStore := &mex_manaFake{InMemoryStore: mana.NewInMemoryStore(), listLedgerErr: errors.New("db down")}
	srv := mex_economyMux(t, mex_seededUsers(t, economyTestGcid), repo.NewInMemUserSubscriptionRepo(),
		manaStore, repo.NewInMemKycRepo(), defaultFakePayments(), nil, httpadapter.EconomyHandlerOptions{})
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, bearerJSON(http.MethodGet, "/api/v1/me/mana/ledger/export", economyTestGcid, nil))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d want 500 body=%s", w.Code, w.Body.String())
	}
	if got := mustJSON(t, w.Body)["code"]; got != "ECONOMY_REPO_ERROR" {
		t.Errorf("code=%v want ECONOMY_REPO_ERROR", got)
	}
}

// -----------------------------------------------------------------------------
// /api/v1/me/kyc/status — KYC-present mapping (kycResponse) + repo errors
// -----------------------------------------------------------------------------

func TestGetKycStatus_Present_MinimalRecord(t *testing.T) {
	t.Parallel()
	users := mex_seededUsers(t, economyTestGcid)
	kycRepo := repo.NewInMemKycRepo()
	v := &kyc.Verification{
		VerificationID: "019f0000-0000-7000-8000-00000000kyc1",
		Gcid:           economyTestGcid,
		Method:         kyc.MethodSingpass,
		Status:         kyc.StatusPending,
		Provider:       "ndi",
	}
	if err := kycRepo.Save(context.Background(), v); err != nil {
		t.Fatalf("seed kyc: %v", err)
	}
	srv := mex_economyMux(t, users, repo.NewInMemUserSubscriptionRepo(), repo.NewInMemManaStore(),
		kycRepo, defaultFakePayments(), nil, httpadapter.EconomyHandlerOptions{})

	w := httptest.NewRecorder()
	srv.ServeHTTP(w, bearerJSON(http.MethodGet, "/api/v1/me/kyc/status", economyTestGcid, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	got := mustJSON(t, w.Body)
	if got["verification_id"] != v.VerificationID {
		t.Errorf("verification_id=%v", got["verification_id"])
	}
	if _, ok := got["audit_log"]; ok {
		t.Errorf("audit_log present on record without audit entries: %v", got)
	}
	if _, ok := got["document_uri"]; ok {
		t.Errorf("document_uri present on minimal record: %v", got)
	}
}

func TestGetKycStatus_Present_RichRecord(t *testing.T) {
	t.Parallel()
	users := mex_seededUsers(t, economyTestGcid)
	kycRepo := repo.NewInMemKycRepo()
	now := time.Now().UTC()
	v := &kyc.Verification{
		VerificationID:  "019f0000-0000-7000-8000-00000000kyc2",
		Gcid:            economyTestGcid,
		Method:          kyc.MethodManualDoc,
		Status:          kyc.StatusVerified,
		Provider:        "ndi",
		DocumentURI:     "gs://docs/scan.pdf",
		VerifiedAt:      &now,
		RejectedAt:      &now,
		RejectionCode:   "DOC_BLURRY",
		FeeChargedCents: 999,
		Currency:        "USD",
		AuditLog: []kyc.AuditEntry{
			{Event: "verified", ActorGcid: "01970000-0000-7000-9000-000000000001", Notes: "self", OccurredAt: now},
		},
	}
	if err := kycRepo.Save(context.Background(), v); err != nil {
		t.Fatalf("seed kyc: %v", err)
	}
	srv := mex_economyMux(t, users, repo.NewInMemUserSubscriptionRepo(), repo.NewInMemManaStore(),
		kycRepo, defaultFakePayments(), nil, httpadapter.EconomyHandlerOptions{})

	w := httptest.NewRecorder()
	srv.ServeHTTP(w, bearerJSON(http.MethodGet, "/api/v1/me/kyc/status", economyTestGcid, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	got := mustJSON(t, w.Body)
	for _, k := range []string{"verification_id", "gcid", "method", "status", "provider",
		"document_uri", "verified_at", "rejected_reason", "fee_charged_cents", "currency"} {
		if _, ok := got[k]; !ok {
			t.Errorf("rich kycResponse missing %s: %v", k, got)
		}
	}
	audit, ok := got["audit_log"].([]any)
	if !ok || len(audit) != 1 {
		t.Fatalf("audit_log=%v want 1 entry", got["audit_log"])
	}
	entry := audit[0].(map[string]any)
	if entry["actor_gcid"] == nil || entry["notes"] == nil {
		t.Errorf("audit entry missing actor_gcid/notes: %v", entry)
	}
}

func TestGetKycStatus_RepoError_Returns500(t *testing.T) {
	t.Parallel()
	kycRepo := &mex_kycFake{InMemKycRepo: repo.NewInMemKycRepo(), getErr: errors.New("db down")}
	srv := mex_economyMux(t, mex_seededUsers(t, economyTestGcid), repo.NewInMemUserSubscriptionRepo(),
		repo.NewInMemManaStore(), kycRepo, defaultFakePayments(), nil, httpadapter.EconomyHandlerOptions{})
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, bearerJSON(http.MethodGet, "/api/v1/me/kyc/status", economyTestGcid, nil))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d want 500 body=%s", w.Code, w.Body.String())
	}
	if got := mustJSON(t, w.Body)["code"]; got != "KYC_REPO_ERROR" {
		t.Errorf("code=%v want KYC_REPO_ERROR", got)
	}
}

// -----------------------------------------------------------------------------
// /api/v1/me/kyc/singpass:initiate — remaining branches
// -----------------------------------------------------------------------------

func TestInitiateSingpass_SaveError_Returns500(t *testing.T) {
	t.Parallel()
	kycRepo := &mex_kycFake{InMemKycRepo: repo.NewInMemKycRepo(), saveErr: errors.New("write failed")}
	srv := mex_economyMux(t, mex_seededUsers(t, economyTestGcid), repo.NewInMemUserSubscriptionRepo(),
		repo.NewInMemManaStore(), kycRepo, defaultFakePayments(), nil,
		httpadapter.EconomyHandlerOptions{SingpassAuthURL: "https://stg-id.singpass.gov.sg/auth"})
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, bearerJSON(http.MethodPost, "/api/v1/me/kyc/singpass:initiate", economyTestGcid,
		map[string]any{"return_url": "https://app.chora.site/kyc/callback"}))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d want 500 body=%s", w.Code, w.Body.String())
	}
	if got := mustJSON(t, w.Body)["code"]; got != "KYC_REPO_ERROR" {
		t.Errorf("code=%v want KYC_REPO_ERROR", got)
	}
}
