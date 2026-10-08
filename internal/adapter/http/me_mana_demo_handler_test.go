// Handler-level specs for POST /api/v1/me/mana/demo-grant.
package httpadapter_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	httpadapter "github.com/apollo-chora/chora-identity/internal/adapter/http"
	"github.com/apollo-chora/chora-identity/internal/adapter/inmem"
	"github.com/apollo-chora/chora-identity/internal/adapter/repo"
	"github.com/apollo-chora/chora-identity/internal/domain/identity"
	mana "github.com/apollo-chora/chora-identity/internal/domain/user_mana"
)

const (
	demoGcidA = "01970000-0000-7000-8000-00000000da01"
	demoGcidB = "01970000-0000-7000-8000-00000000da02"
)

// newDemoServer wires a DemoManaHandler over the in-memory mana store and
// returns the mux plus the store so a test can inspect balances directly.
func newDemoServer(t *testing.T, cfg httpadapter.DemoManaConfig, gcids ...string) (http.Handler, *mana.InMemoryStore) {
	t.Helper()
	users := inmem.NewUserRepository()
	for _, g := range gcids {
		u, err := identity.NewUser(identity.NewUserParams{
			Email: g + "@chora.dev", IdentityProvider: identity.ProviderOIDC, FederatedSubject: g,
		})
		if err != nil {
			t.Fatalf("NewUser(%s): %v", g, err)
		}
		u.Gcid = g
		if err := users.Save(context.Background(), u); err != nil {
			t.Fatalf("Save(%s): %v", g, err)
		}
	}
	store := repo.NewInMemManaStore()
	mux := http.NewServeMux()
	httpadapter.NewDemoManaHandler(users, store, cfg).RegisterRoutes(mux)
	return mux, store
}

func demoEnabled(units int64) httpadapter.DemoManaConfig {
	return httpadapter.DemoManaConfig{
		Enabled:          true,
		GrantUnits:       units,
		MaxPerGcid:       10,
		TotalBudgetUnits: 1_000_000_000,
	}
}

func demoPost(gcid, key string, body string) *http.Request {
	var buf bytes.Buffer
	if body != "" {
		_, _ = buf.WriteString(body)
	}
	r := httptest.NewRequest(http.MethodPost, "/api/v1/me/mana/demo-grant", &buf)
	r.Header.Set("Authorization", "Bearer "+gcid)
	r.Header.Set("Content-Type", "application/json")
	if key != "" {
		r.Header.Set("Idempotency-Key", key)
	}
	return r
}

func doDemo(t *testing.T, h http.Handler, r *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

func demoBody(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("invalid json (status %d): %v body=%s", rec.Code, err, rec.Body.String())
	}
	return out
}

// --- tests -------------------------------------------------------------------

func TestDemoGrant_FlagOff_Returns404(t *testing.T) {
	// The zero value of DemoManaConfig is disabled — default OFF.
	h, store := newDemoServer(t, httpadapter.DemoManaConfig{}, demoGcidA)

	rec := doDemo(t, h, demoPost(demoGcidA, "k-1", ""))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (body=%s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "DEMO_UNAVAILABLE") {
		t.Errorf("body = %s, want DEMO_UNAVAILABLE", rec.Body.String())
	}
	if got := mustBalance(t, store, demoGcidA); got != 0 {
		t.Errorf("balance = %d, want 0 — a disabled demo must not credit", got)
	}
}

func TestDemoGrant_MissingIdempotencyKey_Returns400(t *testing.T) {
	h, store := newDemoServer(t, demoEnabled(1_000_000), demoGcidA)

	rec := doDemo(t, h, demoPost(demoGcidA, "", ""))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (body=%s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "IDEMPOTENCY_KEY_REQUIRED") {
		t.Errorf("body = %s, want IDEMPOTENCY_KEY_REQUIRED", rec.Body.String())
	}
	if got := mustBalance(t, store, demoGcidA); got != 0 {
		t.Errorf("balance = %d, want 0", got)
	}
}

func TestDemoGrant_Success_ReturnsGrantShape(t *testing.T) {
	h, store := newDemoServer(t, demoEnabled(1_000_000), demoGcidA)

	rec := doDemo(t, h, demoPost(demoGcidA, "k-ok", ""))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	body := demoBody(t, rec)
	if body["granted_units"] != float64(1_000_000) {
		t.Errorf("granted_units = %v, want 1000000", body["granted_units"])
	}
	if body["balance_units"] != float64(1_000_000) {
		t.Errorf("balance_units = %v, want 1000000", body["balance_units"])
	}
	if body["replayed"] != false {
		t.Errorf("replayed = %v, want false", body["replayed"])
	}
	if body["reason"] != "demo_grant" {
		t.Errorf("reason = %v, want demo_grant", body["reason"])
	}

	// The ledger row must be a mint under demo_grant.
	entries, err := store.ListLedger(context.Background(), mana.LedgerFilter{Gcid: demoGcidA})
	if err != nil {
		t.Fatalf("ListLedger: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("ledger rows = %d, want 1", len(entries))
	}
	if entries[0].Direction != mana.DirectionMint || entries[0].Reason != mana.ReasonDemoGrant {
		t.Errorf("entry = %s/%s, want mint/demo_grant", entries[0].Direction, entries[0].Reason)
	}
	if got := mustBalance(t, store, demoGcidA); got != 1_000_000 {
		t.Errorf("balance = %d, want 1000000", got)
	}
}

func TestDemoGrant_SameIdempotencyKey_GrantsExactlyOnce(t *testing.T) {
	h, store := newDemoServer(t, demoEnabled(1_000_000), demoGcidA)

	for i := 0; i < 5; i++ {
		rec := doDemo(t, h, demoPost(demoGcidA, "k-replay", ""))
		if rec.Code != http.StatusOK {
			t.Fatalf("attempt %d: status = %d, want 200 (body=%s)", i, rec.Code, rec.Body.String())
		}
		body := demoBody(t, rec)
		if i == 0 && body["replayed"] != false {
			t.Errorf("first attempt replayed = %v, want false", body["replayed"])
		}
		if i > 0 && body["replayed"] != true {
			t.Errorf("attempt %d replayed = %v, want true", i, body["replayed"])
		}
	}
	if got := mustBalance(t, store, demoGcidA); got != 1_000_000 {
		t.Errorf("balance = %d, want 1000000 — the key must grant exactly once", got)
	}
	entries, _ := store.ListLedger(context.Background(), mana.LedgerFilter{Gcid: demoGcidA})
	if len(entries) != 1 {
		t.Errorf("ledger rows = %d, want exactly 1", len(entries))
	}
}

func TestDemoGrant_ReportedBalanceReflectsSpending(t *testing.T) {
	// A replay after the user has spent part of the grant must report the
	// CURRENT balance, never top it back up.
	h, store := newDemoServer(t, demoEnabled(1_000_000), demoGcidA)

	if rec := doDemo(t, h, demoPost(demoGcidA, "k-1", "")); rec.Code != http.StatusOK {
		t.Fatalf("first: status = %d", rec.Code)
	}
	spend(t, store, demoGcidA, 400_000)

	rec := doDemo(t, h, demoPost(demoGcidA, "k-1", ""))
	if rec.Code != http.StatusOK {
		t.Fatalf("replay: status = %d", rec.Code)
	}
	body := demoBody(t, rec)
	if body["replayed"] != true {
		t.Errorf("replayed = %v, want true", body["replayed"])
	}
	if body["balance_units"] != float64(600_000) {
		t.Errorf("balance_units = %v, want 600000 (the spent balance)", body["balance_units"])
	}
	if got := mustBalance(t, store, demoGcidA); got != 600_000 {
		t.Errorf("balance = %d, want 600000", got)
	}
}

func TestDemoGrant_WrongGcid_CannotCreditAnotherAccount(t *testing.T) {
	// The GCID comes ONLY from the validated session context. A caller must not
	// be able to credit a different account by naming it in the body or query.
	h, store := newDemoServer(t, demoEnabled(1_000_000), demoGcidA, demoGcidB)

	req := demoPost(demoGcidA, "k-target", `{"gcid":"`+demoGcidB+`","units":999999}`)
	req.URL.RawQuery = "gcid=" + demoGcidB
	rec := doDemo(t, h, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	body := demoBody(t, rec)
	if body["granted_units"] != float64(1_000_000) {
		t.Errorf("granted_units = %v, want the FIXED 1000000 — the body must be ignored", body["granted_units"])
	}
	if got := mustBalance(t, store, demoGcidA); got != 1_000_000 {
		t.Errorf("A balance = %d, want 1000000", got)
	}
	if got := mustBalance(t, store, demoGcidB); got != 0 {
		t.Errorf("B balance = %d, want 0 — A must not be able to credit B", got)
	}
}

func TestDemoGrant_PerGcidCap_Returns429(t *testing.T) {
	cfg := demoEnabled(1_000_000)
	cfg.MaxPerGcid = 2
	h, store := newDemoServer(t, cfg, demoGcidA)

	for i := 1; i <= 2; i++ {
		rec := doDemo(t, h, demoPost(demoGcidA, "k-cap-"+strings.Repeat("x", i), ""))
		if rec.Code != http.StatusOK {
			t.Fatalf("grant %d: status = %d, want 200", i, rec.Code)
		}
	}
	rec := doDemo(t, h, demoPost(demoGcidA, "k-cap-3", ""))
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429 (body=%s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "DEMO_GRANT_LIMIT_REACHED") {
		t.Errorf("body = %s, want DEMO_GRANT_LIMIT_REACHED", rec.Body.String())
	}
	if got := mustBalance(t, store, demoGcidA); got != 2_000_000 {
		t.Errorf("balance = %d, want 2000000 (capped, not over-granted)", got)
	}
}

func TestDemoGrant_TotalBudget_Returns429(t *testing.T) {
	cfg := demoEnabled(1_000_000)
	cfg.MaxPerGcid = 100
	cfg.TotalBudgetUnits = 2_500_000
	h, store := newDemoServer(t, cfg, demoGcidA, demoGcidB)

	// Two full grants from A consume 2,000,000 of the 2,500,000 budget.
	for i, k := range []string{"k-b1", "k-b2"} {
		rec := doDemo(t, h, demoPost(demoGcidA, k, ""))
		if rec.Code != http.StatusOK {
			t.Fatalf("A grant %d: status = %d, want 200", i, rec.Code)
		}
	}
	// A third would push the total to 3,000,000 > 2,500,000.
	rec := doDemo(t, h, demoPost(demoGcidA, "k-b3", ""))
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429 (body=%s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "DEMO_GRANT_BUDGET_EXHAUSTED") {
		t.Errorf("body = %s, want DEMO_GRANT_BUDGET_EXHAUSTED", rec.Body.String())
	}
	if got := mustBalance(t, store, demoGcidA); got != 2_000_000 {
		t.Errorf("A balance = %d, want 2000000", got)
	}
}

func TestDemoGrant_ConcurrentSameKey_GrantsExactlyOnce(t *testing.T) {
	h, store := newDemoServer(t, demoEnabled(1_000_000), demoGcidA)

	const workers = 12
	recs := make([]*httptest.ResponseRecorder, workers)
	done := make(chan struct{})
	for i := range workers {
		go func(i int) {
			defer func() { done <- struct{}{} }()
			recs[i] = httptest.NewRecorder()
			h.ServeHTTP(recs[i], demoPost(demoGcidA, "k-race", ""))
		}(i)
	}
	for range workers {
		<-done
	}

	var ok, replayed int
	for i := range workers {
		switch {
		case recs[i].Code == http.StatusOK && !strings.Contains(recs[i].Body.String(), `"replayed":true`):
			ok++
		case recs[i].Code == http.StatusOK:
			replayed++
		default:
			t.Errorf("worker %d: status = %d body=%s", i, recs[i].Code, recs[i].Body.String())
		}
	}
	if ok != 1 {
		t.Errorf("fresh grants = %d, want exactly 1", ok)
	}
	if replayed != workers-1 {
		t.Errorf("replays = %d, want %d", replayed, workers-1)
	}
	if got := mustBalance(t, store, demoGcidA); got != 1_000_000 {
		t.Errorf("balance = %d, want 1000000 (granted once)", got)
	}
}

func TestDemoGrant_GetMethod_Returns405(t *testing.T) {
	h, _ := newDemoServer(t, demoEnabled(1_000_000), demoGcidA)
	r := httptest.NewRequest(http.MethodGet, "/api/v1/me/mana/demo-grant", nil)
	r.Header.Set("Authorization", "Bearer "+demoGcidA)
	rec := doDemo(t, h, r)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", rec.Code)
	}
}

func TestDemoGrant_ReusedKeyWithDifferentPayload_Returns409(t *testing.T) {
	// The key is already recorded for a DIFFERENT operation (here: a manual
	// grant of 500). Reporting a replay would silently accept the mismatch, so
	// the handler must surface the idempotency conflict instead.
	h, store := newDemoServer(t, demoEnabled(1_000_000), demoGcidA)

	if _, err := store.CreditWallet(context.Background(), mana.CreditWalletInput{
		Gcid: demoGcidA, Units: 500, Direction: mana.DirectionMint,
		Reason: mana.ReasonDemoGrant, IdempotencyKey: "k-conflict",
	}); err != nil {
		t.Fatalf("seed the conflicting entry: %v", err)
	}

	rec := doDemo(t, h, demoPost(demoGcidA, "k-conflict", ""))
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409 (body=%s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "IDEMPOTENCY_KEY_CONFLICT") {
		t.Errorf("body = %s, want IDEMPOTENCY_KEY_CONFLICT", rec.Body.String())
	}
	if got := mustBalance(t, store, demoGcidA); got != 500 {
		t.Errorf("balance = %d, want the untouched 500", got)
	}
}

func TestDemoGrant_ReplayAfterCapReached_StillReturns200(t *testing.T) {
	// The idempotency re-check runs BEFORE the cap check inside the credit
	// transaction, so re-sending a key that already granted must not start
	// failing once the cap is reached.
	cfg := demoEnabled(1_000_000)
	cfg.MaxPerGcid = 1
	h, store := newDemoServer(t, cfg, demoGcidA)

	if rec := doDemo(t, h, demoPost(demoGcidA, "k-first", "")); rec.Code != http.StatusOK {
		t.Fatalf("first grant: status = %d", rec.Code)
	}
	// The cap is now exhausted for a NEW key...
	if rec := doDemo(t, h, demoPost(demoGcidA, "k-second", "")); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("new key: status = %d, want 429", rec.Code)
	}
	// ...but replaying the granted key still succeeds.
	rec := doDemo(t, h, demoPost(demoGcidA, "k-first", ""))
	if rec.Code != http.StatusOK {
		t.Fatalf("replay: status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	if body := demoBody(t, rec); body["replayed"] != true {
		t.Errorf("replayed = %v, want true", body["replayed"])
	}
	if got := mustBalance(t, store, demoGcidA); got != 1_000_000 {
		t.Errorf("balance = %d, want 1000000", got)
	}
}

// --- helpers -----------------------------------------------------------------

func mustBalance(t *testing.T, store *mana.InMemoryStore, gcid string) int64 {
	t.Helper()
	m, err := store.GetMana(context.Background(), gcid)
	if err != nil {
		t.Fatalf("GetMana(%s): %v", gcid, err)
	}
	if m == nil {
		return 0
	}
	return m.BalanceUnits
}

// spend debits a wallet directly (a stand-in for the user consuming mana).
func spend(t *testing.T, store *mana.InMemoryStore, gcid string, units int64) {
	t.Helper()
	m, err := store.GetMana(context.Background(), gcid)
	if err != nil {
		t.Fatalf("GetMana: %v", err)
	}
	if m == nil {
		m = mana.NewUserMana(gcid)
	}
	if err := m.Debit(units); err != nil {
		t.Fatalf("Debit: %v", err)
	}
	if err := store.SaveMana(context.Background(), m); err != nil {
		t.Fatalf("SaveMana: %v", err)
	}
}
