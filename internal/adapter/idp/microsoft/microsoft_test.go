// Package microsoft_test holds the RED-phase TDD specs for the Microsoft
// (Azure AD / Microsoft personal + work) OIDC adapter.
//
// Microsoft OIDC supports both personal accounts (live.com / outlook.com /
// hotmail.com) and work / school accounts (Azure AD tenant). The "common"
// endpoint multiplexes both. Per locked stack this is one of the four IdPs
// federated through the upstream identity provider — chora-identity itself talks
// directly to Microsoft for sandbox / Phyllis MVP §3 Step 2; production
// production wires through Identity Platform.
//
// Endpoints sourced from env (MICROSOFT_OIDC_ISSUER_URL etc) — no inline
// config. Discovery URL convention:
//
//	https://login.microsoftonline.com/{tenant}/v2.0/.well-known/openid-configuration
//
// The adapter implements:
//  1. AuthorizationURL (PKCE + state) — builds /authorize URL.
//  2. ExchangeCode — POSTs /token, returns access+id+refresh.
//  3. ValidateIDToken — verifies signature against MS JWKS + issuer +
//     audience claims.
//  4. UserInfo — GET /v1.0/me with Bearer (Microsoft Graph) — extracts
//     email, name, sub (oid).
//  5. Federate — orchestrates ExchangeCode → ValidateIDToken → UserInfo →
//     emits chora.identity.federation.succeeded.v1 envelope-conformant.
package microsoft_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/apollo-chora/chora-identity/internal/adapter/idp/microsoft"
)

const (
	testClientID     = "chora-msft-client"
	testClientSecret = "chora-msft-secret"
	testRedirectURI  = "https://chora.site/auth/microsoft/callback"
	testTenant       = "common"
)

// ─────────────────────────────────────────────────────────────────────────────
// AuthorizationURL — builds /authorize URL with state + PKCE challenge.
// ─────────────────────────────────────────────────────────────────────────────

func TestMicrosoftClient_AuthorizationURL_ContainsRequiredParams(t *testing.T) {
	t.Parallel()
	c := microsoft.New(microsoft.Config{
		IssuerURL:    "https://login.microsoftonline.com/common/v2.0",
		Tenant:       testTenant,
		ClientID:     testClientID,
		ClientSecret: testClientSecret,
		RedirectURI:  testRedirectURI,
	})
	got, err := c.AuthorizationURL("state-x", "challenge-y")
	if err != nil {
		t.Fatalf("AuthorizationURL: %v", err)
	}
	mustContain := []string{
		"login.microsoftonline.com",
		"client_id=" + testClientID,
		"response_type=code",
		"scope=openid",
		"state=state-x",
		"code_challenge=challenge-y",
		"code_challenge_method=S256",
	}
	for _, s := range mustContain {
		if !strings.Contains(got, s) {
			t.Fatalf("expected URL to contain %q, got %s", s, got)
		}
	}
	// Microsoft requires email + profile for basic claims.
	if !strings.Contains(got, "email") || !strings.Contains(got, "profile") {
		t.Errorf("expected email+profile scopes in URL: %s", got)
	}
}

func TestMicrosoftClient_AuthorizationURL_RejectsEmpty(t *testing.T) {
	t.Parallel()
	c := microsoft.New(microsoft.Config{IssuerURL: "", ClientID: testClientID})
	if _, err := c.AuthorizationURL("s", "c"); err == nil {
		t.Fatalf("expected error when MICROSOFT_OIDC_ISSUER_URL not set")
	}
	c2 := microsoft.New(microsoft.Config{IssuerURL: "https://x", ClientID: ""})
	if _, err := c2.AuthorizationURL("s", "c"); err == nil {
		t.Fatalf("expected error when MICROSOFT_OIDC_CLIENT_ID not set")
	}
	c3 := microsoft.New(microsoft.Config{IssuerURL: "https://x", ClientID: testClientID})
	if _, err := c3.AuthorizationURL("", "c"); err == nil {
		t.Fatalf("expected error empty state")
	}
	if _, err := c3.AuthorizationURL("s", ""); err == nil {
		t.Fatalf("expected error empty code_challenge")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// ExchangeCode — POST /token, returns Tokens.
// ─────────────────────────────────────────────────────────────────────────────

func TestMicrosoftClient_ExchangeCode_HappyPath(t *testing.T) {
	t.Parallel()

	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if err := r.ParseForm(); err != nil {
			t.Fatalf("ParseForm: %v", err)
		}
		if got := r.Form.Get("grant_type"); got != "authorization_code" {
			t.Errorf("grant_type = %q", got)
		}
		if got := r.Form.Get("code"); got != "auth-code-1" {
			t.Errorf("code = %q", got)
		}
		if got := r.Form.Get("code_verifier"); got != "verifier-1" {
			t.Errorf("code_verifier = %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token":  "at-1",
			"id_token":      "id-token-1",
			"refresh_token": "rt-1",
			"token_type":    "Bearer",
			"expires_in":    3600,
		})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := microsoft.New(microsoft.Config{
		IssuerURL:    srv.URL,
		ClientID:     testClientID,
		ClientSecret: testClientSecret,
		RedirectURI:  testRedirectURI,
		Tenant:       testTenant,
	})
	tok, err := c.ExchangeCode(context.Background(), "auth-code-1", "verifier-1")
	if err != nil {
		t.Fatalf("ExchangeCode: %v", err)
	}
	if tok.AccessToken != "at-1" {
		t.Errorf("AccessToken = %q", tok.AccessToken)
	}
	if tok.IDToken != "id-token-1" {
		t.Errorf("IDToken = %q", tok.IDToken)
	}
	if tok.RefreshToken != "rt-1" {
		t.Errorf("RefreshToken = %q", tok.RefreshToken)
	}
}

func TestMicrosoftClient_ExchangeCode_PropagatesNon200(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
	}))
	defer srv.Close()
	c := microsoft.New(microsoft.Config{IssuerURL: srv.URL, ClientID: testClientID, ClientSecret: testClientSecret, RedirectURI: testRedirectURI})
	if _, err := c.ExchangeCode(context.Background(), "bad", "v"); err == nil {
		t.Fatalf("expected error on 400")
	}
}

func TestMicrosoftClient_ExchangeCode_RejectsEmptyArgs(t *testing.T) {
	t.Parallel()
	c := microsoft.New(microsoft.Config{IssuerURL: "https://x.invalid", ClientID: testClientID})
	if _, err := c.ExchangeCode(context.Background(), "", "v"); err == nil {
		t.Fatalf("expected empty code error")
	}
	if _, err := c.ExchangeCode(context.Background(), "c", ""); err == nil {
		t.Fatalf("expected empty verifier error")
	}
	c2 := microsoft.New(microsoft.Config{IssuerURL: "", ClientID: testClientID})
	if _, err := c2.ExchangeCode(context.Background(), "c", "v"); err == nil {
		t.Fatalf("expected empty issuer error")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// UserInfo — GET /oidc/userinfo with Bearer token.
// ─────────────────────────────────────────────────────────────────────────────

func TestMicrosoftClient_UserInfo_ParsesGraphClaims(t *testing.T) {
	t.Parallel()
	mux := http.NewServeMux()
	mux.HandleFunc("/oidc/userinfo", func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer at-1" {
			t.Errorf("Authorization = %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"sub": "msft-oid-12345",
			"name": "Phyllis Tan",
			"email": "phyllis@mightymind.sg",
			"preferred_username": "phyllis@mightymind.sg",
			"locale": "en-SG"
		}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := microsoft.New(microsoft.Config{IssuerURL: srv.URL, ClientID: testClientID})
	info, err := c.UserInfo(context.Background(), "at-1")
	if err != nil {
		t.Fatalf("UserInfo: %v", err)
	}
	if info.Sub != "msft-oid-12345" {
		t.Errorf("Sub = %q", info.Sub)
	}
	if info.Email != "phyllis@mightymind.sg" {
		t.Errorf("Email = %q", info.Email)
	}
	if info.Name != "Phyllis Tan" {
		t.Errorf("Name = %q", info.Name)
	}
	if info.Locale != "en-SG" {
		t.Errorf("Locale = %q", info.Locale)
	}
}

func TestMicrosoftClient_UserInfo_PropagatesNon200(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	c := microsoft.New(microsoft.Config{IssuerURL: srv.URL, ClientID: testClientID})
	if _, err := c.UserInfo(context.Background(), "expired"); err == nil {
		t.Fatalf("expected error on 401")
	}
}

func TestMicrosoftClient_UserInfo_RejectsEmptyToken(t *testing.T) {
	t.Parallel()
	c := microsoft.New(microsoft.Config{IssuerURL: "https://x.invalid", ClientID: testClientID})
	if _, err := c.UserInfo(context.Background(), ""); err == nil {
		t.Fatalf("expected empty access token error")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Federate — orchestrates ExchangeCode → UserInfo → publish federation event.
// ─────────────────────────────────────────────────────────────────────────────

func TestMicrosoftClient_Federate_PublishesEnvelopeConformantEvent(t *testing.T) {
	t.Parallel()

	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "at-1",
			"id_token":     "id-token-1",
		})
	})
	mux.HandleFunc("/oidc/userinfo", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"sub":"msft-oid-9","name":"Phyllis","email":"phyllis@mightymind.sg"}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	pub := &recordingPublisher{}
	c := microsoft.New(microsoft.Config{
		IssuerURL:    srv.URL,
		ClientID:     testClientID,
		ClientSecret: testClientSecret,
		RedirectURI:  testRedirectURI,
		Tenant:       testTenant,
		Publisher:    pub,
	})

	res, err := c.Federate(context.Background(), microsoft.FederateInput{
		GCID:         "gcid-1",
		TenantID:     "01970000-0000-7000-8000-0000000000aa",
		Code:         "code-1",
		CodeVerifier: "verifier-1",
		Traceparent:  "00-aabb-ccdd-01",
	})
	if err != nil {
		t.Fatalf("Federate: %v", err)
	}
	if res.Sub != "msft-oid-9" {
		t.Errorf("Sub = %q", res.Sub)
	}
	if got := len(pub.records); got != 1 {
		t.Fatalf("expected 1 event, got %d", got)
	}
	rec := pub.records[0]
	// Topic shape: chora.identity.federation.{succeeded,rejected}.v1
	if rec.Topic != "chora.identity.federation.succeeded.v1" {
		t.Errorf("Topic = %q", rec.Topic)
	}
	if rec.Payload["provider"] != "microsoft" {
		t.Errorf("provider = %v", rec.Payload["provider"])
	}
	if rec.Payload["sub"] != "msft-oid-9" {
		t.Errorf("sub = %v", rec.Payload["sub"])
	}
	if rec.GCID != "gcid-1" || rec.TenantID != "01970000-0000-7000-8000-0000000000aa" {
		t.Errorf("envelope tenant/gcid wrong: %+v", rec)
	}
	if rec.Traceparent != "00-aabb-ccdd-01" {
		t.Errorf("Traceparent = %q", rec.Traceparent)
	}
	if rec.SourceService != "chora-identity" {
		t.Errorf("source_service = %q", rec.SourceService)
	}
	// IMDA evidence: federation.succeeded carries D1 accountability per spec.
	if got := rec.Payload["chora_imda_dimension"]; got != "accountability" {
		t.Errorf("expected chora_imda_dimension=accountability, got %v", got)
	}
}

func TestMicrosoftClient_Federate_RejectionEmitsSafetyEvidence(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
	}))
	defer srv.Close()
	pub := &recordingPublisher{}
	c := microsoft.New(microsoft.Config{
		IssuerURL: srv.URL, ClientID: testClientID, ClientSecret: testClientSecret,
		RedirectURI: testRedirectURI, Publisher: pub,
	})
	_, err := c.Federate(context.Background(), microsoft.FederateInput{
		GCID: "gcid-1", TenantID: "01970000-0000-7000-8000-0000000000aa",
		Code: "code-bad", CodeVerifier: "v",
	})
	if err == nil {
		t.Fatalf("expected error on /token 400")
	}
	if got := len(pub.records); got != 1 {
		t.Fatalf("expected 1 rejection event, got %d", got)
	}
	if pub.records[0].Topic != "chora.identity.federation.rejected.v1" {
		t.Errorf("Topic = %q", pub.records[0].Topic)
	}
	if got := pub.records[0].Payload["chora_imda_dimension"]; got != "safety_and_robustness" {
		t.Errorf("expected safety_and_robustness, got %v", got)
	}
}

func TestMicrosoftClient_Federate_ValidatesRequiredFields(t *testing.T) {
	t.Parallel()
	c := microsoft.New(microsoft.Config{IssuerURL: "https://x.invalid", ClientID: testClientID})
	cases := []microsoft.FederateInput{
		{GCID: "", TenantID: "t", Code: "c", CodeVerifier: "v"},
		{GCID: "g", TenantID: "", Code: "c", CodeVerifier: "v"},
		{GCID: "g", TenantID: "t", Code: "", CodeVerifier: "v"},
		{GCID: "g", TenantID: "t", Code: "c", CodeVerifier: ""},
	}
	for i, in := range cases {
		if _, err := c.Federate(context.Background(), in); err == nil {
			t.Errorf("case %d: expected error", i)
		}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Test helper — minimal Publisher recorder.
// ─────────────────────────────────────────────────────────────────────────────

type recordingPublisher struct {
	records []microsoft.PublishedRecord
}

func (r *recordingPublisher) Publish(topic string, env microsoft.EventEnvelope, payload map[string]any) error {
	r.records = append(r.records, microsoft.PublishedRecord{
		Topic:         topic,
		EventID:       env.EventID,
		TenantID:      env.TenantID,
		GCID:          env.GCID,
		Traceparent:   env.Traceparent,
		SourceProject: env.SourceProject,
		SourceService: env.SourceService,
		SchemaVersion: env.SchemaVersion,
		Payload:       payload,
	})
	return nil
}
