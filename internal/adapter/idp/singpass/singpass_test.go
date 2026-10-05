// Package singpass_test holds the RED-phase TDD specs for the Singpass NDI
// (National Digital Identity) sandbox client.
//
// Singpass is Singapore's national OIDC IdP. The NDI sandbox issues test
// credentials at stg-id.singpass.gov.sg. This adapter implements the OIDC
// Authorization-Code-with-PKCE flow against the sandbox issuer:
//
//  1. AuthorizationURL → builds /authorize URL with state + PKCE challenge.
//  2. ExchangeCode      → POSTs to /token with code + verifier, returns tokens.
//  3. UserInfo          → GETs /userinfo with access_token, returns claims
//     (NRIC/FIN sub, name, email if scope grants it).
//  4. Link              → publishes chora.identity.singpass.linked.v1 event.
//
// All endpoints sourced from env (SINGPASS_ISSUER_URL etc) — no inline config.
// httptest server emulates the NDI sandbox; production wiring is identical
// shape with only env values changed.
package singpass_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/apollo-chora/chora-identity/internal/adapter/idp/singpass"
)

const (
	testClientID     = "chora-test-client"
	testClientSecret = "chora-test-secret"
	testRedirectURI  = "https://chora.site/auth/singpass/callback"
)

// -----------------------------------------------------------------------------
// AuthorizationURL — builds the /authorize URL with PKCE + state.
// -----------------------------------------------------------------------------

func TestSingpassClient_AuthorizationURL_ContainsRequiredParams(t *testing.T) {
	t.Parallel()
	c := singpass.New(singpass.Config{
		IssuerURL:    "https://stg-id.singpass.gov.sg",
		ClientID:     testClientID,
		ClientSecret: testClientSecret,
		RedirectURI:  testRedirectURI,
	})
	got, err := c.AuthorizationURL("state-xyz", "challenge-abc")
	if err != nil {
		t.Fatalf("AuthorizationURL: unexpected error: %v", err)
	}
	mustContain := []string{
		"https://stg-id.singpass.gov.sg/auth",
		"client_id=" + testClientID,
		"response_type=code",
		"scope=openid",
		"state=state-xyz",
		"code_challenge=challenge-abc",
		"code_challenge_method=S256",
	}
	for _, s := range mustContain {
		if !strings.Contains(got, s) {
			t.Fatalf("expected URL to contain %q, got %s", s, got)
		}
	}
}

func TestSingpassClient_AuthorizationURL_RejectsEmptyIssuer(t *testing.T) {
	t.Parallel()
	c := singpass.New(singpass.Config{IssuerURL: "", ClientID: testClientID})
	if _, err := c.AuthorizationURL("s", "c"); err == nil {
		t.Fatalf("expected error when SINGPASS_ISSUER_URL not set")
	}
}

func TestSingpassClient_AuthorizationURL_RejectsEmptyState(t *testing.T) {
	t.Parallel()
	c := singpass.New(singpass.Config{
		IssuerURL: "https://stg-id.singpass.gov.sg",
		ClientID:  testClientID,
	})
	if _, err := c.AuthorizationURL("", "c"); err == nil {
		t.Fatalf("expected error for empty state")
	}
	if _, err := c.AuthorizationURL("s", ""); err == nil {
		t.Fatalf("expected error for empty code_challenge")
	}
}

// -----------------------------------------------------------------------------
// ExchangeCode — POST to /token, returns access+id token.
// -----------------------------------------------------------------------------

func TestSingpassClient_ExchangeCode_HappyPath(t *testing.T) {
	t.Parallel()

	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		// Form-encoded body per RFC 6749.
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
			"access_token": "at-1",
			"id_token":     "id-token-1",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := singpass.New(singpass.Config{
		IssuerURL:    srv.URL,
		ClientID:     testClientID,
		ClientSecret: testClientSecret,
		RedirectURI:  testRedirectURI,
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
}

func TestSingpassClient_ExchangeCode_PropagatesNon200(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
	}))
	defer srv.Close()

	c := singpass.New(singpass.Config{IssuerURL: srv.URL, ClientID: testClientID, ClientSecret: testClientSecret, RedirectURI: testRedirectURI})
	if _, err := c.ExchangeCode(context.Background(), "bad", "v"); err == nil {
		t.Fatalf("expected error on 400 response")
	}
}

func TestSingpassClient_ExchangeCode_RejectsEmptyArgs(t *testing.T) {
	t.Parallel()
	c := singpass.New(singpass.Config{IssuerURL: "https://x.invalid", ClientID: testClientID})
	if _, err := c.ExchangeCode(context.Background(), "", "v"); err == nil {
		t.Fatalf("expected error empty code")
	}
	if _, err := c.ExchangeCode(context.Background(), "c", ""); err == nil {
		t.Fatalf("expected error empty verifier")
	}
}

// -----------------------------------------------------------------------------
// UserInfo — GET /userinfo with Bearer token.
// -----------------------------------------------------------------------------

func TestSingpassClient_UserInfo_ParsesNDIClaims(t *testing.T) {
	t.Parallel()
	mux := http.NewServeMux()
	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		authz := r.Header.Get("Authorization")
		if authz != "Bearer at-1" {
			t.Errorf("Authorization = %q", authz)
		}
		w.Header().Set("Content-Type", "application/json")
		// NDI sub format: NRIC/FIN s/g/t/f-prefixed numeric.
		_, _ = w.Write([]byte(`{
			"sub": "S1234567A",
			"name": "Phyllis Tan",
			"email": "phyllis@example.sg"
		}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := singpass.New(singpass.Config{IssuerURL: srv.URL, ClientID: testClientID})
	info, err := c.UserInfo(context.Background(), "at-1")
	if err != nil {
		t.Fatalf("UserInfo: %v", err)
	}
	if info.Sub != "S1234567A" {
		t.Errorf("Sub = %q", info.Sub)
	}
	if info.Name != "Phyllis Tan" {
		t.Errorf("Name = %q", info.Name)
	}
	if info.Email != "phyllis@example.sg" {
		t.Errorf("Email = %q", info.Email)
	}
}

func TestSingpassClient_UserInfo_PropagatesNon200(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	c := singpass.New(singpass.Config{IssuerURL: srv.URL, ClientID: testClientID})
	if _, err := c.UserInfo(context.Background(), "expired"); err == nil {
		t.Fatalf("expected error on 401")
	}
}

func TestSingpassClient_UserInfo_RejectsEmptyToken(t *testing.T) {
	t.Parallel()
	c := singpass.New(singpass.Config{IssuerURL: "https://x.invalid", ClientID: testClientID})
	if _, err := c.UserInfo(context.Background(), ""); err == nil {
		t.Fatalf("expected error empty access token")
	}
}

// -----------------------------------------------------------------------------
// Link — orchestrates full callback flow + emits envelope-conformant event.
// -----------------------------------------------------------------------------

func TestSingpassClient_Link_PublishesEnvelopeConformantEvent(t *testing.T) {
	t.Parallel()

	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "at-1", "id_token": "id-token-1"})
	})
	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"sub":"S1234567A","name":"Phyllis Tan","email":"phyllis@example.sg"}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	pub := &recordingPublisher{}
	c := singpass.New(singpass.Config{
		IssuerURL:    srv.URL,
		ClientID:     testClientID,
		ClientSecret: testClientSecret,
		RedirectURI:  testRedirectURI,
		Publisher:    pub,
	})

	res, err := c.Link(context.Background(), singpass.LinkInput{
		GCID:         "gcid-1",
		TenantID:     "01970000-0000-7000-8000-0000000000aa",
		Code:         "code-1",
		CodeVerifier: "verifier-1",
		Traceparent:  "00-aabb-ccdd-01",
	})
	if err != nil {
		t.Fatalf("Link: %v", err)
	}
	if res.Sub != "S1234567A" {
		t.Errorf("Sub = %q", res.Sub)
	}
	if got := len(pub.records); got != 1 {
		t.Fatalf("expected 1 event published, got %d", got)
	}
	rec := pub.records[0]
	if rec.Topic != "chora.identity.singpass.linked.v1" {
		t.Errorf("Topic = %q", rec.Topic)
	}
	// Envelope mandatory fields.
	if rec.EventID == "" || rec.IdempotencyKey == "" {
		t.Errorf("expected event_id + idempotency_key")
	}
	if rec.TenantID != "01970000-0000-7000-8000-0000000000aa" {
		t.Errorf("TenantID = %q", rec.TenantID)
	}
	if rec.GCID != "gcid-1" {
		t.Errorf("GCID = %q", rec.GCID)
	}
	if rec.Traceparent != "00-aabb-ccdd-01" {
		t.Errorf("Traceparent = %q", rec.Traceparent)
	}
	if rec.SourceProject == "" || rec.SourceService != "chora-identity" {
		t.Errorf("source_service = %q (want chora-identity)", rec.SourceService)
	}
	if rec.SchemaVersion < 1 {
		t.Errorf("schema_version = %d", rec.SchemaVersion)
	}
	if rec.Payload["sub"] != "S1234567A" {
		t.Errorf("payload.sub = %v", rec.Payload["sub"])
	}
	if rec.Payload["provider"] != "singpass" {
		t.Errorf("payload.provider = %v", rec.Payload["provider"])
	}
}

func TestSingpassClient_Link_ValidatesRequiredFields(t *testing.T) {
	t.Parallel()
	c := singpass.New(singpass.Config{IssuerURL: "https://x.invalid", ClientID: testClientID})
	cases := []singpass.LinkInput{
		{GCID: "", TenantID: "t", Code: "c", CodeVerifier: "v"},
		{GCID: "g", TenantID: "", Code: "c", CodeVerifier: "v"},
		{GCID: "g", TenantID: "t", Code: "", CodeVerifier: "v"},
		{GCID: "g", TenantID: "t", Code: "c", CodeVerifier: ""},
	}
	for i, in := range cases {
		if _, err := c.Link(context.Background(), in); err == nil {
			t.Errorf("case %d: expected error for missing required field", i)
		}
	}
}

// -----------------------------------------------------------------------------
// Additional edge cases for coverage parity (≥85%).
// -----------------------------------------------------------------------------

func TestSingpassClient_AuthorizationURL_RejectsMissingClientID(t *testing.T) {
	t.Parallel()
	c := singpass.New(singpass.Config{IssuerURL: "https://x", ClientID: ""})
	if _, err := c.AuthorizationURL("s", "c"); err == nil {
		t.Fatalf("expected error for missing client_id")
	}
}

func TestSingpassClient_ExchangeCode_RejectsBadJSON(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{not-json`))
	}))
	defer srv.Close()
	c := singpass.New(singpass.Config{IssuerURL: srv.URL, ClientID: testClientID, ClientSecret: testClientSecret, RedirectURI: testRedirectURI})
	if _, err := c.ExchangeCode(context.Background(), "code", "verifier"); err == nil {
		t.Fatalf("expected JSON decode error")
	}
}

func TestSingpassClient_ExchangeCode_RejectsEmptyAccessToken(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	c := singpass.New(singpass.Config{IssuerURL: srv.URL, ClientID: testClientID, ClientSecret: testClientSecret, RedirectURI: testRedirectURI})
	if _, err := c.ExchangeCode(context.Background(), "code", "verifier"); err == nil {
		t.Fatalf("expected error for empty access_token")
	}
}

func TestSingpassClient_ExchangeCode_RejectsEmptyIssuer(t *testing.T) {
	t.Parallel()
	c := singpass.New(singpass.Config{IssuerURL: "", ClientID: testClientID})
	if _, err := c.ExchangeCode(context.Background(), "code", "verifier"); err == nil {
		t.Fatalf("expected error for empty issuer")
	}
}

func TestSingpassClient_UserInfo_RejectsEmptyIssuer(t *testing.T) {
	t.Parallel()
	c := singpass.New(singpass.Config{IssuerURL: "", ClientID: testClientID})
	if _, err := c.UserInfo(context.Background(), "at"); err == nil {
		t.Fatalf("expected error for empty issuer")
	}
}

func TestSingpassClient_UserInfo_RejectsEmptySub(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"sub":""}`))
	}))
	defer srv.Close()
	c := singpass.New(singpass.Config{IssuerURL: srv.URL, ClientID: testClientID})
	if _, err := c.UserInfo(context.Background(), "at"); err == nil {
		t.Fatalf("expected error for empty sub")
	}
}

func TestSingpassClient_UserInfo_RejectsBadJSON(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{bad`))
	}))
	defer srv.Close()
	c := singpass.New(singpass.Config{IssuerURL: srv.URL, ClientID: testClientID})
	if _, err := c.UserInfo(context.Background(), "at"); err == nil {
		t.Fatalf("expected JSON decode error")
	}
}

func TestSingpassClient_Link_NoPublisher_StillReturnsResult(t *testing.T) {
	t.Parallel()
	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "at-1", "id_token": "id-token-1"})
	})
	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"sub":"S1234567A","name":"X","email":"x@y.sg"}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := singpass.New(singpass.Config{IssuerURL: srv.URL, ClientID: testClientID, ClientSecret: testClientSecret, RedirectURI: testRedirectURI})
	res, err := c.Link(context.Background(), singpass.LinkInput{
		GCID: "gcid-1", TenantID: "01970000-0000-7000-8000-0000000000aa",
		Code: "c", CodeVerifier: "v",
	})
	if err != nil {
		t.Fatalf("Link without Publisher: %v", err)
	}
	if res.Sub != "S1234567A" {
		t.Errorf("Sub = %q", res.Sub)
	}
}

// -----------------------------------------------------------------------------
// Test helper — minimal Publisher recorder so the singpass adapter package
// stays free of cross-package test fixtures.
// -----------------------------------------------------------------------------

type recordingPublisher struct {
	records []singpass.PublishedRecord
}

func (r *recordingPublisher) Publish(topic string, env singpass.EventEnvelope, payload map[string]any) error {
	r.records = append(r.records, singpass.PublishedRecord{
		Topic:          topic,
		EventID:        env.EventID,
		IdempotencyKey: env.IdempotencyKey,
		TenantID:       env.TenantID,
		GCID:           env.GCID,
		Traceparent:    env.Traceparent,
		SourceProject:  env.SourceProject,
		SourceService:  env.SourceService,
		SchemaVersion:  env.SchemaVersion,
		Payload:        payload,
	})
	return nil
}
