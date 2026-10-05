// Package singpass_test — RED-phase TDD specs for the Singpass NDI MyInfo
// client extension. Builds on the OIDC base client (singpass.go +
// singpass_test.go) by adding /person + redaction helpers.
//
// MyInfo is Singpass' citizen-data API; after the OIDC consent grants
// myinfo scopes, the access token may be presented to /person to retrieve
// verified personal data (NRIC, name, address, employment, etc.). The
// chora-identity service uses this for two purposes:
//
//  1. KYC verification (status verified_singpass) — proof of identity.
//  2. Course application form auto-fill (A-CRS-3) — saves learner typing.
//
// Per ddd-enforcement.md cross-DB queries forbidden — chora-delivery
// (Course Application) MUST consume the prefill payload via the
// /v1/me/myinfo-prefill HTTP endpoint, NOT by reaching into chora_identity.
//
// All endpoints + signing keys come from env / Secret Manager:
//
//	SINGPASS_MYINFO_URL    → https://stg-id.singpass.gov.sg/person (sandbox)
//	                          https://id.singpass.gov.sg/person (prod)
//	SINGPASS_REDIRECT_URI  → https://chora.site/auth/singpass/callback
//	SINGPASS_TOKEN_URL     → /token override (defaults to {issuer}/token)
//	SINGPASS_USERINFO_URL  → /userinfo override (defaults to {issuer}/userinfo)
//
// No inline config — see CLAUDE.md §6 + secrets-and-env skill.
package singpass_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/apollo-chora/chora-identity/internal/adapter/idp/singpass"
)

// -----------------------------------------------------------------------------
// MyInfoPerson — happy path
// -----------------------------------------------------------------------------

func TestSingpassClient_MyInfoPerson_HappyPath(t *testing.T) {
	t.Parallel()

	mux := http.NewServeMux()
	mux.HandleFunc("/person", func(w http.ResponseWriter, r *http.Request) {
		// Bearer auth required.
		if got := r.Header.Get("Authorization"); got != "Bearer mi-token-1" {
			t.Errorf("Authorization=%q", got)
		}
		// NDI MyInfo response shape: each field is a {value, classification, lastupdated}
		// envelope — we keep the test fixture lean but representative.
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"name": {"value": "Phyllis Tan"},
			"uinfin": {"value": "S1234567A"},
			"email": {"value": "phyllis@example.sg"},
			"mobileno": {"areacode": {"value": "65"}, "nbr": {"value": "98765432"}},
			"regadd": {
				"block": {"value": "123"},
				"street": {"value": "Marina Boulevard"},
				"floor": {"value": "12"},
				"unit": {"value": "01"},
				"postal": {"value": "018989"},
				"country": {"value": "SG"}
			},
			"employmentsector": {"value": "Information Technology"},
			"employment": {"value": "Acme Corp Pte Ltd"},
			"sex": {"value": "F"},
			"dob": {"value": "1992-04-15"},
			"nationality": {"value": "SG"}
		}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := singpass.New(singpass.Config{
		IssuerURL: srv.URL,
		MyInfoURL: srv.URL + "/person",
		ClientID:  testClientID,
	})
	person, err := c.MyInfoPerson(context.Background(), "mi-token-1")
	if err != nil {
		t.Fatalf("MyInfoPerson: %v", err)
	}

	// Top-line claims.
	if person.Name != "Phyllis Tan" {
		t.Errorf("Name=%q", person.Name)
	}
	if person.UINFIN != "S1234567A" {
		t.Errorf("UINFIN=%q", person.UINFIN)
	}
	if person.Email != "phyllis@example.sg" {
		t.Errorf("Email=%q", person.Email)
	}
	if person.MobileE164 != "+6598765432" {
		t.Errorf("MobileE164=%q", person.MobileE164)
	}
	if person.EmployerName != "Acme Corp Pte Ltd" {
		t.Errorf("EmployerName=%q", person.EmployerName)
	}
	if person.EmploymentSector != "Information Technology" {
		t.Errorf("EmploymentSector=%q", person.EmploymentSector)
	}
	if person.RegisteredAddress.PostalCode != "018989" {
		t.Errorf("PostalCode=%q", person.RegisteredAddress.PostalCode)
	}
	if person.DateOfBirth != "1992-04-15" {
		t.Errorf("DateOfBirth=%q", person.DateOfBirth)
	}
}

// -----------------------------------------------------------------------------
// MyInfoPerson — failure modes
// -----------------------------------------------------------------------------

func TestSingpassClient_MyInfoPerson_RejectsEmptyToken(t *testing.T) {
	t.Parallel()
	c := singpass.New(singpass.Config{IssuerURL: "https://x.invalid", MyInfoURL: "https://x.invalid/person"})
	if _, err := c.MyInfoPerson(context.Background(), ""); err == nil {
		t.Fatalf("expected error empty access token")
	}
}

func TestSingpassClient_MyInfoPerson_RejectsEmptyMyInfoURL(t *testing.T) {
	t.Parallel()
	c := singpass.New(singpass.Config{IssuerURL: "https://x.invalid"})
	if _, err := c.MyInfoPerson(context.Background(), "tk"); err == nil {
		t.Fatalf("expected error when SINGPASS_MYINFO_URL not configured")
	}
}

func TestSingpassClient_MyInfoPerson_PropagatesNon200(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":"insufficient_scope"}`))
	}))
	defer srv.Close()
	c := singpass.New(singpass.Config{IssuerURL: "https://x.invalid", MyInfoURL: srv.URL})
	if _, err := c.MyInfoPerson(context.Background(), "tk"); err == nil {
		t.Fatalf("expected error on 403")
	}
}

func TestSingpassClient_MyInfoPerson_RejectsBadJSON(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{not-json`))
	}))
	defer srv.Close()
	c := singpass.New(singpass.Config{IssuerURL: "https://x.invalid", MyInfoURL: srv.URL})
	if _, err := c.MyInfoPerson(context.Background(), "tk"); err == nil {
		t.Fatalf("expected JSON decode error")
	}
}

// -----------------------------------------------------------------------------
// MyInfoURL fallback — when not provided, falls back to {IssuerURL}/person.
// -----------------------------------------------------------------------------

func TestSingpassClient_MyInfoPerson_FallsBackToIssuerPersonPath(t *testing.T) {
	t.Parallel()
	mux := http.NewServeMux()
	mux.HandleFunc("/person", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"name":{"value":"X"},"uinfin":{"value":"S0000000A"}}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	// MyInfoURL deliberately empty — client should derive {Issuer}/person.
	c := singpass.New(singpass.Config{IssuerURL: srv.URL})
	p, err := c.MyInfoPerson(context.Background(), "tk")
	if err != nil {
		t.Fatalf("MyInfoPerson fallback: %v", err)
	}
	if p.UINFIN != "S0000000A" {
		t.Errorf("UINFIN=%q", p.UINFIN)
	}
}
