// microsoft_gap_test.go — error-branch coverage for the Microsoft OIDC
// adapter (malformed response bodies, empty-token responses, transport
// errors, publisher failures) — mirrors the google_gap_test.go shape.
package microsoft_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/apollo-chora/chora-identity/internal/adapter/idp/microsoft"
)

type msftFailingRoundTripper struct{}

func (msftFailingRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("transport exploded")
}

func TestMicrosoftClient_ExchangeCode_InvalidJSONAndEmptyToken(t *testing.T) {
	t.Parallel()
	badJSON := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`<html>oops</html>`))
	}))
	defer badJSON.Close()
	c := microsoft.New(microsoft.Config{IssuerURL: badJSON.URL, ClientID: testClientID})
	if _, err := c.ExchangeCode(context.Background(), "code", "verifier"); err == nil {
		t.Error("ExchangeCode must error on an undecodable token body")
	}

	noToken := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"id_token":"only-id","expires_in":3600}`))
	}))
	defer noToken.Close()
	c2 := microsoft.New(microsoft.Config{IssuerURL: noToken.URL, ClientID: testClientID})
	if _, err := c2.ExchangeCode(context.Background(), "code", "verifier"); err == nil {
		t.Error("ExchangeCode must reject a response with no access_token")
	}
}

func TestMicrosoftClient_ExchangeCode_TransportError(t *testing.T) {
	t.Parallel()
	c := microsoft.New(microsoft.Config{
		IssuerURL:  "http://127.0.0.1:1",
		ClientID:   testClientID,
		HTTPClient: &http.Client{Transport: msftFailingRoundTripper{}},
	})
	if _, err := c.ExchangeCode(context.Background(), "code", "verifier"); err == nil {
		t.Fatal("ExchangeCode must propagate a transport error")
	}
}

func TestMicrosoftClient_UserInfo_InvalidJSONAndEmptySub(t *testing.T) {
	t.Parallel()
	badBody := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`not json`))
	}))
	defer badBody.Close()
	c := microsoft.New(microsoft.Config{IssuerURL: badBody.URL, ClientID: testClientID})
	if _, err := c.UserInfo(context.Background(), "tok"); err == nil {
		t.Error("UserInfo must error on an undecodable body")
	}

	emptySub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"name":"No Sub","email":"x@y.dev"}`))
	}))
	defer emptySub.Close()
	c2 := microsoft.New(microsoft.Config{IssuerURL: emptySub.URL, ClientID: testClientID})
	if _, err := c2.UserInfo(context.Background(), "tok"); err == nil {
		t.Error("UserInfo must reject a body without sub")
	}
}

func TestMicrosoftClient_UserInfo_TransportError(t *testing.T) {
	t.Parallel()
	c := microsoft.New(microsoft.Config{
		IssuerURL:  "http://127.0.0.1:1",
		ClientID:   testClientID,
		HTTPClient: &http.Client{Transport: msftFailingRoundTripper{}},
	})
	if _, err := c.UserInfo(context.Background(), "tok"); err == nil {
		t.Fatal("UserInfo must propagate a transport error")
	}
}

type msftRecorder struct {
	topics []string
}

func (r *msftRecorder) Publish(topic string, _ microsoft.EventEnvelope, _ map[string]any) error {
	r.topics = append(r.topics, topic)
	return nil
}

func TestMicrosoftClient_Federate_RejectionPublishesEvidence(t *testing.T) {
	t.Parallel()
	pub := &msftRecorder{}
	c := microsoft.New(microsoft.Config{
		IssuerURL: "http://127.0.0.1:1",
		ClientID:  testClientID,
		Publisher: pub,
	})
	if _, err := c.Federate(context.Background(), microsoft.FederateInput{
		GCID: "g", TenantID: "t", Code: "bad", CodeVerifier: "v",
	}); err == nil {
		t.Fatal("Federate must fail when the token endpoint is unreachable")
	}
	found := false
	for _, tp := range pub.topics {
		if tp == "chora.identity.federation.rejected.v1" {
			found = true
		}
	}
	if !found {
		t.Errorf("rejection evidence topic not published; got %v", pub.topics)
	}
}

type msftFailingPublisher struct{}

func (msftFailingPublisher) Publish(string, microsoft.EventEnvelope, map[string]any) error {
	return errors.New("publisher down")
}

func TestMicrosoftClient_Federate_PublishErrorFailsLoud(t *testing.T) {
	t.Parallel()
	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"access_token":"tok","expires_in":3600}`))
	})
	mux.HandleFunc("/oidc/userinfo", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"sub":"s1","name":"N","email":"e@d.c"}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := microsoft.New(microsoft.Config{
		IssuerURL: srv.URL,
		ClientID:  testClientID,
		Publisher: msftFailingPublisher{},
	})
	if _, err := c.Federate(context.Background(), microsoft.FederateInput{
		GCID: "g", TenantID: "t", Code: "c", CodeVerifier: "v",
	}); err == nil {
		t.Fatal("Federate must fail loud when publishing the success event errors")
	}
}
