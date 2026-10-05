// Package singpass implements an OIDC client for Singpass National Digital
// Identity (NDI) sandbox issuer (stg-id.singpass.gov.sg) per the locked
// architecture (CLAUDE.md §1 "Standards" + the platform architecture notes
// "Singpass / SkillsFuture Singapore").
//
// Singpass is one of the OIDC providers federated through the upstream
// identity provider (CLAUDE.md §1 "Identity provider"). This adapter handles the
// raw OIDC Authorization-Code-with-PKCE flow against the NDI test issuer
// for the M11/M12 bring-up phase before Identity Platform onboarding lands.
//
// Hexagonal note: this is an ADAPTER. The domain / handler layer depends
// on a Client interface; the concrete sandbox-vs-production split lives
// in env vars (SINGPASS_ISSUER_URL etc) — no inline config per the
// secrets-and-env skill + .claude/rules/development-execution.md.
//
// Surface mapping: H+ (Hub+) tenant admin "Link Singpass" + A+ learner
// onboarding (signing in with NDI) — both surfaces hit the same client.
package singpass

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/apollo-chora/chora-common/env"
)

// -----------------------------------------------------------------------------
// Config — all values sourced from env vars (no inline config).
// -----------------------------------------------------------------------------

// Config holds the OIDC client configuration. Sandbox values:
//
//	SINGPASS_ISSUER_URL        → https://stg-id.singpass.gov.sg
//	SINGPASS_CLIENT_ID         → assigned by NDI onboarding
//	SINGPASS_CLIENT_SECRET     → assigned by NDI onboarding (Secret Manager)
//	SINGPASS_REDIRECT_URI      → https://chora.site/v1/me/kyc/singpass/callback
//	SINGPASS_TOKEN_URL         → optional override; defaults to {Issuer}/token
//	SINGPASS_USERINFO_URL      → optional override; defaults to {Issuer}/userinfo
//	SINGPASS_MYINFO_URL        → optional override; defaults to {Issuer}/person
//	SINGPASS_AUTHORIZATION_URL → optional override; defaults to {Issuer}/auth
//
// Production switches IssuerURL to id.singpass.gov.sg and uses production
// client credentials from Secret Manager — the adapter shape is unchanged.
type Config struct {
	IssuerURL        string
	ClientID         string
	ClientSecret     string
	RedirectURI      string
	AuthorizationURL string       // optional; defaults to {IssuerURL}/auth
	TokenURL         string       // optional; defaults to {IssuerURL}/token
	UserInfoURL      string       // optional; defaults to {IssuerURL}/userinfo
	MyInfoURL        string       // optional; defaults to {IssuerURL}/person
	HTTPClient       *http.Client // optional; defaults to http.DefaultClient with 10s timeout
	Publisher        Publisher    // optional; required only for Link()
}

// Client is the Singpass NDI OIDC adapter.
type Client struct {
	cfg        Config
	httpClient *http.Client
}

// New constructs a Client. Validation is lazy (on each call) so callers can
// build a partially-configured client for tests of individual methods.
func New(cfg Config) *Client {
	c := &Client{cfg: cfg, httpClient: cfg.HTTPClient}
	if c.httpClient == nil {
		c.httpClient = &http.Client{Timeout: 10 * time.Second}
	}
	return c
}

// -----------------------------------------------------------------------------
// AuthorizationURL — builds the /authorize redirect URL with PKCE + state.
// -----------------------------------------------------------------------------

// AuthorizationURL returns the URL to redirect the browser to for Singpass
// login. state is the CSRF nonce; codeChallenge is the PKCE S256 challenge.
//
// Caller is responsible for storing (state → code_verifier) in a short-lived
// session store and validating state on the callback before calling
// ExchangeCode.
func (c *Client) AuthorizationURL(state, codeChallenge string) (string, error) {
	if strings.TrimSpace(c.cfg.IssuerURL) == "" {
		return "", errors.New("singpass: SINGPASS_ISSUER_URL not configured")
	}
	if strings.TrimSpace(c.cfg.ClientID) == "" {
		return "", errors.New("singpass: SINGPASS_CLIENT_ID not configured")
	}
	if strings.TrimSpace(state) == "" {
		return "", errors.New("singpass: state is required")
	}
	if strings.TrimSpace(codeChallenge) == "" {
		return "", errors.New("singpass: code_challenge is required")
	}

	q := url.Values{}
	q.Set("client_id", c.cfg.ClientID)
	q.Set("response_type", "code")
	q.Set("scope", "openid")
	q.Set("state", state)
	q.Set("code_challenge", codeChallenge)
	q.Set("code_challenge_method", "S256")
	if c.cfg.RedirectURI != "" {
		q.Set("redirect_uri", c.cfg.RedirectURI)
	}
	authURL := strings.TrimSpace(c.cfg.AuthorizationURL)
	if authURL == "" {
		authURL = strings.TrimRight(c.cfg.IssuerURL, "/") + "/auth"
	}
	return authURL + "?" + q.Encode(), nil
}

// -----------------------------------------------------------------------------
// ExchangeCode — POST /token, returns Tokens.
// -----------------------------------------------------------------------------

// Tokens is the subset of the OIDC token response we use.
type Tokens struct {
	AccessToken string `json:"access_token"`
	IDToken     string `json:"id_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

// ExchangeCode trades an authorization code (and PKCE verifier) for tokens.
func (c *Client) ExchangeCode(ctx context.Context, code, codeVerifier string) (*Tokens, error) {
	if strings.TrimSpace(c.cfg.IssuerURL) == "" {
		return nil, errors.New("singpass: SINGPASS_ISSUER_URL not configured")
	}
	if strings.TrimSpace(code) == "" {
		return nil, errors.New("singpass: code is required")
	}
	if strings.TrimSpace(codeVerifier) == "" {
		return nil, errors.New("singpass: code_verifier is required")
	}

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("code_verifier", codeVerifier)
	form.Set("client_id", c.cfg.ClientID)
	if c.cfg.ClientSecret != "" {
		form.Set("client_secret", c.cfg.ClientSecret)
	}
	if c.cfg.RedirectURI != "" {
		form.Set("redirect_uri", c.cfg.RedirectURI)
	}

	tokenURL := strings.TrimSpace(c.cfg.TokenURL)
	if tokenURL == "" {
		tokenURL = strings.TrimRight(c.cfg.IssuerURL, "/") + "/token"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("singpass: build token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("singpass: token request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("singpass: read token response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("singpass: token endpoint status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var tok Tokens
	if err := json.Unmarshal(body, &tok); err != nil {
		return nil, fmt.Errorf("singpass: decode token response: %w", err)
	}
	if tok.AccessToken == "" {
		return nil, errors.New("singpass: token endpoint returned empty access_token")
	}
	return &tok, nil
}

// -----------------------------------------------------------------------------
// UserInfo — GET /userinfo with Bearer token.
// -----------------------------------------------------------------------------

// UserInfo holds the identity claims returned by Singpass NDI /userinfo.
//
// NDI sub format: NRIC/FIN with prefix S/T (citizen/PR), F/G (foreigner),
// e.g. "S1234567A". The full PII surface (DOB, name in different scripts,
// addresses) requires Singpass MyInfo scopes — this MVP only requests
// openid + the basic profile claims that NDI grants by default.
type UserInfo struct {
	Sub   string `json:"sub"`
	Name  string `json:"name"`
	Email string `json:"email"`
}

// UserInfo fetches the /userinfo endpoint with a Bearer access token.
func (c *Client) UserInfo(ctx context.Context, accessToken string) (*UserInfo, error) {
	if strings.TrimSpace(c.cfg.IssuerURL) == "" {
		return nil, errors.New("singpass: SINGPASS_ISSUER_URL not configured")
	}
	if strings.TrimSpace(accessToken) == "" {
		return nil, errors.New("singpass: access token is required")
	}

	infoURL := strings.TrimSpace(c.cfg.UserInfoURL)
	if infoURL == "" {
		infoURL = strings.TrimRight(c.cfg.IssuerURL, "/") + "/userinfo"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, infoURL, nil)
	if err != nil {
		return nil, fmt.Errorf("singpass: build userinfo request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("singpass: userinfo request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("singpass: read userinfo response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("singpass: userinfo endpoint status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var info UserInfo
	if err := json.Unmarshal(body, &info); err != nil {
		return nil, fmt.Errorf("singpass: decode userinfo response: %w", err)
	}
	if info.Sub == "" {
		return nil, errors.New("singpass: userinfo returned empty sub")
	}
	return &info, nil
}

// -----------------------------------------------------------------------------
// Link — full callback orchestration: ExchangeCode → UserInfo → Publish.
// -----------------------------------------------------------------------------

// LinkInput captures the parameters needed to complete the linking flow on
// Singpass callback.
type LinkInput struct {
	GCID         string // existing Chora identity to attach Singpass to
	TenantID     string // tenant scope for the event envelope
	Code         string // authorization_code from Singpass /authorize redirect
	CodeVerifier string // PKCE verifier matching the prior /authorize challenge
	Traceparent  string // W3C trace context (mandatory per CLAUDE.md §6)
	Tracestate   string // W3C tracestate (optional)
}

// LinkResult exposes the linked Singpass identity claims.
type LinkResult struct {
	Sub   string
	Name  string
	Email string
}

// Link is the full Singpass callback orchestration. It exchanges the auth
// code for tokens, fetches userinfo, and publishes the
// chora.identity.singpass.linked.v1 event with all envelope fields populated.
//
// Production callers (chora-identity HTTP /auth/singpass/callback handler)
// will additionally:
//   - persist a SingpassLink record in chora_identity DB
//   - update User.identity_provider / federated_subject if first-time link
//
// Those side-effects are out of scope for the adapter — they live in domain
// services per hexagonal direction.
func (c *Client) Link(ctx context.Context, in LinkInput) (*LinkResult, error) {
	if strings.TrimSpace(in.GCID) == "" {
		return nil, errors.New("singpass: gcid is required")
	}
	if strings.TrimSpace(in.TenantID) == "" {
		return nil, errors.New("singpass: tenant_id is required")
	}
	if strings.TrimSpace(in.Code) == "" {
		return nil, errors.New("singpass: code is required")
	}
	if strings.TrimSpace(in.CodeVerifier) == "" {
		return nil, errors.New("singpass: code_verifier is required")
	}

	tok, err := c.ExchangeCode(ctx, in.Code, in.CodeVerifier)
	if err != nil {
		return nil, err
	}
	info, err := c.UserInfo(ctx, tok.AccessToken)
	if err != nil {
		return nil, err
	}

	if c.cfg.Publisher != nil {
		env := newEnvelope(in.TenantID, in.GCID, in.Traceparent, in.Tracestate)
		payload := map[string]any{
			"gcid":         in.GCID,
			"sub":          info.Sub,
			"name":         info.Name,
			"email":        info.Email,
			"provider":     "singpass",
			"linked_at":    env.OccurredAt.Format(time.RFC3339Nano),
			"id_token_set": tok.IDToken != "",
		}
		if err := c.cfg.Publisher.Publish("chora.identity.singpass.linked.v1", env, payload); err != nil {
			return nil, fmt.Errorf("singpass: publish linked event: %w", err)
		}
	}

	return &LinkResult{
		Sub:   info.Sub,
		Name:  info.Name,
		Email: info.Email,
	}, nil
}

// -----------------------------------------------------------------------------
// Event publisher port — kept locally so the adapter has no cross-package
// dependency on a particular publisher implementation. Production wires the
// Pub/Sub publisher (M12); tests inject a recorder.
// -----------------------------------------------------------------------------

// EventEnvelope mirrors the mandatory fields of chora.common.v1.EventEnvelope.
type EventEnvelope struct {
	EventID        string
	IdempotencyKey string
	TenantID       string
	GCID           string
	OccurredAt     time.Time
	PublishedAt    time.Time
	Traceparent    string
	Tracestate     string
	SourceProject  string
	SourceService  string
	SchemaVersion  int32
}

// Publisher is the port used by Link() to emit the singpass.linked.v1 event.
type Publisher interface {
	Publish(topic string, env EventEnvelope, payload map[string]any) error
}

// PublishedRecord is the test-friendly capture shape for recorder publishers.
type PublishedRecord struct {
	Topic          string
	EventID        string
	IdempotencyKey string
	TenantID       string
	GCID           string
	Traceparent    string
	SourceProject  string
	SourceService  string
	SchemaVersion  int32
	Payload        map[string]any
}

// SourceProject + SourceService for envelope provenance. chora-identity
// runs in the chora-local platform host project.
const (
	SourceService = "chora-identity"
)

// SourceProject + SourceService for envelope provenance. chora-identity
// runs in the chora-local platform host project.
//
// Was a hardcoded literal until 2026-09-02 (CHO-2419). No manifest could reach
// it, so a second org stamped every event with chora-local and any consumer
// filtering on source_project would have been filtering on a lie.
// CHORA_SOURCE_PROJECT is now set on every event-emitting service; the literal
// stays as the fallback so this estate is provably unchanged.
var SourceProject = env.GetOrDefault("CHORA_SOURCE_PROJECT", "chora-local")

func newEnvelope(tenantID, gcid, traceparent, tracestate string) EventEnvelope {
	now := time.Now().UTC()
	id := uuid.Must(uuid.NewV7()).String()
	return EventEnvelope{
		EventID:        id,
		IdempotencyKey: id,
		TenantID:       tenantID,
		GCID:           gcid,
		OccurredAt:     now,
		PublishedAt:    now,
		Traceparent:    traceparent,
		Tracestate:     tracestate,
		SourceProject:  SourceProject,
		SourceService:  SourceService,
		SchemaVersion:  1,
	}
}
