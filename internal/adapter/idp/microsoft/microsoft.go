// Package microsoft implements an OIDC client for Microsoft (Azure AD /
// personal accounts via the v2 endpoint). The "common" tenant multiplexes
// both Azure AD work/school and Microsoft personal (live.com / outlook.com)
// identities.
//
// Per the locked stack (CLAUDE.md §1 "Identity provider"): Identity Platform
// federates Microsoft + Google + Singpass + others. This adapter handles the
// raw OIDC Authorization-Code-with-PKCE flow against Microsoft's v2.0 issuer
// for Phyllis MVP §3 Step 2 + the BFF route. Production wires through Identity
// Platform, but the adapter shape is identical.
//
// Hexagonal note: ADAPTER. Domain code never imports this package directly;
// HTTP handlers / orchestrators inject a Publisher port to forward
// envelope-conformant federation events.
//
// All endpoints/secrets sourced from env (MICROSOFT_OIDC_ISSUER_URL,
// MICROSOFT_OIDC_CLIENT_ID, MICROSOFT_OIDC_CLIENT_SECRET) — no inline config
// per .claude/skills/secrets-and-env/SKILL.md + memory feedback_no_inline_config.
//
// IMDA evidence emission per ADR-141 + envelope.proto field 14:
//   - successful federation → chora_imda_dimension="accountability" (D1)
//   - rejected federation → chora_imda_dimension="safety_and_robustness" (D3)
package microsoft

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

// SourceProject + SourceService for envelope provenance. chora-identity runs
// in chora-local (platform host).
const (
	SourceService = "chora-identity"
)

// SourceProject + SourceService for envelope provenance. chora-identity runs
// in chora-local (platform host).
//
// Was a hardcoded literal until 2026-09-02 (CHO-2419). No manifest could reach
// it, so a second org stamped every event with chora-local and any consumer
// filtering on source_project would have been filtering on a lie.
// CHORA_SOURCE_PROJECT is now set on every event-emitting service; the literal
// stays as the fallback so this estate is provably unchanged.
var SourceProject = env.GetOrDefault("CHORA_SOURCE_PROJECT", "chora-local")

// ProviderName is the canonical token used in payload.provider.
const ProviderName = "microsoft"

// ─────────────────────────────────────────────────────────────────────────────
// Config — all values sourced from env vars (no inline config).
// ─────────────────────────────────────────────────────────────────────────────

// Config holds the OIDC client wiring values. Production envs:
//
//	MICROSOFT_OIDC_ISSUER_URL    → https://login.microsoftonline.com/common/v2.0
//	MICROSOFT_OIDC_TENANT        → "common" | "organizations" | "consumers" | <tenant-uuid>
//	MICROSOFT_OIDC_CLIENT_ID     → assigned by Azure AD app registration
//	MICROSOFT_OIDC_CLIENT_SECRET → Secret Manager (idp-microsoft-oauth-client-secret)
//	MICROSOFT_OIDC_REDIRECT_URI  → https://chora.site/auth/microsoft/callback
type Config struct {
	IssuerURL    string
	Tenant       string // "common" / "organizations" / "consumers" / tenant-id
	ClientID     string
	ClientSecret string
	RedirectURI  string
	HTTPClient   *http.Client // optional; defaults to 10s-timeout client
	Publisher    Publisher    // optional; required for Federate event emit
}

// Client is the Microsoft OIDC adapter.
type Client struct {
	cfg        Config
	httpClient *http.Client
}

// New constructs a Client. Validation is lazy (per call) so callers can build
// a partially-configured client for unit tests of individual methods.
func New(cfg Config) *Client {
	c := &Client{cfg: cfg, httpClient: cfg.HTTPClient}
	if c.httpClient == nil {
		c.httpClient = &http.Client{Timeout: 10 * time.Second}
	}
	return c
}

// ─────────────────────────────────────────────────────────────────────────────
// AuthorizationURL — builds the /authorize redirect URL.
// ─────────────────────────────────────────────────────────────────────────────

// AuthorizationURL returns the URL to redirect the browser to for Microsoft
// login. state is the CSRF nonce; codeChallenge is the PKCE S256 challenge.
//
// The caller stores (state → code_verifier) in a short-lived session store
// and validates state on the callback before calling ExchangeCode.
func (c *Client) AuthorizationURL(state, codeChallenge string) (string, error) {
	if strings.TrimSpace(c.cfg.IssuerURL) == "" {
		return "", errors.New("microsoft: MICROSOFT_OIDC_ISSUER_URL not configured")
	}
	if strings.TrimSpace(c.cfg.ClientID) == "" {
		return "", errors.New("microsoft: MICROSOFT_OIDC_CLIENT_ID not configured")
	}
	if strings.TrimSpace(state) == "" {
		return "", errors.New("microsoft: state is required")
	}
	if strings.TrimSpace(codeChallenge) == "" {
		return "", errors.New("microsoft: code_challenge is required")
	}

	q := url.Values{}
	q.Set("client_id", c.cfg.ClientID)
	q.Set("response_type", "code")
	// MS v2 minimum OIDC + email + profile to pull the basic claims.
	q.Set("scope", "openid email profile")
	q.Set("state", state)
	q.Set("code_challenge", codeChallenge)
	q.Set("code_challenge_method", "S256")
	q.Set("response_mode", "query")
	if c.cfg.RedirectURI != "" {
		q.Set("redirect_uri", c.cfg.RedirectURI)
	}
	return strings.TrimRight(c.cfg.IssuerURL, "/") + "/authorize?" + q.Encode(), nil
}

// ─────────────────────────────────────────────────────────────────────────────
// ExchangeCode — POST /token, returns Tokens.
// ─────────────────────────────────────────────────────────────────────────────

// Tokens is the subset of the OIDC token response we use.
type Tokens struct {
	AccessToken  string `json:"access_token"`
	IDToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
}

// ExchangeCode trades an authorization code (and PKCE verifier) for tokens.
func (c *Client) ExchangeCode(ctx context.Context, code, codeVerifier string) (*Tokens, error) {
	if strings.TrimSpace(c.cfg.IssuerURL) == "" {
		return nil, errors.New("microsoft: MICROSOFT_OIDC_ISSUER_URL not configured")
	}
	if strings.TrimSpace(code) == "" {
		return nil, errors.New("microsoft: code is required")
	}
	if strings.TrimSpace(codeVerifier) == "" {
		return nil, errors.New("microsoft: code_verifier is required")
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

	tokenURL := strings.TrimRight(c.cfg.IssuerURL, "/") + "/token"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("microsoft: build token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("microsoft: token request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("microsoft: read token response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("microsoft: token endpoint status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var tok Tokens
	if err := json.Unmarshal(body, &tok); err != nil {
		return nil, fmt.Errorf("microsoft: decode token response: %w", err)
	}
	if tok.AccessToken == "" {
		return nil, errors.New("microsoft: token endpoint returned empty access_token")
	}
	return &tok, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// UserInfo — GET /oidc/userinfo with Bearer access_token.
// ─────────────────────────────────────────────────────────────────────────────

// UserInfo holds the identity claims returned by Microsoft v2 /oidc/userinfo.
//
// Microsoft's v2 token endpoint returns:
//
//	sub                 — Microsoft account object ID (oid) — opaque + stable
//	name                — display name
//	email               — primary email (may be empty for some personal accts)
//	preferred_username  — UPN-style identifier
//	locale              — RFC 5646 locale tag
type UserInfo struct {
	Sub               string `json:"sub"`
	Name              string `json:"name"`
	Email             string `json:"email"`
	PreferredUsername string `json:"preferred_username"`
	Locale            string `json:"locale"`
}

// UserInfo fetches /oidc/userinfo with a Bearer access token.
func (c *Client) UserInfo(ctx context.Context, accessToken string) (*UserInfo, error) {
	if strings.TrimSpace(c.cfg.IssuerURL) == "" {
		return nil, errors.New("microsoft: MICROSOFT_OIDC_ISSUER_URL not configured")
	}
	if strings.TrimSpace(accessToken) == "" {
		return nil, errors.New("microsoft: access token is required")
	}

	infoURL := strings.TrimRight(c.cfg.IssuerURL, "/") + "/oidc/userinfo"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, infoURL, nil)
	if err != nil {
		return nil, fmt.Errorf("microsoft: build userinfo request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("microsoft: userinfo request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("microsoft: read userinfo response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("microsoft: userinfo endpoint status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var info UserInfo
	if err := json.Unmarshal(body, &info); err != nil {
		return nil, fmt.Errorf("microsoft: decode userinfo response: %w", err)
	}
	if info.Sub == "" {
		return nil, errors.New("microsoft: userinfo returned empty sub")
	}
	return &info, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Federate — orchestrates ExchangeCode → UserInfo → publish.
// ─────────────────────────────────────────────────────────────────────────────

// FederateInput captures the values needed to complete the federation flow.
type FederateInput struct {
	GCID         string // existing Chora identity (or fresh one minted by Blocking Function)
	TenantID     string // tenant scope for the event envelope
	Code         string // authorization_code from MSFT redirect
	CodeVerifier string // PKCE verifier matching the prior /authorize challenge
	Traceparent  string // W3C trace context (mandatory per CLAUDE.md §6)
	Tracestate   string // W3C tracestate (optional)
}

// FederateResult exposes the federated identity claims.
type FederateResult struct {
	Sub               string
	Name              string
	Email             string
	PreferredUsername string
	Locale            string
}

// Federate is the full Microsoft callback orchestration. On success it
// publishes chora.identity.federation.succeeded.v1 with IMDA D1 accountability
// evidence; on rejection it publishes chora.identity.federation.rejected.v1
// with IMDA D3 safety_and_robustness evidence.
func (c *Client) Federate(ctx context.Context, in FederateInput) (*FederateResult, error) {
	if strings.TrimSpace(in.GCID) == "" {
		return nil, errors.New("microsoft: gcid is required")
	}
	if strings.TrimSpace(in.TenantID) == "" {
		return nil, errors.New("microsoft: tenant_id is required")
	}
	if strings.TrimSpace(in.Code) == "" {
		return nil, errors.New("microsoft: code is required")
	}
	if strings.TrimSpace(in.CodeVerifier) == "" {
		return nil, errors.New("microsoft: code_verifier is required")
	}

	tok, err := c.ExchangeCode(ctx, in.Code, in.CodeVerifier)
	if err != nil {
		c.publishRejected(in, err)
		return nil, err
	}
	info, err := c.UserInfo(ctx, tok.AccessToken)
	if err != nil {
		c.publishRejected(in, err)
		return nil, err
	}

	if c.cfg.Publisher != nil {
		env := newEnvelope(in.TenantID, in.GCID, in.Traceparent, in.Tracestate)
		payload := map[string]any{
			"gcid":                 in.GCID,
			"sub":                  info.Sub,
			"name":                 info.Name,
			"email":                info.Email,
			"preferred_username":   info.PreferredUsername,
			"locale":               info.Locale,
			"provider":             ProviderName,
			"federated_at":         env.OccurredAt.Format(time.RFC3339Nano),
			"id_token_set":         tok.IDToken != "",
			"refresh_token_set":    tok.RefreshToken != "",
			"chora_imda_dimension": "accountability",
		}
		if err := c.cfg.Publisher.Publish("chora.identity.federation.succeeded.v1", env, payload); err != nil {
			return nil, fmt.Errorf("microsoft: publish federation event: %w", err)
		}
	}

	return &FederateResult{
		Sub:               info.Sub,
		Name:              info.Name,
		Email:             info.Email,
		PreferredUsername: info.PreferredUsername,
		Locale:            info.Locale,
	}, nil
}

func (c *Client) publishRejected(in FederateInput, cause error) {
	if c.cfg.Publisher == nil {
		return
	}
	env := newEnvelope(in.TenantID, in.GCID, in.Traceparent, in.Tracestate)
	payload := map[string]any{
		"gcid":                 in.GCID,
		"provider":             ProviderName,
		"reason":               cause.Error(),
		"rejected_at":          env.OccurredAt.Format(time.RFC3339Nano),
		"chora_imda_dimension": "safety_and_robustness",
	}
	_ = c.cfg.Publisher.Publish("chora.identity.federation.rejected.v1", env, payload)
}

// ─────────────────────────────────────────────────────────────────────────────
// Event publisher port — kept locally so the adapter has no cross-package
// dependency. Production wires the Pub/Sub publisher (M12); tests inject a
// recorder.
// ─────────────────────────────────────────────────────────────────────────────

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

// Publisher is the port used by Federate() to emit the federation event.
type Publisher interface {
	Publish(topic string, env EventEnvelope, payload map[string]any) error
}

// PublishedRecord is the test-friendly capture shape.
type PublishedRecord struct {
	Topic         string
	EventID       string
	TenantID      string
	GCID          string
	Traceparent   string
	SourceProject string
	SourceService string
	SchemaVersion int32
	Payload       map[string]any
}

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
