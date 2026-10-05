// myinfo.go — Singpass NDI MyInfo /person reader (DEPRECATED under Path A).
//
// Per Path A scope minimisation (2026-05-10), Chora persists ONLY the OIDC
// `sub` UUID via /userinfo. The /person endpoint surfaces NRIC/FIN, name,
// DOB, address, employment etc. — none of which are persisted. The
// MyInfoPerson parser is retained for diagnostic + emergency-investigation
// flows but is NOT called from the KYC HTTP handler.
//
// Removed under Path A:
//   - RedactNRICLast4 helper (NRIC never reaches Chora)
//   - CourseApplicationPrefill projection (the prefill aggregate is dead)
//   - AsCourseApplicationPrefill method
//
// Companion docs:
//   - services/chora-identity/migrations/0004_singpass_sub_minimisation.sql
//   - services/chora-identity/config/PII_Closure_Map.yaml
//   - docs/design/singpass-kyc-explainer.md
//   - docs/design/ux_singpass_kyc.md
//
// All endpoints sourced from env (no inline config) — see singpass.go Config.
package singpass

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// -----------------------------------------------------------------------------
// MyInfoPerson — projected /person response
// -----------------------------------------------------------------------------

// MyInfoAddress is the projected MyInfo registered-address envelope.
type MyInfoAddress struct {
	Block      string `json:"block,omitempty"`
	Street     string `json:"street,omitempty"`
	Floor      string `json:"floor,omitempty"`
	Unit       string `json:"unit,omitempty"`
	PostalCode string `json:"postal_code,omitempty"`
	Country    string `json:"country,omitempty"`
}

// MyInfoPerson is the projected /person response (DEPRECATED under Path A).
// Retained for diagnostic / emergency investigation flows only — the KYC
// HTTP handler does not call MyInfoPerson and never persists these fields.
type MyInfoPerson struct {
	Name              string        `json:"name,omitempty"`
	UINFIN            string        `json:"uinfin,omitempty"`
	Email             string        `json:"email,omitempty"`
	MobileE164        string        `json:"mobile_e164,omitempty"`
	EmployerName      string        `json:"employer_name,omitempty"`
	EmploymentSector  string        `json:"employment_sector,omitempty"`
	DateOfBirth       string        `json:"date_of_birth,omitempty"`
	Nationality       string        `json:"nationality,omitempty"`
	Sex               string        `json:"sex,omitempty"`
	RegisteredAddress MyInfoAddress `json:"registered_address,omitempty"`
}

// -----------------------------------------------------------------------------
// MyInfoPerson — fetcher
// -----------------------------------------------------------------------------

// MyInfoPerson fetches the /person citizen-data record using the access token
// returned from ExchangeCode. The token MUST have been issued with myinfo
// scopes (the OAuth consent must have included myinfo.* permissions).
//
// Endpoint URL precedence:
//  1. cfg.MyInfoURL — explicit override (preferred for production)
//  2. {cfg.IssuerURL}/person — sandbox fallback so dev rigs that only set
//     SINGPASS_ISSUER_URL still function.
func (c *Client) MyInfoPerson(ctx context.Context, accessToken string) (*MyInfoPerson, error) {
	if strings.TrimSpace(accessToken) == "" {
		return nil, errors.New("singpass: access token is required")
	}
	myInfoURL := strings.TrimSpace(c.cfg.MyInfoURL)
	if myInfoURL == "" {
		issuer := strings.TrimSpace(c.cfg.IssuerURL)
		if issuer == "" {
			return nil, errors.New("singpass: SINGPASS_MYINFO_URL or SINGPASS_ISSUER_URL must be configured")
		}
		myInfoURL = strings.TrimRight(issuer, "/") + "/person"
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, myInfoURL, nil)
	if err != nil {
		return nil, fmt.Errorf("singpass: build myinfo request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("singpass: myinfo request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("singpass: read myinfo response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("singpass: myinfo endpoint status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	// Parse the MyInfo envelope shape.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("singpass: decode myinfo response: %w", err)
	}

	person := &MyInfoPerson{
		Name:             extractValue(raw["name"]),
		UINFIN:           extractValue(raw["uinfin"]),
		Email:            extractValue(raw["email"]),
		EmployerName:     extractValue(raw["employment"]),
		EmploymentSector: extractValue(raw["employmentsector"]),
		DateOfBirth:      extractValue(raw["dob"]),
		Nationality:      extractValue(raw["nationality"]),
		Sex:              extractValue(raw["sex"]),
	}
	person.MobileE164 = extractMobileE164(raw["mobileno"])
	person.RegisteredAddress = extractAddress(raw["regadd"])
	return person, nil
}

// -----------------------------------------------------------------------------
// MyInfo envelope helpers
// -----------------------------------------------------------------------------

// extractValue parses a {"value": "..."} envelope and returns the value or "".
func extractValue(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var env struct {
		Value string `json:"value"`
	}
	if err := json.Unmarshal(raw, &env); err == nil {
		return env.Value
	}
	return ""
}

// extractMobileE164 parses {"areacode":{"value":"65"}, "nbr":{"value":"98765432"}}
// and returns "+6598765432" (or "" on missing/invalid input).
func extractMobileE164(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var env struct {
		AreaCode struct {
			Value string `json:"value"`
		} `json:"areacode"`
		Nbr struct {
			Value string `json:"value"`
		} `json:"nbr"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return ""
	}
	if env.AreaCode.Value == "" || env.Nbr.Value == "" {
		return ""
	}
	return "+" + env.AreaCode.Value + env.Nbr.Value
}

// extractAddress parses the regadd envelope.
func extractAddress(raw json.RawMessage) MyInfoAddress {
	if len(raw) == 0 {
		return MyInfoAddress{}
	}
	var env struct {
		Block struct {
			Value string `json:"value"`
		} `json:"block"`
		Street struct {
			Value string `json:"value"`
		} `json:"street"`
		Floor struct {
			Value string `json:"value"`
		} `json:"floor"`
		Unit struct {
			Value string `json:"value"`
		} `json:"unit"`
		Postal struct {
			Value string `json:"value"`
		} `json:"postal"`
		Country struct {
			Value string `json:"value"`
		} `json:"country"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return MyInfoAddress{}
	}
	return MyInfoAddress{
		Block:      env.Block.Value,
		Street:     env.Street.Value,
		Floor:      env.Floor.Value,
		Unit:       env.Unit.Value,
		PostalCode: env.Postal.Value,
		Country:    env.Country.Value,
	}
}
