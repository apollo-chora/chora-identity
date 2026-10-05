// MyInfo prefill aggregate (DEPRECATED under Singpass Path A, 2026-05-10).
//
// Originally introduced as S6.3 §3 to hold per-user MyInfo data fetched after
// a successful Singpass KYC. Path A scope minimisation makes that aggregate
// dead — Chora persists ONLY the OIDC `sub` UUID (kyc.Verification.SingpassSub)
// and explicitly NEVER stores NRIC, name, DOB, address, employment, or any
// other MyInfo field.
//
// The aggregate type definitions remain in this file so the in-memory repo
// adapter (used by tests + the legacy /v1/me/myinfo-prefill stub-route) still
// compiles. The HTTP route always returns 404 (KYC_PREFILL_DEPRECATED) —
// see internal/adapter/http/kyc_handler.go::getMyInfoPrefill.
//
// Removal plan: this file is scheduled for outright deletion at M12+ once
// chora-web S9 stops querying the deprecated route. Keeping it for one
// release prevents dependent test fixtures (in repo/inmem_prefill.go) from
// breaking the wider chora-identity build.
package kyc

import (
	"context"
	"errors"
	"strings"
	"time"
)

// -----------------------------------------------------------------------------
// MyInfoPrefill aggregate root
// -----------------------------------------------------------------------------

// MyInfoPrefill is the per-user MyInfo prefill aggregate.
type MyInfoPrefill struct {
	PrefillID          string
	Gcid               string
	FullName           string
	UINFINRaw          string // raw NRIC — adapters MUST encrypt at rest
	UINFINMasked       string // masked last-4 form (display-safe)
	Email              string
	MobileE164         string
	DateOfBirth        string
	Nationality        string
	Sex                string
	EmployerName       string
	EmploymentSector   string
	AddressBlock       string
	AddressStreet      string
	AddressFloor       string
	AddressUnit        string
	PostalCode         string
	Country            string
	VerifiedBySingpass bool
	Source             string // e.g. "singpass_myinfo" / "manual_entry"
	RetrievedAt        time.Time
	CreatedAt          time.Time
	UpdatedAt          time.Time
	DeletedAt          *time.Time
}

// NewPrefillParams is the constructor input for NewPrefill.
type NewPrefillParams struct {
	Gcid               string
	FullName           string
	UINFINRaw          string
	Email              string
	MobileE164         string
	DateOfBirth        string
	Nationality        string
	Sex                string
	EmployerName       string
	EmploymentSector   string
	AddressBlock       string
	AddressStreet      string
	AddressFloor       string
	AddressUnit        string
	PostalCode         string
	Country            string
	VerifiedBySingpass bool
	Source             string
}

// NewPrefill mints a fresh MyInfoPrefill aggregate.
func NewPrefill(p NewPrefillParams) (*MyInfoPrefill, error) {
	if strings.TrimSpace(p.Gcid) == "" {
		return nil, errors.New("kyc: gcid required")
	}
	now := time.Now().UTC()
	return &MyInfoPrefill{
		PrefillID:          newUUIDv7(),
		Gcid:               p.Gcid,
		FullName:           p.FullName,
		UINFINRaw:          p.UINFINRaw,
		UINFINMasked:       maskNRIC(p.UINFINRaw),
		Email:              p.Email,
		MobileE164:         p.MobileE164,
		DateOfBirth:        p.DateOfBirth,
		Nationality:        p.Nationality,
		Sex:                p.Sex,
		EmployerName:       p.EmployerName,
		EmploymentSector:   p.EmploymentSector,
		AddressBlock:       p.AddressBlock,
		AddressStreet:      p.AddressStreet,
		AddressFloor:       p.AddressFloor,
		AddressUnit:        p.AddressUnit,
		PostalCode:         p.PostalCode,
		Country:            p.Country,
		VerifiedBySingpass: p.VerifiedBySingpass,
		Source:             p.Source,
		RetrievedAt:        now,
		CreatedAt:          now,
		UpdatedAt:          now,
	}, nil
}

// AsRedacted returns the redacted view (suitable for HTTP response). Never
// includes the raw NRIC.
func (p *MyInfoPrefill) AsRedacted() map[string]any {
	out := map[string]any{
		"prefill_id":           p.PrefillID,
		"full_name":            p.FullName,
		"nric_last4_masked":    p.UINFINMasked,
		"email":                p.Email,
		"mobile_e164":          p.MobileE164,
		"date_of_birth":        p.DateOfBirth,
		"nationality":          p.Nationality,
		"sex":                  p.Sex,
		"employer_name":        p.EmployerName,
		"employment_sector":    p.EmploymentSector,
		"address_block":        p.AddressBlock,
		"address_street":       p.AddressStreet,
		"address_floor":        p.AddressFloor,
		"address_unit":         p.AddressUnit,
		"postal_code":          p.PostalCode,
		"country":              p.Country,
		"verified_by_singpass": p.VerifiedBySingpass,
		"source":               p.Source,
		"retrieved_at":         p.RetrievedAt.Format(time.RFC3339),
	}
	return out
}

// SoftDelete pseudonymises this prefill row (closure saga semantics).
func (p *MyInfoPrefill) SoftDelete() {
	if p.DeletedAt != nil {
		return
	}
	now := time.Now().UTC()
	p.DeletedAt = &now
	p.UINFINRaw = ""
	p.UpdatedAt = now
}

// -----------------------------------------------------------------------------
// PrefillRepository port
// -----------------------------------------------------------------------------

// ErrPrefillNotFound — sentinel.
var ErrPrefillNotFound = errors.New("kyc: prefill not found")

// PrefillRepository is the persistence port for MyInfoPrefill.
type PrefillRepository interface {
	Save(ctx context.Context, p *MyInfoPrefill) error
	GetByGcid(ctx context.Context, gcid string) (*MyInfoPrefill, error)
}

// -----------------------------------------------------------------------------
// helpers
// -----------------------------------------------------------------------------

// maskNRIC mirrors singpass.RedactNRICLast4 — kept inline so the domain
// package has no cross-package dependency on the adapter.
func maskNRIC(uinfin string) string {
	s := strings.TrimSpace(uinfin)
	if s == "" {
		return ""
	}
	if len(s) < 5 {
		return ""
	}
	return "*****" + s[len(s)-4:]
}
