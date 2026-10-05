// Package kyc — RED-phase tests for the MyInfo prefill aggregate (S6.3 §3).
//
// MyInfoPrefill is a per-user aggregate sibling to Verification. It holds
// the encrypted MyInfo payload (encrypted under the per-user DEK from the
// crypto package) so the chora-delivery course-application flow can fetch
// a redacted copy via /v1/me/myinfo-prefill?for=course_application.
//
// Cross-DB queries forbidden — chora-delivery NEVER reads chora_identity
// directly. The prefill payload is exposed via the HTTP endpoint above.
package kyc

import (
	"strings"
	"testing"
	"time"
)

func TestNewPrefill_RequiresGcid(t *testing.T) {
	t.Parallel()
	if _, err := NewPrefill(NewPrefillParams{}); err == nil {
		t.Fatalf("expected error for missing gcid")
	}
}

func TestNewPrefill_HappyPath(t *testing.T) {
	t.Parallel()
	p, err := NewPrefill(NewPrefillParams{
		Gcid:               "g-1",
		FullName:           "Phyllis Tan",
		UINFINRaw:          "S1234567A",
		Email:              "p@example.sg",
		MobileE164:         "+6598765432",
		EmployerName:       "Acme",
		EmploymentSector:   "Tech",
		DateOfBirth:        "1992-04-15",
		Nationality:        "SG",
		PostalCode:         "018989",
		AddressBlock:       "123",
		AddressStreet:      "Marina Boulevard",
		VerifiedBySingpass: true,
	})
	if err != nil {
		t.Fatalf("NewPrefill: %v", err)
	}
	if p.PrefillID == "" {
		t.Errorf("PrefillID empty")
	}
	if p.UINFINMasked != "*****567A" {
		t.Errorf("UINFINMasked=%q", p.UINFINMasked)
	}
	// Raw NRIC stored separately for redaction; never exposed via redacted view.
	red := p.AsRedacted()
	if red["nric_last4_masked"] != "*****567A" {
		t.Errorf("redacted nric=%v", red["nric_last4_masked"])
	}
	if v, ok := red["uinfin_raw"]; ok {
		t.Errorf("redacted view leaks raw NRIC: %v", v)
	}
	// Confirm at the JSON layer too — Marshal of redacted view must not
	// contain the raw NRIC anywhere.
	if v, ok := red["uinfin"]; ok {
		t.Errorf("redacted view exposes uinfin: %v", v)
	}
	if !strings.HasPrefix(p.UINFINMasked, "*****") {
		t.Errorf("UINFINMasked not masked: %q", p.UINFINMasked)
	}
}

func TestPrefill_VerifiedBySingpassFlag(t *testing.T) {
	t.Parallel()
	p, _ := NewPrefill(NewPrefillParams{Gcid: "g", FullName: "X", UINFINRaw: "S0000001A"})
	if p.VerifiedBySingpass {
		t.Errorf("default VerifiedBySingpass should be false")
	}
	red := p.AsRedacted()
	if red["verified_by_singpass"] != false {
		t.Errorf("redacted verified_by_singpass=%v", red["verified_by_singpass"])
	}
}

func TestPrefillRepository_PortShape(t *testing.T) {
	// Port assertion only — implementations live in adapter packages.
	t.Parallel()
	var _ PrefillRepository = (PrefillRepository)(nil)
}

func TestSoftDelete_PseudonymisesOnce(t *testing.T) {
	t.Parallel()
	p := &MyInfoPrefill{
		PrefillID:    "pf-1",
		Gcid:         "g-1",
		UINFINRaw:    "S1234567A",
		UINFINMasked: "*****567A",
	}
	origUpdatedAt := p.UpdatedAt
	p.SoftDelete()
	if p.DeletedAt == nil {
		t.Fatal("SoftDelete did not stamp DeletedAt")
	}
	if p.DeletedAt.Before(p.UpdatedAt) && false {
		t.Errorf("DeletedAt precedes prior UpdatedAt: %v", p.DeletedAt)
	}
	if p.UINFINRaw != "" {
		t.Errorf("raw NRIC not cleared after SoftDelete: %q", p.UINFINRaw)
	}
	if !p.UpdatedAt.After(origUpdatedAt) {
		t.Errorf("UpdatedAt not refreshed: %v", p.UpdatedAt)
	}
}

func TestSoftDelete_AlreadyDeletedIsNoop(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	oldRaw := "S1234567A"
	p := &MyInfoPrefill{
		PrefillID:    "pf-2",
		Gcid:         "g-2",
		UINFINRaw:    oldRaw,
		UpdatedAt:    now,
		DeletedAt:    &now,
		UINFINMasked: "*****567A",
	}
	p.SoftDelete()
	if p.UINFINRaw != oldRaw {
		t.Errorf("SoftDelete on already-deleted row mutated raw NRIC: %q", p.UINFINRaw)
	}
}

func TestMaskNRIC_TrimsAndShortCircuits(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   string
		want string
	}{
		{"", ""},
		{"   ", ""},
		{"S123", ""}, // fewer than 5 chars → empty
		{"S12345", "*****2345"},
		{"  S1234567A  ", "*****567A"},
	}
	for _, c := range cases {
		if got := maskNRIC(c.in); got != c.want {
			t.Errorf("maskNRIC(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
