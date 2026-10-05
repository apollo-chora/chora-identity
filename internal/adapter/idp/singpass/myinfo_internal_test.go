// myinfo_internal_test.go — internal-package coverage for the unexported
// MyInfo envelope extractors (extractValue / extractMobileE164 /
// extractAddress) — all nil/malformed/partial-envelope branches.
package singpass

import (
	"encoding/json"
	"testing"
)

func TestExtractValue_EnvelopeAndMalformed(t *testing.T) {
	t.Parallel()
	if got := extractValue(nil); got != "" {
		t.Errorf("nil raw → %q, want empty", got)
	}
	if got := extractValue(json.RawMessage(`{"value":"Phyllis Tan"}`)); got != "Phyllis Tan" {
		t.Errorf("valid envelope → %q", got)
	}
	if got := extractValue(json.RawMessage(`not json`)); got != "" {
		t.Errorf("undecodable raw → %q, want empty", got)
	}
	if got := extractValue(json.RawMessage(`{"other":1}`)); got != "" {
		t.Errorf("missing value key → %q, want empty", got)
	}
}

func TestExtractMobileE164_EnvelopeAndPartial(t *testing.T) {
	t.Parallel()
	if got := extractMobileE164(nil); got != "" {
		t.Errorf("nil raw → %q, want empty", got)
	}
	full := json.RawMessage(`{"areacode":{"value":"65"},"nbr":{"value":"98765432"}}`)
	if got := extractMobileE164(full); got != "+6598765432" {
		t.Errorf("full envelope → %q, want +6598765432", got)
	}
	// Missing area code → empty (not a partial number).
	noArea := json.RawMessage(`{"areacode":{},"nbr":{"value":"98765432"}}`)
	if got := extractMobileE164(noArea); got != "" {
		t.Errorf("missing area code → %q, want empty", got)
	}
	// Undecodable → empty.
	if got := extractMobileE164(json.RawMessage(`[]`)); got != "" {
		t.Errorf("undecodable raw → %q, want empty", got)
	}
}

func TestExtractAddress_EnvelopeAndMalformed(t *testing.T) {
	t.Parallel()
	if got := extractAddress(nil); got != (MyInfoAddress{}) {
		t.Errorf("nil raw → %+v, want zero address", got)
	}
	full := json.RawMessage(`{
		"block":{"value":"1"},
		"street":{"value":"Raffles Pl"},
		"floor":{"value":"05"},
		"unit":{"value":"123"},
		"postal":{"value":"039594"},
		"country":{"value":"SG"}
	}`)
	got := extractAddress(full)
	want := MyInfoAddress{Block: "1", Street: "Raffles Pl", Floor: "05", Unit: "123", PostalCode: "039594", Country: "SG"}
	if got != want {
		t.Errorf("full envelope → %+v, want %+v", got, want)
	}
	// Undecodable → zero address.
	if got := extractAddress(json.RawMessage(`not json`)); got != (MyInfoAddress{}) {
		t.Errorf("undecodable raw → %+v, want zero address", got)
	}
}
