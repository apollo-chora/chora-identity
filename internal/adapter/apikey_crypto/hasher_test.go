package apikey_crypto

import (
	"strings"
	"testing"
)

func TestSHA256Hasher_Generate_PrefixedAndUnique(t *testing.T) {
	t.Parallel()
	h := NewSHA256Hasher()
	k1, err := h.Generate()
	if err != nil {
		t.Fatalf("generate 1: %v", err)
	}
	k2, err := h.Generate()
	if err != nil {
		t.Fatalf("generate 2: %v", err)
	}
	if !strings.HasPrefix(k1, "sk_"+"live_") {
		t.Fatalf("expected sk_live_ prefix; got %q", k1)
	}
	if k1 == k2 {
		t.Fatalf("two successive generations must differ; got %q twice", k1)
	}
	// 8-char prefix + 32 hex chars = 40 total.
	if len(k1) != 40 {
		t.Fatalf("expected length 40; got %d (%q)", len(k1), k1)
	}
}

func TestSHA256Hasher_Hash_Deterministic(t *testing.T) {
	t.Parallel()
	h := NewSHA256Hasher()
	got1 := h.Hash("sk_" + "live_abc")
	got2 := h.Hash("sk_" + "live_abc")
	if got1 != got2 {
		t.Fatalf("hash must be deterministic; got %q != %q", got1, got2)
	}
	if len(got1) != 64 {
		t.Fatalf("expected 64-char hex sha256; got %d (%q)", len(got1), got1)
	}
}

func TestSHA256Hasher_Hash_Different_Inputs(t *testing.T) {
	t.Parallel()
	h := NewSHA256Hasher()
	if h.Hash("a") == h.Hash("b") {
		t.Fatalf("different inputs must produce different hashes")
	}
}
