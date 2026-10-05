// jwksinmem_test.go — adapter tests for the in-memory JWKS provider.
package jwksinmem_test

import (
	"testing"

	"github.com/apollo-chora/chora-identity/internal/adapter/jwksinmem"
)

func TestProvider_New_HasOneECAndOneRSAKey(t *testing.T) {
	t.Parallel()
	p, err := jwksinmem.New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	keys := p.PublicKeys()
	if len(keys) != 2 {
		t.Fatalf("len(keys)=%d want 2", len(keys))
	}
	algs := map[string]int{}
	for _, k := range keys {
		algs[k.Alg]++
	}
	if algs["ES256"] != 1 || algs["RS256"] != 1 {
		t.Errorf("algs=%v want one ES256 + one RS256", algs)
	}
}

func TestProvider_KIDsAreStableAndNonEmpty(t *testing.T) {
	t.Parallel()
	p, _ := jwksinmem.New()
	keys := p.PublicKeys()
	for _, k := range keys {
		if k.KID == "" {
			t.Errorf("KID empty for alg=%q", k.Alg)
		}
	}
}

func TestProvider_PrivateKeysAccessible(t *testing.T) {
	t.Parallel()
	p, _ := jwksinmem.New()
	if p.ECPrivate() == nil {
		t.Errorf("ECPrivate nil")
	}
	if p.RSAPrivate() == nil {
		t.Errorf("RSAPrivate nil")
	}
}

func TestProvider_PublicKeysReturnsCopy(t *testing.T) {
	t.Parallel()
	p, _ := jwksinmem.New()
	first := p.PublicKeys()
	first[0].KID = "tampered"
	second := p.PublicKeys()
	if second[0].KID == "tampered" {
		t.Errorf("PublicKeys() must return a defensive copy, not internal state")
	}
}
