// dek_stub_gap_test.go — error-branch coverage for the in-memory KeyManager
// (empty-gcid guards, corrupted-ciphertext + invalid-base64 paths, never-
// issued shred tombstone).
package crypto_test

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/apollo-chora/chora-identity/internal/domain/crypto"
)

func TestInMemoryKeyManager_EmptyGcidGuards(t *testing.T) {
	t.Parallel()
	km := crypto.NewInMemoryKeyManager([]byte("master"))
	if _, err := km.IssueDEK("  "); err == nil {
		t.Error("IssueDEK with blank gcid must error")
	}
	if err := km.ShredDEK("  "); err == nil {
		t.Error("ShredDEK with blank gcid must error")
	}
	if _, err := km.Encrypt("", []byte("x")); err == nil {
		t.Error("Encrypt with blank gcid must error")
	}
	if _, err := km.Decrypt("", []byte("x")); err == nil {
		t.Error("Decrypt with blank gcid must error")
	}
	if _, err := km.Tokenise("", "field", "value"); err == nil {
		t.Error("Tokenise with blank gcid must error")
	}
}

func TestInMemoryKeyManager_DecryptInvalidBase64(t *testing.T) {
	t.Parallel()
	km := crypto.NewInMemoryKeyManager([]byte("master"))
	if _, err := km.IssueDEK("gcid-a"); err != nil {
		t.Fatalf("issue: %v", err)
	}
	if _, err := km.Decrypt("gcid-a", []byte("!!!not-base64!!!")); !errors.Is(err, crypto.ErrCorruptedCiphertext) {
		t.Errorf("invalid base64: err=%v, want ErrCorruptedCiphertext", err)
	}
}

func TestInMemoryKeyManager_DecryptTooShortPayload(t *testing.T) {
	t.Parallel()
	km := crypto.NewInMemoryKeyManager([]byte("master"))
	if _, err := km.IssueDEK("gcid-b"); err != nil {
		t.Fatalf("issue: %v", err)
	}
	// 12 bytes of base64 decodes to < 32 → tag-size check rejects.
	if _, err := km.Decrypt("gcid-b", []byte("c2hvcnQ=")); !errors.Is(err, crypto.ErrCorruptedCiphertext) {
		t.Errorf("short payload: err=%v, want ErrCorruptedCiphertext", err)
	}
}

func TestInMemoryKeyManager_DecryptTamperedTag(t *testing.T) {
	t.Parallel()
	km := crypto.NewInMemoryKeyManager([]byte("master"))
	master2 := crypto.NewInMemoryKeyManager([]byte("master-2")) // different master → different DEK
	h1, err := km.IssueDEK("gcid-c")
	if err != nil {
		t.Fatalf("issue 1: %v", err)
	}
	if _, err := master2.IssueDEK("gcid-c"); err != nil {
		t.Fatalf("issue 2: %v", err)
	}
	ct, err := km.Encrypt("gcid-c", []byte("secret"))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if _, err := km.Decrypt("gcid-c", ct); err != nil {
		t.Fatalf("own decrypt: %v", err)
	}
	// h1 unused except to keep deterministic flows; tamper via a different key.
	_ = h1
	if _, err := master2.Decrypt("gcid-c", ct); !errors.Is(err, crypto.ErrCorruptedCiphertext) {
		t.Errorf("cross-key decrypt: err=%v, want ErrCorruptedCiphertext", err)
	}
}

func TestInMemoryKeyManager_ShredNeverIssuedTombstones(t *testing.T) {
	t.Parallel()
	km := crypto.NewInMemoryKeyManager([]byte("master"))
	g := "never-issued"
	// Shredding a never-issued gcid is a no-op (returns nil) and inserts a
	// tombstone — subsequent ops report ErrDEKShredded, NOT ErrDEKNotFound.
	if err := km.ShredDEK(g); err != nil {
		t.Fatalf("shred never-issued: %v", err)
	}
	if _, err := km.Decrypt(g, []byte("AAAA")); !errors.Is(err, crypto.ErrDEKShredded) {
		t.Errorf("decrypt after tombstone: err=%v, want ErrDEKShredded", err)
	}
	if _, err := km.Tokenise(g, "f", "v"); !errors.Is(err, crypto.ErrDEKShredded) {
		t.Errorf("tokenise after tombstone: err=%v, want ErrDEKShredded", err)
	}
}

func TestInMemoryKeyManager_TokeniseEmptyValueAllowed(t *testing.T) {
	t.Parallel()
	km := crypto.NewInMemoryKeyManager([]byte("master"))
	if _, err := km.IssueDEK("gcid-d"); err != nil {
		t.Fatalf("issue: %v", err)
	}
	tok, err := km.Tokenise("gcid-d", "field", "")
	if err != nil {
		t.Fatalf("tokenise empty value: %v", err)
	}
	if decoded, err := hex.DecodeString(tok); err != nil || len(decoded) != sha256.Size {
		t.Errorf("token %q is not a 32-byte hex digest (decoded=%d err=%v)", tok, len(decoded), err)
	}
}
