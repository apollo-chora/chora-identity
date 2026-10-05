package cryptolocal_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/apollo-chora/chora-identity/internal/adapter/cryptolocal"
	"github.com/apollo-chora/chora-identity/internal/domain/crypto"
)

func kek(b byte) string {
	return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{b}, 32))
}

func TestNewLocalKEKKeyManager_RequiresKEK(t *testing.T) {
	_, err := cryptolocal.NewLocalKEKKeyManager("", cryptolocal.NewInMemoryWrappedDEKStore())
	if !errors.Is(err, cryptolocal.ErrKEKMissing) {
		t.Fatalf("empty KEK err = %v, want ErrKEKMissing", err)
	}
}

func TestNewLocalKEKKeyManager_RejectsWrongLength(t *testing.T) {
	short := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 16))
	if _, err := cryptolocal.NewLocalKEKKeyManager(short, cryptolocal.NewInMemoryWrappedDEKStore()); !errors.Is(err, cryptolocal.ErrKEKInvalid) {
		t.Fatalf("short KEK err = %v, want ErrKEKInvalid", err)
	}
	if _, err := cryptolocal.NewLocalKEKKeyManager("not-base64!!", cryptolocal.NewInMemoryWrappedDEKStore()); !errors.Is(err, cryptolocal.ErrKEKInvalid) {
		t.Fatalf("bad base64 err = %v, want ErrKEKInvalid", err)
	}
}

func TestLocalKEKKeyManager_RoundTrip(t *testing.T) {
	km, err := cryptolocal.NewLocalKEKKeyManager(kek(7), cryptolocal.NewInMemoryWrappedDEKStore())
	if err != nil {
		t.Fatalf("NewLocalKEKKeyManager: %v", err)
	}
	if _, err := km.IssueDEK("gcid-1"); err != nil {
		t.Fatalf("IssueDEK: %v", err)
	}
	ct, err := km.Encrypt("gcid-1", []byte("hello world"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if bytes.Contains(ct, []byte("hello world")) {
		t.Fatal("ciphertext contains plaintext")
	}
	pt, err := km.Decrypt("gcid-1", ct)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if string(pt) != "hello world" {
		t.Errorf("plaintext = %q", pt)
	}

	tok1, err := km.Tokenise("gcid-1", "email", "a@b.c")
	if err != nil {
		t.Fatalf("Tokenise: %v", err)
	}
	tok2, _ := km.Tokenise("gcid-1", "email", "a@b.c")
	if tok1 != tok2 {
		t.Error("Tokenise is not deterministic")
	}
	tok3, _ := km.Tokenise("gcid-1", "email", "x@y.z")
	if tok1 == tok3 {
		t.Error("Tokenise collided across values")
	}
}

func TestLocalKEKKeyManager_ShredMakesCiphertextUnrecoverable(t *testing.T) {
	km, err := cryptolocal.NewLocalKEKKeyManager(kek(9), cryptolocal.NewInMemoryWrappedDEKStore())
	if err != nil {
		t.Fatalf("NewLocalKEKKeyManager: %v", err)
	}
	if _, err := km.IssueDEK("gcid-shred"); err != nil {
		t.Fatalf("IssueDEK: %v", err)
	}
	ct, err := km.Encrypt("gcid-shred", []byte("secret"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if err := km.ShredDEK("gcid-shred"); err != nil {
		t.Fatalf("ShredDEK: %v", err)
	}
	if _, err := km.Decrypt("gcid-shred", ct); !errors.Is(err, crypto.ErrDEKShredded) {
		t.Fatalf("Decrypt after shred err = %v, want ErrDEKShredded", err)
	}
	// Shred is idempotent.
	if err := km.ShredDEK("gcid-shred"); err != nil {
		t.Fatalf("ShredDEK (repeat): %v", err)
	}
}

func TestLocalKEKKeyManager_UnknownGcidIsNotFound(t *testing.T) {
	km, err := cryptolocal.NewLocalKEKKeyManager(kek(3), cryptolocal.NewInMemoryWrappedDEKStore())
	if err != nil {
		t.Fatalf("NewLocalKEKKeyManager: %v", err)
	}
	if _, err := km.Encrypt("never-issued", []byte("x")); !errors.Is(err, crypto.ErrDEKNotFound) {
		t.Fatalf("Encrypt unknown gcid err = %v, want ErrDEKNotFound", err)
	}
}

func TestLocalKEKKeyManager_AADBindsWrapToGcid(t *testing.T) {
	store := cryptolocal.NewInMemoryWrappedDEKStore()
	km, err := cryptolocal.NewLocalKEKKeyManager(kek(5), store)
	if err != nil {
		t.Fatalf("NewLocalKEKKeyManager: %v", err)
	}
	if _, err := km.IssueDEK("gcid-a"); err != nil {
		t.Fatalf("IssueDEK: %v", err)
	}
	wrapped, err := store.Get(context.Background(), "gcid-a")
	if err != nil || wrapped == nil {
		t.Fatalf("store.Get: %v %v", wrapped, err)
	}
	// Move the wrapped DEK to a different gcid — the AAD must reject it.
	if err := store.Put(context.Background(), crypto.WrappedDEK{Gcid: "gcid-b", Wrapped: wrapped.Wrapped}); err != nil {
		t.Fatalf("store.Put: %v", err)
	}
	if _, err := km.Encrypt("gcid-b", []byte("x")); err == nil {
		t.Fatal("cross-gcid unwrap must fail (AAD mismatch)")
	}
}

func TestLocalKEKKeyManager_WrongKEKCannotUnwrap(t *testing.T) {
	store := cryptolocal.NewInMemoryWrappedDEKStore()
	km1, _ := cryptolocal.NewLocalKEKKeyManager(kek(1), store)
	if _, err := km1.IssueDEK("gcid-1"); err != nil {
		t.Fatalf("IssueDEK: %v", err)
	}
	km2, _ := cryptolocal.NewLocalKEKKeyManager(kek(2), store)
	if _, err := km2.Encrypt("gcid-1", []byte("x")); err == nil {
		t.Fatal("a different KEK must not unwrap another KEK's wrapped DEK")
	}
}
