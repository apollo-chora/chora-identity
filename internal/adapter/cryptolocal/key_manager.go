// Package cryptolocal is the cloud-neutral envelope-encryption crypto.KeyManager
// for chora-identity.
//
// It is a drop-in replacement for the retired Cloud KMS adapter and keeps the
// exact same crypto.KeyManager port the identity domain depends on:
//
//   - IssueDEK mints a RANDOM 32-byte per-user DEK, wraps it with the local
//     master KEK (AES-256-GCM, AAD-bound to the gcid), and persists ONLY the
//     wrapped form via a crypto.WrappedDEKStore.
//   - Encrypt / Decrypt AES-256-GCM with the unwrapped per-user DEK.
//   - Tokenise = hex(HMAC-SHA256(dek, field||":"||value)) — deterministic.
//   - ShredDEK tombstones the wrapped row: the plaintext DEK was never
//     persisted, so deleting the only wrapped copy renders every ciphertext
//     under that DEK permanently undecryptable (the real crypto-shred).
//
// The master KEK is provided by the environment (CHORA_LOCAL_KEK, base64 of a
// 32-byte key). Envelope encryption is NEVER silently disabled: a missing or
// malformed KEK is a hard error at construction time, and every key operation
// runs against the real AEAD.
package cryptolocal

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/apollo-chora/chora-identity/internal/domain/crypto"
)

// KEKEnv is the environment variable carrying the base64-encoded 32-byte
// master KEK. It MUST be set (no implicit dev fallback) so envelope
// encryption can never be silently downgraded.
const KEKEnv = "CHORA_LOCAL_KEK"

// ErrKEKMissing is returned when CHORA_LOCAL_KEK is unset or empty.
var ErrKEKMissing = fmt.Errorf("cryptolocal: %s is required (base64 of a 32-byte AES-256 KEK); refusing to run without envelope encryption", KEKEnv)

// ErrKEKInvalid is returned when the KEK is present but not a base64 32-byte key.
var ErrKEKInvalid = errors.New("cryptolocal: invalid KEK")

const (
	dekBytes     = 32 // AES-256
	nonceBytes   = 12 // AES-GCM standard nonce
	kekBytes     = 32 // AES-256
	defaultOpTTL = 10 * time.Second
)

// LocalKEKKeyManager implements crypto.KeyManager via local AES-256-GCM
// envelope encryption under a single process-wide KEK.
type LocalKEKKeyManager struct {
	kek     cipher.AEAD
	store   crypto.WrappedDEKStore
	timeout time.Duration

	// mu serialises IssueDEK so a concurrent double-issue cannot double-wrap.
	mu sync.Mutex
}

// NewLocalKEKKeyManager builds the manager from a base64-encoded 32-byte KEK.
// A malformed KEK is a hard error (fail-loud — never a silent plaintext path).
func NewLocalKEKKeyManager(kekB64 string, store crypto.WrappedDEKStore) (*LocalKEKKeyManager, error) {
	if strings.TrimSpace(kekB64) == "" {
		return nil, ErrKEKMissing
	}
	if store == nil {
		return nil, errors.New("cryptolocal: nil WrappedDEKStore")
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(kekB64))
	if err != nil {
		// Tolerate URL-safe / unpadded encodings for operator convenience.
		if raw, err = base64.RawStdEncoding.DecodeString(strings.TrimSpace(kekB64)); err != nil {
			if raw, err = base64.RawURLEncoding.DecodeString(strings.TrimSpace(kekB64)); err != nil {
				return nil, fmt.Errorf("%w: not valid base64: %v", ErrKEKInvalid, err)
			}
		}
	}
	if len(raw) != kekBytes {
		return nil, fmt.Errorf("%w: decoded length %d, want %d", ErrKEKInvalid, len(raw), kekBytes)
	}
	block, err := aes.NewCipher(raw)
	if err != nil {
		return nil, fmt.Errorf("cryptolocal: aes: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("cryptolocal: gcm: %w", err)
	}
	return &LocalKEKKeyManager{kek: aead, store: store, timeout: defaultOpTTL}, nil
}

// NewLocalKEKKeyManagerFromEnv reads CHORA_LOCAL_KEK and constructs the
// manager. A missing KEK fails explicitly (see ErrKEKMissing).
func NewLocalKEKKeyManagerFromEnv(store crypto.WrappedDEKStore) (*LocalKEKKeyManager, error) {
	return NewLocalKEKKeyManager(os.Getenv(KEKEnv), store)
}

func (m *LocalKEKKeyManager) ctx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), m.timeout)
}

// aad binds each wrap to its gcid so a wrapped DEK can only be unwrapped in
// the matching gcid context — even the shared KEK cannot cross-mix users.
func aad(gcid string) []byte { return []byte("gcid:" + gcid) }

// IssueDEK mints a random DEK, wraps it with the master KEK (AAD-bound), and
// persists the wrapped form. Idempotent — an existing live DEK is returned
// without re-wrapping. The handle is a non-secret stable id (never key material).
func (m *LocalKEKKeyManager) IssueDEK(gcid string) (string, error) {
	if strings.TrimSpace(gcid) == "" {
		return "", errors.New("gcid is required")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	ctx, cancel := m.ctx()
	defer cancel()

	if existing, err := m.store.Get(ctx, gcid); err != nil {
		return "", fmt.Errorf("cryptolocal: issue lookup: %w", err)
	} else if existing != nil && !existing.Deleted {
		return handle(gcid), nil
	}

	dek := make([]byte, dekBytes)
	if _, err := io.ReadFull(rand.Reader, dek); err != nil {
		return "", fmt.Errorf("cryptolocal: dek gen: %w", err)
	}
	wrapped, err := m.wrap(gcid, dek)
	if err != nil {
		return "", err
	}
	if err := m.store.Put(ctx, crypto.WrappedDEK{
		Gcid:       gcid,
		Wrapped:    wrapped,
		KEKVersion: "local-kek-v1",
	}); err != nil {
		return "", fmt.Errorf("cryptolocal: persist wrapped dek: %w", err)
	}
	return handle(gcid), nil
}

// ShredDEK tombstones the wrapped DEK — crypto-shred. Idempotent.
func (m *LocalKEKKeyManager) ShredDEK(gcid string) error {
	if strings.TrimSpace(gcid) == "" {
		return errors.New("gcid is required")
	}
	ctx, cancel := m.ctx()
	defer cancel()
	if err := m.store.MarkDeleted(ctx, gcid, "shred-"+handle(gcid)); err != nil {
		return fmt.Errorf("cryptolocal: shred: %w", err)
	}
	return nil
}

// Encrypt AES-256-GCM encrypts with the unwrapped per-user DEK. Layout:
// nonce(12) || aesgcm(ciphertext||tag). Raises ErrDEKShredded/ErrDEKNotFound.
func (m *LocalKEKKeyManager) Encrypt(gcid string, plaintext []byte) ([]byte, error) {
	dek, err := m.unwrap(gcid)
	if err != nil {
		return nil, err
	}
	gcm, err := newGCM(dek)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, nonceBytes)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("cryptolocal: nonce: %w", err)
	}
	return gcm.Seal(nonce, nonce, plaintext, aad(gcid)), nil
}

// Decrypt reverses Encrypt. Raises ErrDEKShredded/ErrDEKNotFound/ErrCorruptedCiphertext.
func (m *LocalKEKKeyManager) Decrypt(gcid string, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < nonceBytes {
		return nil, fmt.Errorf("%w: ciphertext shorter than nonce", crypto.ErrCorruptedCiphertext)
	}
	dek, err := m.unwrap(gcid)
	if err != nil {
		return nil, err
	}
	gcm, err := newGCM(dek)
	if err != nil {
		return nil, err
	}
	nonce, body := ciphertext[:nonceBytes], ciphertext[nonceBytes:]
	pt, err := gcm.Open(nil, nonce, body, aad(gcid))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", crypto.ErrCorruptedCiphertext, err)
	}
	return pt, nil
}

// Tokenise = hex(HMAC-SHA256(dek, field||":"||value)) — deterministic per DEK.
func (m *LocalKEKKeyManager) Tokenise(gcid, field, value string) (string, error) {
	dek, err := m.unwrap(gcid)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, dek)
	_, _ = mac.Write([]byte(field))
	_, _ = mac.Write([]byte{':'})
	_, _ = mac.Write([]byte(value))
	return hex.EncodeToString(mac.Sum(nil)), nil
}

// wrap AES-256-GCM-seals plaintext under the master KEK (AAD-bound to gcid).
func (m *LocalKEKKeyManager) wrap(gcid string, plaintext []byte) ([]byte, error) {
	nonce := make([]byte, nonceBytes)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("cryptolocal: wrap nonce: %w", err)
	}
	return m.kek.Seal(nonce, nonce, plaintext, aad(gcid)), nil
}

// unwrap loads the wrapped DEK and AEAD-opens it to the plaintext DEK
// (in-memory only; never persisted). Returns ErrDEKNotFound when never issued,
// ErrDEKShredded when tombstoned.
func (m *LocalKEKKeyManager) unwrap(gcid string) ([]byte, error) {
	ctx, cancel := m.ctx()
	defer cancel()
	w, err := m.store.Get(ctx, gcid)
	if err != nil {
		return nil, fmt.Errorf("cryptolocal: unwrap lookup: %w", err)
	}
	if w == nil {
		return nil, fmt.Errorf("%w: gcid=%s", crypto.ErrDEKNotFound, gcid)
	}
	if w.Deleted || len(w.Wrapped) == 0 {
		return nil, fmt.Errorf("%w: gcid=%s; prior ciphertext UNRECOVERABLE", crypto.ErrDEKShredded, gcid)
	}
	if len(w.Wrapped) < nonceBytes {
		return nil, fmt.Errorf("%w: wrapped dek shorter than nonce", crypto.ErrCorruptedCiphertext)
	}
	nonce, body := w.Wrapped[:nonceBytes], w.Wrapped[nonceBytes:]
	dek, err := m.kek.Open(nil, nonce, body, aad(gcid))
	if err != nil {
		return nil, fmt.Errorf("cryptolocal: unwrap: %w", err)
	}
	return dek, nil
}

func newGCM(dek []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, fmt.Errorf("cryptolocal: aes: %w", err)
	}
	return cipher.NewGCM(block)
}

// handle is a non-secret, stable, gcid-derived id for logs / audit — never key
// material (a one-way hash of the gcid, not the DEK).
func handle(gcid string) string {
	sum := sha256.Sum256([]byte("dek-handle:" + gcid))
	return hex.EncodeToString(sum[:])[:12]
}

// InMemoryWrappedDEKStore is the dev/test wrapped-DEK store. NOT durable —
// production wires the pg-backed adapter (chora_identity.user_dek_wrap).
type InMemoryWrappedDEKStore struct {
	mu sync.Mutex
	m  map[string]*crypto.WrappedDEK
}

// NewInMemoryWrappedDEKStore constructs an empty in-memory store.
func NewInMemoryWrappedDEKStore() *InMemoryWrappedDEKStore {
	return &InMemoryWrappedDEKStore{m: map[string]*crypto.WrappedDEK{}}
}

// Get returns a copy of the wrapped-DEK record, or (nil, nil) if absent.
func (s *InMemoryWrappedDEKStore) Get(_ context.Context, gcid string) (*crypto.WrappedDEK, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	w, ok := s.m[gcid]
	if !ok {
		return nil, nil
	}
	cp := *w
	cp.Wrapped = append([]byte(nil), w.Wrapped...)
	return &cp, nil
}

// Put persists a freshly wrapped DEK. Idempotent — re-put is a no-op.
func (s *InMemoryWrappedDEKStore) Put(_ context.Context, dek crypto.WrappedDEK) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.m[dek.Gcid]; ok {
		return nil
	}
	cp := dek
	cp.Wrapped = append([]byte(nil), dek.Wrapped...)
	s.m[dek.Gcid] = &cp
	return nil
}

// MarkDeleted tombstones the row and scrubs the wrapped bytes. Idempotent.
func (s *InMemoryWrappedDEKStore) MarkDeleted(_ context.Context, gcid, opID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	w, ok := s.m[gcid]
	if !ok || w.Deleted {
		return nil
	}
	w.Wrapped = nil
	w.Deleted = true
	w.KMSOperationID = opID
	return nil
}

// compile-time: the manager satisfies the KeyManager port.
var _ crypto.KeyManager = (*LocalKEKKeyManager)(nil)

// compile-time: the in-memory store satisfies the WrappedDEKStore port.
var _ crypto.WrappedDEKStore = (*InMemoryWrappedDEKStore)(nil)
