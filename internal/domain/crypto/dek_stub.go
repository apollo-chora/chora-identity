// Package crypto is the per-user DEK (data encryption key) management stub
// used by the federated closure saga's crypto-shred step.
//
// MVP design:
//   - Master key in-process (replaceable with Cloud KMS CMEK in M12+).
//   - Per-user DEK derived from the master via HMAC-SHA256(master, gcid).
//   - "Encrypt" = HMAC + payload XOR (NOT a real cipher; intentionally weak
//     so tests can demonstrate round-trip + crypto-shred semantics without
//     pulling in a full AES-GCM dependency for a stub).
//   - ShredDEK(gcid) deletes the in-memory key entry; subsequent decrypt of
//     ANY ciphertext encrypted under that key fails with ErrDEKShredded.
//   - Tokenise(gcid, field, value) = HMAC-SHA256(dek, field|value) hex.
//
// Production wiring is the CloudKMSKeyManager in internal/adapter/cryptokms
// (envelope encryption, ADR-186):
//   - Master KEK = shared Cloud KMS cmek-data-plane (per-tenant KEK deferred).
//   - Per-user DEK = RANDOM bytes wrapped by the master KEK (AAD-bound to gcid);
//     ONLY the wrapped form is persisted (chora_identity.user_dek_wrap).
//   - Encrypt / Decrypt = AES-256-GCM with the unwrapped DEK.
//   - ShredDEK = DELETE the wrapped DEK row (NOT DestroyCryptoKeyVersion —
//     Cloud KMS cannot delete CryptoKeys and per-user keys don't scale; ADR-186
//     rejects that model). The plaintext DEK was never stored, so deleting the
//     only wrapped copy makes the ciphertext permanently undecryptable.
//
// Hexagonal: this package is dependency-free w.r.t. infrastructure.
package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
)

// -----------------------------------------------------------------------------
// PII classification — re-export so callers can tag fields.
// -----------------------------------------------------------------------------

type PIIClass string

const (
	PIIClassLow      PIIClass = "low"
	PIIClassMedium   PIIClass = "medium"
	PIIClassHigh     PIIClass = "high"
	PIIClassCritical PIIClass = "critical"
)

// -----------------------------------------------------------------------------
// Errors
// -----------------------------------------------------------------------------

var (
	// ErrDEKNotFound is returned when Encrypt / Decrypt / Tokenise is called
	// with a gcid that has no issued DEK.
	ErrDEKNotFound = errors.New("dek not found for gcid")

	// ErrDEKShredded is returned by Decrypt when the underlying DEK has been
	// deleted via ShredDEK — data is unrecoverable.
	ErrDEKShredded = errors.New("dek shredded; data unrecoverable")

	// ErrCorruptedCiphertext is returned by Decrypt when the input is not a
	// valid base64-encoded payload of the expected shape.
	ErrCorruptedCiphertext = errors.New("ciphertext corrupted")
)

// -----------------------------------------------------------------------------
// KeyManager port
// -----------------------------------------------------------------------------

// KeyManager is the per-user DEK management port. The InMemoryKeyManager is
// the MVP stub; future Cloud KMS wiring will swap in via this interface.
type KeyManager interface {
	IssueDEK(gcid string) (handle string, err error)
	ShredDEK(gcid string) error
	Encrypt(gcid string, plaintext []byte) ([]byte, error)
	Decrypt(gcid string, ciphertext []byte) ([]byte, error)
	Tokenise(gcid, field, value string) (string, error)
}

// -----------------------------------------------------------------------------
// dekState tracks the per-user DEK. `shredded` is set true on ShredDEK; once
// shredded, the actual key bytes are zeroed and never re-derived (we keep the
// entry to distinguish "shredded" from "never issued" for clearer errors).
// -----------------------------------------------------------------------------

type dekState struct {
	key      []byte
	handle   string // hex prefix used as a non-secret identifier
	shredded bool
}

// -----------------------------------------------------------------------------
// InMemoryKeyManager — the MVP stub.
// -----------------------------------------------------------------------------

// InMemoryKeyManager satisfies KeyManager backed by a per-process map keyed
// by gcid. NOT thread-safe across processes — fine for a single Cloud Run
// instance + the deferred Cloud KMS wiring.
type InMemoryKeyManager struct {
	mu     sync.RWMutex
	master []byte
	deks   map[string]*dekState
}

// NewInMemoryKeyManager constructs an in-memory KeyManager keyed by `master`.
// In production, master is bootstrapped via Secret Manager + Workload Identity
// Federation — never an inline literal.
func NewInMemoryKeyManager(master []byte) *InMemoryKeyManager {
	return &InMemoryKeyManager{
		master: append([]byte(nil), master...),
		deks:   make(map[string]*dekState),
	}
}

// IssueDEK derives a per-user DEK from the master via HMAC-SHA256(master, gcid)
// and stores it under gcid. The returned `handle` is a non-secret 8-char
// hex prefix of the DEK (used for logs / audit trail; NEVER for key recovery).
func (km *InMemoryKeyManager) IssueDEK(gcid string) (string, error) {
	g := strings.TrimSpace(gcid)
	if g == "" {
		return "", errors.New("gcid is required")
	}
	mac := hmac.New(sha256.New, km.master)
	_, _ = mac.Write([]byte(g))
	key := mac.Sum(nil)
	handle := hex.EncodeToString(key[:4])

	km.mu.Lock()
	defer km.mu.Unlock()
	km.deks[g] = &dekState{
		key:    key,
		handle: handle,
	}
	return handle, nil
}

// ShredDEK deletes the per-user DEK; subsequent encrypt / decrypt fails.
// Idempotent — shredding an already-shredded DEK is a no-op. Shredding a
// never-issued DEK is also a no-op (we don't want callers to need to know
// whether a DEK was ever issued before invoking the saga's crypto-shred step).
func (km *InMemoryKeyManager) ShredDEK(gcid string) error {
	g := strings.TrimSpace(gcid)
	if g == "" {
		return errors.New("gcid is required")
	}
	km.mu.Lock()
	defer km.mu.Unlock()
	d, ok := km.deks[g]
	if !ok {
		// Insert a tombstone so subsequent Decrypt yields ErrDEKShredded
		// (rather than ErrDEKNotFound) — matches the semantic that "this user
		// has been crypto-shredded".
		km.deks[g] = &dekState{shredded: true}
		return nil
	}
	// Zero the key bytes for hygiene.
	for i := range d.key {
		d.key[i] = 0
	}
	d.key = nil
	d.shredded = true
	return nil
}

// Encrypt produces a base64-encoded payload encrypted under the per-user DEK.
//
// Stub algorithm: HMAC-SHA256(dek, plaintext) || plaintext XOR keystream where
// keystream = HMAC-SHA256(dek, "stream").  This is intentionally NOT a real
// cipher — it is a deterministic stub that round-trips with Decrypt and
// becomes meaningless once ShredDEK deletes the DEK. Production swaps to
// AES-256-GCM (likely via cloud KMS).
func (km *InMemoryKeyManager) Encrypt(gcid string, plaintext []byte) ([]byte, error) {
	d, err := km.lookupActive(gcid)
	if err != nil {
		return nil, err
	}
	mac := hmac.New(sha256.New, d.key)
	_, _ = mac.Write(plaintext)
	tag := mac.Sum(nil) // 32 bytes

	stream := keystream(d.key, len(plaintext))
	ct := make([]byte, len(plaintext))
	for i := range plaintext {
		ct[i] = plaintext[i] ^ stream[i]
	}
	// Layout: tag || ct, then base64.
	combined := append(tag, ct...)
	return []byte(base64.StdEncoding.EncodeToString(combined)), nil
}

// Decrypt reverses Encrypt. Returns ErrDEKShredded if the DEK has been
// shredded; ErrDEKNotFound if the DEK was never issued; ErrCorruptedCiphertext
// for bad input.
func (km *InMemoryKeyManager) Decrypt(gcid string, ciphertext []byte) ([]byte, error) {
	d, err := km.lookupActive(gcid)
	if err != nil {
		return nil, err
	}
	combined, err := base64.StdEncoding.DecodeString(string(ciphertext))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCorruptedCiphertext, err)
	}
	if len(combined) < 32 {
		return nil, ErrCorruptedCiphertext
	}
	tag, ct := combined[:32], combined[32:]
	stream := keystream(d.key, len(ct))
	plain := make([]byte, len(ct))
	for i := range ct {
		plain[i] = ct[i] ^ stream[i]
	}
	mac := hmac.New(sha256.New, d.key)
	_, _ = mac.Write(plain)
	if !hmac.Equal(mac.Sum(nil), tag) {
		return nil, ErrCorruptedCiphertext
	}
	return plain, nil
}

// Tokenise produces a deterministic pseudonym for (gcid, field, value):
// hex(HMAC-SHA256(dek, field || ":" || value)). Same input always yields the
// same token (so cross-table joins on the pseudonym still work). Different
// gcids / fields produce different tokens.
func (km *InMemoryKeyManager) Tokenise(gcid, field, value string) (string, error) {
	d, err := km.lookupActive(gcid)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, d.key)
	_, _ = mac.Write([]byte(field))
	_, _ = mac.Write([]byte{':'})
	_, _ = mac.Write([]byte(value))
	return hex.EncodeToString(mac.Sum(nil)), nil
}

// -----------------------------------------------------------------------------
// internal helpers
// -----------------------------------------------------------------------------

func (km *InMemoryKeyManager) lookupActive(gcid string) (*dekState, error) {
	g := strings.TrimSpace(gcid)
	if g == "" {
		return nil, errors.New("gcid is required")
	}
	km.mu.RLock()
	defer km.mu.RUnlock()
	d, ok := km.deks[g]
	if !ok {
		return nil, fmt.Errorf("%w: gcid=%s", ErrDEKNotFound, g)
	}
	if d.shredded {
		return nil, fmt.Errorf("%w: gcid=%s", ErrDEKShredded, g)
	}
	return d, nil
}

// keystream derives a deterministic keystream of length n from the DEK by
// chaining HMAC-SHA256 outputs with a counter prefix. Stub-only — not a CSPRNG.
func keystream(key []byte, n int) []byte {
	out := make([]byte, 0, n)
	counter := byte(0)
	for len(out) < n {
		mac := hmac.New(sha256.New, key)
		_, _ = mac.Write([]byte("stream"))
		_, _ = mac.Write([]byte{counter})
		out = append(out, mac.Sum(nil)...)
		counter++
	}
	return out[:n]
}
