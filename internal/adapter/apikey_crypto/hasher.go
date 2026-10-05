// Package apikey_crypto is the production Hasher adapter for the apikey
// domain — SHA-256 over a 16-byte CSPRNG seed, prefixed with sk_live_.
//
// Ported (and refactored to the new hexagonal layout) from
// chora-iam/internal/adapters/crypto/api_key_hasher.go as part of M12.2.E.1.
//
// Hexagonal: ADAPTER. Implements apikey.Hasher. No domain or other adapter
// dependencies — depends on crypto/rand + crypto/sha256 only.
package apikey_crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// SHA256Hasher implements apikey.Hasher using SHA-256 of CSPRNG random bytes,
// prefixed with sk_live_.
type SHA256Hasher struct{}

// NewSHA256Hasher constructs the production hasher.
func NewSHA256Hasher() *SHA256Hasher { return &SHA256Hasher{} }

// Generate returns a fresh plaintext key: "sk_live_" + 32 hex chars (16 random
// bytes). The plaintext must be surfaced to the user once and then discarded;
// only the hash (via Hash) is ever stored.
func (h *SHA256Hasher) Generate() (string, error) {
	b := make([]byte, 16) // 16 bytes -> 32 hex chars
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("apikey_crypto: rand: %w", err)
	}
	return "sk_live_" + hex.EncodeToString(b), nil
}

// Hash returns the SHA-256 hex digest of the plaintext. Constant output length
// (64 hex chars) — suitable for column-equality lookups in the key_hash column.
func (h *SHA256Hasher) Hash(plaintext string) string {
	sum := sha256.Sum256([]byte(plaintext))
	return hex.EncodeToString(sum[:])
}
