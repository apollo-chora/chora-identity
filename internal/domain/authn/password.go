// password.go — Argon2id password hashing with PHC-string encoding.
//
// The PHC string format is
//
//	$argon2id$v=19$m=65536,t=3,p=2$<b64salt>$<b64hash>
//
// so the cost parameters travel with every hash and verification never has to
// guess them. The primitive is golang.org/x/crypto/argon2.IDKey; this file only
// encodes/parses the parameters and performs the constant-time comparison.
package authn

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Argon2id parameters (RFC 9106 recommended profile for password hashing).
const (
	Argon2MemoryKiB   = 65536 // 64 MiB
	Argon2Iterations  = 3
	Argon2Parallelism = 2
	Argon2SaltBytes   = 16
	Argon2HashBytes   = 32
	Argon2Version     = argon2.Version // 0x13 (19)

	// MaxPasswordBytes is the hard upper bound enforced at the HTTP boundary.
	// Argon2 is memory-hard, so an unbounded password is a memory-amplification
	// DoS vector.
	MaxPasswordBytes = 1024
)

// ErrInvalidPHC is returned when a stored hash is not a parseable Argon2id PHC
// string.
var ErrInvalidPHC = errors.New("authn: invalid argon2id PHC hash")

// ErrPasswordTooLong is returned when a candidate password exceeds
// MaxPasswordBytes.
var ErrPasswordTooLong = fmt.Errorf("authn: password exceeds %d bytes", MaxPasswordBytes)

// phcParams are the decoded cost parameters of a PHC string.
type phcParams struct {
	Memory      uint32
	Iterations  uint32
	Parallelism uint8
	Salt        []byte
	Hash        []byte
}

// HashPassword derives an Argon2id hash of password with a fresh random salt
// and returns the canonical PHC string.
func HashPassword(password string) (string, error) {
	if len(password) > MaxPasswordBytes {
		return "", ErrPasswordTooLong
	}
	salt := make([]byte, Argon2SaltBytes)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return "", fmt.Errorf("authn: salt: %w", err)
	}
	sum := argon2.IDKey(
		[]byte(password), salt,
		Argon2Iterations, Argon2MemoryKiB, Argon2Parallelism, Argon2HashBytes,
	)
	return encodePHC(Argon2MemoryKiB, Argon2Iterations, Argon2Parallelism, salt, sum), nil
}

// VerifyPassword reports whether password matches the PHC hash. It parses the
// cost parameters from the hash, re-derives with them, and compares in constant
// time. A malformed hash is an error; a mismatch is (false, nil).
func VerifyPassword(password, phc string) (bool, error) {
	p, err := parsePHC(phc)
	if err != nil {
		return false, err
	}
	sum := argon2.IDKey(
		[]byte(password), p.Salt,
		p.Iterations, p.Memory, p.Parallelism, uint32(len(p.Hash)),
	)
	return subtle.ConstantTimeCompare(sum, p.Hash) == 1, nil
}

// encodePHC renders the canonical PHC string. Salt + hash use unpadded standard
// base64 (the PHC convention).
func encodePHC(memory, iterations uint32, parallelism uint8, salt, hash []byte) string {
	return fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		Argon2Version, memory, iterations, parallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
	)
}

// parsePHC decodes an Argon2id PHC string into its cost parameters.
func parsePHC(phc string) (*phcParams, error) {
	parts := strings.Split(strings.TrimSpace(phc), "$")
	// "", "argon2id", "v=19", "m=..,t=..,p=..", salt, hash
	if len(parts) != 6 || parts[0] != "" {
		return nil, fmt.Errorf("%w: expected 6 $-separated fields", ErrInvalidPHC)
	}
	if parts[1] != "argon2id" {
		return nil, fmt.Errorf("%w: algorithm %q", ErrInvalidPHC, parts[1])
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return nil, fmt.Errorf("%w: version %q: %v", ErrInvalidPHC, parts[2], err)
	}
	if version != Argon2Version {
		return nil, fmt.Errorf("%w: unsupported version %d", ErrInvalidPHC, version)
	}

	var memory, iterations uint32
	var parallelism uint8
	for _, kv := range strings.Split(parts[3], ",") {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			return nil, fmt.Errorf("%w: parameter %q", ErrInvalidPHC, kv)
		}
		n, err := strconv.ParseUint(v, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("%w: parameter %q: %v", ErrInvalidPHC, kv, err)
		}
		switch k {
		case "m":
			memory = uint32(n)
		case "t":
			iterations = uint32(n)
		case "p":
			if n == 0 || n > 255 {
				return nil, fmt.Errorf("%w: parallelism %d out of range", ErrInvalidPHC, n)
			}
			parallelism = uint8(n)
		default:
			return nil, fmt.Errorf("%w: unknown parameter %q", ErrInvalidPHC, k)
		}
	}
	if memory == 0 || iterations == 0 || parallelism == 0 {
		return nil, fmt.Errorf("%w: missing m/t/p", ErrInvalidPHC)
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return nil, fmt.Errorf("%w: salt: %v", ErrInvalidPHC, err)
	}
	hash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return nil, fmt.Errorf("%w: hash: %v", ErrInvalidPHC, err)
	}
	if len(salt) == 0 || len(hash) == 0 {
		return nil, fmt.Errorf("%w: empty salt or hash", ErrInvalidPHC)
	}
	return &phcParams{
		Memory:      memory,
		Iterations:  iterations,
		Parallelism: parallelism,
		Salt:        salt,
		Hash:        hash,
	}, nil
}
