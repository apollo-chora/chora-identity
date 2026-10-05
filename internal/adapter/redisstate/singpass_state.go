// Package redisstate is the Memorystore-backed adapter for the Singpass OIDC
// state store (CHO-2419 follow-up, 2026-09-02).
//
// It replaces InMemSingpassStateRepository on the production path. The
// in-memory store was single-replica-correct and chora-identity's HPA allows
// up to 5, so a callback could land on a pod that never saw the redirect and
// the KYC flow would fail with no obvious cause, under exactly the load that
// makes it hardest to diagnose.
//
// Three properties, in the order they matter:
//
//   - SHARED. Every replica reads the same store, which is the whole point.
//   - SINGLE-USE. GetAndConsume is GETDEL, one round trip, atomic at the
//     server. Two concurrent callbacks holding the same state token cannot
//     both proceed, so a replayed callback fails. The port doc already
//     specified this ("via Lua GET+DEL atomically"); GETDEL is the same
//     guarantee without the script.
//   - FAIL-CLOSED. Every Redis error propagates. A state check that degrades
//     to "allow" when the store is unreachable is a CSRF hole, so this returns
//     an error and the caller denies. It never returns a record on error.
//
// ⚠ The store is EXPECTED TO VANISH. cost-pause DELETES the Memorystore
// instance and cost-resume recreates it with fresh AUTH and CA material, so
// this adapter must tolerate the endpoint disappearing between restarts.
// It does so by never dialling at construction: go-redis connects lazily, so a
// missing instance surfaces as a failed operation (denied callback, correct)
// rather than a failed boot (crash-loop, not correct). Losing in-flight
// five-minute OAuth state across a pause is acceptable; refusing to start is
// not.
package redisstate

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	goredis "github.com/redis/go-redis/v9"

	httpadapter "github.com/apollo-chora/chora-identity/internal/adapter/http"
)

// keyPrefix namespaces state tokens inside the shared Memorystore instance,
// which chora-delivery and chora-user-event-stream also use.
const keyPrefix = "chora-identity:singpass:state:"

// DefaultTTL bounds how long a redirect roundtrip may take. The port doc
// specifies 10 minutes; Singpass authorisation is typically well under one.
const DefaultTTL = 10 * time.Minute

// ErrStateNotFound is returned when the token is absent, already consumed or
// expired. The three are deliberately indistinguishable to the caller: telling
// a client which one it hit is a probing oracle.
var ErrStateNotFound = errors.New("singpass: state not found")

// Config is the dial configuration. CACertPEM is optional; when empty the
// connection is plaintext, which is only appropriate inside the mesh.
type Config struct {
	Addr      string
	Password  string
	CACertPEM string
	TTL       time.Duration
}

// Store implements httpadapter.SingpassStateRepository over Redis.
type Store struct {
	c   *goredis.Client
	ttl time.Duration
}

// NewStore builds the adapter. It does NOT dial: see the package doc on why a
// missing instance must not fail the boot.
func NewStore(cfg Config) (*Store, error) {
	tlsCfg, err := buildTLS(cfg.CACertPEM)
	if err != nil {
		return nil, err
	}
	ttl := cfg.TTL
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	return &Store{
		c: goredis.NewClient(&goredis.Options{
			Addr:      cfg.Addr,
			Password:  cfg.Password,
			TLSConfig: tlsCfg,
		}),
		ttl: ttl,
	}, nil
}

// buildTLS mirrors the verification chora-user-event-stream already uses
// against the same instance: the Memorystore CA is not in the system pool, so
// the chain is verified explicitly rather than skipped.
func buildTLS(caPEM string) (*tls.Config, error) {
	if caPEM == "" {
		return nil, nil
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(caPEM)) {
		return nil, errors.New("redisstate: CA cert PEM contained no certificate")
	}
	return &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true, //nolint:gosec // chain verified in VerifyPeerCertificate
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			certs := make([]*x509.Certificate, 0, len(rawCerts))
			for _, raw := range rawCerts {
				c, err := x509.ParseCertificate(raw)
				if err != nil {
					return err
				}
				certs = append(certs, c)
			}
			if len(certs) == 0 {
				return errors.New("redisstate: server presented no certificate")
			}
			inter := x509.NewCertPool()
			for _, c := range certs[1:] {
				inter.AddCert(c)
			}
			_, err := certs[0].Verify(x509.VerifyOptions{Roots: pool, Intermediates: inter})
			return err
		},
	}, nil
}

func key(state string) string { return keyPrefix + state }

// Put stores the record under its state token with a TTL.
//
// SetNX rather than Set: a token that already exists is a collision or a
// replayed redirect, and overwriting it would silently discard the first
// flow's verifier. The caller mints a fresh random token, so a collision here
// is a signal, not routine.
func (s *Store) Put(ctx context.Context, st *httpadapter.SingpassStateRecord) error {
	if st == nil || st.State == "" {
		return errors.New("redisstate: state record must carry a token")
	}
	ttl := s.ttl
	if !st.ExpiresAt.IsZero() {
		if d := time.Until(st.ExpiresAt); d > 0 {
			ttl = d
		}
	}
	b, err := json.Marshal(st)
	if err != nil {
		return fmt.Errorf("redisstate: marshal state: %w", err)
	}
	ok, err := s.c.SetNX(ctx, key(st.State), b, ttl).Result()
	if err != nil {
		return fmt.Errorf("redisstate: put state: %w", err)
	}
	if !ok {
		return errors.New("redisstate: state token already in use")
	}
	return nil
}

// Get reads without consuming. Kept for the tests and admin tooling the port
// doc describes; the callback path MUST use GetAndConsume.
func (s *Store) Get(ctx context.Context, state string) (*httpadapter.SingpassStateRecord, error) {
	b, err := s.c.Get(ctx, key(state)).Bytes()
	if errors.Is(err, goredis.Nil) {
		return nil, ErrStateNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("redisstate: get state: %w", err)
	}
	return decode(b)
}

// Delete removes the record. Absent is not an error: the caller's intent is
// that the token no longer be usable, and it is not.
func (s *Store) Delete(ctx context.Context, state string) error {
	if err := s.c.Del(ctx, key(state)).Err(); err != nil {
		return fmt.Errorf("redisstate: delete state: %w", err)
	}
	return nil
}

// GetAndConsume atomically reads and removes the record.
//
// GETDEL is a single command, so the read and the delete cannot interleave:
// of two concurrent callbacks presenting the same token, exactly one receives
// the record and the other gets ErrStateNotFound. An expired entry is already
// gone by TTL, so the "never resurrected on retry" clause in the port doc
// holds without extra work.
func (s *Store) GetAndConsume(ctx context.Context, state string) (*httpadapter.SingpassStateRecord, error) {
	b, err := s.c.GetDel(ctx, key(state)).Bytes()
	if errors.Is(err, goredis.Nil) {
		return nil, ErrStateNotFound
	}
	if err != nil {
		// Fail closed. The token is NOT treated as valid because the store
		// could not be reached.
		return nil, fmt.Errorf("redisstate: consume state: %w", err)
	}
	rec, err := decode(b)
	if err != nil {
		return nil, err
	}
	if !rec.ExpiresAt.IsZero() && time.Now().UTC().After(rec.ExpiresAt) {
		return nil, ErrStateNotFound
	}
	return rec, nil
}

func decode(b []byte) (*httpadapter.SingpassStateRecord, error) {
	var rec httpadapter.SingpassStateRecord
	if err := json.Unmarshal(b, &rec); err != nil {
		return nil, fmt.Errorf("redisstate: decode state: %w", err)
	}
	return &rec, nil
}

// Close releases the client.
func (s *Store) Close() error { return s.c.Close() }

// Compile-time assertion that the adapter satisfies the port.
var _ httpadapter.SingpassStateRepository = (*Store)(nil)
