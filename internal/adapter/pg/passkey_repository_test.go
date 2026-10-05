// passkey_repository_test.go — unit tests for the pgx-backed PasskeyChallenge
// + PasskeyCredential repositories.
//
// Two test surfaces (mirrors user_repository_test.go convention):
//
//  1. Unit tests against a stub Querier — exercise the SQL the adapter
//     emits + scan logic without a live database. Run on every `go test`.
//  2. Integration tests against a live chora_identity database — gated
//     behind the `integration` build tag (see passkey_integration_test.go
//     when added). RLS isolation is N/A because passkey_challenges +
//     passkey_credentials are identity-scoped (NOT tenant-scoped), same
//     pattern as the `users` table (migration 0001 §"users").
//
// TDD: this file is the RED phase for M12 deferral close-out (the inmem
// repo file header at internal/adapter/inmem/passkey_repository.go:4 marks
// the pg adapter as "deferred to M12").
package pg_test

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/apollo-chora/chora-identity/internal/adapter/pg"
	"github.com/apollo-chora/chora-identity/internal/domain/identity"
)

// ----------------------------------------------------------------------------
// PasskeyChallenge — unit tests
// ----------------------------------------------------------------------------

func TestPasskeyChallengeRepo_Save_InsertsExpectedColumns(t *testing.T) {
	t.Parallel()

	q := &stubQuerier{}
	r := pg.NewPasskeyChallengeRepositoryWithQuerier(q)

	c, err := identity.NewPasskeyChallenge(identity.NewPasskeyChallengeParams{
		ChallengeBytes: []byte("32-bytes-of-entropy-12345678901234"),
		RPID:           "chora.site",
		UserHandle:     "phyllis@chora.dev",
		TTL:            5 * time.Minute,
	})
	if err != nil {
		t.Fatalf("NewPasskeyChallenge: %v", err)
	}

	if err := r.Save(context.Background(), c); err != nil {
		t.Fatalf("Save: %v", err)
	}

	if len(q.execCalls) != 1 {
		t.Fatalf("expected 1 Exec call, got %d", len(q.execCalls))
	}
	got := q.execCalls[0]
	if !contains(got.sql, "INSERT INTO passkey_challenges") {
		t.Errorf("expected SQL to INSERT INTO passkey_challenges; got %q", got.sql)
	}
	if !contains(got.sql, "ON CONFLICT") {
		t.Errorf("Save must be UPSERT (ON CONFLICT clause); got %q", got.sql)
	}
	// First arg must be challenge_id (PK).
	if gotID, ok := got.args[0].(string); !ok || gotID != c.ChallengeID {
		t.Errorf("first arg want challenge_id %q; got %v", c.ChallengeID, got.args[0])
	}
}

func TestPasskeyChallengeRepo_Save_RejectsTerminalConsumedRow(t *testing.T) {
	t.Parallel()

	// Stub: GetByID returns a row already in Consumed status.
	q := &stubQuerier{
		rowResponses: []func(dest ...any) error{
			func(dest ...any) error {
				// Match scanChallenge column order:
				// challenge_id, challenge_bytes, rp_id, user_handle, status,
				// verified_gcid, created_at, expires_at
				*dest[0].(*string) = "01970000-0000-7000-8000-cccccccccccc"
				*dest[1].(*[]byte) = []byte("32-bytes-of-entropy-12345678901234")
				*dest[2].(*string) = "chora.site"
				*dest[3].(*string) = ""
				*dest[4].(*string) = string(identity.PasskeyChallengeStatusConsumed)
				*dest[5].(*string) = "01970000-0000-7000-8000-bbbbbbbbbbbb"
				*dest[6].(*time.Time) = time.Now().UTC()
				*dest[7].(*time.Time) = time.Now().UTC().Add(5 * time.Minute)
				return nil
			},
		},
	}
	r := pg.NewPasskeyChallengeRepositoryWithQuerier(q)

	// Build a challenge with the same id but a non-consumed local state —
	// adapter MUST detect the terminal stored row + reject.
	c := &identity.PasskeyChallenge{
		ChallengeID:    "01970000-0000-7000-8000-cccccccccccc",
		ChallengeBytes: []byte("32-bytes-of-entropy-12345678901234"),
		RPID:           "chora.site",
		Status:         identity.PasskeyChallengeStatusVerified,
		CreatedAt:      time.Now().UTC(),
		ExpiresAt:      time.Now().UTC().Add(5 * time.Minute),
	}
	err := r.Save(context.Background(), c)
	if !errors.Is(err, identity.ErrPasskeyChallengeConsumed) {
		t.Fatalf("expected ErrPasskeyChallengeConsumed; got %v", err)
	}
	// No exec should have fired.
	if len(q.execCalls) != 0 {
		t.Errorf("expected 0 Exec calls when stored row is consumed; got %d", len(q.execCalls))
	}
}

func TestPasskeyChallengeRepo_GetByID_HappyPath(t *testing.T) {
	t.Parallel()

	id := "01970000-0000-7000-8000-aaaaaaaaaaaa"
	now := time.Now().UTC()
	q := &stubQuerier{
		rowResponses: []func(dest ...any) error{
			func(dest ...any) error {
				*dest[0].(*string) = id
				*dest[1].(*[]byte) = []byte("32-bytes-of-entropy-12345678901234")
				*dest[2].(*string) = "chora.site"
				*dest[3].(*string) = "phyllis@chora.dev"
				*dest[4].(*string) = string(identity.PasskeyChallengeStatusPending)
				*dest[5].(*string) = ""
				*dest[6].(*time.Time) = now
				*dest[7].(*time.Time) = now.Add(5 * time.Minute)
				return nil
			},
		},
	}
	r := pg.NewPasskeyChallengeRepositoryWithQuerier(q)

	got, err := r.GetByID(context.Background(), id)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.ChallengeID != id {
		t.Errorf("ChallengeID = %q, want %q", got.ChallengeID, id)
	}
	if got.Status != identity.PasskeyChallengeStatusPending {
		t.Errorf("Status = %q, want pending", got.Status)
	}
	if !bytes.Equal(got.ChallengeBytes, []byte("32-bytes-of-entropy-12345678901234")) {
		t.Errorf("ChallengeBytes mismatch")
	}
}

func TestPasskeyChallengeRepo_GetByID_NotFoundMapsToDomainError(t *testing.T) {
	t.Parallel()

	q := &stubQuerier{} // Empty rowResponses → ErrNoRows.
	r := pg.NewPasskeyChallengeRepositoryWithQuerier(q)

	_, err := r.GetByID(context.Background(), "missing")
	if err == nil {
		t.Fatalf("expected error")
	}
	if !errors.Is(err, identity.ErrPasskeyChallengeNotFound) {
		t.Errorf("expected identity.ErrPasskeyChallengeNotFound, got %T %v", err, err)
	}
}

// ----------------------------------------------------------------------------
// PasskeyCredential — unit tests
// ----------------------------------------------------------------------------

func TestPasskeyCredentialRepo_Save_InsertsExpectedColumns(t *testing.T) {
	t.Parallel()

	q := &stubQuerier{}
	r := pg.NewPasskeyCredentialRepositoryWithQuerier(q)

	c, err := identity.NewPasskeyCredential(identity.NewPasskeyCredentialParams{
		Gcid:            "01970000-0000-7000-8000-aaaaaaaaaaaa",
		CredentialID:    []byte{0x01, 0x02, 0x03, 0x04},
		PublicKeyCOSE:   []byte("cose-key-bytes"),
		AttestationType: "none",
		RPID:            "chora.site",
	})
	if err != nil {
		t.Fatalf("NewPasskeyCredential: %v", err)
	}

	if err := r.Save(context.Background(), c); err != nil {
		t.Fatalf("Save: %v", err)
	}

	if len(q.execCalls) != 1 {
		t.Fatalf("expected 1 Exec call, got %d", len(q.execCalls))
	}
	got := q.execCalls[0]
	if !contains(got.sql, "INSERT INTO passkey_credentials") {
		t.Errorf("expected SQL to INSERT INTO passkey_credentials; got %q", got.sql)
	}
	if !contains(got.sql, "ON CONFLICT") {
		t.Errorf("Save must be UPSERT (ON CONFLICT clause); got %q", got.sql)
	}
}

func TestPasskeyCredentialRepo_GetByCredentialID_HappyPath(t *testing.T) {
	t.Parallel()

	credID := []byte{0x01, 0x02, 0x03, 0x04}
	now := time.Now().UTC()
	q := &stubQuerier{
		rowResponses: []func(dest ...any) error{
			func(dest ...any) error {
				// Match scanCredential column order:
				// credential_uuid, gcid, credential_id, public_key, attestation_type,
				// rp_id, sign_count, status, created_at, last_used_at
				*dest[0].(*string) = "01970000-0000-7000-8000-bbbbbbbbbbbb"
				*dest[1].(*string) = "01970000-0000-7000-8000-aaaaaaaaaaaa"
				*dest[2].(*[]byte) = credID
				*dest[3].(*[]byte) = []byte("cose-key-bytes")
				*dest[4].(*string) = "none"
				*dest[5].(*string) = "chora.site"
				var sc int64 = 7
				*dest[6].(*int64) = sc
				*dest[7].(*string) = string(identity.PasskeyCredentialStatusActive)
				*dest[8].(*time.Time) = now
				if v, ok := dest[9].(**time.Time); ok {
					_ = v
				}
				return nil
			},
		},
	}
	r := pg.NewPasskeyCredentialRepositoryWithQuerier(q)

	got, err := r.GetByCredentialID(context.Background(), credID)
	if err != nil {
		t.Fatalf("GetByCredentialID: %v", err)
	}
	if got.SignCount != 7 {
		t.Errorf("SignCount = %d, want 7", got.SignCount)
	}
	if !bytes.Equal(got.CredentialID, credID) {
		t.Errorf("CredentialID mismatch")
	}
}

func TestPasskeyCredentialRepo_GetByCredentialID_NotFoundMapsToDomainError(t *testing.T) {
	t.Parallel()

	q := &stubQuerier{}
	r := pg.NewPasskeyCredentialRepositoryWithQuerier(q)

	_, err := r.GetByCredentialID(context.Background(), []byte("missing"))
	if err == nil {
		t.Fatalf("expected error")
	}
	if !errors.Is(err, identity.ErrPasskeyCredentialNotFound) {
		t.Errorf("expected identity.ErrPasskeyCredentialNotFound, got %T %v", err, err)
	}
}

// stubRowsBytes is a Rows stub returning a sequence of (credential_uuid, gcid,
// credential_id, public_key, attestation_type, rp_id, sign_count, status,
// created_at, last_used_at) tuples.
type stubRowsBytes struct {
	idx  int
	rows []func(dest ...any) error
	err  error
}

func (r *stubRowsBytes) Next() bool {
	if r.idx >= len(r.rows) {
		return false
	}
	return true
}
func (r *stubRowsBytes) Scan(dest ...any) error {
	if r.idx >= len(r.rows) {
		return errors.New("stubRowsBytes: scan past end")
	}
	scanFn := r.rows[r.idx]
	r.idx++
	return scanFn(dest...)
}
func (r *stubRowsBytes) Close() error { return nil }
func (r *stubRowsBytes) Err() error   { return r.err }

func TestPasskeyCredentialRepo_ListByGcid_HappyPath(t *testing.T) {
	t.Parallel()

	gcid := "01970000-0000-7000-8000-aaaaaaaaaaaa"
	now := time.Now().UTC()

	q := &stubQuerierWithQuery{
		stubQuerier: &stubQuerier{},
		queryRows: &stubRowsBytes{
			rows: []func(dest ...any) error{
				func(dest ...any) error {
					*dest[0].(*string) = "01970000-0000-7000-8000-cccccccccccc"
					*dest[1].(*string) = gcid
					*dest[2].(*[]byte) = []byte("cred-1")
					*dest[3].(*[]byte) = []byte("k1")
					*dest[4].(*string) = "none"
					*dest[5].(*string) = "chora.site"
					var sc int64 = 1
					*dest[6].(*int64) = sc
					*dest[7].(*string) = string(identity.PasskeyCredentialStatusActive)
					*dest[8].(*time.Time) = now
					return nil
				},
				func(dest ...any) error {
					*dest[0].(*string) = "01970000-0000-7000-8000-dddddddddddd"
					*dest[1].(*string) = gcid
					*dest[2].(*[]byte) = []byte("cred-2")
					*dest[3].(*[]byte) = []byte("k2")
					*dest[4].(*string) = "none"
					*dest[5].(*string) = "chora.site"
					var sc int64 = 2
					*dest[6].(*int64) = sc
					*dest[7].(*string) = string(identity.PasskeyCredentialStatusActive)
					*dest[8].(*time.Time) = now
					return nil
				},
			},
		},
	}
	r := pg.NewPasskeyCredentialRepositoryWithListQuerier(q)

	got, err := r.ListByGcid(context.Background(), gcid)
	if err != nil {
		t.Fatalf("ListByGcid: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 credentials, got %d", len(got))
	}
	if got[0].SignCount != 1 || got[1].SignCount != 2 {
		t.Errorf("SignCount order/value mismatch")
	}
}

// stubQuerierWithQuery extends stubQuerier with a Query method to satisfy
// the ListQuerier surface used by ListByGcid.
type stubQuerierWithQuery struct {
	*stubQuerier
	queryRows pg.Rows
	queryErr  error
}

func (s *stubQuerierWithQuery) Query(_ context.Context, _ string, _ ...any) (pg.Rows, error) {
	if s.queryErr != nil {
		return nil, s.queryErr
	}
	return s.queryRows, nil
}

// Compile-time assertions — verify the adapters satisfy the domain ports.
var (
	_ identity.PasskeyChallengeRepository  = (*pg.PasskeyChallengeRepository)(nil)
	_ identity.PasskeyCredentialRepository = (*pg.PasskeyCredentialRepository)(nil)
)
