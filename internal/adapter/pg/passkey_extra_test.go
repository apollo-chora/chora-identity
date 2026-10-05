// passkey_extra_test.go — pushes passkey_repository.go toward 100%: the
// *PgxPoolQuerier constructors, the nil-arg guards, the non-ErrNoRows error
// branches, the nullable helper branches and the ListByGcid failure modes.
// All drive the same stub Querier surface as passkey_repository_test.go.
package pg_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/apollo-chora/chora-identity/internal/adapter/pg"
	"github.com/apollo-chora/chora-identity/internal/domain/identity"
)

func TestPasskeyChallengeRepo_New(t *testing.T) {
	t.Parallel()
	r := pg.NewPasskeyChallengeRepository(nil)
	if r == nil {
		t.Fatal("NewPasskeyChallengeRepository(nil) must return a non-nil repo")
	}
}

func TestPasskeyChallengeRepo_Save_NilChallenge(t *testing.T) {
	t.Parallel()
	q := &stubQuerier{}
	r := pg.NewPasskeyChallengeRepositoryWithQuerier(q)
	if err := r.Save(context.Background(), nil); err == nil {
		t.Fatal("Save(nil) err = nil, want fail-loud error")
	}
	if len(q.execCalls) != 0 {
		t.Fatalf("Save(nil) must not Exec; got %d", len(q.execCalls))
	}
}

func TestPasskeyChallengeRepo_Save_PreflightErrorPropagates(t *testing.T) {
	t.Parallel()
	boom := errors.New("preflight boom")
	q := &stubQuerier{rowResponses: []func(dest ...any) error{
		func(...any) error { return boom }, // GetByID scan fails (non-ErrNoRows)
	}}
	r := pg.NewPasskeyChallengeRepositoryWithQuerier(q)
	c := &identity.PasskeyChallenge{
		ChallengeID: "01970000-0000-7000-8000-eeeeeeeeeeee",
		Status:      identity.PasskeyChallengeStatusPending,
		CreatedAt:   time.Now().UTC(),
		ExpiresAt:   time.Now().UTC().Add(time.Minute),
	}
	err := r.Save(context.Background(), c)
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want wrapped preflight boom", err)
	}
	if len(q.execCalls) != 0 {
		t.Fatalf("preflight failure must not Exec; got %d", len(q.execCalls))
	}
}

func TestPasskeyChallengeRepo_GetByID_ScanErrorWraps(t *testing.T) {
	t.Parallel()
	boom := errors.New("challenge scan boom")
	q := &stubQuerier{rowResponses: []func(dest ...any) error{
		func(...any) error { return boom },
	}}
	r := pg.NewPasskeyChallengeRepositoryWithQuerier(q)
	_, err := r.GetByID(context.Background(), "x")
	if err == nil || errors.Is(err, identity.ErrPasskeyChallengeNotFound) || !errors.Is(err, boom) {
		t.Fatalf("err = %v, want wrapped boom (NOT the not-found sentinel)", err)
	}
}

func TestPasskeyCredentialRepo_New(t *testing.T) {
	t.Parallel()
	r := pg.NewPasskeyCredentialRepository(nil)
	if r == nil {
		t.Fatal("NewPasskeyCredentialRepository(nil) must return a non-nil repo")
	}
}

func TestPasskeyCredentialRepo_Save_NilCredential(t *testing.T) {
	t.Parallel()
	q := &stubQuerier{}
	r := pg.NewPasskeyCredentialRepositoryWithQuerier(q)
	if err := r.Save(context.Background(), nil); err == nil {
		t.Fatal("Save(nil) err = nil, want fail-loud error")
	}
	if len(q.execCalls) != 0 {
		t.Fatalf("Save(nil) must not Exec; got %d", len(q.execCalls))
	}
}

func TestPasskeyCredentialRepo_GetByCredentialID_ScanErrorWraps(t *testing.T) {
	t.Parallel()
	boom := errors.New("credential scan boom")
	q := &stubQuerier{rowResponses: []func(dest ...any) error{
		func(...any) error { return boom },
	}}
	r := pg.NewPasskeyCredentialRepositoryWithQuerier(q)
	_, err := r.GetByCredentialID(context.Background(), []byte("cred"))
	if err == nil || errors.Is(err, identity.ErrPasskeyCredentialNotFound) || !errors.Is(err, boom) {
		t.Fatalf("err = %v, want wrapped boom (NOT the not-found sentinel)", err)
	}
}

func TestPasskeyCredentialRepo_GetByCredentialID_LastUsedAtSet(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	q := &stubQuerier{rowResponses: []func(dest ...any) error{
		func(dest ...any) error {
			*dest[0].(*string) = "01970000-0000-7000-8000-ffffffffffff"
			*dest[1].(*string) = "01970000-0000-7000-8000-aaaaaaaaaaaa"
			*dest[2].(*[]byte) = []byte("cred")
			*dest[3].(*[]byte) = []byte("k")
			*dest[4].(*string) = "none"
			*dest[5].(*string) = "chora.site"
			var sc int64 = 3
			*dest[6].(*int64) = sc
			*dest[7].(*string) = string(identity.PasskeyCredentialStatusActive)
			*dest[8].(*time.Time) = now
			*dest[9].(**time.Time) = &now // last_used_at set → non-nil + UTC
			return nil
		},
	}}
	r := pg.NewPasskeyCredentialRepositoryWithQuerier(q)
	got, err := r.GetByCredentialID(context.Background(), []byte("cred"))
	if err != nil {
		t.Fatalf("GetByCredentialID: %v", err)
	}
	if got.LastUsedAt == nil || !got.LastUsedAt.Equal(now) {
		t.Fatalf("LastUsedAt = %v, want %v", got.LastUsedAt, now)
	}
}

func TestPasskeyCredentialRepo_ListByGcid_NoListQuerierWired(t *testing.T) {
	t.Parallel()
	r := pg.NewPasskeyCredentialRepositoryWithQuerier(&stubQuerier{})
	_, err := r.ListByGcid(context.Background(), "01970000-0000-7000-8000-aaaaaaaaaaaa")
	if err == nil {
		t.Fatal("ListByGcid without a ListQuerier must fail loud")
	}
}

func TestPasskeyCredentialRepo_ListByGcid_QueryErrorWraps(t *testing.T) {
	t.Parallel()
	boom := errors.New("list query boom")
	q := &stubQuerierWithQuery{stubQuerier: &stubQuerier{}, queryErr: boom}
	r := pg.NewPasskeyCredentialRepositoryWithListQuerier(q)
	_, err := r.ListByGcid(context.Background(), "01970000-0000-7000-8000-aaaaaaaaaaaa")
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want wrapped boom", err)
	}
}

func TestPasskeyCredentialRepo_ListByGcid_ScanErrorWraps(t *testing.T) {
	t.Parallel()
	boom := errors.New("row scan boom")
	q := &stubQuerierWithQuery{stubQuerier: &stubQuerier{}, queryRows: &stubRowsBytes{
		rows: []func(dest ...any) error{func(...any) error { return boom }},
	}}
	r := pg.NewPasskeyCredentialRepositoryWithListQuerier(q)
	_, err := r.ListByGcid(context.Background(), "01970000-0000-7000-8000-aaaaaaaaaaaa")
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want wrapped boom", err)
	}
}

func TestPasskeyCredentialRepo_ListByGcid_RowsErrPropagates(t *testing.T) {
	t.Parallel()
	boom := errors.New("iter boom")
	now := time.Now().UTC()
	q := &stubQuerierWithQuery{stubQuerier: &stubQuerier{}, queryRows: &stubRowsBytes{
		rows: []func(dest ...any) error{
			func(dest ...any) error {
				*dest[0].(*string) = "01970000-0000-7000-8000-ffffffffffff"
				*dest[1].(*string) = "01970000-0000-7000-8000-aaaaaaaaaaaa"
				*dest[2].(*[]byte) = []byte("cred")
				*dest[3].(*[]byte) = []byte("k")
				*dest[4].(*string) = "none"
				*dest[5].(*string) = "chora.site"
				var sc int64 = 3
				*dest[6].(*int64) = sc
				*dest[7].(*string) = string(identity.PasskeyCredentialStatusActive)
				*dest[8].(*time.Time) = now
				return nil
			},
		},
		err: boom,
	}}
	r := pg.NewPasskeyCredentialRepositoryWithListQuerier(q)
	_, err := r.ListByGcid(context.Background(), "01970000-0000-7000-8000-aaaaaaaaaaaa")
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want rows.Err boom", err)
	}
}

func TestPasskeyCredentialRepo_ListByGcid_NilPoolViaConstructorFailsLoud(t *testing.T) {
	t.Parallel()
	// The production constructor wires poolListQuerier around the *PgxPoolQuerier;
	// a wrapper carrying a nil pool must fail loud on the list path (no way to
	// reach a real *pgxpool.Pool offline).
	r := pg.NewPasskeyCredentialRepository(&pg.PgxPoolQuerier{})
	_, err := r.ListByGcid(context.Background(), "01970000-0000-7000-8000-aaaaaaaaaaaa")
	if err == nil {
		t.Fatal("nil pool must fail loud on ListByGcid")
	}
}

func TestPasskeyCredentialRepo_Save_FullyPopulatedNullableBranches(t *testing.T) {
	t.Parallel()
	// A credential with EVERY nullable field set exercises the non-nil arms of
	// nullableBytes / nullableStr / nullableTime (the empty/nil arms are already
	// covered by the minimal Save test).
	now := time.Now().UTC()
	c, err := identity.NewPasskeyCredential(identity.NewPasskeyCredentialParams{
		Gcid:                     "01970000-0000-7000-8000-aaaaaaaaaaaa",
		CredentialID:             []byte{0x01, 0x02, 0x03, 0x04},
		PublicKeyCOSE:            []byte("cose-key-bytes"),
		AttestationType:          "packed",
		RPID:                     "chora.site",
		InitialSignCount:         9,
		AAGUID:                   []byte("aaguid-bytes"),
		AttestationVerified:      true,
		AuthenticatorDescription: "YubiKey 5C",
		MDSCertificationLevel:    "L3",
		AttestationObject:        []byte("attestation-object"),
	})
	if err != nil {
		t.Fatalf("NewPasskeyCredential: %v", err)
	}
	c.LastUsedAt = &now

	q := &stubQuerier{}
	if err := pg.NewPasskeyCredentialRepositoryWithQuerier(q).Save(context.Background(), c); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if len(q.execCalls) != 1 {
		t.Fatalf("exec calls = %d, want 1", len(q.execCalls))
	}
	args := q.execCalls[0].args
	// $12 aaguid, $14 authenticator_description, $15 mds_certification_level,
	// $16 attestation_object must be the raw values (non-nil arms).
	if string(args[11].([]byte)) != "aaguid-bytes" {
		t.Errorf("aaguid arg = %v", args[11])
	}
	if args[13] != "YubiKey 5C" || args[14] != "L3" {
		t.Errorf("description/cert args = %v / %v", args[13], args[14])
	}
	if string(args[15].([]byte)) != "attestation-object" {
		t.Errorf("attestation_object arg = %v", args[15])
	}
	// $11 last_used_at must be the time value (non-nil arm of nullableTime).
	ll, ok := args[10].(time.Time)
	if !ok || !ll.Equal(now) {
		t.Errorf("last_used_at arg = %v (%T), want the time value", args[10], args[10])
	}
}
