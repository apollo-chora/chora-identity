// user_dek_wrap_extra_test.go — error branches for user_dek_wrap_repository.go:
// Get scan error, Put / MarkDeleted exec errors (a stub Querier whose Exec fails).
package pg_test

import (
	"context"
	"errors"
	"testing"

	"github.com/apollo-chora/chora-identity/internal/adapter/pg"
	"github.com/apollo-chora/chora-identity/internal/domain/crypto"
)

// failingQuerier records Exec calls and returns execErr; QueryRow returns
// canned scans.
type failingQuerier struct {
	base    *stubQuerier
	execErr error
}

func (f *failingQuerier) Exec(ctx context.Context, sql string, args ...any) error {
	f.base.Exec(ctx, sql, args...)
	return f.execErr
}
func (f *failingQuerier) QueryRow(ctx context.Context, sql string, args ...any) pg.Row {
	return f.base.QueryRow(ctx, sql, args...)
}

func TestUserDEKWrap_Get_ScanErrorWraps(t *testing.T) {
	boom := errors.New("dek scan boom")
	q := &stubQuerier{rowResponses: []func(dest ...any) error{
		func(...any) error { return boom },
	}}
	r := pg.NewUserDEKWrapRepository(q)
	_, err := r.Get(context.Background(), dekGcid)
	if err == nil || !errors.Is(err, boom) {
		t.Fatalf("err = %v, want wrapped boom", err)
	}
}

func TestUserDEKWrap_Put_ExecErrorWraps(t *testing.T) {
	boom := errors.New("dek write boom")
	q := &failingQuerier{base: &stubQuerier{}, execErr: boom}
	r := pg.NewUserDEKWrapRepository(q)
	err := r.Put(context.Background(), crypto.WrappedDEK{Gcid: dekGcid, Wrapped: []byte("w"), KEKVersion: "kv1"})
	if err == nil || !errors.Is(err, boom) {
		t.Fatalf("err = %v, want wrapped boom", err)
	}
}

func TestUserDEKWrap_MarkDeleted_ExecErrorWraps(t *testing.T) {
	boom := errors.New("dek tombstone boom")
	q := &failingQuerier{base: &stubQuerier{}, execErr: boom}
	r := pg.NewUserDEKWrapRepository(q)
	err := r.MarkDeleted(context.Background(), dekGcid, "shred-1")
	if err == nil || !errors.Is(err, boom) {
		t.Fatalf("err = %v, want wrapped boom", err)
	}
}
