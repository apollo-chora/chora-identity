package pg_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/apollo-chora/chora-identity/internal/adapter/pg"
	"github.com/apollo-chora/chora-identity/internal/domain/crypto"
)

const dekGcid = "01970000-0000-7000-8000-0000000d11aa"

func TestUserDEKWrap_Get_Absent_ReturnsNil(t *testing.T) {
	q := &stubQuerier{} // empty rowResponses → ErrNoRows
	r := pg.NewUserDEKWrapRepository(q)
	w, err := r.Get(context.Background(), dekGcid)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if w != nil {
		t.Fatalf("expected nil for absent gcid, got %+v", w)
	}
}

func TestUserDEKWrap_Get_MapsLiveRow(t *testing.T) {
	q := &stubQuerier{rowResponses: []func(dest ...any) error{
		func(dest ...any) error {
			*dest[0].(*[]byte) = []byte("wrapped-bytes")
			*dest[1].(*string) = "kv9"
			*dest[2].(*string) = ""
			*dest[3].(**time.Time) = nil // deleted_at NULL → alive
			return nil
		},
	}}
	r := pg.NewUserDEKWrapRepository(q)
	w, err := r.Get(context.Background(), dekGcid)
	if err != nil {
		t.Fatal(err)
	}
	if w == nil || string(w.Wrapped) != "wrapped-bytes" || w.KEKVersion != "kv9" || w.Deleted {
		t.Fatalf("bad mapping: %+v", w)
	}
}

func TestUserDEKWrap_Get_TombstonedRow(t *testing.T) {
	now := time.Now()
	q := &stubQuerier{rowResponses: []func(dest ...any) error{
		func(dest ...any) error {
			*dest[0].(*[]byte) = []byte{}
			*dest[1].(*string) = "kv9"
			*dest[2].(*string) = "shred-1"
			*dest[3].(**time.Time) = &now // deleted_at set → tombstoned
			return nil
		},
	}}
	r := pg.NewUserDEKWrapRepository(q)
	w, err := r.Get(context.Background(), dekGcid)
	if err != nil {
		t.Fatal(err)
	}
	if w == nil || !w.Deleted || w.KMSOperationID != "shred-1" {
		t.Fatalf("expected tombstoned row, got %+v", w)
	}
}

func TestUserDEKWrap_Put_InsertOnConflict(t *testing.T) {
	q := &stubQuerier{}
	r := pg.NewUserDEKWrapRepository(q)
	if err := r.Put(context.Background(), crypto.WrappedDEK{
		Gcid: dekGcid, Wrapped: []byte("w"), KEKVersion: "kv1",
	}); err != nil {
		t.Fatal(err)
	}
	if len(q.execCalls) != 1 {
		t.Fatalf("expected 1 Exec, got %d", len(q.execCalls))
	}
	c := q.execCalls[0]
	if !strings.Contains(c.sql, "INSERT INTO user_dek_wrap") || !strings.Contains(c.sql, "ON CONFLICT") {
		t.Fatalf("unexpected insert sql: %s", c.sql)
	}
	if c.args[0] != dekGcid || string(c.args[1].([]byte)) != "w" || c.args[2] != "kv1" {
		t.Fatalf("unexpected insert args: %#v", c.args)
	}
}

func TestUserDEKWrap_MarkDeleted_Tombstone(t *testing.T) {
	q := &stubQuerier{}
	r := pg.NewUserDEKWrapRepository(q)
	if err := r.MarkDeleted(context.Background(), dekGcid, "shred-z"); err != nil {
		t.Fatal(err)
	}
	if len(q.execCalls) != 1 {
		t.Fatalf("expected 1 Exec, got %d", len(q.execCalls))
	}
	c := q.execCalls[0]
	if !strings.Contains(c.sql, "UPDATE user_dek_wrap") || !strings.Contains(c.sql, "deleted_at") || !strings.Contains(c.sql, "wrapped_dek") {
		t.Fatalf("unexpected tombstone sql: %s", c.sql)
	}
	if c.args[0] != dekGcid || c.args[1] != "shred-z" {
		t.Fatalf("unexpected tombstone args: %#v", c.args)
	}
}
