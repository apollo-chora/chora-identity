// inmem_prefill_durability_test.go covers the fail-loud behaviour added
// 2026-09-02: with a database configured, an in-memory MyInfo prefill store is
// discarding real PII, so it must say so at the point of loss rather than
// return a silent nil.
package repo

import (
	"context"
	"errors"
	"testing"

	"github.com/apollo-chora/chora-identity/internal/domain/kyc"
)

func prefill(gcid string) *kyc.MyInfoPrefill {
	return &kyc.MyInfoPrefill{
		PrefillID: "pf-1",
		Gcid:      gcid,
		FullName:  "Test Subject",
		UINFINRaw: "S1234567D",
		Source:    "singpass_myinfo",
	}
}

// No database configured is the dev shape: the store is the intended adapter,
// so Save must behave exactly as before.
func TestSaveIsUnchangedWithoutDatabase(t *testing.T) {
	t.Setenv("CHORA_DB_DSN", "")
	t.Setenv("CHORA_DURABILITY_GUARD", "")
	r := NewInMemPrefillRepo()
	if err := r.Save(context.Background(), prefill("gcid-1")); err != nil {
		t.Fatalf("Save without a database must succeed: %v", err)
	}
	if !r.HasPrefill("gcid-1") {
		t.Fatal("record must be stored")
	}
}

// Report mode is the current production shape. It must still store, because
// refusing here would break the live Singpass KYC path for a gap no adapter yet
// exists to fix, but it must no longer be silent.
func TestSaveStillStoresInReportMode(t *testing.T) {
	t.Setenv("CHORA_DB_DSN", "postgres://example/db")
	t.Setenv("CHORA_DURABILITY_GUARD", "")
	r := NewInMemPrefillRepo()
	if err := r.Save(context.Background(), prefill("gcid-2")); err != nil {
		t.Fatalf("report mode must not fail the write: %v", err)
	}
	if !r.HasPrefill("gcid-2") {
		t.Fatal("report mode must still store the record")
	}
	if !r.warned {
		t.Fatal("report mode must have emitted the one-time loud warning")
	}
}

// Enforce mode is what an operator turns on once durability is required. It
// must refuse the write and must NOT store, so a caller cannot mistake a
// volatile write for a durable one.
func TestSaveRefusesInEnforceMode(t *testing.T) {
	t.Setenv("CHORA_DB_DSN", "postgres://example/db")
	t.Setenv("CHORA_DURABILITY_GUARD", "enforce")
	r := NewInMemPrefillRepo()
	err := r.Save(context.Background(), prefill("gcid-3"))
	if !errors.Is(err, ErrPrefillNotDurable) {
		t.Fatalf("enforce mode must return ErrPrefillNotDurable, got %v", err)
	}
	if r.HasPrefill("gcid-3") {
		t.Fatal("enforce mode must not store the record it refused")
	}
}

// The construction-time read is what decides the behaviour, so a repo built
// without a database keeps working even if the env changes afterwards. This
// pins that, so nobody later assumes Save re-reads the environment per call.
func TestDatabasePresenceIsReadAtConstruction(t *testing.T) {
	t.Setenv("CHORA_DB_DSN", "")
	r := NewInMemPrefillRepo()
	t.Setenv("CHORA_DB_DSN", "postgres://example/db")
	t.Setenv("CHORA_DURABILITY_GUARD", "enforce")
	if err := r.Save(context.Background(), prefill("gcid-4")); err != nil {
		t.Fatalf("a repo constructed without a database must keep its behaviour: %v", err)
	}
}
