// CHO-1883 Phase 1 — keyset (cursor) pagination for the mana ledger.
// Cursor = base64url(recorded_at RFC3339Nano "|" entry_id); next page selects
// rows strictly older than that (recorded_at, entry_id) tuple. Order is
// recorded_at DESC, entry_id DESC (stable total order across ties).
package user_mana

import (
	"context"
	"testing"
	"time"
)

func seedEntry(id, gcid string, at time.Time) *LedgerEntry {
	return &LedgerEntry{
		EntryID:           id,
		Gcid:              gcid,
		Direction:         DirectionDebit,
		Units:             10,
		Reason:            ReasonFamiliarAction,
		BalanceAfterUnits: 1000,
		RecordedAt:        at,
	}
}

func TestLedgerCursor_RoundTrip(t *testing.T) {
	e := seedEntry(
		"019f0000-0000-7000-8000-000000000abc",
		"g1",
		time.Date(2026, 6, 26, 6, 27, 21, 123456789, time.UTC),
	)
	cur := EncodeLedgerCursor(e)
	if cur == "" {
		t.Fatal("EncodeLedgerCursor returned empty for a non-nil entry")
	}
	ct, cid, err := DecodeLedgerCursor(cur)
	if err != nil {
		t.Fatalf("DecodeLedgerCursor: %v", err)
	}
	if !ct.Equal(e.RecordedAt) {
		t.Errorf("recorded_at = %v; want %v", ct, e.RecordedAt)
	}
	if cid != e.EntryID {
		t.Errorf("entry_id = %q; want %q", cid, e.EntryID)
	}
}

func TestLedgerCursor_EmptyAndMalformed(t *testing.T) {
	if EncodeLedgerCursor(nil) != "" {
		t.Error("nil entry must encode to empty string")
	}
	if ct, cid, err := DecodeLedgerCursor(""); err != nil || cid != "" || !ct.IsZero() {
		t.Errorf("empty cursor must decode to (zero, \"\", nil); got (%v, %q, %v)", ct, cid, err)
	}
	for _, bad := range []string{"!!!not-base64!!!", "bm9waXBl" /* base64("nopipe") */} {
		if _, _, err := DecodeLedgerCursor(bad); err == nil {
			t.Errorf("DecodeLedgerCursor(%q) = nil err; want ErrInvalidFilter", bad)
		}
	}
}

func TestInMemoryStore_ListLedger_KeysetPagination(t *testing.T) {
	store := NewInMemoryStore()
	gcid := "01970000-0000-7000-8000-00000000ec01"
	base := time.Date(2026, 6, 26, 0, 0, 0, 0, time.UTC)
	// 5 entries, ascending recorded_at + ascending entry_id.
	ids := []string{
		"019f0000-0000-7000-8000-00000000000a",
		"019f0000-0000-7000-8000-00000000000b",
		"019f0000-0000-7000-8000-00000000000c",
		"019f0000-0000-7000-8000-00000000000d",
		"019f0000-0000-7000-8000-00000000000e",
	}
	for i, id := range ids {
		if err := store.AppendLedger(context.Background(), seedEntry(id, gcid, base.Add(time.Duration(i)*time.Minute))); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}

	// Page 1 — newest two (e, d).
	p1, err := store.ListLedger(context.Background(), LedgerFilter{Gcid: gcid, PageSize: 2})
	if err != nil {
		t.Fatalf("page1: %v", err)
	}
	if len(p1) != 2 {
		t.Fatalf("page1 len=%d; want 2", len(p1))
	}
	if !p1[0].RecordedAt.After(p1[1].RecordedAt) {
		t.Error("page1 not newest-first (recorded_at DESC)")
	}
	if p1[0].EntryID != ids[4] || p1[1].EntryID != ids[3] {
		t.Errorf("page1 ids = %s,%s; want e,d", p1[0].EntryID, p1[1].EntryID)
	}

	// Page 2 — via cursor of the last row of page 1 (c, b).
	p2, err := store.ListLedger(context.Background(), LedgerFilter{Gcid: gcid, PageSize: 2, Cursor: EncodeLedgerCursor(p1[1])})
	if err != nil {
		t.Fatalf("page2: %v", err)
	}
	if len(p2) != 2 {
		t.Fatalf("page2 len=%d; want 2", len(p2))
	}
	if !p1[1].RecordedAt.After(p2[0].RecordedAt) {
		t.Error("page2 overlaps page1 (cursor keyset not applied)")
	}
	if p2[0].EntryID != ids[2] || p2[1].EntryID != ids[1] {
		t.Errorf("page2 ids = %s,%s; want c,b", p2[0].EntryID, p2[1].EntryID)
	}

	// Page 3 — only one row left (a).
	p3, err := store.ListLedger(context.Background(), LedgerFilter{Gcid: gcid, PageSize: 2, Cursor: EncodeLedgerCursor(p2[1])})
	if err != nil {
		t.Fatalf("page3: %v", err)
	}
	if len(p3) != 1 || p3[0].EntryID != ids[0] {
		t.Fatalf("page3 = %v; want exactly [a]", p3)
	}
}
