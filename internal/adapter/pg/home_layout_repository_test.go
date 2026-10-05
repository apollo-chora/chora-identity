// home_layout_repository_test.go - RED-phase specs for the pgx-backed
// home_layout persistence (ADR-240 Track B). Reuses the pg_test stubQuerier +
// collapseWS + prefsGCID from ui_preferences_repository_test.go. Asserts the
// targeted jsonb_set of the home_layout key (other ui_preferences keys
// preserved), verbatim position-field round-trip, and the empty-home (D7) shape.
package pg_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/apollo-chora/chora-identity/internal/adapter/pg"
	"github.com/apollo-chora/chora-identity/internal/domain/identity"
)

func TestUIPreferencesRepository_UpsertHomeLayout_JsonbSetHomeLayoutScopedByGcid(t *testing.T) {
	t.Parallel()
	q := &stubQuerier{
		rowResponses: []func(dest ...any) error{
			func(dest ...any) error { *(dest[0].(*int)) = 1; return nil }, // RETURNING 1
		},
	}
	r := pg.NewUIPreferencesRepositoryWithQuerier(q)

	layout := identity.HomeLayout{
		Pins: []identity.HomePin{
			{ID: "a-plus-dashboard", Raw: []byte(`{"id":"a-plus-dashboard","x":0,"y":0}`)},
			{ID: "wallet", Raw: []byte(`{"id":"wallet","x":1,"y":0}`)},
		},
		UpdatedAt: time.Date(2026, 7, 18, 12, 0, 0, 0, time.UTC),
	}
	if err := r.UpsertHomeLayout(context.Background(), prefsGCID, layout); err != nil {
		t.Fatalf("UpsertHomeLayout: %v", err)
	}
	if len(q.rowCalls) != 1 {
		t.Fatalf("want 1 QueryRow (UPDATE ... RETURNING) call, got %d", len(q.rowCalls))
	}
	got := q.rowCalls[0]
	up := collapseWS(strings.ToUpper(got.sql))
	if !strings.HasPrefix(up, "UPDATE USERS") {
		t.Errorf("must be an UPDATE users; got %q", got.sql)
	}
	if !strings.Contains(got.sql, "jsonb_set") || !strings.Contains(got.sql, "home_layout") {
		t.Errorf("must jsonb_set the home_layout key (preserve other prefs); got %q", got.sql)
	}
	if strings.Contains(got.sql, "dashboard_layout") {
		t.Errorf("home-layout upsert must NOT touch the dashboard_layout key; got %q", got.sql)
	}
	if !strings.Contains(got.sql, "deleted_at IS NULL") {
		t.Errorf("must not write soft-deleted rows; got %q", got.sql)
	}
	if got.args[0] != prefsGCID {
		t.Errorf("gcid arg = %v; want %q (scoped by caller)", got.args[0], prefsGCID)
	}
	frag, ok := got.args[1].(string)
	if !ok {
		t.Fatalf("second arg type = %T; want the home_layout JSON string", got.args[1])
	}
	var wire struct {
		Pins      []json.RawMessage `json:"pins"`
		UpdatedAt string            `json:"updated_at"`
	}
	if err := json.Unmarshal([]byte(frag), &wire); err != nil {
		t.Fatalf("home_layout arg is not valid JSON: %v (%q)", err, frag)
	}
	if len(wire.Pins) != 2 {
		t.Fatalf("persisted pins len = %d; want 2", len(wire.Pins))
	}
	// Position fields (D10) preserved verbatim - the backend never drops them.
	if !strings.Contains(string(wire.Pins[0]), `"x":0`) || !strings.Contains(string(wire.Pins[1]), `"x":1`) {
		t.Errorf("persisted pins must preserve position fields verbatim; got %s", frag)
	}
	if wire.UpdatedAt != "2026-07-18T12:00:00Z" {
		t.Errorf("persisted updated_at = %q; want RFC3339 2026-07-18T12:00:00Z", wire.UpdatedAt)
	}
}

func TestUIPreferencesRepository_UpsertHomeLayout_EmptyPins_D7(t *testing.T) {
	t.Parallel()
	q := &stubQuerier{
		rowResponses: []func(dest ...any) error{
			func(dest ...any) error { *(dest[0].(*int)) = 1; return nil },
		},
	}
	r := pg.NewUIPreferencesRepositoryWithQuerier(q)
	// ADR-240 D7: an empty home is a legitimate persisted state - pins must
	// serialise as [] (never null, which would decode ambiguously).
	if err := r.UpsertHomeLayout(context.Background(), prefsGCID, identity.HomeLayout{
		Pins: nil, UpdatedAt: time.Date(2026, 7, 18, 12, 0, 0, 0, time.UTC),
	}); err != nil {
		t.Fatalf("UpsertHomeLayout(empty): %v", err)
	}
	frag := q.rowCalls[0].args[1].(string)
	if !strings.Contains(collapseWS(frag), `"pins":[]`) {
		t.Errorf("empty home must persist pins:[] (not null); got %q", frag)
	}
}

func TestUIPreferencesRepository_UpsertHomeLayout_UnknownGcid_ErrUserNotFound(t *testing.T) {
	t.Parallel()
	q := &stubQuerier{
		rowResponses: []func(dest ...any) error{
			func(dest ...any) error { return pg.ErrNoRows },
		},
	}
	r := pg.NewUIPreferencesRepositoryWithQuerier(q)
	err := r.UpsertHomeLayout(context.Background(), prefsGCID, identity.HomeLayout{UpdatedAt: time.Now().UTC()})
	if !errors.Is(err, identity.ErrUserNotFound) {
		t.Errorf("err = %v; want identity.ErrUserNotFound when no live user carries the gcid", err)
	}
}

func TestUIPreferencesRepository_UpsertHomeLayout_EmptyGcid_Rejected(t *testing.T) {
	t.Parallel()
	r := pg.NewUIPreferencesRepositoryWithQuerier(&stubQuerier{})
	if err := r.UpsertHomeLayout(context.Background(), "  ", identity.HomeLayout{UpdatedAt: time.Now()}); err == nil {
		t.Error("empty gcid must be rejected before touching the DB")
	}
}

func TestUIPreferencesRepository_GetUIPreferences_DecodesHomeLayout(t *testing.T) {
	t.Parallel()
	q := &stubQuerier{
		rowResponses: []func(dest ...any) error{
			func(dest ...any) error {
				*(dest[0].(*[]byte)) = []byte(`{"home_layout":{"pins":[{"id":"wallet","x":2,"y":1}],"updated_at":"2026-07-18T12:00:00Z"}}`)
				return nil
			},
		},
	}
	r := pg.NewUIPreferencesRepositoryWithQuerier(q)
	prefs, err := r.GetUIPreferences(context.Background(), prefsGCID)
	if err != nil {
		t.Fatalf("GetUIPreferences: %v", err)
	}
	if prefs.HomeLayout == nil {
		t.Fatal("HomeLayout = nil; want the decoded layout")
	}
	if len(prefs.HomeLayout.Pins) != 1 || prefs.HomeLayout.Pins[0].ID != "wallet" {
		t.Fatalf("decoded pins = %+v; want one pin id=wallet", prefs.HomeLayout.Pins)
	}
	if !strings.Contains(string(prefs.HomeLayout.Pins[0].Raw), `"x":2`) {
		t.Errorf("decoded pin must preserve position fields verbatim; got %s", prefs.HomeLayout.Pins[0].Raw)
	}
	if !prefs.HomeLayout.UpdatedAt.Equal(time.Date(2026, 7, 18, 12, 0, 0, 0, time.UTC)) {
		t.Errorf("UpdatedAt = %v; want 2026-07-18T12:00:00Z", prefs.HomeLayout.UpdatedAt)
	}
}

func TestUIPreferencesRepository_GetUIPreferences_DecodesBothLayouts(t *testing.T) {
	t.Parallel()
	// Both keys coexist in the JSONB column; decoding one must not drop the other.
	q := &stubQuerier{
		rowResponses: []func(dest ...any) error{
			func(dest ...any) error {
				*(dest[0].(*[]byte)) = []byte(`{"dashboard_layout":{"order":["map"],"updated_at":"2026-07-06T12:00:00Z"},"home_layout":{"pins":[{"id":"wallet"}],"updated_at":"2026-07-18T12:00:00Z"}}`)
				return nil
			},
		},
	}
	r := pg.NewUIPreferencesRepositoryWithQuerier(q)
	prefs, err := r.GetUIPreferences(context.Background(), prefsGCID)
	if err != nil {
		t.Fatalf("GetUIPreferences: %v", err)
	}
	if prefs.DashboardLayout == nil || prefs.HomeLayout == nil {
		t.Fatalf("both layouts must decode; got dashboard=%v home=%v", prefs.DashboardLayout, prefs.HomeLayout)
	}
}

func TestUIPreferencesRepository_GetUIPreferences_EmptyStore_NilHomeLayout(t *testing.T) {
	t.Parallel()
	q := &stubQuerier{
		rowResponses: []func(dest ...any) error{
			func(dest ...any) error { *(dest[0].(*[]byte)) = []byte(`{}`); return nil },
		},
	}
	r := pg.NewUIPreferencesRepositoryWithQuerier(q)
	prefs, err := r.GetUIPreferences(context.Background(), prefsGCID)
	if err != nil {
		t.Fatalf("GetUIPreferences: %v", err)
	}
	if prefs.HomeLayout != nil {
		t.Errorf("empty ui_preferences must yield nil HomeLayout, got %+v", prefs.HomeLayout)
	}
}

func TestUIPreferencesRepository_GetUIPreferences_EmptyGcid_Rejected(t *testing.T) {
	t.Parallel()
	r := pg.NewUIPreferencesRepositoryWithQuerier(&stubQuerier{})
	if _, err := r.GetUIPreferences(context.Background(), "  "); err == nil {
		t.Error("empty gcid GET must be rejected before touching the DB")
	}
}

func TestUIPreferencesRepository_GetUIPreferences_MalformedColumn_Errors(t *testing.T) {
	t.Parallel()
	q := &stubQuerier{
		rowResponses: []func(dest ...any) error{
			func(dest ...any) error { *(dest[0].(*[]byte)) = []byte(`{not json`); return nil },
		},
	}
	r := pg.NewUIPreferencesRepositoryWithQuerier(q)
	if _, err := r.GetUIPreferences(context.Background(), prefsGCID); err == nil {
		t.Error("a malformed ui_preferences column must surface an error (fail-loud), not a silent nil")
	}
}

func TestUIPreferencesRepository_GetUIPreferences_HomeLayoutBadUpdatedAt_Errors(t *testing.T) {
	t.Parallel()
	q := &stubQuerier{
		rowResponses: []func(dest ...any) error{
			func(dest ...any) error {
				*(dest[0].(*[]byte)) = []byte(`{"home_layout":{"pins":[],"updated_at":"garbage"}}`)
				return nil
			},
		},
	}
	r := pg.NewUIPreferencesRepositoryWithQuerier(q)
	if _, err := r.GetUIPreferences(context.Background(), prefsGCID); err == nil {
		t.Error("an unparseable home_layout.updated_at must surface an error (fail-loud)")
	}
}

func TestUIPreferencesRepository_GetUIPreferences_ScanError_Wrapped(t *testing.T) {
	t.Parallel()
	q := &stubQuerier{
		rowResponses: []func(dest ...any) error{
			func(dest ...any) error { return errors.New("connection reset") },
		},
	}
	r := pg.NewUIPreferencesRepositoryWithQuerier(q)
	_, err := r.GetUIPreferences(context.Background(), prefsGCID)
	if err == nil || errors.Is(err, identity.ErrUserNotFound) {
		t.Errorf("a non-ErrNoRows scan error must surface (not ErrUserNotFound); got %v", err)
	}
}
