// ui_preferences_extra_test.go — pushes ui_preferences_repository.go toward
// 100%: the *PgxPoolQuerier constructor, the decode error branches (bad JSON,
// bad RFC3339 updated_at, nil/empty column), the home_layout path and the
// Upsert* non-ErrNoRows errors.
package pg_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/apollo-chora/chora-identity/internal/adapter/pg"
	"github.com/apollo-chora/chora-identity/internal/domain/identity"
)

func TestUIPreferencesRepository_New(t *testing.T) {
	t.Parallel()
	r := pg.NewUIPreferencesRepository(nil)
	if r == nil {
		t.Fatal("NewUIPreferencesRepository(nil) must return a non-nil repo")
	}
}

func TestUIPreferencesRepository_GetUIPreferences_NilColumn_NoError(t *testing.T) {
	t.Parallel()
	q := &stubQuerier{rowResponses: []func(dest ...any) error{
		func(dest ...any) error {
			*(dest[0].(*[]byte)) = nil // ui_preferences NULL → zero-value prefs
			return nil
		},
	}}
	prefs, err := pg.NewUIPreferencesRepositoryWithQuerier(q).GetUIPreferences(context.Background(), prefsGCID)
	if err != nil {
		t.Fatalf("GetUIPreferences: %v", err)
	}
	if prefs == nil || prefs.DashboardLayout != nil || prefs.HomeLayout != nil {
		t.Fatalf("NULL ui_preferences must yield zero-value prefs, got %+v", prefs)
	}
}

func TestUIPreferencesRepository_GetUIPreferences_ScanErrorWraps(t *testing.T) {
	t.Parallel()
	boom := errors.New("prefs scan boom")
	q := &stubQuerier{rowResponses: []func(dest ...any) error{
		func(...any) error { return boom },
	}}
	_, err := pg.NewUIPreferencesRepositoryWithQuerier(q).GetUIPreferences(context.Background(), prefsGCID)
	if err == nil || errors.Is(err, identity.ErrUserNotFound) || !errors.Is(err, boom) {
		t.Fatalf("err = %v, want wrapped boom (NOT ErrUserNotFound)", err)
	}
}

func TestUIPreferencesRepository_GetUIPreferences_BadJSON_Errors(t *testing.T) {
	t.Parallel()
	q := &stubQuerier{rowResponses: []func(dest ...any) error{
		func(dest ...any) error {
			*(dest[0].(*[]byte)) = []byte(`{not json`)
			return nil
		},
	}}
	_, err := pg.NewUIPreferencesRepositoryWithQuerier(q).GetUIPreferences(context.Background(), prefsGCID)
	if err == nil || !strings.Contains(err.Error(), "decode ui_preferences") {
		t.Fatalf("err = %v, want decode error", err)
	}
}

func TestUIPreferencesRepository_GetUIPreferences_BadDashboardUpdatedAt_Errors(t *testing.T) {
	t.Parallel()
	q := &stubQuerier{rowResponses: []func(dest ...any) error{
		func(dest ...any) error {
			*(dest[0].(*[]byte)) = []byte(`{"dashboard_layout":{"order":["map"],"updated_at":"not-a-time"}}`)
			return nil
		},
	}}
	_, err := pg.NewUIPreferencesRepositoryWithQuerier(q).GetUIPreferences(context.Background(), prefsGCID)
	if err == nil || !strings.Contains(err.Error(), "dashboard_layout.updated_at") {
		t.Fatalf("err = %v, want updated_at parse error", err)
	}
}

func TestUIPreferencesRepository_GetUIPreferences_HomeLayoutPath(t *testing.T) {
	t.Parallel()
	q := &stubQuerier{rowResponses: []func(dest ...any) error{
		func(dest ...any) error {
			*(dest[0].(*[]byte)) = []byte(`{
				"dashboard_layout":{"order":["map","cast"],"updated_at":"2026-07-06T12:00:00Z"},
				"home_layout":{"pins":[{"id":"course-1","x":1,"y":2}],"updated_at":"2026-07-07T08:00:00Z"}
			}`)
			return nil
		},
	}}
	prefs, err := pg.NewUIPreferencesRepositoryWithQuerier(q).GetUIPreferences(context.Background(), prefsGCID)
	if err != nil {
		t.Fatalf("GetUIPreferences: %v", err)
	}
	if prefs.DashboardLayout == nil || len(prefs.DashboardLayout.Order) != 2 {
		t.Fatalf("dashboard layout: %+v", prefs.DashboardLayout)
	}
	if prefs.HomeLayout == nil || len(prefs.HomeLayout.Pins) != 1 {
		t.Fatalf("home layout: %+v", prefs.HomeLayout)
	}
	pin := prefs.HomeLayout.Pins[0]
	if pin.ID != "course-1" || !strings.Contains(string(pin.Raw), `"x":1`) {
		t.Fatalf("pin round-trip: id=%q raw=%s", pin.ID, pin.Raw)
	}
	if !prefs.HomeLayout.UpdatedAt.Equal(time.Date(2026, 7, 7, 8, 0, 0, 0, time.UTC)) {
		t.Errorf("home updated_at = %v", prefs.HomeLayout.UpdatedAt)
	}
}

func TestUIPreferencesRepository_GetUIPreferences_BadHomeUpdatedAt_Errors(t *testing.T) {
	t.Parallel()
	q := &stubQuerier{rowResponses: []func(dest ...any) error{
		func(dest ...any) error {
			*(dest[0].(*[]byte)) = []byte(`{"home_layout":{"pins":[],"updated_at":"nope"}}`)
			return nil
		},
	}}
	_, err := pg.NewUIPreferencesRepositoryWithQuerier(q).GetUIPreferences(context.Background(), prefsGCID)
	if err == nil || !strings.Contains(err.Error(), "home_layout.updated_at") {
		t.Fatalf("err = %v, want home updated_at parse error", err)
	}
}

func TestUIPreferencesRepository_UpsertDashboardLayout_ScanErrorWraps(t *testing.T) {
	t.Parallel()
	boom := errors.New("upsert scan boom")
	q := &stubQuerier{rowResponses: []func(dest ...any) error{
		func(...any) error { return boom },
	}}
	err := pg.NewUIPreferencesRepositoryWithQuerier(q).UpsertDashboardLayout(context.Background(), prefsGCID,
		identity.DashboardLayout{Order: []identity.DashboardWrapperKey{identity.DashboardWrapperMap}, UpdatedAt: time.Now().UTC()})
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want wrapped boom", err)
	}
}

func TestUIPreferencesRepository_UpsertHomeLayout_AllPaths(t *testing.T) {
	t.Parallel()
	layout := identity.HomeLayout{
		Pins:      []identity.HomePin{{ID: "course-1", Raw: []byte(`{"id":"course-1","x":1}`)}},
		UpdatedAt: time.Date(2026, 7, 7, 8, 0, 0, 0, time.UTC),
	}

	// happy: RETURNING 1 → success.
	q := &stubQuerier{rowResponses: []func(dest ...any) error{
		func(dest ...any) error { *(dest[0].(*int)) = 1; return nil },
	}}
	r := pg.NewUIPreferencesRepositoryWithQuerier(q)
	if err := r.UpsertHomeLayout(context.Background(), prefsGCID, layout); err != nil {
		t.Fatalf("UpsertHomeLayout happy: %v", err)
	}
	frag, ok := q.rowCalls[0].args[1].(string)
	if !ok || !strings.Contains(frag, `{"pins`) {
		t.Fatalf("home fragment: %v (%T)", q.rowCalls[0].args[1], q.rowCalls[0].args[1])
	}

	// unknown gcid → ErrUserNotFound.
	q2 := &stubQuerier{rowResponses: []func(dest ...any) error{
		func(...any) error { return pg.ErrNoRows },
	}}
	if err := pg.NewUIPreferencesRepositoryWithQuerier(q2).UpsertHomeLayout(context.Background(), prefsGCID, layout); !errors.Is(err, identity.ErrUserNotFound) {
		t.Fatalf("err = %v, want ErrUserNotFound", err)
	}

	// empty gcid → rejected before SQL.
	if err := pg.NewUIPreferencesRepositoryWithQuerier(&stubQuerier{}).UpsertHomeLayout(context.Background(), "  ", layout); err == nil {
		t.Fatal("empty gcid must be rejected")
	}

	// generic scan error → wrapped.
	boom := errors.New("home upsert boom")
	q3 := &stubQuerier{rowResponses: []func(dest ...any) error{
		func(...any) error { return boom },
	}}
	if err := pg.NewUIPreferencesRepositoryWithQuerier(q3).UpsertHomeLayout(context.Background(), prefsGCID, layout); !errors.Is(err, boom) {
		t.Fatalf("err = %v, want wrapped boom", err)
	}
}

func TestUIPreferencesRepository_EncodeHomeLayout_InvalidPinRaw_Errors(t *testing.T) {
	t.Parallel()
	// A pin whose Raw bytes are malformed JSON must fail the encode (the write
	// path validates; this is the belt-and-braces branch of json.Marshal).
	q := &stubQuerier{}
	layout := identity.HomeLayout{
		Pins:      []identity.HomePin{{ID: "broken", Raw: []byte(`{`)}},
		UpdatedAt: time.Now().UTC(),
	}
	err := pg.NewUIPreferencesRepositoryWithQuerier(q).UpsertHomeLayout(context.Background(), prefsGCID, layout)
	if err == nil || !strings.Contains(err.Error(), "encode home_layout") {
		t.Fatalf("err = %v, want encode error", err)
	}
	if len(q.rowCalls) != 0 {
		t.Fatalf("encode failure must not QueryRow; got %d", len(q.rowCalls))
	}
}
