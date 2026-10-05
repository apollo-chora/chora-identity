// ui_preferences_repository_test.go — RED-phase specs for the pgx-backed
// UIPreferencesRepository (SP2.9). Unit tests against a stub Querier assert the
// SQL the adapter emits (targeted ui_preferences read/write on the users row,
// scoped by gcid) + the JSONB marshal/scan round-trip. Written BEFORE the impl.
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

const prefsGCID = "01970000-0000-7000-8000-0000000000aa"

// collapseWS normalises runs of whitespace to a single space so SQL-shape
// assertions are insensitive to the adapter's aligned formatting.
func collapseWS(s string) string { return strings.Join(strings.Fields(s), " ") }

func TestUIPreferencesRepository_GetUIPreferences_SelectsUiPreferencesScopedByGcid(t *testing.T) {
	t.Parallel()
	q := &stubQuerier{
		rowResponses: []func(dest ...any) error{
			func(dest ...any) error {
				// Single column: ui_preferences JSONB (as raw bytes).
				*(dest[0].(*[]byte)) = []byte(`{"dashboard_layout":{"order":["cast","map","courses"],"updated_at":"2026-07-06T12:00:00Z"}}`)
				return nil
			},
		},
	}
	r := pg.NewUIPreferencesRepositoryWithQuerier(q)

	prefs, err := r.GetUIPreferences(context.Background(), prefsGCID)
	if err != nil {
		t.Fatalf("GetUIPreferences: %v", err)
	}
	if len(q.rowCalls) != 1 {
		t.Fatalf("want 1 QueryRow call, got %d", len(q.rowCalls))
	}
	got := q.rowCalls[0]
	up := collapseWS(strings.ToUpper(got.sql))
	if !strings.Contains(got.sql, "ui_preferences") || !strings.Contains(up, "FROM USERS") {
		t.Errorf("SELECT must read ui_preferences FROM users; got %q", got.sql)
	}
	if !strings.Contains(got.sql, "deleted_at IS NULL") {
		t.Errorf("SELECT must filter soft-deleted rows; got %q", got.sql)
	}
	if got.args[0] != prefsGCID {
		t.Errorf("gcid arg = %v; want %q (scoped by caller, never body)", got.args[0], prefsGCID)
	}
	if prefs.DashboardLayout == nil {
		t.Fatal("DashboardLayout = nil; want the decoded layout")
	}
	wantOrder := []identity.DashboardWrapperKey{identity.DashboardWrapperCast, identity.DashboardWrapperMap, identity.DashboardWrapperCourses}
	if len(prefs.DashboardLayout.Order) != len(wantOrder) {
		t.Fatalf("order len = %d; want %d", len(prefs.DashboardLayout.Order), len(wantOrder))
	}
	for i, k := range wantOrder {
		if prefs.DashboardLayout.Order[i] != k {
			t.Errorf("order[%d] = %q; want %q", i, prefs.DashboardLayout.Order[i], k)
		}
	}
	if !prefs.DashboardLayout.UpdatedAt.Equal(time.Date(2026, 7, 6, 12, 0, 0, 0, time.UTC)) {
		t.Errorf("UpdatedAt = %v; want 2026-07-06T12:00:00Z", prefs.DashboardLayout.UpdatedAt)
	}
}

func TestUIPreferencesRepository_GetUIPreferences_EmptyStore_NilLayoutNoError(t *testing.T) {
	t.Parallel()
	q := &stubQuerier{
		rowResponses: []func(dest ...any) error{
			func(dest ...any) error {
				*(dest[0].(*[]byte)) = []byte(`{}`) // ui_preferences default '{}'::jsonb
				return nil
			},
		},
	}
	r := pg.NewUIPreferencesRepositoryWithQuerier(q)

	prefs, err := r.GetUIPreferences(context.Background(), prefsGCID)
	if err != nil {
		t.Fatalf("GetUIPreferences: %v", err)
	}
	if prefs == nil || prefs.DashboardLayout != nil {
		t.Errorf("empty ui_preferences must yield UIPreferences{DashboardLayout:nil}, got %+v", prefs)
	}
}

func TestUIPreferencesRepository_GetUIPreferences_UnknownGcid_ErrUserNotFound(t *testing.T) {
	t.Parallel()
	q := &stubQuerier{
		rowResponses: []func(dest ...any) error{
			func(dest ...any) error { return pg.ErrNoRows },
		},
	}
	r := pg.NewUIPreferencesRepositoryWithQuerier(q)

	_, err := r.GetUIPreferences(context.Background(), prefsGCID)
	if !errors.Is(err, identity.ErrUserNotFound) {
		t.Errorf("err = %v; want identity.ErrUserNotFound on missing row", err)
	}
}

func TestUIPreferencesRepository_UpsertDashboardLayout_JsonbSetScopedByGcid(t *testing.T) {
	t.Parallel()
	q := &stubQuerier{
		rowResponses: []func(dest ...any) error{
			func(dest ...any) error { *(dest[0].(*int)) = 1; return nil }, // RETURNING 1
		},
	}
	r := pg.NewUIPreferencesRepositoryWithQuerier(q)

	layout := identity.DashboardLayout{
		Order:     []identity.DashboardWrapperKey{identity.DashboardWrapperCast, identity.DashboardWrapperMap, identity.DashboardWrapperCourses},
		UpdatedAt: time.Date(2026, 7, 6, 12, 0, 0, 0, time.UTC),
	}
	if err := r.UpsertDashboardLayout(context.Background(), prefsGCID, layout); err != nil {
		t.Fatalf("UpsertDashboardLayout: %v", err)
	}
	if len(q.rowCalls) != 1 {
		t.Fatalf("want 1 QueryRow (UPDATE ... RETURNING) call, got %d", len(q.rowCalls))
	}
	got := q.rowCalls[0]
	up := collapseWS(strings.ToUpper(got.sql))
	if !strings.HasPrefix(up, "UPDATE USERS") {
		t.Errorf("must be an UPDATE users; got %q", got.sql)
	}
	if !strings.Contains(got.sql, "jsonb_set") || !strings.Contains(got.sql, "dashboard_layout") {
		t.Errorf("must jsonb_set the dashboard_layout key (preserve other prefs); got %q", got.sql)
	}
	if !strings.Contains(got.sql, "deleted_at IS NULL") {
		t.Errorf("must not write soft-deleted rows; got %q", got.sql)
	}
	if got.args[0] != prefsGCID {
		t.Errorf("gcid arg = %v; want %q (scoped by caller)", got.args[0], prefsGCID)
	}
	// Second arg = the dashboard_layout JSON fragment (snake_case wire).
	frag, ok := got.args[1].(string)
	if !ok {
		t.Fatalf("second arg type = %T; want the dashboard_layout JSON string", got.args[1])
	}
	var wire struct {
		Order     []string `json:"order"`
		UpdatedAt string   `json:"updated_at"`
	}
	if err := json.Unmarshal([]byte(frag), &wire); err != nil {
		t.Fatalf("dashboard_layout arg is not valid JSON: %v (%q)", err, frag)
	}
	if strings.Join(wire.Order, ",") != "cast,map,courses" {
		t.Errorf("persisted order = %v; want [cast map courses]", wire.Order)
	}
	if wire.UpdatedAt != "2026-07-06T12:00:00Z" {
		t.Errorf("persisted updated_at = %q; want RFC3339 2026-07-06T12:00:00Z", wire.UpdatedAt)
	}
}

func TestUIPreferencesRepository_UpsertDashboardLayout_UnknownGcid_ErrUserNotFound(t *testing.T) {
	t.Parallel()
	q := &stubQuerier{
		rowResponses: []func(dest ...any) error{
			func(dest ...any) error { return pg.ErrNoRows }, // no row updated
		},
	}
	r := pg.NewUIPreferencesRepositoryWithQuerier(q)

	err := r.UpsertDashboardLayout(context.Background(), prefsGCID, identity.DashboardLayout{
		Order:     []identity.DashboardWrapperKey{identity.DashboardWrapperMap},
		UpdatedAt: time.Now().UTC(),
	})
	if !errors.Is(err, identity.ErrUserNotFound) {
		t.Errorf("err = %v; want identity.ErrUserNotFound when no live user carries the gcid", err)
	}
}

func TestUIPreferencesRepository_UpsertDashboardLayout_EmptyGcid_Rejected(t *testing.T) {
	t.Parallel()
	r := pg.NewUIPreferencesRepositoryWithQuerier(&stubQuerier{})
	err := r.UpsertDashboardLayout(context.Background(), "  ", identity.DashboardLayout{
		Order: []identity.DashboardWrapperKey{identity.DashboardWrapperMap}, UpdatedAt: time.Now(),
	})
	if err == nil {
		t.Error("empty gcid must be rejected before touching the DB")
	}
}
