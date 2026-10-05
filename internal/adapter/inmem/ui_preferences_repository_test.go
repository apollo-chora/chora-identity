// ui_preferences_repository_test.go — direct specs for the in-memory
// UIPreferencesRepository (SP2.9 dev/test adapter).
package inmem_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/apollo-chora/chora-identity/internal/adapter/inmem"
	"github.com/apollo-chora/chora-identity/internal/domain/identity"
)

const g = "01970000-0000-7000-8000-0000000000aa"

func TestInmemUIPreferences_EmptyStore_NilLayout(t *testing.T) {
	r := inmem.NewUIPreferencesRepository()
	got, err := r.GetUIPreferences(context.Background(), g)
	if err != nil {
		t.Fatalf("GetUIPreferences: %v", err)
	}
	if got.DashboardLayout != nil {
		t.Errorf("unset store must yield nil DashboardLayout, got %+v", got.DashboardLayout)
	}
}

func TestInmemUIPreferences_Upsert_then_Get(t *testing.T) {
	r := inmem.NewUIPreferencesRepository()
	want := identity.DashboardLayout{
		Order:     []identity.DashboardWrapperKey{identity.DashboardWrapperCast, identity.DashboardWrapperMap},
		UpdatedAt: time.Date(2026, 7, 6, 12, 0, 0, 0, time.UTC),
	}
	if err := r.UpsertDashboardLayout(context.Background(), g, want); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	got, err := r.GetUIPreferences(context.Background(), g)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.DashboardLayout == nil || len(got.DashboardLayout.Order) != 2 ||
		got.DashboardLayout.Order[0] != identity.DashboardWrapperCast {
		t.Errorf("round-trip mismatch: %+v", got.DashboardLayout)
	}
	// Stored slice must be a copy — mutating the input must not corrupt state.
	want.Order[0] = identity.DashboardWrapperCourses
	reget, _ := r.GetUIPreferences(context.Background(), g)
	if reget.DashboardLayout.Order[0] != identity.DashboardWrapperCast {
		t.Error("stored order must be defensively copied from the input")
	}
}

func TestInmemUIPreferences_SeedKnownGcids_UnknownRejected(t *testing.T) {
	r := inmem.NewUIPreferencesRepository().SeedKnownGcids(g)
	err := r.UpsertDashboardLayout(context.Background(), "01970000-0000-7000-8000-0000000000ff",
		identity.DashboardLayout{Order: []identity.DashboardWrapperKey{identity.DashboardWrapperMap}, UpdatedAt: time.Now()})
	if !errors.Is(err, identity.ErrUserNotFound) {
		t.Errorf("unseeded gcid must be ErrUserNotFound, got %v", err)
	}
}

func TestInmemUIPreferences_EmptyGcid_Rejected(t *testing.T) {
	r := inmem.NewUIPreferencesRepository()
	if _, err := r.GetUIPreferences(context.Background(), " "); err == nil {
		t.Error("empty gcid GET must error")
	}
	if err := r.UpsertDashboardLayout(context.Background(), "", identity.DashboardLayout{}); err == nil {
		t.Error("empty gcid Upsert must error")
	}
}
