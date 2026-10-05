// home_layout_repository_test.go - RED-phase specs for the in-memory
// home_layout store (ADR-240 Track B). Reuses the const g from
// ui_preferences_repository_test.go (same inmem_test package).
package inmem_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/apollo-chora/chora-identity/internal/adapter/inmem"
	"github.com/apollo-chora/chora-identity/internal/domain/identity"
)

func TestInmemUIPreferences_EmptyStore_NilHomeLayout(t *testing.T) {
	r := inmem.NewUIPreferencesRepository()
	got, err := r.GetUIPreferences(context.Background(), g)
	if err != nil {
		t.Fatalf("GetUIPreferences: %v", err)
	}
	if got.HomeLayout != nil {
		t.Errorf("unset store must yield nil HomeLayout, got %+v", got.HomeLayout)
	}
}

func TestInmemUIPreferences_UpsertHome_then_Get(t *testing.T) {
	r := inmem.NewUIPreferencesRepository()
	want := identity.HomeLayout{
		Pins:      []identity.HomePin{{ID: "wallet", Raw: []byte(`{"id":"wallet","x":1}`)}},
		UpdatedAt: time.Date(2026, 7, 18, 12, 0, 0, 0, time.UTC),
	}
	if err := r.UpsertHomeLayout(context.Background(), g, want); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	got, err := r.GetUIPreferences(context.Background(), g)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.HomeLayout == nil || len(got.HomeLayout.Pins) != 1 || got.HomeLayout.Pins[0].ID != "wallet" {
		t.Errorf("round-trip mismatch: %+v", got.HomeLayout)
	}
	// Stored pins must be defensively copied - mutating the input Raw must not
	// corrupt stored state.
	want.Pins[0].Raw[0] = 'X'
	reget, _ := r.GetUIPreferences(context.Background(), g)
	if reget.HomeLayout.Pins[0].Raw[0] != '{' {
		t.Error("stored pin Raw must be defensively copied from the input")
	}
}

func TestInmemUIPreferences_Home_and_Dashboard_Coexist(t *testing.T) {
	r := inmem.NewUIPreferencesRepository()
	if err := r.UpsertDashboardLayout(context.Background(), g, identity.DashboardLayout{
		Order: []identity.DashboardWrapperKey{identity.DashboardWrapperMap}, UpdatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("dashboard upsert: %v", err)
	}
	if err := r.UpsertHomeLayout(context.Background(), g, identity.HomeLayout{
		Pins: []identity.HomePin{{ID: "wallet", Raw: []byte(`{"id":"wallet"}`)}}, UpdatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("home upsert: %v", err)
	}
	got, _ := r.GetUIPreferences(context.Background(), g)
	if got.DashboardLayout == nil || got.HomeLayout == nil {
		t.Errorf("both layouts must survive; got dashboard=%v home=%v", got.DashboardLayout, got.HomeLayout)
	}
}

func TestInmemUIPreferences_UpsertHome_SeedKnownGcids_UnknownRejected(t *testing.T) {
	r := inmem.NewUIPreferencesRepository().SeedKnownGcids(g)
	err := r.UpsertHomeLayout(context.Background(), "01970000-0000-7000-8000-0000000000ff",
		identity.HomeLayout{Pins: []identity.HomePin{{ID: "x", Raw: []byte(`{"id":"x"}`)}}, UpdatedAt: time.Now()})
	if !errors.Is(err, identity.ErrUserNotFound) {
		t.Errorf("unseeded gcid must be ErrUserNotFound, got %v", err)
	}
}

func TestInmemUIPreferences_UpsertHome_EmptyGcid_Rejected(t *testing.T) {
	r := inmem.NewUIPreferencesRepository()
	if err := r.UpsertHomeLayout(context.Background(), "", identity.HomeLayout{}); err == nil {
		t.Error("empty gcid Upsert must error")
	}
}
