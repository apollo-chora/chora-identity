// configure_attestation_test.go — ADR-187 attestation wiring at the
// composition root: the off-path (default), the enabled-but-cold path
// (missing FIDO MDS config), and the enabled+fully-configured path (starts
// the background MDS refresh). Behavior assertions are structural (the
// PasskeyHandler keeps its attestation state private); the point is to
// exercise every branch of the env-driven selector.
package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/apollo-chora/chora-identity/internal/adapter/events"
	httpadapter "github.com/apollo-chora/chora-identity/internal/adapter/http"
)

func TestConfigureAttestation_ModeOffIsNoop(t *testing.T) {
	t.Setenv("CHORA_ATTESTATION_MODE", "off")
	h := &httpadapter.PasskeyHandler{}
	// Must return immediately without touching the handler or starting any
	// background refresh; a panic / nil-deref here would fail the test.
	configureAttestation(context.Background(), h)
}

func TestConfigureAttestation_UnsetModeIsNoop(t *testing.T) {
	t.Setenv("CHORA_ATTESTATION_MODE", "")
	h := &httpadapter.PasskeyHandler{}
	configureAttestation(context.Background(), h)
}

func TestConfigureAttestation_EnabledColdConfig(t *testing.T) {
	t.Setenv("CHORA_ATTESTATION_MODE", "record")
	t.Setenv("FIDO_MDS_BLOB_URL", "")
	t.Setenv("FIDO_MDS_ROOT_BUNDLE_PEM", "")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h := &httpadapter.PasskeyHandler{}
	// Enabled but no MDS URL / roots → trust store stays cold; must still
	// run without panicking and NOT start a background refresh goroutine.
	configureAttestation(ctx, h)
}

func TestConfigureAttestation_EnabledFullConfigStartsRefresh(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The MDS blob URL returns garbage — the initial refresh fails and
		// is reported to the error callback; the goroutine then waits for
		// the next tick until the context is cancelled.
		http.Error(w, "not a JWS blob", http.StatusNotFound)
	}))
	defer ts.Close()

	t.Setenv("CHORA_ATTESTATION_MODE", "record")
	t.Setenv("FIDO_MDS_BLOB_URL", ts.URL)
	t.Setenv("FIDO_MDS_ROOT_BUNDLE_PEM", selfSignedCertPEM(t))
	t.Setenv("FIDO_MDS_REFRESH_INTERVAL", "1h")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h := &httpadapter.PasskeyHandler{}
	configureAttestation(ctx, h)
	// Give the background refresh goroutine a moment to run its initial
	// fetch, then cancel so it shuts down cleanly.
	time.Sleep(50 * time.Millisecond)
	cancel()
}

// -----------------------------------------------------------------------------
// gcidResolvedShim — http.EmittedEvent → events.GCIDResolvedPublisher bridge
// -----------------------------------------------------------------------------

func TestGCIDResolvedShim_PublishesEnvelope(t *testing.T) {
	t.Parallel()
	rec := events.NewRecorder()
	shim := &gcidResolvedShim{inner: events.NewGCIDResolvedPublisher(rec)}

	err := shim.PublishGCIDResolved(context.Background(), httpadapter.EmittedEvent{
		GCID:             "01970000-0000-7000-8000-000000000001",
		TenantID:         "01970000-0000-7000-8000-00000000ee01",
		Email:            "learner@example.com",
		FirebaseUID:      "fed-sub-1",
		IdempotencyKey:   "idem-1",
		MembershipsCount: 2,
	})
	if err != nil {
		t.Fatalf("PublishGCIDResolved: %v", err)
	}
	got := rec.RecordedByTopic(events.TopicGCIDResolved)
	if len(got) != 1 {
		t.Fatalf("got %d gcid.resolved records, want 1", len(got))
	}
	if got[0].Envelope.GCID != "01970000-0000-7000-8000-000000000001" {
		t.Errorf("envelope gcid = %q, want the shimmed GCID", got[0].Envelope.GCID)
	}
	if got[0].Payload["memberships_count"] != 2 {
		t.Errorf("memberships_count = %v, want 2", got[0].Payload["memberships_count"])
	}
}
