// otlp_test.go — OTLP wiring shim coverage.
//
// The shim delegates to libs/chora-go-common/otel (Init) and
// libs/chora-go-common/bootstrap (InitAsync). In dev mode — no
// OTEL_EXPORTER_OTLP_ENDPOINT and no detectable project label — the common
// lib routes spans to stdouttrace, so both paths are exercised offline
// without a Cloud Trace exporter. These tests also lock the propagator
// installation contract (W3C TraceContext + Baggage) that the HTTP
// middleware depends on.
package observability

import (
	"context"
	"testing"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
)

// forceDevTelemetry pins the env so the common lib selects its offline
// stdouttrace path regardless of the host environment.
func forceDevTelemetry(t *testing.T) {
	t.Helper()
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
	t.Setenv("GOOGLE_CLOUD_PROJECT", "")
	t.Setenv("CHORA_OTLP_INIT_TIMEOUT_SECONDS", "5")
}

func TestInstallPropagator_SetsComposite(t *testing.T) {
	installPropagator()
	prop := otel.GetTextMapPropagator()
	if prop == nil {
		t.Fatal("GetTextMapPropagator() returned nil after installPropagator")
	}
	// The composite must carry trace context — the HTTP middleware depends
	// on it. Extract a traceparent header and confirm the resulting context
	// carries a valid trace ID.
	carrier := propagation.HeaderCarrier{}
	carrier.Set("traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
	ctx := prop.Extract(context.Background(), carrier)
	sc := trace.SpanContextFromContext(ctx)
	if !sc.HasTraceID() {
		t.Error("propagator failed to extract the W3C trace id from traceparent")
	}
	if sc.TraceID().String() != "4bf92f3577b34da6a3ce929d0e0e4736" {
		t.Errorf("extracted trace id = %s, want 4bf92f3577b34da6a3ce929d0e0e4736", sc.TraceID())
	}
}

func TestInit_DevModeSucceedsAndShutsDown(t *testing.T) {
	forceDevTelemetry(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	shutdown, err := Init(ctx)
	if err != nil {
		t.Fatalf("Init (dev mode) failed: %v — is the host configured for a live exporter?", err)
	}
	if shutdown == nil {
		t.Fatal("Init returned a nil shutdown func")
	}
	shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelShutdown()
	if err := shutdown(shutdownCtx); err != nil {
		t.Errorf("shutdown: %v", err)
	}
}

func TestInitAsync_DevModeSettlesAndShutsDown(t *testing.T) {
	forceDevTelemetry(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	handle := InitAsync(ctx)
	if handle == nil {
		t.Fatal("InitAsync returned nil handle")
	}
	res := handle.WaitContext(ctx)
	if res.Shutdown == nil {
		t.Fatal("WaitContext returned a result with a nil Shutdown")
	}
	shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelShutdown()
	if err := res.Shutdown(shutdownCtx); err != nil {
		t.Errorf("async shutdown: %v", err)
	}
}
