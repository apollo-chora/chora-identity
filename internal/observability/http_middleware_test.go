package observability

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

// helper — install an in-memory exporter so we can assert the spans the
// middleware emits.
func installTestProvider(t *testing.T) *tracetest.SpanRecorder {
	t.Helper()
	rec := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSpanProcessor(rec),
	)
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))
	t.Cleanup(func() { _ = tp.Shutdown(t.Context()) })
	return rec
}

func TestHTTPMiddleware_EmitsSpanPerRequest(t *testing.T) {
	rec := installTestProvider(t)

	called := false
	mw := HTTPMiddleware()
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))

	r := httptest.NewRequest(http.MethodGet, "/me", nil)
	r.Header.Set("X-Tenant-Id", "01935b5a-9bcf-7000-8000-000000000010")
	r.Header.Set("gcid", "01935b5a-9bcf-7000-8000-000000000099")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if !called {
		t.Fatalf("inner handler not called")
	}
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d", w.Code)
	}
	spans := rec.Ended()
	if len(spans) != 1 {
		t.Fatalf("expected 1 span; got %d", len(spans))
	}
	span := spans[0]
	if !strings.Contains(span.Name(), "/me") {
		t.Fatalf("span name should contain /me; got %q", span.Name())
	}
	if !strings.Contains(span.Name(), "GET") {
		t.Fatalf("span name should contain GET; got %q", span.Name())
	}
	// Confirm tenant + gcid attributes stamped.
	gotTenant, gotGcid := false, false
	for _, attr := range span.Attributes() {
		if string(attr.Key) == "chora.tenant.id" && attr.Value.AsString() == "01935b5a-9bcf-7000-8000-000000000010" {
			gotTenant = true
		}
		if string(attr.Key) == "chora.gcid" && attr.Value.AsString() == "01935b5a-9bcf-7000-8000-000000000099" {
			gotGcid = true
		}
	}
	if !gotTenant {
		t.Fatalf("missing chora.tenant.id attribute")
	}
	if !gotGcid {
		t.Fatalf("missing chora.gcid attribute")
	}
}

func TestHTTPMiddleware_StampsErrorOn5xx(t *testing.T) {
	rec := installTestProvider(t)
	mw := HTTPMiddleware()
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	r := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	spans := rec.Ended()
	if len(spans) != 1 {
		t.Fatalf("expected 1 span; got %d", len(spans))
	}
	span := spans[0]
	if span.Status().Code.String() != "Error" {
		t.Fatalf("expected Error status on 5xx; got %v", span.Status().Code)
	}
}

func TestHTTPMiddleware_PropagatesIncomingTraceparent(t *testing.T) {
	_ = installTestProvider(t)
	mw := HTTPMiddleware()

	// Capture the propagated trace context by reading the response header.
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	// Inbound traceparent — the middleware extracts it then re-injects.
	r.Header.Set("traceparent", "00-1234567890abcdef1234567890abcdef-1234567890abcdef-01")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Header().Get("traceparent") == "" {
		t.Fatalf("expected response traceparent header to be set")
	}
}
