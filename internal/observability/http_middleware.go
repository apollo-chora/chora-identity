// HTTP middleware that emits an OTel span per request — fills the audit gap
// flagged in audit-identity-fillgaps.md §4.3 (TracerProvider registered but
// no spans started).
//
// Per Tier 3 D13 + ai-observability-cloud-trace skill:
//   - W3C traceparent + tracestate headers extracted on inbound + propagated.
//   - Span name follows the convention `{service}.http.{method}.{route}`.
//   - Tenant + GCID stamped on the span attributes when present in headers.
//   - On 5xx response, span status is set to Error.
//
// Production wiring is identical — the OTLP exporter pipes spans direct to
// Cloud Trace via OTEL_EXPORTER_OTLP_ENDPOINT.
//
// This middleware is INTENTIONALLY local to chora-identity (rather than
// pulling libs/chora-go-common/observability) until the workspace's
// version-resolution issue around the cross-module replace directive is
// resolved separately. The shape is API-compatible with that lib's
// HTTPMiddleware.
package observability

import (
	"net/http"
	"strconv"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
)

// tracer returns the chora-identity tracer scoped to this service.
func tracer() trace.Tracer {
	return otel.Tracer("chora-identity")
}

// statusRecorder wraps http.ResponseWriter to capture the response code.
type statusRecorder struct {
	http.ResponseWriter
	status int
	bytes  int64
}

func (sr *statusRecorder) WriteHeader(code int) {
	sr.status = code
	sr.ResponseWriter.WriteHeader(code)
}

func (sr *statusRecorder) Write(p []byte) (int, error) {
	if sr.status == 0 {
		sr.status = http.StatusOK
	}
	n, err := sr.ResponseWriter.Write(p)
	sr.bytes += int64(n)
	return n, err
}

// HTTPMiddleware emits an OTel span around every request.
//
// Span name: "chora-identity.http.{METHOD}.{path}".
// Attributes:
//   - http.method, http.target, http.status_code, http.response_size_bytes
//   - chora.tenant.id, chora.gcid (when present in headers)
//   - chora.adapter.version = "chora-identity" (constant)
//
// W3C traceparent / tracestate are extracted from inbound headers via the
// global TextMapPropagator (configured by Init); the resulting context
// carries the trace context downstream + into the span body.
func HTTPMiddleware() func(http.Handler) http.Handler {
	prop := otel.GetTextMapPropagator()
	if prop == nil {
		// Defensive — if Init() didn't set a propagator, install the default.
		prop = propagation.TraceContext{}
		otel.SetTextMapPropagator(prop)
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := prop.Extract(r.Context(), propagation.HeaderCarrier(r.Header))

			spanName := "chora-identity.http." + r.Method + "." + r.URL.Path
			ctx, span := tracer().Start(ctx, spanName)
			defer span.End()

			// Stamp standard + chora-specific attributes.
			span.SetAttributes(
				attribute.String("http.method", r.Method),
				attribute.String("http.target", r.URL.Path),
				attribute.String("chora.adapter.version", "chora-identity"),
			)
			if tenantID := r.Header.Get("X-Tenant-Id"); tenantID != "" {
				span.SetAttributes(attribute.String("chora.tenant.id", tenantID))
			}
			if gcid := r.Header.Get("gcid"); gcid != "" {
				span.SetAttributes(attribute.String("chora.gcid", gcid))
			} else if gcid := r.Header.Get("X-Chora-GCID"); gcid != "" {
				span.SetAttributes(attribute.String("chora.gcid", gcid))
			}

			// Inject trace context into the response so downstream callers
			// (e.g., chora-bff-gateway) can correlate.
			prop.Inject(ctx, propagation.HeaderCarrier(w.Header()))

			sr := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(sr, r.WithContext(ctx))

			span.SetAttributes(
				attribute.Int("http.status_code", sr.status),
				attribute.String("http.status_code.str", strconv.Itoa(sr.status)),
				attribute.Int64("http.response_size_bytes", sr.bytes),
			)
			if sr.status >= 500 {
				span.SetStatus(codes.Error, "5xx response")
			} else if sr.status >= 400 {
				// 4xx is set as a warning-style attribute, not Error — client errors
				// are not service failures per OTel conventions.
				span.SetAttributes(attribute.Bool("http.client_error", true))
			}
		})
	}
}
