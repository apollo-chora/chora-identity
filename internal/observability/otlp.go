// Package observability is a thin compatibility shim that delegates to the
// canonical libs/chora-go-common/otel package per Wave B (2026-05-14, tracker
// #146). The previous local implementation duplicated the
// otlptracegrpc + WithInsecure() pattern, which silently failed the TLS
// handshake against telemetry.googleapis.com:443 and dropped every span.
//
// The canonical lib wires a real Cloud Trace exporter (ADC auth + TLS); this
// shim preserves the local Init(ctx) signature so call sites in
// cmd/server/main.go keep compiling without edits. Spans now reach Cloud
// Trace correctly per Tier 3 D13.
//
// Beyond plain delegation, this shim installs the W3C TraceContext + Baggage
// composite propagator after init — preserving the propagator behaviour the
// local impl provided so HTTPMiddleware + any gRPC interceptors can
// extract/inject traceparent headers across service boundaries.
//
// Paydown II (2026-05-14, tracker #151 / C(a).S1.b follow-on) added the
// async variant InitAsync that returns a bootstrap.OTLPHandle; pod
// bootstrap can now run pgx pool init with the FULL bootstrap deadline
// while OTLP wiring proceeds in its own goroutine + own deadline. The
// propagator is set immediately so HTTP middleware can extract/inject
// traceparent headers even before the exporter has finished initializing.
// See libs/chora-go-common/bootstrap/README.md for the migration recipe.
package observability

import (
	"context"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"

	"github.com/apollo-chora/chora-common/bootstrap"
	commonobs "github.com/apollo-chora/chora-common/observability"
	commonotel "github.com/apollo-chora/chora-common/otel"
)

// serviceName is the canonical OTLP service.name attribute for this binary.
const serviceName = "chora-identity"

// version is bumped per-release; matches the constant in cmd/server/main.go.
const version = "0.1.0"

// installPropagator sets the W3C TraceContext + Baggage propagator. Called
// from both Init and InitAsync paths so HTTPMiddleware + any future gRPC
// interceptors can extract/inject traceparent headers across service
// boundaries (per Tier 3 D13 OTLP-everywhere mandate). The canonical lib
// does not set a propagator; the local impl always did.
func installPropagator() {
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))
}

// Init wires the OTel exporter via the canonical lib and registers a global
// TracerProvider + W3C TraceContext+Baggage propagator. Returns a shutdown
// func the caller MUST defer to flush spans on exit. Public signature
// preserved for backward compatibility.
//
// Prefer InitAsync in new call sites — it decouples OTLP init from pgx
// pool bootstrap per C(a).S1 path (b).
func Init(ctx context.Context) (shutdown func(context.Context) error, err error) {
	shutdown, err = commonotel.Init(ctx, serviceName, version)
	if err != nil {
		return nil, err
	}
	installPropagator()
	return shutdown, nil
}

// InitAsync is the fail-soft non-blocking variant of Init per C(a).S1
// path (b) — tracker #151. Delegates to commonobs.InitOTLPAsync so OTLP
// init runs in its own goroutine with its own deadline
// (CHORA_OTLP_INIT_TIMEOUT_SECONDS, default 15s). Timeout / init-error
// degrade to a no-op shutdown so pgx pool + Pub/Sub clients get the FULL
// bootstrap budget.
//
// The W3C propagator is installed synchronously here so HTTP middleware
// + gRPC interceptors can extract/inject traceparent headers from request
// one even before the exporter completes initialization. Pre-init spans
// are dropped (no TracerProvider yet) but traceparent propagation is
// uninterrupted.
func InitAsync(ctx context.Context) *bootstrap.OTLPHandle {
	installPropagator()
	return commonobs.InitOTLPAsync(ctx, serviceName, version)
}
