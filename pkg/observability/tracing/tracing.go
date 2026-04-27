// Package tracing is a thin wrapper around the OpenTelemetry global
// TracerProvider so the pipeline and modules can start spans without
// coupling to a specific exporter (DESIGN.md M9).
//
// Operators wire up their own SDK provider at startup (OTLP HTTP, OTLP
// gRPC, stdout, ...) and call otel.SetTracerProvider(p). When no
// provider is registered the OTel global returns a no-op tracer, so
// every span call in this package becomes free.
//
// Trace context propagation in/out of lwauth follows W3C traceparent.
// The HTTP server uses otelhttp.NewHandler at the listener; the gRPC
// server uses otelgrpc.NewServerHandler. Both extract the incoming
// span context so pipeline spans become children of the caller's.
package tracing

import (
	"context"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace"
)

// instrumentationName is the Tracer name lwauth uses. Operators filter
// on this in their backend ("show me only lwauth spans").
const instrumentationName = "github.com/mikeappsec/lightweightauth"

// Tracer returns the lwauth-named Tracer from the global provider.
// Always non-nil; safe to call before any provider is registered (the
// OTel global is a no-op then).
func Tracer() trace.Tracer {
	return otel.Tracer(instrumentationName)
}

// TraceIDFromContext returns the W3C trace-id (hex) for ctx, or "" if
// no span is active. Used by the audit sink to correlate decisions with
// distributed traces without forcing a tracing dependency on consumers.
func TraceIDFromContext(ctx context.Context) string {
	sc := trace.SpanContextFromContext(ctx)
	if !sc.IsValid() {
		return ""
	}
	return sc.TraceID().String()
}
