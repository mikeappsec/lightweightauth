# pkg/observability/tracing

OpenTelemetry distributed tracing integration.

## Usage

```go
import (
    "github.com/mikeappsec/lightweightauth/pkg/observability/tracing"
)

// Initialize tracer (typically at startup)
tp, err := tracing.NewProvider(tracing.ProviderConfig{
    ServiceName: "lwauth",
    Endpoint:    "otel-collector:4317",
    Insecure:    false,
})
defer tp.Shutdown(ctx)

// Extract trace ID from context (e.g., for audit log correlation)
traceID := tracing.TraceIDFromContext(ctx)

// Access the tracer for custom spans
tracer := tracing.Tracer()
ctx, span := tracer.Start(ctx, "custom-operation")
defer span.End()
```

## Configuration

```yaml
tracing:
  enabled: true
  endpoint: "otel-collector:4317"
  insecure: false
  serviceName: "lwauth"
  sampleRate: 1.0
  propagation: "w3c"  # W3C traceparent (default)
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `false` | Enable tracing |
| `endpoint` | string | — | OTLP gRPC collector address |
| `insecure` | bool | `false` | Skip TLS for collector |
| `serviceName` | string | `"lwauth"` | Service name in spans |
| `sampleRate` | float | `1.0` | Trace sampling ratio (0.0–1.0) |
| `propagation` | string | `"w3c"` | Context propagation format |

## Span Attributes

The pipeline automatically adds these attributes to auth spans:

| Attribute | Description |
|-----------|-------------|
| `lwauth.decision` | allow/deny |
| `lwauth.identifier.type` | Identity method used |
| `lwauth.subject` | Authenticated subject |
| `lwauth.latency_ms` | Decision latency |

## Features

- W3C `traceparent` header propagation (incoming → outgoing)
- No-op when tracing is disabled or no provider is configured (zero overhead)
- `TraceIDFromContext()` for correlating audit logs with traces
- OTLP/gRPC exporter to any OpenTelemetry-compatible collector
- Configurable sampling rate for high-traffic deployments
- Graceful shutdown flushes pending spans

## How It Works

1. `NewProvider()` configures the OTLP exporter and registers a global `TracerProvider`.
2. HTTP/gRPC middleware extracts the `traceparent` header from incoming requests, creating a span context.
3. The pipeline creates child spans for each stage (identify → authorize → mutate).
4. Decision attributes are set on the root span before it ends.
5. If no provider is configured, `Tracer()` returns a no-op tracer (zero-cost passthrough).
