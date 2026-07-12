# pkg/observability/tracing

Thin wrapper around the OpenTelemetry **global** `TracerProvider`.
This package doesn't construct a provider, exporter, or config of its
own — it exposes exactly two functions.

## Usage

```go
import (
    "github.com/mikeappsec/lightweightauth/pkg/observability/tracing"
)

// Operators wire up their own OTel SDK provider and register it
// globally — this package has no provider/exporter construction at all.
otel.SetTracerProvider(myProvider)

// Extract trace ID from context (e.g., for audit log correlation)
traceID := tracing.TraceIDFromContext(ctx)

// Access the lwauth-named tracer for custom spans
tracer := tracing.Tracer()
ctx, span := tracer.Start(ctx, "custom-operation")
defer span.End()
```

There is no `NewProvider`, `ProviderConfig`, or `Shutdown` method —
none of that exists in this package. It's exactly:

```go
func Tracer() trace.Tracer
func TraceIDFromContext(ctx context.Context) string
```

## Configuration — not wired in

There is no `tracing:` key on `AuthConfig`
(`internal/config/config.go` has zero references to `tracing`) and no
`Config`/`ProviderConfig` type in this package to bind such a YAML
block to. Tracing is entirely a Go-level concern: call
`otel.SetTracerProvider(p)` yourself at process start with whatever
SDK provider/exporter/sampler you want; until you do, every span call
in this package resolves to the OTel no-op tracer and costs ~5ns.

## Span Attributes

The pipeline (`internal/pipeline/engine.go`) sets these on spans —
note the names differ from what you might expect:

| Attribute | Description |
|-----------|-------------|
| `lwauth.method` / `lwauth.host` / `lwauth.path` / `lwauth.tenant` | Request metadata |
| `lwauth.identity.subject` | Authenticated subject — **not** `lwauth.subject` |
| `lwauth.identity.source` | The identifier that matched — **not** `lwauth.identifier.type` |
| `lwauth.decision` | allow/deny/error |
| `lwauth.cache_hit` | Whether the decision cache served this |
| `lwauth.policy_version` / `lwauth.shadow_disagreement` | D2 shadow-mode fields |
| `lwauth.mutator` | Response mutator name, per mutate span |
| `lwauth.revocation.*` | Revocation-check attributes |

There is no `lwauth.latency_ms` span attribute — latency is only
recorded via the `lwauth_decision_latency_seconds` Prometheus
histogram and the audit `Event.LatencyMs` field, never as a span
attribute.

## Features

- No-op when no provider is registered (zero overhead)
- `TraceIDFromContext()` for correlating audit logs with traces
- Trace name is `github.com/mikeappsec/lightweightauth`, filterable in your backend

**Not implemented, despite this package's own doc comment claiming
otherwise:** W3C `traceparent` propagation via `otelhttp.NewHandler`/
`otelgrpc.NewServerHandler` at the HTTP/gRPC listeners — no file in
this repository imports `go.opentelemetry.io/contrib` (which houses
both), so incoming trace context is not actually extracted at the
listener today. If you need propagation, wire it yourself around the
listeners.

## How It Works

1. An embedder registers a `TracerProvider` globally via
   `otel.SetTracerProvider(p)` — this package plays no part in that.
2. The pipeline creates child spans for each stage (identify →
   authorize → mutate) via `Tracer()`.
3. Decision attributes are set on the relevant span (see table above).
4. If no provider is configured, `Tracer()` returns the OTel no-op
   tracer (zero-cost passthrough).
