# Observability — metrics, tracing, audit (M9)

Three independent surfaces, each opt-in but enabled with one line of
config or one process-level wiring call. All three are zero-cost when
unused: the OTel global tracer is a no-op until an exporter is
registered, the audit sink defaults to `audit.Discard`, and the
Prometheus registry is mounted on the existing HTTP listener.

**Source:** [pkg/observability/metrics](https://github.com/mikeappsec/lightweightauth/tree/main/pkg/observability/metrics/),
[pkg/observability/tracing](https://github.com/mikeappsec/lightweightauth/tree/main/pkg/observability/tracing/),
[pkg/observability/audit](https://github.com/mikeappsec/lightweightauth/tree/main/pkg/observability/audit/).

## Prometheus metrics

Mounted at `/metrics` on the same listener that serves Door A. No new
port to expose.

| Metric                                | Type            | Labels                              |
|---------------------------------------|-----------------|-------------------------------------|
| `lwauth_decisions_total`              | counter         | `outcome`, `authorizer`, `tenant`   |
| `lwauth_decision_latency_seconds`     | histogram (16 buckets, 100µs…3.3s) | same                |
| `lwauth_identifier_total`             | counter         | `identifier`, `outcome` (`match`/`no_match`/`error`) |
| `lwauth_shadow_disagreement_total`    | counter         | `policy_version`, `tenant`          |
| `lwauth_canary_agreement_total`       | counter         | `policy_version`, `tenant`, `agreement` |
| `lwauth_revocation_checks_total`      | counter         | `result` (`hit`/`miss`)             |
| `lwauth_revocation_duration_seconds`  | histogram       | `result`                            |
| `lwauth_ratelimit_denied_total`       | counter         | `tenant`                            |
| `lwauth_cache_hits_total`             | CounterFunc     | `cache`                             |
| `lwauth_cache_misses_total`           | CounterFunc     | `cache`                             |
| `lwauth_cache_evictions_total`        | CounterFunc     | `cache`                             |
| `lwauth_cache_stale_served_total`     | counter         | `cache`                             |
| `lwauth_key_verify_total`             | counter         | `kid`, `result`                     |
| `lwauth_key_state`                    | gauge           | `kid`, `state`                      |
| `lwauth_config_reloads_total`         | counter         | `result` (`success`/`error`)        |

Cache stats use `prometheus.CounterFunc` — the registry pulls live
`atomic.Uint64` values from `cache.Stats` at scrape time, so a
hot-reload that builds a new `*cache.Decision` just changes what the
registered closure dereferences.

```yaml
# Optional values — enabled by default. Override only to turn off.
observability:
  metrics:
    enabled: true
    namespace: lwauth      # default; emits lwauth_*
```

```promql
# Sample queries
sum(rate(lwauth_decisions_total{outcome="deny"}[5m])) by (authorizer)
histogram_quantile(0.99, sum(rate(lwauth_decision_latency_seconds_bucket[5m])) by (le))
sum(rate(lwauth_identifier_total{outcome="error"}[5m])) by (identifier)
```

## OpenTelemetry tracing

Spans emitted by `pipeline.Engine.Evaluate`:

```text
pipeline.Evaluate                  attributes: lwauth.method,host,path,tenant,decision,cache_hit
├── pipeline.Identify              attributes: lwauth.identity.subject, identity.source
└── pipeline.Mutate                attributes: lwauth.mutator
```

No exporter is wired in core. Operators register their own
`TracerProvider` at process start; until they do, every span call
resolves to the OTel no-op tracer and costs ~5 ns.

```go
// main.go — operator-side wiring
import (
    "go.opentelemetry.io/otel"
    "go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
    "go.opentelemetry.io/otel/sdk/trace"
)

func main() {
    exp, _ := otlptracegrpc.New(ctx, otlptracegrpc.WithEndpoint("otel-collector:4317"))
    tp := trace.NewTracerProvider(trace.WithBatcher(exp))
    otel.SetTracerProvider(tp)
    defer tp.Shutdown(ctx)
    // ... lwauthd.Run(ctx, cfg)
}
```

Trace context propagation in/out of lwauth uses the standard
`otelhttp` / `otelgrpc` server handlers — operators wrap them around
the listeners themselves.

`tracing.TraceIDFromContext(ctx)` exposes the W3C trace-id, so audit
lines and distributed traces correlate.

## Structured audit log

One JSON line per terminal decision via a `Sink` interface.

```json
{
  "level":"INFO","msg":"audit",
  "ts":"2026-04-28T12:00:00Z",
  "tenant":"acme",
  "subject":"alice",
  "identity_source":"jwt",
  "authorizer":"rbac",
  "decision":"allow",
  "deny_reason":"",
  "http_status":200,
  "method":"GET",
  "host":"api.example.com",
  "path":"/things",
  "latency_ms":1.7,
  "cache_hit":true,
  "trace_id":"4bf92f3577b34da6a3ce929d0e0e4736"
}
```

The default `audit.NewSlogSink` writes through a caller-supplied
`*slog.Logger`. Replace it with any sink that satisfies the interface
to ship to Kafka / OpenSearch / Loki.

```go
// main.go — replace the default sink
audit.SetDefault(audit.NewSlogSink(slog.New(
    slog.NewJSONHandler(os.Stdout, nil),
)))
```

Headers and request bodies are deliberately **not** logged — operators
who need them enable trace context propagation and read the request
span instead.

### `lwauthctl audit` tail

Filters the JSONL stream by tenant / subject / decision:

```bash
kubectl logs deploy/lwauth -f \
  | lwauthctl audit --tenant=acme --decision=deny --follow
```

## Configuration recap

```yaml
observability:
  metrics:
    enabled: true
  tracing:
    # Tracing is operator-wired (see code sample above). No YAML knobs;
    # the no-op default keeps cost at ~5 ns/span until a TracerProvider
    # is registered at process start.
  audit:
    sink: slog                          # slog | discard
```

## References

- DESIGN: [DESIGN.md §M9](../DESIGN.md).
- Sources: [pkg/observability/metrics/metrics.go](https://github.com/mikeappsec/lightweightauth/blob/main/pkg/observability/metrics/metrics.go),
  [pkg/observability/tracing/tracing.go](https://github.com/mikeappsec/lightweightauth/blob/main/pkg/observability/tracing/tracing.go),
  [pkg/observability/audit/audit.go](https://github.com/mikeappsec/lightweightauth/blob/main/pkg/observability/audit/audit.go).
- `lwauthctl audit`: [cmd/lwauthctl](https://github.com/mikeappsec/lightweightauth/tree/main/cmd/lwauthctl/).
