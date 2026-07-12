# pkg/observability/audit

Structured audit logging for security-critical events. One `Event`
per terminal pipeline decision.

## Usage

```go
import (
    "github.com/mikeappsec/lightweightauth/pkg/observability/audit"
)

sink := audit.NewAsyncSink(audit.NewSlogSink(logger), 4096)

sink.Record(ctx, &audit.Event{
    Timestamp:      time.Now(),
    Subject:        "user:jane@example.com",
    Method:         "GET",
    Path:           "/api/admin",
    Decision:       "deny",
    DenyReason:     "insufficient_permissions",
    HTTPStatus:     403,
})
```

There is no `AsyncSinkConfig` struct, no `NewStdoutSink`, and no
`Emit` method — `NewAsyncSink(inner Sink, bufSize int) *AsyncSink`
takes two positional args, and the `Sink` interface's single method
is `Record(ctx, *Event)`. There's also no `Event.Type`/`.Action`/
`.Resource`/`.Reason` field.

## `Event` fields

```go
type Event struct {
    Timestamp          time.Time // RFC 3339Nano
    Tenant              string
    Subject             string
    IdentitySource      string  // the identifier that matched
    Authorizer          string  // the authorizer that produced the decision
    Decision            string  // "allow" / "deny" / "error"
    DenyReason          string
    HTTPStatus          int
    Method, Host, Path  string
    LatencyMs           float64
    CacheHit            bool
    TraceID             string
    PolicyVersion       string  // D2
    ShadowDisagreement  bool    // D2
    CanaryAgreement     string  // D3
}
```

There is no `EventDecision`/`EventRevocation`/`EventConfigChange`/
`EventKeyRotation`/`EventFederationSync` enum — `Event` isn't typed by
kind, it's always "one terminal decision."

## Configuration (`AuthConfig.audit:`)

The real, AuthConfig-wired `audit:` key only covers redaction and
data-residency routing — it does **not** configure sinks, sampling
rates, or a `securityEvents` toggle:

```yaml
audit:
  redaction:
    fields:
      - name: subject
        action: hash        # "hash" (SHA-256 HMAC) or "drop"
      - name: path
        action: drop
  dataResidency:
    region: eu-west-1
```

Recognised `redaction.fields[].name` values: `subject`, `path`,
`host`, `deny_reason`, `identity_source`, `trace_id`
(`internal/config/config.go`'s `RedactionSpec` doc comment).

Sink composition (`AsyncSink`, `MultiSink`, `SamplingSink`, etc.,
below) is a **Go-API-only** concern — there's no YAML schema for
wiring sinks together; an embedder composes them in code.

## Sinks

| Sink | Constructor | Description |
|------|-------------|-------------|
| `SlogSink` | `NewSlogSink(*slog.Logger)` | Structured slog record at INFO, message `"audit"` — the on-disk format (JSON in production) is the handler's concern, not this package's |
| `AsyncSink` | `NewAsyncSink(inner Sink, bufSize int)` | Non-blocking wrapper with a bounded channel; drops + logs a one-time `slog.Warn` on overflow (`Dropped()` returns an in-process `atomic.Int64` — **not** a Prometheus metric) |
| `MultiSink` | `NewMultiSink(sinks ...Sink)` | Fan-out to multiple sinks; a panicking sink is recovered and logged, doesn't take down the others |
| `RedactingSink` | `NewRedactingSink(inner, fields []RedactionField, hmacKey []byte)` | Applies the `audit.redaction` config above |
| `TenantAwareSink` | `NewTenantAwareSink(inner)` | — |
| `RegionRoutingSink` | `NewRegionRoutingSink(...)` | Routes events to per-region sinks per `dataResidency` |
| `SamplingSink` | `NewSamplingSink(inner, rules []SamplingRule, opts...)` | Rule-based sampling; deny/error/shadow-disagreement/canary-disagreement events are **always** emitted via hard-coded pre-rules that user rules cannot override |
| `RecentRing` | `NewRecentRing(capacity int)` | In-memory ring buffer of recent events (used by the admin explain/debug surface) |
| Kafka | `pkg/observability/audit/kafka` | External sink backend |
| Loki | `pkg/observability/audit/loki` | External sink backend |

There is no `StdoutSink`, no `webhook` sink type, and no `file` sink
type with `maxSizeMB`/`maxBackups` — none of those exist.

## Features

- Security-critical events (deny, error, shadow/canary disagreement)
  are never dropped by `SamplingSink`'s hard-coded pre-rules
- `AsyncSink` prevents audit I/O from adding latency to the request path
- `MultiSink` for parallel delivery to multiple backends
- `Discard` is a comparable no-op `Sink` singleton for tests/dev

## How It Works

1. Pipeline emits `audit.Event` at each terminal decision.
2. Whatever `Sink` chain an embedder composed (e.g.
   `MultiSink(AsyncSink(RedactingSink(SlogSink(...))), kafkaSink)`)
   processes it — this composition is done in Go code, not driven by
   `AuthConfig` YAML.
3. `AsyncSink` enqueues (non-blocking); drops + increments its
   internal counter on overflow.
