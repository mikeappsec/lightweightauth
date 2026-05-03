# pkg/observability/audit

Structured audit logging for security-critical events.

## Usage

```go
import (
    "github.com/mikeappsec/lightweightauth/pkg/observability/audit"
)

sink := audit.NewAsyncSink(audit.AsyncSinkConfig{
    Inner:    audit.NewStdoutSink(),
    QueueLen: 4096,
})
defer sink.Close()

sink.Emit(ctx, &audit.Event{
    Type:      audit.EventDecision,
    Action:    "deny",
    Subject:   "user:jane@example.com",
    Resource:  "GET /api/admin",
    Reason:    "insufficient_permissions",
    Timestamp: time.Now(),
})
```

## Configuration

```yaml
audit:
  sinks:
    - type: stdout
      format: json
    - type: file
      path: /var/log/lwauth/audit.json
      maxSizeMB: 100
      maxBackups: 5
  sampling:
    allowRate: 0.1
    denyRate: 1.0
  securityEvents: always  # never sampled
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `sinks[].type` | string | `stdout` | Sink type: stdout, file, webhook |
| `sinks[].format` | string | `json` | Output format |
| `sampling.allowRate` | float | `1.0` | Sample rate for allow decisions |
| `sampling.denyRate` | float | `1.0` | Sample rate for deny decisions |
| `securityEvents` | string | `always` | Security events bypass sampling |

## Event Types

| Type | Description |
|------|-------------|
| `EventDecision` | Allow/deny decision |
| `EventRevocation` | Token revoked |
| `EventConfigChange` | Engine config reloaded |
| `EventKeyRotation` | Key lifecycle event |
| `EventFederationSync` | Cross-cluster sync event |

## Sinks

| Sink | Description |
|------|-------------|
| `StdoutSink` | JSON to stdout (container-friendly) |
| `AsyncSink` | Non-blocking wrapper with bounded queue |
| `MultiSink` | Fan-out to multiple sinks |
| `SamplingSink` | Probabilistic sampling (security events exempt) |

## Features

- Security-critical events (revocations, config changes) are NEVER sampled
- AsyncSink prevents audit I/O from adding latency to the request path
- Bounded queue (configurable) with overflow counter metric
- MultiSink for parallel delivery to multiple backends
- Structured JSON output with consistent field names for SIEM ingestion
- Context propagation: trace ID, request ID included when available

## How It Works

1. Pipeline emits `audit.Event` at decision points.
2. `SamplingSink` applies rate-based sampling; security events always pass through.
3. `AsyncSink` enqueues the event (non-blocking); drops + increments counter on overflow.
4. `MultiSink` fans out to configured sinks (stdout, file, webhook) in parallel.
5. Each sink serializes to JSON and writes to its output.
