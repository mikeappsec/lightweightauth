# pkg/observability/metrics

Prometheus metrics recorder for the lwauth decision pipeline.

## Usage

```go
import (
    "github.com/mikeappsec/lightweightauth/pkg/observability/metrics"
    "github.com/prometheus/client_golang/prometheus"
)

reg := prometheus.NewRegistry()
rec := metrics.New(reg)

// Record a decision
rec.ObserveDecision("allow", "jwt", time.Since(start))

// Record an identifier result
rec.ObserveIdentifier("jwt", true, time.Since(start))

// Record shadow-mode evaluation
rec.ObserveShadow("new-policy", "deny", time.Since(start))

// Record canary split
rec.ObserveCanary("canary-v2", "allow", 0.1)

// Record revocation check
rec.ObserveRevocation("hit", time.Since(start))
```

## Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `lwauth_decisions_total` | Counter | `result`, `identifier` | Total auth decisions |
| `lwauth_decision_duration_seconds` | Histogram | `result`, `identifier` | Decision latency |
| `lwauth_identifier_total` | Counter | `type`, `success` | Identifier evaluations |
| `lwauth_identifier_duration_seconds` | Histogram | `type` | Identifier latency |
| `lwauth_shadow_decisions_total` | Counter | `policy`, `result` | Shadow mode evaluations |
| `lwauth_canary_decisions_total` | Counter | `canary`, `result` | Canary split decisions |
| `lwauth_revocation_checks_total` | Counter | `result` | Revocation lookups (hit/miss) |
| `lwauth_revocation_duration_seconds` | Histogram | `result` | Revocation check latency |
| `lwauth_key_verify_total` | Counter | `kid`, `result` | Key verification attempts |
| `lwauth_key_state` | Gauge | `kid`, `state` | Current key lifecycle state |
| `lwauth_config_reloads_total` | Counter | `result` | Config reload attempts |

## Features

- Nil-safe: a nil `*Recorder` is valid (all methods are no-ops)
- Standard Prometheus registration via `prometheus.Registerer`
- Histogram buckets tuned for auth latency (sub-millisecond to 10s)
- Per-identifier and per-policy cardinality for granular SLO tracking
- Zero allocation on the hot path (pre-allocated label sets)

## How It Works

1. `New(reg)` registers all metric descriptors with the Prometheus registry.
2. Pipeline stages call the appropriate `Observe*` method after each operation.
3. Prometheus scraper hits `/metrics` endpoint to collect counters and histograms.
4. A nil recorder is safe to pass anywhere — all method calls become no-ops.
