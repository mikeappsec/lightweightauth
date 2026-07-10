# pkg/observability/metrics

Prometheus metrics recorder for the lwauth decision pipeline.

## Usage

```go
import (
    "github.com/mikeappsec/lightweightauth/pkg/observability/metrics"
)

// Construct an isolated Recorder (owns its own *prometheus.Registry).
// In production, call metrics.SetDefault(...) from main() before
// invoking lwauthd.Run; the pipeline reads metrics.Default() on the
// hot path.
rec := metrics.New()

// Record a terminal decision (one per Evaluate call).
rec.ObserveDecision("allow", "rbac", "acme", 12*time.Millisecond)

// Record an identifier module invocation.
rec.ObserveIdentifier("jwt", "match")

// Record an authorizer module invocation (per-Authorize call,
// incl. canary candidates). Children inside a `composite`
// authorizer are NOT individually observed at this stage  E they
// surface under the composite's own outcome unless the composite
// package itself wires the decorator (planned follow-on).
rec.ObserveAuthorizer("rbac", "deny")

// Shadow / canary / revocation outcomes.
rec.ObserveShadowDisagreement("opa-v2", "acme")
rec.ObserveCanaryAgreement("opa-v2", "acme", "match")
rec.ObserveRevocationCheck("acme", "revoked")
rec.ObserveCacheStaleServed("acme", "allow")
rec.ObserveCacheDistSF("won")
rec.ObserveRateLimitDenied("acme")
```

## Metrics

All histograms use seconds; all counters are monotonic.

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `lwauth_decisions_total` | Counter | `outcome`, `authorizer`, `tenant` | Terminal pipeline decisions (allow / deny / error) |
| `lwauth_decision_latency_seconds` | Histogram | `outcome`, `authorizer`, `tenant` | End-to-end pipeline.Evaluate latency |
| `lwauth_identifier_total` | Counter | `identifier`, `outcome` | Identifier module outcomes (match / no_match / error) |
| `lwauth_authorizer_total` | Counter | `authorizer`, `outcome` | Authorizer module invocation outcomes (allow / deny / error) |
| `lwauth_shadow_disagreement_total` | Counter | `policy_version`, `tenant` | Shadow-mode disagreements (D2) |
| `lwauth_canary_agreement_total` | Counter | `policy_version`, `tenant`, `agreement` | Canary vs production verdict comparisons (D3) |
| `lwauth_revocation_checks_total` | Counter | `tenant`, `result` | Revocation lookups (revoked / not_revoked / error) (E2) |
| `lwauth_cache_stale_served_total` | Counter | `tenant`, `decision` | Stale cache entries served during upstream outage (E3) |
| `lwauth_cache_distsf_total` | Counter | `outcome` | Cross-replica distributed singleflight outcomes (E4) |
| `lwauth_ratelimit_denied_total` | Counter | `tenant` | Per-tenant rate-limit denials (E6) |
| `lwauth_cache_hits_total` | CounterFunc | `cache` | Cache hits by named cache |
| `lwauth_cache_misses_total` | CounterFunc | `cache` | Cache misses by named cache |
| `lwauth_cache_evictions_total` | CounterFunc | `cache` | Cache evictions by named cache |
| `lwauth_cache_layer_hits_total` | CounterFunc | `cache`, `layer` | Per-layer (`l1`/`l2`) cache hits |
| `lwauth_cache_layer_misses_total` | CounterFunc | `cache`, `layer` | Per-layer cache misses |
| `lwauth_fips_enabled` | Gauge |  E | 1 = binary uses a FIPS 140-3 validated crypto module, 0 otherwise |
| `lwauth_build_info` | Gauge | `version`, `commit`, `go_version`, `fips` | Constant 1 with build attributes |

## Features

- Nil-safe: a nil `*Recorder` is valid (all methods are no-ops)
- Process-wide singleton via `Default()` / `SetDefault(...)`
- Private `*prometheus.Registry` per Recorder so tests can assert on a clean metric surface
- Histogram buckets tuned for auth latency (100µs … ~3.3s, 16 exponential buckets)
- Per-identifier and per-authorizer cardinality for granular SLO and health tracking

## How It Works

1. `New()` registers all metric descriptors with a fresh private Prometheus registry.
2. The pipeline (`internal/pipeline/engine.go`) and admin handlers call the appropriate `Observe*` method after each operation via `metrics.Default()` on the hot path.
3. The `/metrics` HTTP endpoint (mounted at `internal/server/http.go`) exposes the Prometheus text-format scrape surface.
4. A nil recorder is safe to pass anywhere  E the process-wide default is always lazily initialised and never nil.