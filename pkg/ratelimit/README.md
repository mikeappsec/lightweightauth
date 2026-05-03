# pkg/ratelimit

Per-tenant token-bucket rate limiter with distributed aggregation support.

## Usage

```go
import (
    "github.com/mikeappsec/lightweightauth/pkg/ratelimit"
)

limiter := ratelimit.New(ratelimit.Spec{
    PerTenant: &ratelimit.Bucket{RPS: 100, Burst: 200},
    Default:   &ratelimit.Bucket{RPS: 50, Burst: 100},
    Overrides: map[string]ratelimit.Bucket{
        "premium-tenant": {RPS: 500, Burst: 1000},
    },
})

allowed := limiter.Allow("tenant-id")
```

## Configuration

```yaml
rateLimit:
  perTenant:
    rps: 100
    burst: 200
  default:
    rps: 50
    burst: 100
  overrides:
    premium-tenant:
      rps: 500
      burst: 1000
  maxBuckets: 100000
  bucketIdleTTL: "5m"
  distributed:
    type: "valkey"
    addr: "valkey:6379"
    keyPrefix: "lwauth/rl/"
    window: "1s"
    failOpen: false
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `perTenant` | Bucket | — | Per-tenant rate (RPS + Burst) |
| `default` | Bucket | — | Fallback when TenantID is empty |
| `overrides` | map | — | Per-tenant quota customization |
| `maxBuckets` | int | `100000` | Max in-memory buckets |
| `bucketIdleTTL` | duration | `5m` | Idle bucket eviction |
| `distributed.type` | string | — | Backend name (e.g. "valkey") |
| `distributed.addr` | string | — | Backend address |
| `distributed.failOpen` | bool | `false` | Skip local check on backend error |

## Features

- Nil `*Limiter` treated as "disabled" (every Allow returns true)
- Background reaper evicts idle buckets per `bucketIdleTTL`
- Per-tenant overrides with 128-char key cap
- Distributed mode: local bucket as safety floor + Valkey sliding window for cluster-wide cap
- `httputil.KeyedLimiter` interface for HTTP middleware integration
- Backend registration via `init()` + factory pattern

## How It Works

1. On each request, resolves the tenant ID from the pipeline context.
2. Looks up (or creates) the tenant's token bucket.
3. Attempts to consume one token; denies with 429 if bucket is empty.
4. In distributed mode: also checks Valkey sliding-window counter for cluster-wide enforcement.
5. Background goroutine evicts buckets idle for > `bucketIdleTTL`.

## Benchmark

Per-tenant `Allow()` cost: ~50ns single-tenant, ~100ns with concurrent access (bucket lock contention). Distributed mode adds one Valkey RTT (~0.2ms in-cluster).
