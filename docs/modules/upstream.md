# Outbound resilience — `pkg/upstream` (M11)

Single primitive that wraps every external dependency lwauth talks to:
the IdP (`oauth2-introspection`, `clientauth`), OPA bundle server,
OpenFGA store, Valkey/Redis cache, and any operator-supplied gRPC
plugin. Composed into one type — `upstream.Guard` — that owns a
circuit breaker, a token-bucket retry budget, and bounded exponential
backoff. Every consumer exposes a uniform `resilience:` block.

**Source:** [pkg/upstream](https://github.com/mikeappsec/lightweightauth/blob/main/pkg/upstream/guard.go).
**Wired into:** `openfga` Check, `oauth2-introspection`,
`clientauth` token fetch, `valkey` cache (Get/Set/Delete each guarded).

## Why this exists

Without bounded retries and a breaker, a flaky upstream amplifies into
a full-fan-out outage:

| Without Guard           | With Guard                                |
|-------------------------|-------------------------------------------|
| Naive 2-retry × 100 RPS = 300 RPS hitting a 500-ing IdP | Breaker opens after 5 failures; the rest fast-fail with `ErrCircuitOpen` (~µs).  |
| Slow IdP eats every worker goroutine | `MaxRetries=0` + breaker = deterministic 503s. |
| 64-worker fan-out under outage | M12 chaos test: 2.15M calls handled, **only 5 reached the broken upstream**, 100% fast-fail rate. |

## Configuration

Every upstream-using module accepts the same block:

```yaml
authorizers:
  - name: rebac
    type: openfga
    config:
      address: openfga.svc:8081
      storeId: 01HX...
      resilience:
        breaker:
          failureThreshold: 5            # consecutive failures to trip
          coolDown: 30s                  # how long open before half-open trial
          halfOpenSuccesses: 1           # successes in half-open to fully close
        retries:
          maxRetries:  2                 # additional attempts after the first
          backoffBase: 50ms              # first-retry sleep; doubles each retry
          backoffMax:  1s                # cap on backoff
        budget:
          capacity:     100              # max concurrent retries in flight
          refillPerSec: 10               # token regen rate
```

| Block       | Field                | Default | Notes |
|-------------|----------------------|---------|-------|
| `breaker`   | `failureThreshold`   | 5       | Consecutive failures to trip closed → open. |
| `breaker`   | `coolDown`           | 30s     | Time in open before admitting a trial call. |
| `breaker`   | `halfOpenSuccesses`  | 1       | Successes in half-open to fully close. |
| `retries`   | `maxRetries`         | 0       | 0 = pure breaker, no retries. |
| `retries`   | `backoffBase`        | 0       | 0 = no backoff (tests / fast-failover). |
| `retries`   | `backoffMax`         | 0       | Cap; ignored when `backoffBase == 0`. |
| `budget`    | `capacity`           | 0       | 0 = retries unlimited (use `maxRetries` to cap). |
| `budget`    | `refillPerSec`       | 0       | Token regen for the budget bucket. |

## Behavior contract

- **Cancellation is caller-driven, not upstream-driven.**
  `context.Canceled` / `context.DeadlineExceeded` from the parent ctx
  are NOT counted against breaker health. A tight deadline against a
  slow IdP cannot trip the breaker. Validated in M12 chaos slice
  (`TestChaos_SlowUpstreamCallerCancelDoesNotTripBreaker`).
- **Definitive answers are not retried.** Operators wire a
  `Retryable` predicate so 4xx / validation errors (a definitive
  upstream answer) neither retry nor count as breaker failures.
- **Sentinel errors map to `module.ErrUpstream`** so the pipeline
  returns deterministic 503-class denies under upstream pressure
  rather than chewing worker goroutines.

## Operational notes

- **One Guard per (tenant, upstream) pair.** A noisy tenant trips its
  own breakers without affecting another tenant's traffic — the M7
  multi-tenancy invariant.
- **Metrics.** Each module exposes the breaker state as a Prometheus
  gauge through its standard module metrics (`*_upstream_state`
  enum: 0=closed, 1=open, 2=half-open).
- **Tuning.** Start with defaults. Bump `failureThreshold` only if the
  upstream has a known noisy-failure baseline; bump `maxRetries` only
  if the upstream is known to be transiently flaky on a stable hash
  (e.g. eventually-consistent token store right after a cluster
  re-shard).

## Code sample (custom embedder)

```go
import "github.com/mikeappsec/lightweightauth/pkg/upstream"

g := upstream.NewGuard(upstream.GuardConfig{
    Breaker: upstream.BreakerConfig{FailureThreshold: 5, CoolDown: 30 * time.Second},
    Budget:  upstream.RetryBudgetConfig{Capacity: 100, RefillPerSec: 10},
    MaxRetries: 2,
    BackoffBase: 50 * time.Millisecond,
    BackoffMax:  time.Second,
})

err := g.Do(ctx, func(ctx context.Context) error {
    return callMyUpstream(ctx)
})
switch {
case errors.Is(err, upstream.ErrCircuitOpen):     // breaker open; fast-fail
case errors.Is(err, upstream.ErrRetryBudgetExceeded): // budget exhausted
case err == nil:                                   // success
default:                                           // last attempt's error
}
```

## References

- DESIGN: [DESIGN.md §M11](../DESIGN.md) "outbound resilience".
- Chaos validation: [tests/chaos/chaos_test.go](https://github.com/mikeappsec/lightweightauth/blob/main/tests/chaos/chaos_test.go) (M12 slice 8).
- Source: [pkg/upstream/guard.go](https://github.com/mikeappsec/lightweightauth/blob/main/pkg/upstream/guard.go),
  [pkg/upstream/breaker.go](https://github.com/mikeappsec/lightweightauth/blob/main/pkg/upstream/breaker.go),
  [pkg/upstream/budget.go](https://github.com/mikeappsec/lightweightauth/blob/main/pkg/upstream/budget.go).
