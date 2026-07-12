# pkg/upstream

Circuit breaker and retry budget for network-touching modules.

## Usage

```go
import (
    "github.com/mikeappsec/lightweightauth/pkg/upstream"
)

guard := upstream.NewGuard(upstream.GuardConfig{
    Breaker: upstream.BreakerConfig{
        FailureThreshold:  5,
        CoolDown:          30 * time.Second,
        HalfOpenSuccesses: 1,
    },
    Budget: upstream.RetryBudgetConfig{
        Capacity:     10,
        RefillPerSec: 1,
    },
    MaxRetries: 2,
})

var resp *http.Response
err := guard.Do(ctx, func(ctx context.Context) error {
    var err error
    resp, err = http.Get("https://idp.example.com/introspect")
    return err
})
```

`Do(ctx context.Context, fn func(context.Context) error) error` takes
a function returning only `error` and itself returns only `error` —
there's no `(any, error)` variant; capture results via closure as
shown above.

## Configuration

The YAML shape is **nested**, not flat — `breaker:` and `retries:`
sub-blocks, with the retry budget nested *inside* `retries:`
(`pkg/upstream/config.go`'s `FromMap`). A flat `resilience:
{failureThreshold: ..., retryBudgetCapacity: ...}` shape (as an
earlier version of this README showed) is silently ignored — `FromMap`
finds no `breaker`/`retries` sub-maps at the top level and produces an
all-defaults `GuardConfig`, discarding every value you set:

```yaml
# In any module's config block:
resilience:
  breaker:
    failureThreshold: 5
    coolDown: "30s"
    halfOpenSuccesses: 1
  retries:
    max: 2
    backoffBase: "100ms"
    backoffMax: "5s"
    budgetCapacity: 10
    budgetRefillPerSec: 1
```

| Block | Field | Default | Description |
|-------|-------|---------|-------------|
| `breaker` | `failureThreshold` | `5` | Consecutive failures before opening |
| `breaker` | `coolDown` | `30s` | Time in open state before half-open probe |
| `breaker` | `halfOpenSuccesses` | `1` | Successes to close from half-open |
| `retries` | `max` | `0` | Max retry attempts (0 = no retries) |
| `retries` | `backoffBase` | `0` | Initial backoff (0 = no backoff) |
| `retries` | `backoffMax` | `0` | Maximum backoff |
| `retries` | `budgetCapacity` | `0` | Retry token bucket size (0 = unlimited, bounded only by `max`) |
| `retries` | `budgetRefillPerSec` | `0` | Tokens added per second |

## Features

- Hystrix-style circuit breaker: Closed → Open → Half-Open → Closed
- Token-bucket retry budget prevents retry storms
- Bounded exponential backoff — **purely deterministic, no jitter**
  (`Guard.backoff()`: `BackoffBase * 2^(N-1)`, capped at `BackoffMax`)
- First attempt is always free (budget only gates retries)
- `ErrCircuitOpen` and `ErrRetryBudgetExceeded` sentinel errors
- Configurable `Retryable` predicate (default excludes context errors)
- All zero-value configs produce safe defaults

## How It Works

1. `Guard.Do()` first checks if the circuit breaker allows a call.
2. If open → returns `ErrCircuitOpen` immediately (no network call).
3. If closed/half-open → executes the function.
4. On success: resets failure counter, closes breaker if half-open.
5. On retryable failure: checks retry budget, applies backoff, retries.
6. After `FailureThreshold` consecutive failures: opens the circuit.
7. After `CoolDown`: transitions to half-open, allows one probe call.

## Benchmark

Guard overhead (closed circuit, no retry): ~15ns per call.

## Thread Safety

| Type | Safe for concurrent use? | Notes |
|------|--------------------------|-------|
| `Guard` | ✅ Yes | Delegates to `Breaker` + `RetryBudget`, both mutex-protected |
| `Breaker` | ✅ Yes | `sync.Mutex` protects state, failures, successes, openedAt |
| `RetryBudget` | ✅ Yes | `sync.Mutex` protects tokens and last-refill timestamp |
| `BreakerConfig` | ✅ Yes | Plain value type; immutable after construction |
| `RetryBudgetConfig` | ✅ Yes | Plain value type; immutable after construction |
| `GuardConfig` | ✅ Yes | Plain value type; immutable after construction |

`Guard.Do()` is safe to call from multiple goroutines simultaneously.
