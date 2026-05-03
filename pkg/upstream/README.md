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

result, err := guard.Do(ctx, func(ctx context.Context) (any, error) {
    return http.Get("https://idp.example.com/introspect")
})
```

## Configuration

```yaml
# In any module's config block:
resilience:
  failureThreshold: 5
  coolDown: "30s"
  halfOpenSuccesses: 1
  retryBudgetCapacity: 10
  retryBudgetRefillPerSec: 1
  maxRetries: 2
  backoffBase: "100ms"
  backoffMax: "5s"
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `failureThreshold` | int | `5` | Consecutive failures before opening |
| `coolDown` | duration | `30s` | Time in open state before half-open probe |
| `halfOpenSuccesses` | int | `1` | Successes to close from half-open |
| `retryBudgetCapacity` | int | `10` | Retry token bucket size |
| `retryBudgetRefillPerSec` | float | `1` | Tokens added per second |
| `maxRetries` | int | `0` | Max retry attempts (0 = no retries) |
| `backoffBase` | duration | `100ms` | Initial backoff |
| `backoffMax` | duration | `5s` | Maximum backoff |

## Features

- Hystrix-style circuit breaker: Closed → Open → Half-Open → Closed
- Token-bucket retry budget prevents retry storms
- Bounded exponential backoff with jitter
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
