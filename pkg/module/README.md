# pkg/module

Core plugin contracts and composable decorator infrastructure for LightweightAuth.

## Interfaces

| Interface | Method | Purpose |
|-----------|--------|---------|
| `Identifier` | `Identify(ctx, *Request) (*Identity, error)` | Extract credential from request |
| `Authorizer` | `Authorize(ctx, *Request, *Identity) (*Decision, error)` | Allow/deny decision |
| `ResponseMutator` | `Mutate(ctx, *Request, *Identity, *Decision) error` | Post-authorize response modification |

All interfaces are intentionally narrow — one interface per pipeline phase.

## Generic Registry

```go
reg := module.NewRegistry[module.Identifier]("identifier")
reg.Register("jwt", jwtFactory)
reg.Register("mtls", mtlsFactory)

id, err := reg.Build("jwt", "my-jwt", rawConfig)
```

`DecoratedRegistry[T]` extends `Registry[T]` with decorator chains applied at build time:

```go
dreg := module.NewDecoratedRegistry[module.Identifier]("identifier")
dreg.AddDecorator(module.WithIdentifierTimeout(5 * time.Second))
dreg.AddDecorator(module.WithIdentifierTracing(tracer))
// All identifiers built through dreg get timeout + tracing automatically.
```

## Decorators

### Timeout

Per-module deadline enforcement. If the inner module doesn't respond within
the deadline, the context is cancelled and a diagnostic error is returned.

```go
module.WithIdentifierTimeout(5 * time.Second)
module.WithAuthorizerTimeout(3 * time.Second)
module.WithMutatorTimeout(2 * time.Second)
```

### Tracing (OTel)

Wraps each call with an OpenTelemetry span named `identifier.<name>`,
`authorizer.<name>`, or `mutator.<name>`. Captures subject/source on
success and sets error status on failure.

```go
module.WithIdentifierTracing(otel.Tracer("lwauth"))
module.WithAuthorizerTracing(otel.Tracer("lwauth"))
module.WithMutatorTracing(otel.Tracer("lwauth"))
```

### Metrics

Records per-call latency and outcome (match/no_match/error for identifiers,
allow/deny/error for authorizers).

```go
module.WithIdentifierMetrics(func(name, outcome string, d time.Duration) {
    histogram.Observe(d.Seconds(), name, outcome)
})
module.WithAuthorizerMetrics(func(name, outcome string, d time.Duration) {
    histogram.Observe(d.Seconds(), name, outcome)
})
```

### Circuit Breaker

Wraps a module with `upstream.Guard` (breaker + retry budget + exponential
backoff). When the breaker is open, calls fail fast without invoking the
inner module.

```go
guard := upstream.NewGuard(upstream.GuardConfig{
    Breaker:    upstream.BreakerConfig{Threshold: 5, Window: 10 * time.Second},
    MaxRetries: 2,
})
module.WithIdentifierBreaker(guard)
module.WithAuthorizerBreaker(guard)
module.WithMutatorBreaker(guard)
```

### Shadow Authorizer

Runs a shadow policy alongside the production authorizer and reports
disagreements via callback. The shadow's result is never used for the
actual decision — it's observe-only.

```go
module.WithShadowAuthorizer(shadowAuthorizer, func(prod, shadow *module.Decision, shadowErr error) {
    metrics.IncShadowDisagreement()
})
```

### Observability (legacy)

```go
module.WithObservability(func(name string, err error) {
    // Called after every Identify
})
```

## Configuration Helper

`DecodeConfig(raw map[string]any, target *T)` uses struct tags for validation:

```go
type Config struct {
    Address string `lwauth:"required"`
    Timeout string `lwauth:"default=5s"`
    Retries int    `lwauth:"default=3,min=0,max=10"`
}
var cfg Config
err := module.DecodeConfig(rawMap, &cfg)
```

## Design Principles

- Modules MUST be safe for concurrent use
- All methods take `*Request` carrying HTTP/gRPC metadata
- Modules MAY add entries to `Request.Context` but MUST NOT retain references
- Decorators compose cleanly without factories knowing about each other
- Zero-cost when not configured (nil checks on hot path)
