# Architecture

This document zooms in on the *internal* structure of the `lwauth` binary.
For the "why" behind these choices, read [DESIGN.md](DESIGN.md) first.

## Component diagram

```
            ┌──────────────────── lwauth process ───────────────────────┐
            │                                                          │
  HTTP   ──►│ httpserver ─┐                                            │
            │             │                                            │
  gRPC    ─►│ grpcnative ─┼─► pipeline.Engine ─► decision               │
  native    │             │     │     ▲                                │
            │             │     │     │                                │
  Envoy   ─►│ extauthz ───┘     │     └── cache layer (lru+singleflight│
  ext_authz │                   │            jwks · introspect · auth) │
            │                   ▼                                      │
            │            ┌─ Identifier ─┐  ┌─ Authorizer ─┐  ┌Mutator┐ │
            │            │ jwt   apikey │  │ rbac   opa   │  │ jwt   │ │
            │            │ mtls  hmac   │  │              │  │ issue │ │
            │            │ oauth2       │  │              │  │       │ │
            │            └──────────────┘  └──────────────┘  └───────┘ │
            │                                                          │
            │ config.Source ◄── file / CRD informer / xDS              │
            └──────────────────────────────────────────────────────────┘
```

## Request flow (Envoy ext_authz path)

```
client ─► Envoy ─(CheckRequest)─► lwauth.extauthz
                                       │
                                       ▼
                              pipeline.Evaluate(req)
                                       │
                         ┌───────────────┼────────────────┐
                         ▼               ▼                ▼
                    Rate Limit     Revocation        Identify
                   (per-tenant     Check            (try each
                    bucket)        (deny-list)       in order)
                         │               │                │
                         ▼               ▼                ▼
                   if exceeded:    if revoked:       Authorize
                   → 429            → 401            (run configured
                                                     authorizer(s))
                                                         │
                                                         ▼
                                                      Mutate
                                                    (add headers,
                                                     mint JWT)
                                                         │
                                                         ▼
                 CheckResponse ─► Envoy ─(allow + headers)─► upstream
                                         (or 401/403/429 to client)
```

## Pipeline contract

Implemented in `internal/pipeline`. Each `Engine` is **immutable**; config
reload constructs a new `Engine` and swaps `atomic.Pointer[Engine]` so live
requests never see a half-applied config.

```go
type Engine struct {
    identifiers    []module.Identifier
    authorizer     module.Authorizer       // single composite (and/or)
    mutators       []module.ResponseMutator
    identifierMode IdentifierMode          // FirstMatch | AllMust
    decisionCache  *cache.Decision
    revocationStore revocation.Store
}

func (e *Engine) Evaluate(ctx, req) (*Decision, *Identity, error)
```

### Identifier modes

| Mode | Execution | Behaviour |
|------|-----------|-----------|
| `FirstMatch` | Sequential | First non-ErrNoMatch result wins; other errors are terminal |
| `AllMust` | Concurrent (`errgroup`) | All identifiers fan out in parallel; first error cancels rest; claims merge in config order (first-writer-wins) |

### Revocation checking

After identification, revocation keys are checked concurrently via
`revocation.ParallelChecker` (bounded `errgroup`). For the common 2-key
case (jti + sub), this halves the latency vs sequential lookups.

## Concurrency model

- One goroutine per inbound RPC (gRPC / HTTP).
- **FirstMatch identifiers** run sequentially (cheap, deterministic, early-exit).
- **AllMust identifiers** fan out concurrently via `errgroup` with bounded
  goroutines — all must succeed, first error cancels the rest. Claims merge
  in config order (first-writer-wins).
- **Revocation checks** use `ParallelChecker` to query multiple keys
  concurrently (bounded worker pool), eliminating sequential round-trips.
- Cache lookups go through `singleflight` keyed by the cache key, so a
  thousand simultaneous requests for the same JWKS/token cause one upstream
  call.
- **Background workers**: Key rotation `Reaper` goroutine, NegCache reaper,
  JWKS refresh (delegated to jwx library).

## Connection pools (Singleton)

Process-wide connection pool singletons in `pkg/connpool` eliminate connection
churn on config reload and share connections across subsystems:

| Pool | Key | Purpose |
|------|-----|---------|
| `connpool.GetValkey(cfg)` | address+user | Shared Valkey client (cache + revocation) |
| `connpool.GetHTTP(base)` | base URL | Shared `*http.Client` with timeouts |
| `connpool.GetGRPC(target, opts)` | target+creds | Shared gRPC `*ClientConn` |

## Configuration & hot reload

```
config.Source ── pushes ──► config.Compiler ── builds ──► *Engine
                                                            │
                                          atomic.Pointer ◄──┘
```

- `config.Source` is an interface: `File`, `CRDInformer`, `XDS`.
- `config.Compiler` validates the config, instantiates modules from the
  registry, and returns a fully-constructed `*Engine`. Errors here mean the
  *new* config is rejected; the previous Engine keeps serving.

## Plugin registry

```go
// pkg/module/generic_registry.go
type Registry[T any] struct { ... }
func NewRegistry[T any](kind string) *Registry[T]
func (r *Registry[T]) Register(typeName string, factory FactoryFunc[T])
func (r *Registry[T]) Build(typeName, instanceName string, cfg map[string]any) (T, error)
```

The `Registry[T]` is generic over `Identifier`, `Authorizer`, and `ResponseMutator`.
Built-ins call `Register()` in their `init()`. A `DecoratedRegistry[T]` extends this
with a composable decorator chain applied automatically at build time.

### Decorator chain

Cross-cutting concerns are applied via decorators rather than embedding logic in
the pipeline engine:

| Decorator | Purpose |
|-----------|---------|
| `WithIdentifierTimeout(d)` | Per-module deadline enforcement |
| `WithIdentifierTracing(tracer)` | OTel span per Identify call |
| `WithIdentifierMetrics(fn)` | Per-call latency/outcome recording |
| `WithIdentifierBreaker(guard)` | Circuit breaker + retry budget |
| `WithAuthorizerTimeout(d)` | Per-authorizer deadline |
| `WithAuthorizerTracing(tracer)` | OTel span per Authorize call |
| `WithAuthorizerMetrics(fn)` | Per-call latency/outcome recording |
| `WithAuthorizerBreaker(guard)` | Circuit breaker + retry budget |
| `WithShadowAuthorizer(shadow, fn)` | Run shadow policy, report disagreements |
| `WithMutatorTimeout(d)` | Per-mutator deadline |
| `WithMutatorTracing(tracer)` | OTel span per Mutate call |
| `WithMutatorBreaker(guard)` | Circuit breaker + retry budget |

Decorators compose via `DecoratedRegistry.AddDecorator(func(T) T)` — they wrap
every module produced by `Build()` in the order they are added (first = innermost).

## Server layer

| File | Responsibility |
|------|----------------|
| `internal/server/http.go` | Native HTTP API + `/healthz`, `/metrics`. |
| `internal/server/grpc_native.go` | `lightweightauth.v1.Auth` service. |
| `internal/server/extauthz.go` | `envoy.service.auth.v3.Authorization`; translates `CheckRequest` ↔ `module.Request` and `Decision` ↔ `CheckResponse`. |

> **Note.** The reverse-proxy (Mode B) data plane is **not** in this repo.
> It lives in the sibling `lightweightauth-proxy` repository, which imports
> this module and wraps `pipeline.Evaluate` with `httputil.ReverseProxy`.
> See [DESIGN.md §9](DESIGN.md#9-repository-topology).

## Error taxonomy

The pipeline distinguishes:

- **RateLimited** — per-tenant rate limit exceeded. 429.
- **Revoked** — credential found in revocation store. 401.
- **NoIdentity** — no identifier matched. Maps to 401.
- **InvalidCredential** — identifier matched but verification failed. 401.
- **Forbidden** — authorizer denied. 403.
- **ConfigError** — bad config / module error. 500 + alert metric.
- **Upstream** — IdP/JWKS unreachable. 503 with `Retry-After`.

Surfacing these distinctly is what enables negative caching to be safe
(only cache `Forbidden`, never `Upstream`).
