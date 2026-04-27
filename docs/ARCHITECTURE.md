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
                   Identify        Authorize         Mutate
                  (try each      (run configured   (add headers,
                   in order)      authorizer(s))    mint JWT)
                       │
                       ▼
                  cache lookups
                       │
                       ▼
                 CheckResponse ─► Envoy ─(allow + headers)─► upstream
                                         (or 401/403 to client)
```

## Pipeline contract

Implemented in `internal/pipeline`. Each `Engine` is **immutable**; config
reload constructs a new `Engine` and swaps `atomic.Pointer[Engine]` so live
requests never see a half-applied config.

```go
type Engine struct {
    identifiers []module.Identifier
    authorizer  module.Authorizer       // single composite (and/or)
    mutators    []module.ResponseMutator
    cache       *cache.Layer
}

func (e *Engine) Evaluate(ctx, req) (*Decision, error)
```

## Concurrency model

- One goroutine per inbound RPC (gRPC / HTTP). No worker pools.
- Identifiers run **sequentially** by default (cheap, deterministic). A
  config flag enables parallel evaluation when an `AuthConfig` lists many
  independent identifiers.
- Cache lookups go through `singleflight` keyed by the cache key, so a
  thousand simultaneous requests for the same JWKS/token cause one upstream
  call.

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
// pkg/module/registry.go (sketch)
var identifiers = map[string]Factory{}
func RegisterIdentifier(name string, f Factory) { identifiers[name] = f }
```

Built-ins call this in their `init()`. The compile-time registry is the
default; an out-of-process registry adapter can be added later that wraps a
gRPC plugin behind the same `Identifier` interface.

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

- **NoIdentity** — no identifier matched. Maps to 401.
- **InvalidCredential** — identifier matched but verification failed. 401.
- **Forbidden** — authorizer denied. 403.
- **ConfigError** — bad config / module error. 500 + alert metric.
- **Upstream** — IdP/JWKS unreachable. 503 with `Retry-After`.

Surfacing these distinctly is what enables negative caching to be safe
(only cache `Forbidden`, never `Upstream`).
