# lightweightauth

A minimalistic, pluggable authentication & authorization service written in Go.
Think of it as a small, embeddable mash-up of [oauth2-proxy](https://github.com/oauth2-proxy/oauth2-proxy)
and [Authorino](https://github.com/Kuadrant/authorino):

- Run **locally** as an HTTP/gRPC sidecar.
- Run in **Kubernetes** as an external authorization service for an
  Envoy data plane (or call LightWeightAuth directly via HTTP/gRPC).
- **Pluggable modules** — swap the IdP, the policy engine, the token validator,
  or the secret store with built-in defaults or your own implementation.

> Status: v1.2 (Tier F). See [docs/DESIGN.md](docs/DESIGN.md) for the full
> architecture and trade-off discussion. Licensed under Apache-2.0.

## Goals

1. Be small. A single static binary with a clean module boundary.
2. Be embeddable. Both as a library (`import`) and as a sidecar (gRPC/HTTP).
3. Be pluggable. Every "policy decision point" is an interface with a default impl.
4. Be Kubernetes-native. CRDs + Helm chart, but also work standalone.
5. Be fast. Decision caching is a first-class design concern, not an afterthought.

## Non-goals

- Replace a full enterprise IdP (Keycloak, Auth0, Okta) — see `lightweightauth-idp`.
- Implement every OAuth2 / OIDC corner case on day one.
- Be a service mesh. We integrate with one (Envoy ext_authz) instead.
- Be a production-grade L7 reverse proxy.

## Project family (sibling repos)

`lightweightauth` is intentionally a small core. Larger or platform-specific
features live in sibling repositories so you only pay for what you use.
See [§9 of DESIGN.md](docs/DESIGN.md#9-repository-topology) for the full topology.

| Repo | Tier | Purpose |
|------|------|---------|
| **`lightweightauth`** *(this repo)* | 1 | Pipeline, built-in modules (JWT, OAuth2, mTLS, HMAC, API key, DPoP, introspection — RBAC, CEL, OPA, OpenFGA, SpiceDB, composite — WASM & gRPC plugins), HTTP + native gRPC + Envoy `ext_authz` servers, CRDs + controller, Helm chart, rate limiting, revocation, federation, bundle registry, session management. |
| **`lightweightauth-idp`** | 2 | Built-in IdP: OIDC issuer, token endpoint, optional admin UI, user store. |
| **`lightweightauth-ebpf`** | 3 *(post-v1)* | Mode-C eBPF redirector for transparent enforcement. Linux only. |
| **`lightweightauth-plugins`** | 2 | SDKs (Go / Python / Rust) and reference out-of-process plugins. |

## Quick links

| Doc | Purpose |
|-----|---------|
| [docs/QUICKSTART.md](docs/QUICKSTART.md) | Build & run locally, in Docker Compose, or in Kubernetes — with verification curls |
| [docs/API.md](docs/API.md) | Centralized HTTP + gRPC endpoint reference (paths, ports, wire shapes, auth expectations) |
| [docs/MILESTONES.md](docs/MILESTONES.md) | M0–M12 feature timeline with copy-paste YAML / Go samples |
| [docs/modules/README.md](docs/modules/README.md) | Per-module reference (every `type:` string + sample) |
| [docs/DESIGN.md](docs/DESIGN.md) | Requirements → recommended design + trade-offs (incl. post-v1 roadmap) |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Component layout, request flow, plugin model |
| [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) | Kubernetes, CRDs, Helm, Envoy integration |
| [docs/security/v1.0-review.md](docs/security/v1.0-review.md) | v1.0 security self-review |

## Repo layout (planned)

```
lightweightauth/
├── cmd/
│   ├── lwauth/              # main service binary (HTTP + gRPC ext_authz/native)
│   └── lwauthctl/           # CLI for config validation, policy management, debugging
├── api/
│   ├── proto/               # gRPC: Envoy ext_authz v3 + native API + plugin v1
│   └── crd/                 # Kubernetes CRD types (AuthConfig, AuthPolicy, IdentityProvider)
├── internal/
│   ├── server/              # HTTP + gRPC servers, ext_authz adapter
│   ├── pipeline/            # auth pipeline: identify → authorize → mutate
│   ├── controller/          # CRD watcher + config push
│   ├── cache/               # decision + JWKS + token-introspection cache
│   └── config/              # config loading, hot reload
├── pkg/
│   ├── module/              # public plugin interfaces + decorator infrastructure
│   ├── identity/            # JWT, OAuth2, mTLS, HMAC, API key, DPoP, introspection
│   ├── authz/               # RBAC, CEL, OPA, OpenFGA, SpiceDB, composite
│   ├── mutator/             # header add/remove/passthrough, JWT issue
│   ├── plugin/              # gRPC + WASM plugin runtimes
│   ├── connpool/            # process-wide connection singletons (Valkey, HTTP, gRPC)
│   ├── ratelimit/           # per-tenant token-bucket rate limiter
│   ├── revocation/          # credential deny-list (memory + Valkey + parallel checker)
│   ├── session/             # browser session (cookie + memory stores)
│   ├── keyrotation/         # verifier-side key rotation with overlap model + reaper
│   ├── upstream/            # circuit breaker + retry budget
│   ├── bundle/              # OCI policy bundle pack/push/pull
│   ├── federation/          # multi-cluster config + revocation sync
│   ├── configstream/        # xDS-style config snapshot streaming
│   ├── observability/       # metrics, tracing, audit (unified facade singleton)
│   ├── buildinfo/           # build metadata + FIPS status
│   ├── lwauthd/             # public daemon embedding surface
│   └── client/go/           # Go SDK for callers of lwauth-protected services
├── deploy/
│   ├── helm/lightweightauth/
│   └── envoy/               # sample Envoy configs
├── docs/
└── examples/
```

The IdP lives in its own sibling repo and is *not* in this tree.

## License

Apache-2.0. The current `LICENSE` file is a placeholder; the full Apache-2.0
text will replace it before the first tagged release.

## Thread Safety

LightweightAuth is designed for high-concurrency server workloads. The following guarantees apply:

- **All module interfaces** (`Identifier`, `Authorizer`, `Mutator`) are safe for concurrent use after construction. The pipeline calls them from multiple goroutines simultaneously.
- **Configuration is immutable** — once a module is built via its factory, no fields change. Hot-reload swaps the entire compiled engine atomically via `configstream.Broker`.
- **Shared infrastructure** (rate limiter, circuit breaker, replay caches, session stores) is internally synchronized with mutexes or atomic operations.
- **Plain value types** (`module.Request`, `module.Identity`, `module.Decision`) are caller-owned per-call and not shared.

See each package's README for per-type thread-safety tables.
