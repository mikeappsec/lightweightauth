# lightweightauth

A minimalistic, pluggable authentication & authorization service written in Go.
Think of it as a small, embeddable mash-up of [oauth2-proxy](https://github.com/oauth2-proxy/oauth2-proxy)
and [Authorino](https://github.com/Kuadrant/authorino):

- Run **locally** as an HTTP/gRPC sidecar.
- Run in **Kubernetes** as an external authorization service for an
  Envoy data plane (or `lightweightauth-proxy`, our sibling repo).
- **Pluggable modules** — swap the IdP, the policy engine, the token validator,
  or the secret store with built-in defaults or your own implementation.

> Status: design phase. See [docs/DESIGN.md](docs/DESIGN.md) for the full
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
- Be a production-grade L7 reverse proxy — that lives in `lightweightauth-proxy`.

## Project family (sibling repos)

`lightweightauth` is intentionally a small core. Larger or platform-specific
features live in sibling repositories so you only pay for what you use.
See [§9 of DESIGN.md](docs/DESIGN.md#9-repository-topology) for the full topology.

| Repo | Tier | Purpose |
|------|------|---------|
| **`lightweightauth`** *(this repo)* | 1 | Pipeline, built-in modules (JWT, mTLS, HMAC, API key, RBAC, OPA, OpenFGA), HTTP + native gRPC + Envoy `ext_authz` servers, CRDs + controller, Helm chart, plugin contract. |
| **`lightweightauth-proxy`** | 1 | Mode-B reverse proxy. Imports this repo as a library, owns TLS hot-reload / HTTP/2 / optional HTTP/3. |
| **`lightweightauth-idp`** | 2 | Built-in IdP: OIDC issuer, token endpoint, optional admin UI, user store. |
| **`lightweightauth-ebpf`** | 3 *(post-v1)* | Mode-C eBPF redirector for transparent enforcement. Linux only. |
| **`lightweightauth-plugins`** | 2 | SDKs (Go / Python / Rust) and reference out-of-process plugins. |

## Quick links

| Doc | Purpose |
|-----|---------|
| [docs/DESIGN.md](docs/DESIGN.md) | Requirements → recommended design + trade-offs |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Component layout, request flow, plugin model |
| [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) | Kubernetes, CRDs, Helm, Envoy integration |

## Repo layout (planned)

```
lightweightauth/
├── cmd/
│   ├── lwauth/              # main service binary (HTTP + gRPC ext_authz/native)
│   └── lwauthctl/           # optional CLI for local config / debugging
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
│   ├── module/              # public plugin interfaces (stable API)
│   ├── identity/            # JWT, OAuth2, mTLS, HMAC, API key built-ins
│   └── authz/               # RBAC, OPA, OpenFGA/SpiceDB adapters
├── deploy/
│   ├── helm/lightweightauth/
│   └── envoy/               # sample Envoy configs
├── docs/
└── examples/
```

The reverse-proxy code (Mode B) and the IdP live in their respective sibling
repos and are *not* in this tree.

## License

Apache-2.0. The current `LICENSE` file is a placeholder; the full Apache-2.0
text will replace it before the first tagged release.
