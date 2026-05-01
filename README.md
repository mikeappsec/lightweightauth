# lightweightauth






































    ARCHITECTURE / DEPLOYMENT entries.    and security/v1.0-review.md alongside the existing DESIGN /    that surfaces QUICKSTART.md, MILESTONES.md, modules/README.md,  - Replaced the three-row Quick links table with a seven-row oneREADME.md:    metric names.    checklist", and troubleshooting bullets keyed to the right    + a real AuthConfig CR), a four-row "universal verification  - Includes a CRD-mode upgrade walkthrough (controller.enabled=true    on the response line, not a 200-with-deny-flag.    with empty body and the deny case carries the deny status code    reason/subject/identitySource), and that healthz returns 200    map<string, list<string>>/tenantId; response: allow/status/    HTTP shape (request: method/host/path/headers as  - Verified end-to-end against ./bin/lwauth: confirms the actual    deny, and /metrics.    and copy-paste verification curls covering /healthz, allow,    each with a self-contained inline AuthConfig (`apikey` + `rbac`)  - Three paths — local binary, Docker Compose, Kubernetes (Helm) —QUICKSTART.md (new):      * the verification gates the upgrade ran clean through.        refresh never gates a code release,      * container bases left at current pins so a base-image        the next controller-runtime minor),        multi_namespace_cache.handlerRegistration; pin lifts on        controller-runtime 0.23.3 does not yet implement on its        ResourceEventHandlerRegistration.HasSyncedChecker which      * why k8s.io/* held at 0.35.4 (k8s 0.36 added        structured-merge-diff + the indirect refresh wave),        alert #1, x/* + jwx + controller-runtime 0.21 → 0.23.3 +      * the bumps that landed (otel 1.41 → 1.43 closes dependabot    pinned" subsection. Documents:  - New "Dependency refresh — what landed and why some deps stayedDESIGN.md (M12 §15):A minimalistic, pluggable authentication & authorization service written in Go.
Think of it as a small, embeddable mash-up of [oauth2-proxy](https://github.com/oauth2-proxy/oauth2-proxy)
and [Authorino](https://github.com/Kuadrant/authorino):

- Run **locally** as an HTTP/gRPC sidecar.
- Run in **Kubernetes** as an external authorization service for an
  Envoy data plane (or call LightWeightAuth directly via HTTP/gRPC).
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
- Be a production-grade L7 reverse proxy.

## Project family (sibling repos)

`lightweightauth` is intentionally a small core. Larger or platform-specific
features live in sibling repositories so you only pay for what you use.
See [§9 of DESIGN.md](docs/DESIGN.md#9-repository-topology) for the full topology.

| Repo | Tier | Purpose |
|------|------|---------|
| **`lightweightauth`** *(this repo)* | 1 | Pipeline, built-in modules (JWT, mTLS, HMAC, API key, RBAC, OPA, OpenFGA), HTTP + native gRPC + Envoy `ext_authz` servers, CRDs + controller, Helm chart, plugin contract. |
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

The IdP lives in its own sibling repo and is *not* in this tree.

## License

Apache-2.0. The current `LICENSE` file is a placeholder; the full Apache-2.0
text will replace it before the first tagged release.
