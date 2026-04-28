# API surface

This is the single reference for every endpoint a default `lwauth`
process exposes. It is hand-written today; the post-v1 roadmap item
[DOC-OPENAPI-1](DESIGN.md) plans to generate an OpenAPI 3.1
document from the same Go structs so this file stops being the source
of truth.

> **Listener defaults.** HTTP on `:8080`, gRPC on `:9001`. Both are
> overridable at startup (`--http-addr`, `--grpc-addr`). Probe paths
> use the Kubernetes `/*z` convention (kube-apiserver / kubelet /
> controller-manager) so they don't collide with user routes; the
> Helm chart's `livenessProbe` and `readinessProbe` defaults assume
> these names.

## HTTP — port `:8080`

Always mounted by [internal/server/http.go](../internal/server/http.go):

| Method | Path | Purpose | Status codes |
|---|---|---|---|
| `POST` | `/v1/authorize` | Main authorization decision (Door C — direct HTTP). Accepts the request shape below; returns `200`/`401`/`403`/`5xx` mirroring the engine decision. | `200` allow, `4xx`/`5xx` deny with `reason` populated |
| `GET`  | `/healthz`       | Liveness. Always `200` once the process is up. K8s uses this to decide *restart*. | `200` |
| `GET`  | `/readyz`        | Readiness. `200` once `EngineHolder.Load()` returns a compiled engine; `503` until then. K8s uses this to decide *route traffic*. | `200`, `503` |
| `GET`  | `/metrics`       | Prometheus scrape. Surfaces the M9 counter/histogram set (`lwauth_decisions_total`, `lwauth_decision_latency_seconds`, `lwauth_identifier_total`, `lwauth_cache_*`). | `200` |

Mounted dynamically when an `oauth2` identifier is configured
([pkg/identity/oauth2/oauth2.go](../pkg/identity/oauth2/oauth2.go)):

| Method | Path | Purpose |
|---|---|---|
| `GET`  | `/oauth2/start`             | Begin auth-code flow (PKCE + state). Redirects to the IdP. |
| `GET`  | `/oauth2/callback`          | IdP redirect target; exchanges `code`, mints session cookie. |
| `GET`  | `/oauth2/userinfo`          | Returns the session subject + email + access-token expiry; opportunistic refresh. |
| `POST` | `/oauth2/refresh`           | Explicit refresh-token rotation. |
| `GET`  | `/oauth2/logout`            | RP-initiated logout (OIDC RP-Initiated Logout 1.0). |
| `POST` | `/oauth2/device/start`      | Device Authorization Grant (RFC 8628) — proxy to IdP device endpoint. Only mounted when `deviceAuthUrl` is configured. |
| `POST` | `/oauth2/device/poll`       | Device-grant token poll. `200`/`202`/`4xx` with the IdP body verbatim on terminal errors. |

Any third-party module that implements
[`module.HTTPMounter`](../pkg/module/module.go) mounts under its own
prefix the same way.

### `POST /v1/authorize` — wire shape

Request body (`Content-Type: application/json`):

```json
{
  "method": "GET",
  "host": "api.example.com",
  "path": "/things/42",
  "headers": { "X-Api-Key": ["demo-key-alice"] },
  "tenantId": "acme"
}
```

- `headers` is `map<string, list<string>>` — Envoy ext_authz
  convention. Every value is a JSON array even when there is one.
- `tenantId` is optional; absent = empty tenant. It feeds the
  per-tenant rate limiter, cache key, audit line, and metric labels.

Response body:

```json
{
  "allow": true,
  "subject": "alice",
  "identitySource": "key",
  "status": 200,
  "reason": "",
  "upstreamHeaders": { "X-User": ["alice"] },
  "responseHeaders": {}
}
```

- On deny, the HTTP status code carries the deny status (`401`/`403`/
  `5xx`) — it is **not** a `200` with `allow=false`. `reason` is the
  human-readable cause; `upstreamHeaders` is empty.
- On allow, `upstreamHeaders` carries any mutator additions
  (`jwt-issue`, `header-add`, `${sub}` expansion, etc.) — proxies in
  front of `lwauth` are expected to merge these onto the upstream
  request.

## gRPC — port `:9001`

Always registered by [pkg/lwauthd/lwauthd.go](../pkg/lwauthd/lwauthd.go):

| Service | RPC(s) | Purpose |
|---|---|---|
| `envoy.service.auth.v3.Authorization` | `Check` (unary) | **Door A.** The Envoy ext_authz contract; this is what an `envoy.filters.http.ext_authz` HttpFilter calls. Allow → `OK`; deny → `PermissionDenied` with a `DeniedHttpResponse` (status + body + headers). |
| `lightweightauth.v1.Auth`             | `Authorize` (unary), `AuthorizeStream` (bidi) | **Door B.** Native gRPC for first-party callers. Decision travels in the body (`allow` boolean + `status` + `deny_reason`), not in the gRPC status, so callers can read both deny reason and response headers in one round trip. `AuthorizeStream` does NOT close on a deny — the caller decides when to disconnect. |
| `grpc.health.v1.Health`               | `Check`, `Watch`           | Standard gRPC health protocol. Advertises both service names above as `SERVING`. Used by `grpc_health_probe`, Envoy clusters, and K8s gRPC probes. |
| _(server reflection)_                 | (the standard set)         | `google.golang.org/grpc/reflection`; lets `grpcurl` enumerate services without a `.proto` file. Disable in production via build flags if undesired. |

Wired only when a control-plane embeds `pkg/configstream`
([pkg/configstream/grpc.go](../pkg/configstream/grpc.go)):

| Service | RPC | Purpose |
|---|---|---|
| `lightweightauth.v1.ConfigDiscovery` | `StreamAuthConfig` (server-streaming) | xDS-style config push. The reconciler calls `Broker.Publish(snapshot)` after every successful Compile-and-Swap; subscribers receive JSON-encoded snapshots tagged with a monotonic version. Latest-wins conflation guarantees a slow consumer can never block `Publish`; late subscribers are primed with the current snapshot. |

### Quick verification

```sh
# HTTP
curl -fsS http://localhost:8080/healthz                               # liveness
curl -fsS http://localhost:8080/readyz                                # readiness
curl -fsS http://localhost:8080/metrics | head                        # Prometheus

curl -isS -X POST http://localhost:8080/v1/authorize \
  -H 'Content-Type: application/json' \
  -d '{"method":"GET","path":"/things","headers":{"X-Api-Key":["demo-key-alice"]}}'

# gRPC (reflection-driven)
grpcurl -plaintext localhost:9001 list
# → envoy.service.auth.v3.Authorization
# → grpc.health.v1.Health
# → grpc.reflection.v1.ServerReflection
# → lightweightauth.v1.Auth

grpcurl -plaintext -d '{"service":"lightweightauth.v1.Auth"}' \
  localhost:9001 grpc.health.v1.Health/Check
# → { "status": "SERVING" }

grpcurl -plaintext -d '{
  "method":"GET","path":"/things",
  "headers":{"x-api-key":"demo-key-alice"}
}' localhost:9001 lightweightauth.v1.Auth/Authorize
```

## Authentication on the API surface itself

| Endpoint | Who's expected to call it | Auth |
|---|---|---|
| `POST /v1/authorize`               | Application proxies / SDKs | None (the *body* carries the credential being authorized). Co-locate with the workload or restrict via NetworkPolicy. |
| `/healthz`, `/readyz`              | Kubernetes / load balancers | None. Idiomatic K8s convention; keep on a private interface or rely on NetworkPolicy. |
| `/metrics`                         | Prometheus scrape          | None. The Helm chart's NetworkPolicy peers selector restricts the source. The post-v1 admin gate ([DOC-OPENAPI-1](DESIGN.md)) covers `/openapi.json` here too. |
| `/oauth2/*`                        | Browsers + IdPs            | Per-flow (PKCE, state cookie, RP-initiated logout). |
| `lightweightauth.v1.Auth`          | First-party services       | TLS on the listener; mTLS via the standard gRPC server credentials. |
| `lightweightauth.v1.ConfigDiscovery` | Control plane only       | TLS on the listener; mTLS strongly recommended — this is a config-push surface. |

## Roadmap items that change this surface

- [DOC-OPENAPI-1](DESIGN.md) — generate this catalog from the Go
  structs and serve at `GET /openapi.json` behind an admin gate.
- [M14](DESIGN.md) — `POST /v1/admin/revoke` (decision-cache
  invalidation, audited).
- [M10-PLUGIN-LIFECYCLE](DESIGN.md) — adds an optional supervised
  dial path (no new public endpoint, but the gRPC dial credentials
  contract gains mTLS).

See [DESIGN.md §7](DESIGN.md) for the full post-v1 roadmap.
