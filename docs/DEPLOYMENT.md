# Deployment

This doc covers how `lwauth` is deployed alongside a data plane. For the
trade-off discussion (Envoy vs self-proxy, CRDs vs ConfigMap, etc.) see
§3 of [DESIGN.md](DESIGN.md).

## Topologies

### 1. Standalone binary (local / dev)

```
client ─► lwauth (HTTP :8080 / gRPC :9001)
                                   ▲
                                   └─ ext_authz / native gRPC clients
```

```sh
lwauth --config ./lwauth.yaml
```

This runs `lightweightauth` as an authorization service only. It does **not**
proxy traffic by itself. To put it in the data path of HTTP requests in a
single binary, use the sibling repo [lightweightauth-proxy](https://github.com/yourorg/lightweightauth-proxy):

```sh
lwauth-proxy --config ./lwauth.yaml --upstream http://localhost:9000
```

Use for local development and integration tests. Not recommended for
production at scale — see DESIGN §3 Mode B.

### 2. Envoy + lwauth sidecar (recommended)

```
client ─► Envoy ──(ext_authz gRPC)──► lwauth
              └──(if allowed)─────► upstream
```

Envoy and `lwauth` run in the same Pod (or as separate Pods sharing a
Service). Envoy's `envoy.filters.http.ext_authz` filter targets
`lwauth:9001`.

**Envoy version policy.** We test against Envoy **1.37.3** (current stable
as of 2026-04). The `envoy.service.auth.v3` API is unchanged from 1.18 →
1.37, so the wiring works on any 1.18+ Envoy. CI and the local-dev
compose use the public `envoyproxy/envoy:v1.37.3` image.

> Hardened-image support (`dhi.io/envoy`, `dhi.io/golang`, `dhi.io/alpine`)
> is deferred to a later milestone — see DESIGN.md §7.

Spin the whole topology up locally:

```sh
docker compose -f deploy/docker/compose.yaml up
# Envoy on :8000, lwauth on :8080, echo upstream behind Envoy
curl -i http://localhost:8000/whatever
```

Sample Envoy snippet:

```yaml
http_filters:
- name: envoy.filters.http.ext_authz
  typed_config:
    "@type": type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthz
    transport_api_version: V3
    grpc_service:
      envoy_grpc:
        cluster_name: lwauth
      timeout: 0.25s
    failure_mode_allow: false
```

### 3. Istio / Gateway API

Same as (2), wired via Istio's `AuthorizationPolicy` with `provider`, or
via a Gateway API extension. The lwauth side is identical — it's the
standard ext_authz contract.

### 4. Native gRPC middleware (no proxy)

App code:

```go
authConn, _ := grpc.Dial("lwauth:9000", grpc.WithTransportCredentials(...))
srv := grpc.NewServer(
    grpc.UnaryInterceptor(lwauth.UnaryInterceptor(authConn)),
)
```

For pure-gRPC stacks where introducing a proxy is overkill.

## Helm chart

Lives at [deploy/helm/lightweightauth](../deploy/helm/lightweightauth/).

```sh
helm install lwauth ./deploy/helm/lightweightauth \
    --set image.tag=v0.1.0 \
    --set crds.install=true
```

`values.yaml` highlights:

| Key | Default | Purpose |
|-----|---------|---------|
| `replicaCount` | 2 | HA. |
| `crds.install` | `true` | Install the `AuthConfig` / `AuthPolicy` CRDs. |
| `controller.enabled` | `true` | Run the CRD-watching controller. |
| `cache.backend` | `memory` | `memory` or `redis`. |
| `metrics.serviceMonitor` | `true` | Prometheus Operator integration. |

For the data-plane, install one of:

- An Envoy chart of your choice, configured with `ext_authz` pointing at
  the `lwauth` Service (sample config under [deploy/envoy/](../deploy/envoy/)).
- The `lightweightauth-proxy` chart (sibling repo) for Mode B.

## CRDs

Three CRDs in `lightweightauth.io/v1alpha1`:

- `AuthConfig` (namespaced) — main config: identifiers + authorizers + mutators.
- `AuthPolicy` (namespaced) — binds an `AuthConfig` to hosts/paths.
- `IdentityProvider` (cluster) — reusable IdP definitions.

A controller (controller-runtime) watches these and:

1. Validates them (admission webhook + status conditions).
2. Compiles them into the on-wire config format.
3. Pushes config to `lwauth` Pods via mounted ConfigMap (M4) or xDS-style
   stream (M5+).

## Production checklist

- [ ] `failure_mode_allow: false` on Envoy — fail closed.
- [ ] Resource requests/limits set on `lwauth` (it's CPU-bound on JWT verify).
- [ ] PDB allowing only `maxUnavailable: 1` if `replicaCount >= 2`.
- [ ] HPA on CPU + custom metric `lwauth_decision_latency_seconds_bucket`.
- [ ] NetworkPolicy: only Envoy/the mesh may talk to `lwauth:9001`.
- [ ] Secrets (HMAC keys, OAuth client secrets) mounted from a real secret
      manager, not committed to `AuthConfig` CRs.
- [ ] Image signed with cosign; verify via Kyverno/Sigstore policy.
