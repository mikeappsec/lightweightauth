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
# file-mode (default): static config, optional fsnotify hot reload
lwauth --config ./lwauth.yaml --watch-config-file

# CRD-mode: watch an AuthConfig CR in a namespace
lwauth --watch-namespace=auth-system --authconfig-name=default
```

This runs `lightweightauth` as an authorization service only. It does **not**
proxy traffic by itself. To put it in the data path of HTTP requests in a
single binary, use the sibling repo [lightweightauth-proxy](https://github.com/mikeappsec/lightweightauth-proxy):

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

Sample boot config: [deploy/envoy/sample.yaml](https://github.com/mikeappsec/lightweightauth/blob/main/deploy/envoy/sample.yaml)
— this is the *minimum that boots*. The **minimum that's safe in
production** (body-binding flags, forwarded-header trust, mTLS anchor
wiring, header redaction) is documented separately in
[docs/deployment/envoy.md](deployment/envoy.md), which also explains
the Envoy half of [SEC-PROXY-1](security/v1.0-review.md#10-outstanding-follow-ups-post-v10).
If you skip that page you will likely deploy a configuration that
silently bypasses HMAC body binding.

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

Lives at [deploy/helm/lightweightauth](https://github.com/mikeappsec/lightweightauth/tree/main/deploy/helm/lightweightauth/).

```sh
helm install lwauth ./deploy/helm/lightweightauth \
    --set image.tag=v0.1.0 \
    --set crds.install=true
```

`values.yaml` highlights:

| Key | Default | Purpose |
|-----|---------|---------|
| `replicaCount` | `2` | HA when not autoscaled. |
| `config.inline` | minimal stub | Inline AuthConfig YAML (file-mode). |
| `config.watch` | `true` | fsnotify hot reload of the mounted ConfigMap. |
| `crds.install` | `true` | Install `AuthConfig` / `AuthPolicy` / `IdentityProvider` CRDs (`helm.sh/resource-policy: keep`). |
| `crds.keep` | `true` | Leave CRDs behind on `helm uninstall`. |
| `controller.enabled` | `false` | Switch from file-mode to CRD-mode. |
| `controller.watchNamespace` | `""` (release ns) | Namespace whose CRs the controller watches. |
| `controller.authConfigName` | `default` | Name of the `AuthConfig` CR to follow. |
| `serviceAccount.create` | `true` | Create the SA used by the controller. |
| `rbac.create` | `true` | Install ClusterRole + binding on `lightweightauth.io/*`. |
| `autoscaling.enabled` | `false` | HPA on CPU. |
| `podDisruptionBudget.enabled` | `false` | PDB with `minAvailable: 1`. |
| `networkPolicy.enabled` | `false` | Lock ingress to listed peers. |
| `metrics.serviceMonitor` | `false` | Requires prometheus-operator CRDs. |

> Cache backend (`memory` / `redis`), token introspection, and
> ServiceMonitor metric content land in M5–M9; the toggles above are
> the chart-level surface area as of M4.

For the data-plane, install one of:

- An Envoy chart of your choice, configured with `ext_authz` pointing at
  the `lwauth` Service (sample config under [deploy/envoy/](https://github.com/mikeappsec/lightweightauth/tree/main/deploy/envoy/)).
- The `lightweightauth-proxy` chart (sibling repo) for Mode B.

## CRDs

Three CRDs in `lightweightauth.io/v1alpha1`:

- `AuthConfig` (namespaced) — main config: identifiers + authorizers + mutators.
- `AuthPolicy` (namespaced) — binds an `AuthConfig` to hosts/paths.
- `IdentityProvider` (cluster) — reusable IdP definitions.

A controller (controller-runtime) watches these and:

1. Reports compile health on `.status` (`ready`, `observedGeneration`,
   `message`). Bad specs are surfaced via the CR, never crash the pod.
2. Compiles `spec` into a `*pipeline.Engine`.
3. Publishes the engine in-process via `EngineHolder.Swap` — every
   subsequent decision uses the new engine atomically. Single-replica
   file-replacement model in M4; xDS-style cluster-wide push lands in
   M11.

## Production checklist

Mode A (Envoy) operators should also work through the dedicated
[Envoy deployment guide](deployment/envoy.md#5-production-checklist),
which covers the SEC-PROXY-1 / SEC-MTLS-1 configuration traps that
are not visible from this page.

- [ ] `failure_mode_allow: false` on Envoy — fail closed.
- [ ] `with_request_body` configured iff any identifier or policy binds
      the body (HMAC, body-keyed CEL/OPA). When set:
      `allow_partial_message: false` and `pack_as_bytes: true` — both
      default-wrong for HMAC. See
      [deployment/envoy.md §3](deployment/envoy.md#3-sec-proxy-1-parity).
- [ ] `include_peer_certificate: true` if and only if you use the
      `mtls` identifier; lwauth-side `trustedIssuers` / `trustedCAs`
      configured (SEC-MTLS-1 fails closed at startup otherwise).
- [ ] Forwarded-header trust pinned: `use_remote_address: true` +
      `xff_num_trusted_hops` set to the real hop count. Don't accept
      arbitrary XFF chains.
- [ ] `response_headers_to_remove: [x-lwauth-reason]` on the outermost
      Envoy so verbose deny reasons don't leak to clients.
- [ ] Resource requests/limits set on `lwauth` (it's CPU-bound on JWT verify).
- [ ] PDB allowing only `maxUnavailable: 1` if `replicaCount >= 2`.
- [ ] HPA on CPU + custom metric `lwauth_decision_latency_seconds_bucket`.
- [ ] NetworkPolicy: only Envoy/the mesh may talk to `lwauth:9001`.
- [ ] Secrets (HMAC keys, OAuth client secrets) mounted from a real secret
      manager, not committed to `AuthConfig` CRs.
- [ ] Image signed with cosign; verify via Kyverno/Sigstore policy.
