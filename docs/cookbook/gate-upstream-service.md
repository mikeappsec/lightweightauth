# Gate an upstream service through lwauth on Kubernetes

You run a workload in a Pod (in this recipe: an HTTP service on port
`8000`) and you want **every external request** to arrive only through
lwauth. Direct hits to the workload from anywhere else in the cluster
must fail. This recipe is the end-to-end Kubernetes deployment of that
shape — Helm install, gateway in front, NetworkPolicy gates on both
sides, and a four-shape verification you can paste into a CI smoke
test.

## What "only through this gateway" actually means

lwauth is an **authorization service**, not a proxy. It returns
`allow`/`deny` over HTTP and gRPC; it does not forward traffic. The
gating you actually deploy has three independent layers:

1. **Envoy in front of the upstream.** The data-plane proxy. Envoy
   calls lwauth via `ext_authz` before forwarding, so a deny short-
   circuits before the upstream sees the request.
2. **NetworkPolicy on the upstream Pod.** Without this, anything in
   the cluster can dial the workload directly on `:8000` and skip
   Envoy entirely. NetworkPolicy is the **only thing that makes the
   gateway non-bypassable** — Envoy + lwauth without it is security
   theatre.
3. **NetworkPolicy on the lwauth Pod.** Already shipped on by default
   in the chart (`networkPolicy.enabled: true`); locks `:9001` to
   Envoy so a hostile workload can't issue `Check` calls itself.

A diagram is worth ten paragraphs:

```text
                ┌──────────────────────────────────────────────┐
                │ Namespace: lwauth-demo                       │
client ──► envoy:80 ──(ext_authz gRPC :9001)──► lwauth         │
              │                                                │
              └────────(if allowed; HTTP)────────► backend:8000│
                                                  ▲           │
                                       ╳ NetworkPolicy:       │
                                         only envoy may reach │
                                         backend:8000         │
                └──────────────────────────────────────────────┘
```

Steps 1-4 land that picture; step 5 proves all four edges of it.

## Prerequisites

- A Kubernetes cluster with a CNI that **enforces NetworkPolicy**
  (Calico, Cilium, kube-router, GKE Dataplane V2). On a CNI that
  silently ignores NetworkPolicy (some lightweight kind setups,
  Docker Desktop's default) the gating in step 4 still renders but
  does not actually block — the recipe falls back to security
  theatre. `kubectl describe networkpolicy` and a denied-direct-hit
  probe (step 5.3) catch this.
- `kubectl`, `helm` 3.12+.
- A working `lwauth` chart (this recipe pins `image.tag=v1.1.0`; pick
  the tag matching your installed CRDs).

This recipe deploys an [`mccutchen/go-httpbin`] container as the
"upstream" because it's small, public, and echoes back exactly what
the gateway forwarded so you can see the auth headers lwauth stamps
on. Swap it for your real workload anywhere it appears — only the
Service `port: 8000` matters to the rest of the recipe.

[`mccutchen/go-httpbin`]: https://github.com/mccutchen/go-httpbin

## 1. Namespace and upstream

```bash
kubectl create namespace lwauth-demo

kubectl -n lwauth-demo apply -f - <<'YAML'
apiVersion: apps/v1
kind: Deployment
metadata:
  name: backend
  labels: { app: backend }
spec:
  replicas: 1
  selector: { matchLabels: { app: backend } }
  template:
    metadata: { labels: { app: backend } }
    spec:
      containers:
        - name: httpbin
          image: mccutchen/go-httpbin:v2.15.0
          args: ["-port", "8000"]
          ports: [{ containerPort: 8000, name: http }]
          readinessProbe:
            httpGet: { path: /status/200, port: 8000 }
---
apiVersion: v1
kind: Service
metadata:
  name: backend
spec:
  selector: { app: backend }
  ports: [{ name: http, port: 8000, targetPort: 8000 }]
YAML
```

At this point `backend.lwauth-demo.svc:8000` is reachable from
anywhere in the cluster. That is the bypass we close in step 4.

## 2. Install lwauth via Helm with the NetworkPolicy locked down

The chart's `networkPolicy` block locks **ingress to lwauth itself** —
it has nothing to do with the upstream. Default-on with no
`allowedFrom` selectors means deny-all (the documented safe failure);
we admit only the Envoy gateway we deploy in step 3.

```bash
helm install lwauth oci://ghcr.io/mikeappsec/lightweightauth/charts/lightweightauth \
  --namespace lwauth-demo \
  --set image.tag=v1.1.0 \
  --set crds.install=true \
  --set controller.enabled=true \
  --set controller.watchNamespace=lwauth-demo \
  --set controller.authConfigName=demo \
  --set 'networkPolicy.allowedFrom.podSelectors[0].app=envoy'
```

!!! warning "`allowedFrom` is `AND` between namespace and pod selectors"
    Within one `from` entry the namespace selector and pod selector
    intersect. The chart emits one entry per selector you list, so
    setting *only* a `podSelectors[0]` admits matching pods **in any
    namespace**. For this recipe both the gateway and lwauth live in
    `lwauth-demo`, so an `app=envoy` pod selector is sufficient. In a
    real deployment where the gateway is in `istio-system` or
    `gateway-system`, add a `namespaceSelectors` entry too.

Now apply the `AuthConfig` the controller will compile:

```bash
kubectl -n lwauth-demo apply -f - <<'YAML'
apiVersion: lightweightauth.io/v1alpha1
kind: AuthConfig
metadata: { name: demo }
spec:
  identifierMode: firstMatch
  identifiers:
    - name: key
      type: apikey
      config:
        headerName: x-api-key
        static:
          demo-key-alice: { subject: alice, roles: [admin] }
  authorizers:
    - name: gate
      type: rbac
      config:
        rolesFrom: claim:roles
        allow: [admin]
YAML

kubectl -n lwauth-demo wait authconfig/demo --for=condition=Ready --timeout=60s
```

If `Ready=False` here the controller's `status.conditions` carries
the compile error verbatim — fix the YAML, no daemon restart needed.

## 3. Deploy Envoy as the gateway in front of the upstream

Envoy is the only thing the public will reach. Its `ext_authz` filter
calls `lwauth.lwauth-demo.svc:9001` before forwarding to
`backend.lwauth-demo.svc:8000`.

```bash
kubectl -n lwauth-demo apply -f - <<'YAML'
apiVersion: v1
kind: ConfigMap
metadata: { name: envoy-config }
data:
  envoy.yaml: |
    static_resources:
      listeners:
      - name: ingress
        address: { socket_address: { address: 0.0.0.0, port_value: 80 } }
        filter_chains:
        - filters:
          - name: envoy.filters.network.http_connection_manager
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
              stat_prefix: ingress
              codec_type: AUTO
              route_config:
                name: local
                virtual_hosts:
                - name: backend
                  domains: ["*"]
                  routes:
                  - match: { prefix: "/" }
                    route: { cluster: backend }
              http_filters:
              - name: envoy.filters.http.ext_authz
                typed_config:
                  "@type": type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthz
                  transport_api_version: V3
                  failure_mode_allow: false
                  clear_route_cache: true
                  grpc_service:
                    envoy_grpc: { cluster_name: lwauth }
                    timeout: 0.25s
              - name: envoy.filters.http.router
                typed_config:
                  "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
      clusters:
      - name: backend
        type: STRICT_DNS
        connect_timeout: 1s
        load_assignment:
          cluster_name: backend
          endpoints:
          - lb_endpoints:
            - endpoint: { address: { socket_address: { address: backend.lwauth-demo.svc.cluster.local, port_value: 8000 } } }
      - name: lwauth
        type: STRICT_DNS
        connect_timeout: 1s
        typed_extension_protocol_options:
          envoy.extensions.upstreams.http.v3.HttpProtocolOptions:
            "@type": type.googleapis.com/envoy.extensions.upstreams.http.v3.HttpProtocolOptions
            explicit_http_config: { http2_protocol_options: {} }
        load_assignment:
          cluster_name: lwauth
          endpoints:
          - lb_endpoints:
            - endpoint: { address: { socket_address: { address: lwauth.lwauth-demo.svc.cluster.local, port_value: 9001 } } }
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: envoy
  labels: { app: envoy }
spec:
  replicas: 1
  selector: { matchLabels: { app: envoy } }
  template:
    metadata: { labels: { app: envoy } }
    spec:
      containers:
        - name: envoy
          image: envoyproxy/envoy:v1.37.3
          args: ["-c", "/etc/envoy/envoy.yaml", "--log-level", "warn"]
          ports: [{ containerPort: 80, name: http }]
          volumeMounts:
            - { name: cfg, mountPath: /etc/envoy }
      volumes:
        - { name: cfg, configMap: { name: envoy-config } }
---
apiVersion: v1
kind: Service
metadata:
  name: envoy
spec:
  selector: { app: envoy }
  ports: [{ name: http, port: 80, targetPort: 80 }]
YAML
```

Two non-default fields are doing real work:

- **`failure_mode_allow: false`** — if lwauth is unreachable, Envoy
  rejects the request rather than failing open. The chart's
  NetworkPolicy plus a single-replica lwauth deploy is a real outage
  surface; failing closed makes it a 503 instead of an authorization
  bypass.
- **`http2_protocol_options: {}` on the lwauth cluster** — the
  ext_authz contract is gRPC, which requires HTTP/2. Without this
  Envoy speaks HTTP/1.1 to lwauth and every Check call fails with
  `UNAVAILABLE`.

## 4. Lock the upstream so only Envoy can reach it

This is the layer that makes the gateway non-bypassable. Without it,
any other Pod in the cluster — a CronJob, a debug shell, the wrong
microservice — can dial `backend.lwauth-demo.svc:8000` and skip
Envoy entirely.

```bash
kubectl -n lwauth-demo apply -f - <<'YAML'
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: { name: backend-only-from-envoy }
spec:
  podSelector:
    matchLabels: { app: backend }
  policyTypes: [Ingress]
  ingress:
    - from:
        - podSelector:
            matchLabels: { app: envoy }
      ports:
        - { port: 8000, protocol: TCP }
YAML
```

!!! warning "Verify the CNI actually enforces this"
    A CNI that ignores NetworkPolicy (Docker Desktop default, some
    kind configurations, AKS without Azure CNI Powered by Cilium)
    silently accepts this manifest and gates nothing. Step 5.3 below
    is the only thing that proves the policy is real — run it on
    every fresh cluster, not just the first one.

## 5. End-to-end verification

Four probes prove every edge of the topology. Run them in order;
each one is `set -e`-safe (exits non-zero if the recipe is broken).

### 5.1 Allow path through the gateway

```bash
kubectl -n lwauth-demo port-forward svc/envoy 8080:80 >/dev/null &
PF=$!; trap "kill $PF" EXIT
sleep 1

curl -fsS http://localhost:8080/headers \
  -H 'x-api-key: demo-key-alice' \
  | tee /tmp/allow.json
```

Expected: HTTP 200 and the JSON body echoes the request headers
`go-httpbin` saw, including any `x-lwauth-*` mutator output. If you
get HTTP 401 here the `AuthConfig` did not become Ready; rerun
`kubectl -n lwauth-demo describe authconfig demo` for the compile
error.

### 5.2 Deny path through the gateway

```bash
curl -isS http://localhost:8080/headers
```

Expected: HTTP `401 Unauthorized` from Envoy with the body lwauth
returned. The upstream Pod's request log is unchanged — `kubectl -n
lwauth-demo logs deploy/backend --since=10s | wc -l` should print
`0` because the request never crossed the gateway.

### 5.3 Direct-to-upstream from another Pod is blocked

This is the probe that proves NetworkPolicy is real. Spin a one-shot
debug pod **without** the `app=envoy` label and try to reach
`backend:8000`:

```bash
kubectl -n lwauth-demo run probe --rm -it --restart=Never \
  --image=curlimages/curl:8.10.1 -- \
  curl -sS --max-time 3 -o /dev/null -w '%{http_code}\n' \
  http://backend.lwauth-demo.svc:8000/status/200
```

Expected: the curl exits non-zero with `Connection timed out` or
`Couldn't connect to server`, and the printed status code is `000`
(no HTTP response). If this prints `200`, the cluster CNI is **not**
enforcing NetworkPolicy and the gateway is bypassable — fix the CNI
before you trust this deployment.

### 5.4 Direct-to-lwauth from another Pod is blocked

Same idea for the auth port — confirms the chart's NetworkPolicy is
keeping random Pods out of `:9001`:

```bash
kubectl -n lwauth-demo run probe --rm -it --restart=Never \
  --image=curlimages/curl:8.10.1 -- \
  curl -sS --max-time 3 -o /dev/null -w '%{http_code}\n' \
  http://lwauth.lwauth-demo.svc:9001/
```

Expected: same shape as 5.3 — connection times out and `000` is
printed. (lwauth's HTTP listener on `:8080` is also gated by the same
policy; the test above happens to use the gRPC port because that's
the one Envoy actually hits.)

## What success looks like

| Probe | Expected | What it proves |
|---|---|---|
| 5.1 allow via gateway | HTTP 200, request body echoed | The full chain works end-to-end. |
| 5.2 deny via gateway | HTTP 401, upstream log unchanged | lwauth deny short-circuits before forwarding. |
| 5.3 direct upstream | connection timeout (`000`) | NetworkPolicy on the workload is enforced. |
| 5.4 direct lwauth | connection timeout (`000`) | Chart-default lockdown is real. |

If 5.1 + 5.2 pass but 5.3 fails (returns `200`), you have a working
demo and a security hole — the gateway is convenience, not a control.
Fix the CNI before promoting beyond a sandbox.

## Cleanup

```bash
helm -n lwauth-demo uninstall lwauth
kubectl delete namespace lwauth-demo
```

`crds.keep: true` (the chart default) leaves the
`AuthConfig` / `IdentityProvider` / `Plugin` CRDs behind so other
releases sharing the cluster aren't surprised. Drop them with
`kubectl delete crd authconfigs.lightweightauth.io …` if this was
the last release.

## Failure modes

- **Cluster CNI does not enforce NetworkPolicy.** Symptom: 5.3
  returns `200`. Fix: switch to a CNI that does (Calico, Cilium), or
  on managed clusters enable the equivalent policy add-on.
- **lwauth's NetworkPolicy admitted nothing.** Symptom: 5.1 returns
  `403` from Envoy with `failed to connect to upstream`; lwauth pod
  logs nothing. Fix: re-check the `--set
  'networkPolicy.allowedFrom.podSelectors[0].app=envoy'` flag — Helm
  silently ignores typos in `--set` paths.
- **`failure_mode_allow: true` left on Envoy.** Symptom: 5.2 returns
  `200`, the upstream's log records the request. Fix: re-render
  Envoy with the value as `false`. Authorization-bypass-on-failure
  is the single most common ext_authz misconfig in the wild.
- **HTTP/1.1 to lwauth.** Symptom: every request returns `503`
  regardless of API key; Envoy logs `upstream connect error`. Fix:
  the `http2_protocol_options: {}` block on the lwauth cluster.
- **`backend` is in another namespace.** Symptom: 5.3 returns `200`
  even on a real CNI. Cause: the NetworkPolicy
  `podSelector: { app: backend }` is namespace-scoped — a same-name
  Pod in another namespace is matched by Envoy's
  `from.podSelector` because no `namespaceSelector` constrains it.
  Fix: add `namespaceSelector: { matchLabels: { kubernetes.io/metadata.name: lwauth-demo } }`
  to the `from` entry.

## References

- [Helm chart values](https://github.com/mikeappsec/lightweightauth/blob/main/deploy/helm/lightweightauth/values.yaml)
  — full surface of `networkPolicy.allowedFrom`, plus the
  `controller.*` knobs used here.
- [Envoy deployment guide](../deployment/envoy.md) — the
  production-grade `ext_authz` config, including
  `with_request_body` flags this recipe omits because the demo
  policy doesn't bind the body.
- [DEPLOYMENT.md §2 Topology 2](../DEPLOYMENT.md) — the higher-level
  topology and the production checklist this recipe is one
  worked example of.
- [`apikey` identifier](../modules/apikey.md), [`rbac` authorizer](../modules/rbac.md)
  — the two modules the demo `AuthConfig` exercises.
