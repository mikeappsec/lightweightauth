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

### Optional: a local kind cluster that *does* enforce NetworkPolicy

If you're testing this recipe on Docker Desktop, Rancher Desktop, or a
stock kind cluster, NetworkPolicy is silently ignored — probes 5.3 and
5.4 will return `200` instead of `000` and the gateway is bypassable.
The shortest path to a local cluster that *does* enforce policy is
kind with kindnet disabled and Cilium installed as the CNI:

```bash
cat <<'YAML' > /tmp/kind-cilium.yaml
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
name: lwauth
networking:
  disableDefaultCNI: true   # so Cilium can be the only CNI
  kubeProxyMode: none       # so Cilium can fully replace kube-proxy
nodes:
  - role: control-plane
  - role: worker
YAML

kind create cluster --config /tmp/kind-cilium.yaml
# Nodes will sit NotReady until the CNI is installed — expected.

cilium install --version 1.19.3 \
  --set kubeProxyReplacement=true \
  --set k8sServiceHost=lwauth-control-plane \
  --set k8sServicePort=6443
cilium status --wait
```

!!! tip "If `cilium status --wait` times out"
    The Cilium agent image is ~260 MiB and the pull from quay.io can
    take several minutes on a cold cluster. The wait timeout fires
    long before that. Re-run `cilium status` (no `--wait`) or
    `kubectl -n kube-system get pods -l k8s-app=cilium -o wide`
    once the pulls finish — if both agent pods are `1/1 Running`
    you're good, regardless of what the wizard said.

If you're running a locally-built lwauth image rather than pulling
from GHCR, side-load it into the cluster before the Helm install.
`kind load` copies the image into every node, so on a multi-node
cluster expect a few seconds per worker:

```bash
kind load docker-image lwauth:dev --name lwauth
```

For a local image you also need to override the chart's image
fields, since the chart defaults pull from GHCR:

```bash
# Add these to the helm install in step 2:
#   --set image.repository=lwauth
#   --set image.tag=dev
#   --set image.pullPolicy=IfNotPresent
```

## 1. Namespace and upstream

The four manifests this recipe applies live next to it under
[`examples/cookbook/gate-upstream-service/`](https://github.com/mikeappsec/lightweightauth/tree/main/examples/cookbook/gate-upstream-service).
Apply them with `kubectl apply -f` rather than retyping; copy-paste
into a heredoc is fine if you'd rather see the YAML inline.

```bash
kubectl create namespace lwauth-demo

# Upstream workload (httpbin) + Service. See backend.yaml for the
# `command: ["go-httpbin"]` note — the upstream image declares no
# ENTRYPOINT so args alone fail to exec.
kubectl -n lwauth-demo apply \
  -f https://raw.githubusercontent.com/mikeappsec/lightweightauth/main/examples/cookbook/gate-upstream-service/backend.yaml
```

At this point `backend.lwauth-demo.svc:8000` is reachable from
anywhere in the cluster. That is the bypass we close in step 4.

## 2. Install lwauth via Helm with the gateway in front of it

Two flags do all the work:

- `gateway.enabled=true` — the chart renders an Envoy `ext_authz`
  proxy (ConfigMap + Deployment + Service) preconfigured to call
  lwauth's gRPC port and forward to your upstream. No hand-rolled
  envoy.yaml; the things ext_authz operators usually get wrong
  (`failure_mode_allow: false`, HTTP/2 to lwauth) are baked in.
- `gateway.upstream.service=backend` — the Service the gateway
  forwards to. Lives in the same namespace as the release.

```bash
helm install lwauth oci://ghcr.io/mikeappsec/lightweightauth/charts/lightweightauth \
  --namespace lwauth-demo \
  --set image.tag=v1.1.0 \
  --set crds.install=true \
  --set controller.enabled=true \
  --set controller.watchNamespace=lwauth-demo \
  --set controller.authConfigName=demo \
  --set gateway.enabled=true \
  --set gateway.upstream.service=backend
```

!!! note "Why no `networkPolicy.allowedFrom` setting"
    The chart auto-admits its own gateway in lwauth's NetworkPolicy
    (selector match on
    `app.kubernetes.io/component=gateway, app.kubernetes.io/instance=<release>`).
    You only need `networkPolicy.allowedFrom.podSelectors` /
    `.namespaceSelectors` if you're calling lwauth from something the
    chart didn't render — a sibling Istio gateway, your own Envoy in
    `gateway-system`, etc.

Now apply the `AuthConfig` the controller will compile:

```bash
kubectl -n lwauth-demo apply \
  -f https://raw.githubusercontent.com/mikeappsec/lightweightauth/main/examples/cookbook/gate-upstream-service/authconfig.yaml

kubectl -n lwauth-demo wait authconfig/demo --for=condition=Ready --timeout=60s
```

If `Ready=False` here the controller's `status.conditions` carries
the compile error verbatim — fix the YAML, no daemon restart needed.

## 3. (No step 3 — the gateway came with step 2.)

Versions of this recipe before chart 0.2 had a third step that
applied ~60 lines of inline Envoy YAML. That responsibility moved
into the chart's `gateway.*` values block; the rendered Pod, Service,
and ConfigMap are identical to what the old step shipped, with the
ext_authz cluster's `http2_protocol_options: {}` and
`failure_mode_allow: false` set centrally so they can't drift.

If you need to bring your own Envoy / Istio / Kong gateway, set
`gateway.enabled=false` (the default) and point your data plane at
`lwauth.<release-namespace>.svc:9001` (gRPC). You'll also need to
add a `podSelector` under `networkPolicy.allowedFrom` so your
gateway can dial lwauth.

## 4. Lock the upstream so only the gateway can reach it

This is the layer that makes the gateway non-bypassable. Without it,
any other Pod in the cluster — a CronJob, a debug shell, the wrong
microservice — can dial `backend.lwauth-demo.svc:8000` and skip the
gateway entirely.

```bash
kubectl -n lwauth-demo apply \
  -f https://raw.githubusercontent.com/mikeappsec/lightweightauth/main/examples/cookbook/gate-upstream-service/netpol-backend.yaml
```

The manifest selects the gateway by its chart-stamped label
(`app.kubernetes.io/component: gateway`) so it works unchanged
regardless of release name. If you set `gateway.enabled=false` and
brought your own Envoy/Istio, edit the selector to match.

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
kubectl -n lwauth-demo port-forward svc/lwauth-gateway 8080:80 >/dev/null &
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
debug pod that does **not** carry the gateway's
`app.kubernetes.io/component=gateway` label and try to reach
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

# If you stood up the optional kind+Cilium cluster from the
# Prerequisites section, drop the whole cluster instead — it's
# faster than uninstalling each piece:
kind delete cluster --name lwauth
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
- **Gateway can't reach lwauth.** Symptom: 5.1 returns `403` from
  Envoy with `failed to connect to upstream`; lwauth pod logs
  nothing. With `gateway.enabled=true` this should not happen — the
  chart auto-admits its own gateway in lwauth's NetworkPolicy. If
  you set `gateway.enabled=false` and brought your own data plane,
  add a matching `podSelector` under
  `networkPolicy.allowedFrom.podSelectors`. Helm silently ignores
  typos in `--set` paths, so `kubectl get networkpolicy -o yaml` is
  the only authoritative check.
- **`failure_mode_allow: true` left on the gateway.** Symptom: 5.2
  returns `200`, the upstream's log records the request. The chart
  defaults `gateway.extAuthz.failureModeAllow=false`; the only way
  to flip it is `--set gateway.extAuthz.failureModeAllow=true`,
  which you should not do.
  Authorization-bypass-on-failure is the single most common
  ext_authz misconfig in the wild.
- **HTTP/1.1 to lwauth.** Symptom: every request returns `503`
  regardless of API key; gateway logs `upstream connect error`.
  Cannot happen with the chart-rendered gateway (the
  `http2_protocol_options: {}` block is hard-coded into the
  ConfigMap template). If you brought your own Envoy and see this,
  add the block to your `lwauth` cluster.
- **`backend` is in another namespace.** Symptom: 5.3 returns `200`
  even on a real CNI. Cause: the NetworkPolicy
  `podSelector: { app: backend }` is namespace-scoped — a same-name
  Pod in another namespace is matched by the gateway's
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
