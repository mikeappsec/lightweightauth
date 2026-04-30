# OpenFGA on an existing Envoy deployment

You already terminate HTTP at Envoy and you already run lwauth as an
`ext_authz` provider — the [Envoy guide](../deployment/envoy.md) has
the minimum-safe filter config nailed down. What you do not have yet
is per-resource ReBAC: "Alice can `viewer` this document, Bob can
`editor` that folder, the engineering team can read every doc owned
by their org."

This recipe wires [`openfga`](../modules/openfga.md) into an existing
`AuthConfig`, composes it under [`composite`](../modules/composite.md)
behind a cheap [`rbac`](../modules/rbac.md) fast path, points the
decision cache at a shared [Valkey](../modules/cache-valkey.md) so
every replica reuses every other replica's answers, and tunes the
[`pkg/upstream`](../modules/upstream.md) Guard so an OpenFGA outage
fails closed deterministically rather than chewing worker goroutines.

The result is a hot path that:

- Returns from in-process cache for repeat decisions (one Valkey
  round-trip on miss).
- Skips OpenFGA entirely for admins (RBAC fast path).
- Fast-fails as `503` when OpenFGA is down, with a tripped breaker
  visible in Prometheus rather than silently amplifying retries
  into a fan-out outage.

## What this recipe assumes

- Envoy 1.18+ with lwauth already running as an `ext_authz` provider.
  If not, work through the [Envoy guide](../deployment/envoy.md)
  first — this recipe builds on that filter config, it does not
  replace it.
- An OpenFGA store and authorization model. The
  [OpenFGA modeling docs](https://openfga.dev/docs/modeling/getting-started)
  cover authoring; this recipe assumes you have a `storeId` and an
  `authorizationModelId` already pinned.
- A Valkey (or Redis-protocol-compatible) deployment reachable from
  every lwauth replica. If you are still on the in-process
  [`memory`](../modules/cache-memory.md) backend you will get a
  working setup but every replica will pay every cache miss
  independently — see step 4 for the trade-off.

This recipe **only** covers the lwauth-side wiring for an OpenFGA
authorizer. It does not cover authoring an FGA model, modeling
multi-tenant graphs, or sizing the FGA store itself. The
[OpenFGA performance guide](https://openfga.dev/docs/getting-started/perf-tuning)
is the right read for the latter.

## 1. Reach OpenFGA from lwauth

Two things must be true before the wiring will work:

1. lwauth's Pod can resolve and reach
   `openfga.<namespace>.svc.cluster.local:8081`. If you front FGA
   with a Service (the Helm chart does), the cluster-local DNS name
   above is what you point at; if you front it with a route on the
   mesh, prefer that.
2. The preshared token from the FGA install (step 2's `apiToken:`)
   has at least `check:read` on the target store. lwauth never
   writes to FGA — it only ever issues `Check` calls.

A minimal Helm install of FGA with a static token (development /
staging shape; production should mint via OIDC):

```bash
helm repo add openfga https://openfga.github.io/helm-charts
helm install openfga openfga/openfga \
  --namespace openfga --create-namespace \
  --set authn.method=preshared \
  --set authn.preshared.keys[0]=$(openssl rand -base64 32) \
  --set datastore.engine=postgres \
  --set datastore.uri=postgresql://...
```

Capture the preshared key into a Kubernetes Secret in the lwauth
namespace; you'll feed it into the AuthConfig in step 2 (literal
value — see the `apiToken` warning there):

```bash
kubectl -n lwauth-system create secret generic openfga-token \
  --from-literal=token=<the-preshared-key> \
  --dry-run=client -o yaml | kubectl apply -f -
```

## 2. Compose `openfga` under `composite` with an RBAC fast path

The `AuthConfig` below uses a `jwt` identifier (the
[Istio recipe](istio-grpc-rbac.md) lands one if you don't); for a
local kind dry-run swap that for `apikey` —
[examples/cookbook/openfga-on-envoy/authconfig.yaml](https://github.com/mikeappsec/lightweightauth/tree/main/examples/cookbook/openfga-on-envoy/authconfig.yaml)
is the wired-up shape used in step 6. The new bits in either case
are:

- The `composite` authorizer in `anyOf` mode. Children run in
  declared order; the first `Permit` short-circuits.
- An `rbac` admin gate as the cheap first child. Admins never touch
  FGA.
- An `openfga` child that derives the `(user, relation, object)`
  triple via Go `text/template` over a fixed
  `{.Identity, .Request}` input.

```yaml
# documents-authconfig.yaml
apiVersion: lightweightauth.io/v1alpha1
kind: AuthConfig
metadata:
  name: documents
  namespace: documents
spec:
  identifiers:
    - name: bearer
      type: jwt
      config:
        issuerUrl: https://idp.example.com/realms/internal
        audiences: [documents-api]

  authorizers:
    - name: gate
      type: composite
      config:
        # anyOf = stop at the first child that returns Permit. Order
        # children cheap -> expensive so the fast paths cache well
        # and FGA only sees traffic the cheaper checks rejected.
        anyOf:
          - name: admins
            type: rbac
            config:
              rolesFrom: claim:realm_access.roles
              # Admins skip every per-resource check. Keep this list
              # short; it is the one path that does not consult FGA.
              allow: [documents-admin]

          - name: rebac
            type: openfga
            config:
              # OpenFGA's HTTP API is on :8080. Port :8081 is gRPC --
              # the lwauth `openfga` adapter speaks HTTP, so pointing
              # it at :8081 produces an opaque `EOF` / `bad protocol`
              # at first request and is one of the most common
              # misconfigurations seen in the wild.
              apiUrl: http://openfga.openfga.svc.cluster.local:8080
              storeId: 01HX...                  # your store id
              authorizationModelId: 01HX...     # pin the model
              apiToken: <preshared-key>          # optional; sent as Bearer
              timeout: 150ms
              # check.{user,relation,object} are Go text/template
              # snippets evaluated against {.Identity, .Request}.
              # Available bindings:
              #   .Identity.Subject, .Identity.Claims (map)
              #   .Request.Method, .Request.Path, .Request.Host
              #   .Request.PathParts (path split on '/', no leading
              #     empty element -- /documents/42 -> ["documents","42"])
              #   .Request.Headers (lowercased keys, first value only)
              # Trim whitespace inside template actions ({{- -}}) so
              # the rendered relation has no stray newline.
              check:
                user: 'user:{{ .Identity.Subject }}'
                relation: |-
                  {{- if eq .Request.Method "GET" -}}viewer
                  {{- else if eq .Request.Method "POST" -}}editor
                  {{- else if eq .Request.Method "PUT" -}}editor
                  {{- else if eq .Request.Method "DELETE" -}}owner
                  {{- end -}}
                # /documents/<id>... -> PathParts[1] is the document id.
                object: 'document:{{ index .Request.PathParts 1 }}'
              # An empty relation/user/object short-circuits to a
              # deterministic 403 inside the adapter -- no FGA round
              # trip is paid to learn that an unknown method maps to
              # nothing. (No config flag is needed; this is the
              # adapter's default behaviour.)

  # See step 3 for the full cache block; the snippet above intentionally
  # omits it so each step stays focused.
```

```bash
kubectl apply -f documents-authconfig.yaml
kubectl -n documents wait authconfig/documents \
  --for=condition=Ready --timeout=60s
```

If `Ready=False` the controller's `status.conditions[0].message`
carries the compile error verbatim (template parse, unknown module
type, missing field). Fix the YAML and re-apply; no daemon restart
needed.

!!! tip "Why RBAC first"
    The cheap-then-expensive ordering is the single biggest knob
    you have over OpenFGA QPS. In production traffic, an admin
    bypass shaves 5-15% of FGA calls outright; a `cel` step that
    rejects obviously-malformed paths shaves another single-digit
    percent. Both are easier to ship now than to retrofit when FGA
    is paged at 03:00.

!!! warning "`apiToken` is read literally"
    The `apiToken:` field is forwarded to FGA as
    `Authorization: Bearer <value>` exactly as written — there is no
    `${FGA_TOKEN}` env-substitution. To inject a Secret, render the
    AuthConfig from a templated source (Helm, Kustomize) or feed the
    value through the lwauth controller's
    `IdentityProvider`-style indirection. Older drafts of this
    recipe shipped `apiToken: ${FGA_TOKEN}`; that produces a
    request header `Authorization: Bearer ${FGA_TOKEN}` (the literal
    six characters), which FGA rejects with `401`.

## 3. Point the decision cache at shared Valkey

Without a shared cache, every lwauth replica pays every miss
independently — three replicas means up to 3× the FGA QPS. With
shared Valkey, a positive answer cached by Pod A serves Pod B's next
request at one round-trip. The full cache block:

```yaml
# Append to the AuthConfig above (same `spec:` block).
  cache:
    # cache.key is fenced: an unknown field name is rejected at load
    # time (SECURITY_HARDENING_2026-04-29 §7), so a typo like
    # `pathTemplate` cannot silently degrade the key.
    key: [sub, method, path]
    ttl: 30s
    negativeTtl: 5s
    backend: valkey
    addr: valkey-master.cache.svc.cluster.local:6379
    # keyPrefix isolates this AuthConfig's decisions from any other
    # AuthConfig sharing the same Valkey. Set it per-tenant.
    keyPrefix: lwauth/documents/
```

A 30 s positive TTL is the right starting point for FGA-backed
decisions: the underlying graph rarely flips inside that window,
and the cache absorbs the bursty re-checks of paginated UIs without
chewing budget. Tune down if you have known-tight permissions
(e.g. break-glass demotions); tune up only after you have evidence
the graph really is that stable.

!!! warning "Negative TTL is a footgun"
    `negativeTtl: 5s` (the default) is intentionally short. A longer
    negative TTL means a freshly-granted permission takes that long
    to start working — which surfaces as "I just gave Bob viewer,
    why does he still see 403?". Do not raise it without
    understanding the user-visible effect.

## 4. Tune the upstream Guard

`openfga` calls go through [`pkg/upstream`](../modules/upstream.md) so
an FGA outage cannot amplify into a fan-out incident. The default
guard is reasonable, but the breaker / retry shape worth being
explicit about for a per-resource authorizer:

```yaml
# Add inside the openfga `config:` block.
              resilience:
                breaker:
                  failureThreshold: 5     # consecutive fails to trip
                  coolDown: 30s           # how long open before half-open trial
                  halfOpenSuccesses: 1
                retries:
                  maxRetries: 1           # one retry; FGA is local, not WAN
                  backoffBase: 25ms
                  backoffMax: 100ms
                budget:
                  capacity: 100           # max retries in flight cluster-wide
                  refillPerSec: 10
```

The defensible defaults:

- **`maxRetries: 1`** — FGA is in-cluster. A second retry on top of
  Envoy's 250 ms `ext_authz` timeout (Envoy guide §2) leaves no room
  for the upstream to actually answer. Pure-breaker (`maxRetries: 0`)
  is also reasonable.
- **`failureThreshold: 5`** — consistent with the lwauth defaults.
  Lower trips spuriously on healthy upstream noise; higher delays
  the fast-fail path under a real outage.
- **Budget capacity 100, refill 10/s** — caps how many concurrent
  retries one tenant's traffic can spend on FGA. A noisy tenant
  cannot starve every other tenant of retry slots.

What you get for the configuration, validated by the M12 chaos slice:
under a 64-worker fan-out against a broken FGA the breaker opens
after 5 fails; the remaining ~2.15 M calls fast-fail in microseconds
with `module.ErrUpstream`, surfacing to clients as `503` rather than
hanging Envoy listeners.

## 5. Verify on the wire

The behaviour you actually want to see, end to end, in this order:

```bash
# 0. Engine compiled and the openfga child is wired in.
kubectl -n lwauth-system logs deploy/lwauth -c lwauth | \
  grep -E 'config: compiled|engine: hot-swap' | tail -3

# 1. Admin calls a write — short-circuits through RBAC, FGA never sees it.
TOKEN=$(./mint-jwt.sh --role documents-admin)
curl -s -o /dev/null -w 'http=%{http_code}  total=%{time_total}\n' \
  -H "authorization: Bearer $TOKEN" \
  -X POST https://documents.example.com/documents/42
# expect: http=200, time_total << 50ms (no FGA round trip)

# 2. Non-admin viewer relationship — first call MISSes the cache,
#    second call HITs.
TOKEN=$(./mint-jwt.sh --sub alice)
for i in 1 2; do
  curl -s -o /dev/null -w "$i: http=%{http_code}  total=%{time_total}\n" \
    -H "authorization: Bearer $TOKEN" \
    https://documents.example.com/documents/42
done
# expect: 1: 200, 50-150ms (cache MISS, FGA Check runs)
#         2: 200, single-digit ms (cache HIT)

# 3. Non-admin without the relationship — deterministic 403, no
#    leak of why on the public response body.
TOKEN=$(./mint-jwt.sh --sub bob)
curl -i -H "authorization: Bearer $TOKEN" \
  https://documents.example.com/documents/42
# expect: HTTP/2 403; the verbose reason is on x-lwauth-reason for
#         logs only (Envoy guide §4.4 strips it at the public edge).

# 4. FGA is unreachable — breaker opens, requests fast-fail.
kubectl -n openfga scale deploy openfga --replicas=0
TOKEN=$(./mint-jwt.sh --sub alice)
for i in $(seq 1 20); do
  curl -s -o /dev/null -w "%{http_code} %{time_total}\n" \
    -H "authorization: Bearer $TOKEN" \
    https://documents.example.com/documents/42
done | sort | uniq -c
# expect: every call is 503 in single-digit ms.
kubectl -n openfga scale deploy openfga --replicas=1
```

Step 4 is the single test most likely to reveal a misconfiguration.
If you see steady-state *slow* 503s (>200 ms each) you are paying
the FGA timeout on every call — the breaker isn't tripping, which
usually means `failureThreshold` is higher than it should be or the
adapter is being rebuilt on each request (config hot-reload thrash).
Start with `lwauth_upstream_state{name="rebac"}` in Prometheus,
which transitions 0 → 1 (closed → open) as the breaker trips.

!!! note "Why scale-to-zero is a soft test"
    `kubectl scale … --replicas=0` removes Service endpoints
    immediately, so dial-fail returns instantly even *before* the
    breaker opens. The slow-then-fast pattern earlier drafts of this
    recipe described shows up only when FGA is reachable but
    unresponsive (a hung pod, an iptables `DROP`, a saturated
    upstream) — that's where the timeout actually fires and the
    breaker has work to do. To exercise that path locally use
    `kubectl exec openfga-0 -- pkill -STOP openfga` instead, which
    keeps the TCP listener up but stalls every `Check` until the
    250 ms timeout.

## 6. What to look at next

- **Per-tenant FGA stores.** `storeId` in the openfga adapter is a
  static string, not a template — to route tenants to different
  stores, declare one openfga child per store under
  [`composite.anyOf`](../modules/composite.md) and gate each with
  a [`cel`](../modules/cel.md) child that matches the tenant claim.
  See [`openfga`](../modules/openfga.md) for the available config.
- **Mixing OpenFGA with OPA.** Use [`opa`](../modules/opa.md) for the
  *macro* policy ("which users may even attempt this surface?") and
  `openfga` for the *per-resource* relationship check; combine via
  `composite.allOf`. See
  [`composite`](../modules/composite.md) for the combinator
  semantics.
- **The HMAC story.** If you ship CLIs that hit this same surface
  with long-lived signing keys, the next recipe is
  [Rotate HMAC secrets without downtime](rotate-hmac.md).

## Appendix A: Run the whole recipe on a local kind cluster

This is the path the recipe is dryrun-tested against on every
release. It substitutes the production-shaped pieces (jwt, postgres-
backed FGA, OIDC token, cluster TLS) for their local-only
equivalents (apikey, in-memory FGA, no auth on FGA, plaintext
HTTP) so you can exercise the openfga adapter end-to-end without
provisioning a database or an IdP.

The artifacts referenced below live under
[`examples/cookbook/openfga-on-envoy/`](https://github.com/mikeappsec/lightweightauth/tree/main/examples/cookbook/openfga-on-envoy)
and reuse `kind-cilium.yaml` + `backend.yaml` from the
[gate-upstream-service recipe](gate-upstream-service.md).

```bash
# 1. Cluster + CNI that actually enforces NetworkPolicy.
kind create cluster --name lwauth \
  --config examples/cookbook/gate-upstream-service/kind-cilium.yaml
cilium install --version 1.19.3 \
  --set kubeProxyReplacement=true \
  --set k8sServiceHost=lwauth-control-plane --set k8sServicePort=6443
kind load docker-image lwauth:dev --name lwauth   # if testing a local build

# 2. Namespace + workloads.
kubectl create namespace lwauth-demo
kubectl -n lwauth-demo apply -f examples/cookbook/openfga-on-envoy/openfga.yaml
kubectl -n lwauth-demo apply -f examples/cookbook/gate-upstream-service/backend.yaml
kubectl -n lwauth-demo wait --for=condition=Available \
  deploy/openfga deploy/backend --timeout=120s

# 3. Bootstrap the FGA store + model + tuples (alice viewer doc:42,
#    carol owner doc:42). The script echoes RESULT_STORE and
#    RESULT_MODEL on stdout; capture them for step 4.
kubectl -n lwauth-demo run fga-init \
  --image=curlimages/curl:8.10.1 --restart=Never --rm -i --command -- \
  sh -s < examples/cookbook/openfga-on-envoy/fga-bootstrap.sh

# 4. Render and apply the AuthConfig (replace placeholders with the
#    IDs from step 3). The chart hasn't been installed yet, but
#    --set crds.install=true on step 5 lays the CRDs in time --
#    apply the AuthConfig AFTER step 5.
helm install lwauth ./deploy/helm/lightweightauth -n lwauth-demo \
  --set image.repository=lwauth --set image.tag=dev --set image.pullPolicy=IfNotPresent \
  --set controller.enabled=true --set controller.authConfigName=demo \
  --set gateway.enabled=true --set gateway.upstream.service=backend \
  --wait --timeout 4m

STORE=<from-step-3>; MODEL=<from-step-3>
sed -e "s/STORE_ID_PLACEHOLDER/$STORE/" -e "s/MODEL_ID_PLACEHOLDER/$MODEL/" \
  examples/cookbook/openfga-on-envoy/authconfig.yaml \
  | kubectl -n lwauth-demo apply -f -
kubectl -n lwauth-demo wait authconfig/demo \
  --for=condition=Ready --timeout=60s

# 5. Probe through the gateway.
kubectl -n lwauth-demo port-forward svc/lwauth-gateway 8080:80 &
PF=$!; trap "kill $PF" EXIT; sleep 2

# admin RBAC fast-path  -> 404 (auth passed, httpbin has no /documents/42)
curl -s -o /dev/null -w 'admin   POST = %{http_code}\n' \
  -X POST -H 'x-api-key: demo-key-admin' http://localhost:8080/documents/42
# alice viewer doc:42  -> 404 (FGA Check returned allowed)
curl -s -o /dev/null -w 'alice   GET  = %{http_code}\n' \
  -H 'x-api-key: demo-key-alice' http://localhost:8080/documents/42
# bob has no tuple    -> 403 (FGA Check returned not allowed)
curl -s -o /dev/null -w 'bob     GET  = %{http_code}\n' \
  -H 'x-api-key: demo-key-bob' http://localhost:8080/documents/42
# carol owner DELETE  -> 404 (FGA Check returned allowed; DELETE -> owner)
curl -s -o /dev/null -w 'carol   DEL  = %{http_code}\n' \
  -X DELETE -H 'x-api-key: demo-key-carol' http://localhost:8080/documents/42
# alice editor (no tuple, POST -> editor) -> 403
curl -s -o /dev/null -w 'alice   POST = %{http_code}\n' \
  -X POST -H 'x-api-key: demo-key-alice' http://localhost:8080/documents/42
```

The `404` responses are the success signal: the gateway forwarded
to the upstream and the upstream (httpbin) just doesn't have a
`/documents/42` route. Swap httpbin for a real backend and the
`404`s become `200`s — the auth shape doesn't change.

```bash
# 6. Cleanup.
kind delete cluster --name lwauth
```

## References

- [`openfga` authorizer](../modules/openfga.md)
- [`composite` authorizer](../modules/composite.md)
- [`rbac` authorizer](../modules/rbac.md)
- [`upstream` guard](../modules/upstream.md)
- [`cache.backend: valkey`](../modules/cache-valkey.md)
- [Envoy + lwauth deployment guide](../deployment/envoy.md)
- [DESIGN.md §5](../DESIGN.md) — decision cache and authorizer composition.
- [OpenFGA reference](https://openfga.dev).
