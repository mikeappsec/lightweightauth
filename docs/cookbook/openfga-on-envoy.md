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
2. The token in `extraEnv.FGA_TOKEN` (step 2) has at least
   `check:read` on the target store. lwauth never writes to FGA —
   it only ever issues `Check` calls.

A minimal Helm install of FGA with a static token (development /
staging shape; production should mint via OIDC):

```bash
helm install openfga oci://ghcr.io/openfga/openfga \
  --namespace openfga --create-namespace \
  --set auth.method=preshared \
  --set auth.preshared.keys[0]=$(openssl rand -base64 32) \
  --set datastore.engine=postgres \
  --set datastore.uri=postgresql://...
```

Capture the preshared key into the lwauth Secret you already use for
sensitive config:

```bash
kubectl -n lwauth-system create secret generic lwauth-secrets \
  --from-literal=fga=<the-preshared-key> \
  --dry-run=client -o yaml | kubectl apply -f -
```

## 2. Compose `openfga` under `composite` with an RBAC fast path

The `AuthConfig` below assumes you already have a `jwt` identifier
(the [Istio recipe](istio-grpc-rbac.md) lands one if you don't). The
new bits are:

- The `composite` authorizer in `firstAllow` mode. Children run in
  declared order; the first `Permit` short-circuits.
- An `rbac` admin gate as the cheap first child. Admins never touch
  FGA.
- An `openfga` child that derives the `(user, relation, object)`
  triple from CEL.

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
        # firstAllow = stop at the first child that returns Permit.
        # Order children cheap -> expensive so the fast paths cache
        # well and FGA only sees traffic the cheaper checks rejected.
        mode: firstAllow
        children:
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
              apiUrl: https://openfga.openfga.svc.cluster.local:8081
              storeId: 01HX...                  # your store id
              authorizationModelId: 01HX...     # pin the model
              apiToken: ${FGA_TOKEN}
              timeout: 150ms
              # CEL bindings: identity.* and request.* are the same
              # vocabulary the cel authorizer uses. The CEL is
              # evaluated once per request before the cache lookup,
              # so keep these expressions side-effect free and cheap.
              check:
                user:     '"user:" + identity.subject'
                # Map HTTP method to FGA relation. Anything other
                # than these explicit branches falls through to a
                # deny-by-default below.
                relation: |
                  request.method == "GET"  ? "viewer" :
                  request.method == "POST" ? "editor" :
                  request.method == "PUT"  ? "editor" :
                  request.method == "DELETE" ? "owner" :
                  ""
                object: |
                  '"document:" + request.path.split("/")[2]'
              # Optional but recommended: a deny-by-default sentinel
              # when CEL produces an empty relation. Without this an
              # unknown method would call FGA with relation:"" and
              # FGA would deny anyway, but you would pay one round
              # trip to learn that.
              denyOnEmptyRelation: true

  # See step 3 for the full cache block; the snippet above intentionally
  # omits it so each step stays focused.
```

```bash
kubectl apply -f documents-authconfig.yaml
```

!!! tip "Why RBAC first"
    The cheap-then-expensive ordering is the single biggest knob
    you have over OpenFGA QPS. In production traffic, an admin
    bypass shaves 5-15% of FGA calls outright; a `cel` step that
    rejects obviously-malformed paths shaves another single-digit
    percent. Both are easier to ship now than to retrofit when FGA
    is paged at 03:00.

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
# expect: the first ~5 are 503 with non-trivial latency, every one
#         after that is 503 in single-digit ms (breaker open).
kubectl -n openfga scale deploy openfga --replicas=1
```

Step 4 is the single test most likely to reveal a misconfiguration.
If you see steady-state slow 503s instead of fast-fail 503s, the
guard config did not stick or the breaker thresholds are higher
than they should be — start with `lwauth_upstream_state{name="rebac"}`
in Prometheus, which transitions 0 → 1 (closed → open) as the
breaker trips.

## 6. What to look at next

- **Per-tenant FGA stores.** `storeId` is a CEL expression too; you
  can route different tenants to different stores by reading
  `identity.claims.tenant`. See
  [`openfga`](../modules/openfga.md).
- **Mixing OpenFGA with OPA.** Use [`opa`](../modules/opa.md) for the
  *macro* policy ("which users may even attempt this surface?") and
  `openfga` for the *per-resource* relationship check; combine via
  `composite.allOf`. See
  [`composite`](../modules/composite.md) for the combinator
  semantics.
- **The HMAC story.** If you ship CLIs that hit this same surface
  with long-lived signing keys, the next recipe is
  [Rotate HMAC secrets without downtime](rotate-hmac.md).

## References

- [`openfga` authorizer](../modules/openfga.md)
- [`composite` authorizer](../modules/composite.md)
- [`rbac` authorizer](../modules/rbac.md)
- [`upstream` guard](../modules/upstream.md)
- [`cache.backend: valkey`](../modules/cache-valkey.md)
- [Envoy + lwauth deployment guide](../deployment/envoy.md)
- [DESIGN.md §5](../DESIGN.md) — decision cache and authorizer composition.
- [OpenFGA reference](https://openfga.dev).
