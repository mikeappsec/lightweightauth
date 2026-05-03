# Per-tenant rate limiting & SLA enforcement

Implement token-bucket rate limiting at the lwauth gateway to prevent
any single tenant from exhausting shared resources. Covers per-tenant
quotas, SLA-tier overrides, cluster-wide distributed limiting via
Valkey, and graceful degradation during backend outages.

## What this recipe assumes

- A multi-tenant deployment where `Request.TenantID` is populated
  (from an `x-tenant-id` header, a JWT claim, or Envoy route metadata).
- You need per-tenant fairness — one noisy tenant must not impact
  others.
- Optionally: cluster-wide coordination via Valkey for consistent
  global quotas across replicas.

## 1. Basic per-tenant rate limiting

The rate limiter runs at the **top** of the pipeline — before
identification. A rate-limited request burns zero compute on JWKS
fetch, introspection, OPA evaluation, or any downstream call:

```yaml
apiVersion: lightweightauth.io/v1alpha1
kind: AuthConfig
metadata:
  name: multi-tenant-api
  namespace: platform
spec:
  rateLimit:
    perTenant:
      rps: 100       # 100 requests/second per tenant
      burst: 200     # allow short bursts up to 200
    default:
      rps: 20        # fallback when tenant ID is empty
      burst: 40

  identifiers:
    - name: bearer
      type: jwt
      config:
        issuerUrl: https://idp.example.com
        audiences: [api]

  authorizers:
    - name: rbac
      type: rbac
      config:
        rolesFrom: claim:roles
        allow: [user, admin]
```

Behavior:

| Scenario | Result |
|----------|--------|
| Tenant under quota | Request proceeds to identification |
| Tenant exceeds burst | `429 Too Many Requests` — no downstream work |
| No tenant ID | `default` bucket applies |
| Rate limiter disabled (`rps: 0`) | Always allow (bypass) |

## 2. SLA-tier overrides

Different tenants pay for different quotas. Use `overrides` to
assign per-tenant limits:

```yaml
  rateLimit:
    perTenant:
      rps: 100
      burst: 200
    default:
      rps: 20
      burst: 40
    overrides:
      # Enterprise tier
      acme-corp:
        rps: 1000
        burst: 2000
      bigco:
        rps: 1000
        burst: 2000
      # Starter tier (below default)
      free-trial-tenant:
        rps: 10
        burst: 20
    maxBuckets: 100000
    bucketIdleTTL: "5m"
```

Override keys match `Request.TenantID` exactly. Unknown tenants fall
through to the `perTenant` defaults.

## 3. Populate tenant ID from JWT claims

If your tenant ID lives in a JWT claim rather than a request header,
configure the tenant extraction:

```yaml
spec:
  tenantFrom: claim:org_id    # extract from identity claims
  # Alternative: header-based
  # tenantFrom: header:x-tenant-id
```

!!! note "Ordering"
    When using `claim:` extraction, the rate limiter must run
    **after** identification to have the claim available. lwauth
    handles this automatically — if `tenantFrom` is claim-based,
    the limiter defers until identity is resolved.

## 4. Cluster-wide distributed rate limiting

By default, each lwauth replica enforces its bucket independently.
With N replicas, a tenant's effective limit is `N × rps`. For strict
global quotas, enable distributed limiting via Valkey:

```yaml
  rateLimit:
    perTenant:
      rps: 200
      burst: 400
    distributed:
      type: valkey
      addr: valkey-master.cache.svc:6379
      username: ${VALKEY_USERNAME}
      password: ${VALKEY_PASSWORD}
      keyPrefix: lwauth-rl/
      tls: false
      window: 1s          # sliding window length
      timeout: 50ms       # per-call deadline
      failOpen: false     # deny on backend error (safe default)
```

Cluster cap = `perTenant.burst` requests per `window` across **all**
replicas. So `rps: 200, burst: 400, window: 1s` means ≤ 400
requests/second per tenant fleet-wide.

The local bucket still fires on every admission as a floor — a single
replica cannot exceed its configured `rps/burst` even if the cluster
cap has headroom.

## 5. Failure modes

| State | Behavior |
|-------|----------|
| Valkey healthy, admits | Local bucket also checked; admit if both allow |
| Valkey healthy, denies | **Deny** — cluster cap is authoritative |
| Valkey errors / circuit open | Fall back to local bucket (per-replica floor) |
| Valkey errors + `failOpen: true` | Allow unconditionally |
| `TenantID == ""` | Skip distributed; `default` local bucket only |

During a Valkey blip, you lose the cluster-wide ceiling but keep the
per-replica floor — a transient `N × rps` worst case, not unbounded.

## 6. Monitoring and alerting

Key metrics to watch:

```promql
# Rate-limited requests per tenant
sum by (tenant) (
  rate(lwauth_decisions_total{outcome="deny", authorizer="ratelimit"}[5m])
)

# Bucket utilization (are tenants close to their limits?)
lwauth_ratelimit_bucket_tokens_remaining{tenant="acme-corp"}

# Distributed backend latency
histogram_quantile(0.99, lwauth_ratelimit_valkey_duration_seconds)
```

Alert when a tenant is consistently hitting their limit — it may
indicate a need for quota increase or a misbehaving client.

## 7. Helm wiring

```yaml
# values.yaml
config:
  inline: |
    rateLimit:
      perTenant:
        rps: 200
        burst: 400
      default:
        rps: 50
        burst: 100
      overrides:
        enterprise-tenant:
          rps: 1000
          burst: 2000
      maxBuckets: 100000
      bucketIdleTTL: 5m
      distributed:
        type: valkey
        addr: valkey-master.cache.svc:6379
        password: "${VALKEY_PASSWORD}"
        keyPrefix: lwauth-rl/
        window: 1s
        timeout: 50ms
        failOpen: false
    identifiers:
      - name: bearer
        type: jwt
        config:
          issuerUrl: https://idp.example.com
          audiences: [api]
    authorizers:
      - name: rbac
        type: rbac
        config:
          rolesFrom: claim:roles
          allow: [user, admin]
env:
  - name: VALKEY_PASSWORD
    valueFrom:
      secretKeyRef:
        name: lwauth-valkey
        key: password
```

## 8. Validate

```bash
# Normal request (under quota)
curl -H "Authorization: Bearer ${TOKEN}" \
     -H "X-Tenant-ID: acme-corp" \
     https://gateway/api/resource
# expect: 200

# Exhaust the burst (send 201 requests rapidly)
for i in $(seq 1 201); do
  curl -s -o /dev/null -w "%{http_code}\n" \
       -H "Authorization: Bearer ${TOKEN}" \
       -H "X-Tenant-ID: free-trial" \
       https://gateway/api/resource
done
# expect: first 20 → 200, then → 429

# Dry-run with tenant
lwauthctl explain --config multi-tenant-api.yaml \
    --request '{"method":"GET","path":"/api/resource","tenantId":"acme-corp","headers":{"authorization":"Bearer ..."}}'
# ratelimit  ✓  acme-corp  tokens=999.8  bucket=2000
# identify   ✓  jwt        subject=alice
# authorize  ✓  rbac
```

## Security notes

- **Rate limit runs first.** Brute-force attacks burn quota before any
  crypto work (argon2id, JWKS fetch) happens.
- **Memory bounded.** `maxBuckets: 100000` + `bucketIdleTTL: 5m`
  ensures idle buckets are reaped. At ~200 bytes/bucket that's ~20 MB.
- **Tenant spoofing.** Ensure `X-Tenant-ID` is set by a trusted proxy
  (Envoy route metadata), not the end client. Or use `tenantFrom:
  claim:org_id` to derive from the verified identity.
- **Valkey ACL.** Use a dedicated Valkey user with minimal permissions:
  `+EVAL +ZADD +ZCARD +ZREMRANGEBYSCORE +PEXPIRE -@all`.

## Teardown

```bash
kubectl delete authconfig multi-tenant-api -n platform
```
