# Per-tenant rate limit (M11)

Token-bucket limiter keyed by `Request.TenantID`. Runs at the very top
of the pipeline so a misbehaving tenant cannot exhaust shared module
resources (an OPA hot loop, an OpenFGA call, an introspection RPC).

**Source:** [pkg/ratelimit](../../pkg/ratelimit/ratelimit.go).
**Wired into:** `pipeline.Engine.Evaluate` via `Options.RateLimiter`.

## When to use

- Multi-tenant deployments where one tenant must not impact another.
- DoS-resistance at the gateway when there is no upstream rate limiter
  (Envoy local rate limit, NGINX `limit_req`, …).

**Disabled by default** — a typed-nil limiter is one branch per
request, free until enabled.

## Configuration

```yaml
# AuthConfig.spec (CRD) or top-level (file mode)
rateLimit:
  perTenant:
    rps:   200    # steady-state tokens/second
    burst: 400    # bucket capacity (max instant burst)
  default:
    rps:   50
    burst: 100
```

| Field        | Behavior                                                              |
|--------------|-----------------------------------------------------------------------|
| `perTenant`  | One bucket per `Request.TenantID`. `rps: 0` disables.                 |
| `default`    | Fallback when `TenantID` is empty. `rps: 0` disables (always allow).  |
| `rps`        | Refill rate (tokens/second). Float — `0.5` is valid.                  |
| `burst`      | Bucket capacity. Tokens accumulate up to this max while idle.         |

## Behavior on exhaustion

- Limiter denies → pipeline returns `Decision{Allow:false, HTTPStatus: 429, DenyReason: "rate-limit"}`.
- The deny short-circuits **before** any identifier work — no JWKS
  fetch, no introspection, no OPA evaluation. Cost of a rate-limited
  request is one map lookup + one CAS.
- Counted in `lwauth_decisions_total{outcome="deny", authorizer="ratelimit"}`.

## Helm wiring

File mode:

```yaml
# values.yaml
config:
  inline: |
    rateLimit:
      perTenant: { rps: 200, burst: 400 }
      default:   { rps: 50,  burst: 100 }
    identifiers: [...]
    authorizers: [...]
```

CRD mode — same block under `spec.rateLimit:` of an `AuthConfig`.

## Operational notes

- **Tenant identity.** `Request.TenantID` is populated by Door A from
  the `x-tenant-id` header (configurable) or by Door B from the
  `tenant_id` field of `authv1.AuthorizeRequest`. Pipelines fronting a
  multi-tenant Envoy cluster typically stamp it from the Envoy route's
  metadata.
- **Memory.** One bucket struct per tenant; cleanup of idle tenants
  is handled by an LRU sweep when `len(buckets) > 16384`. Operators
  with very high tenant cardinality should keep `burst` modest to
  bound the working set.
- **Distribution.** Buckets are local to each lwauth replica by
  default (token count is goroutine-state, not shared via Valkey).
  With N replicas a tenant's effective limit is `N × rps`. For
  deployments where that's unacceptable, opt into the cluster-wide
  aggregator (K-DOS-1) below; otherwise sticky-routing or aggregate
  rate limiting belongs at the L7 proxy in front of lwauth.

## Cluster-wide aggregation (K-DOS-1, v1.1+)

By default, each replica enforces its bucket independently. To cap a
tenant across **every** lwauth replica in the deployment, add a
`distributed:` block:

```yaml
rateLimit:
  perTenant:
    rps: 200
    burst: 400
  distributed:
    type: valkey
    addr: valkey-master.cache.svc:6379
    password: ${VALKEY_PASSWORD}    # optional
    keyPrefix: lwauth-rl/           # optional, default empty
    tls: false
    window: 1s                      # rolling window length (default 1s)
    timeout: 50ms                   # per-call deadline (default 50ms)
    failOpen: false                 # what to do on backend error (default false)
```

| Field        | Behaviour                                                                              |
|--------------|----------------------------------------------------------------------------------------|
| `type`       | Registered backend name. v1.1 ships `valkey`. Required when block present.             |
| `addr`       | Valkey/Redis 7.x TCP address. Required.                                                |
| `keyPrefix`  | Prepended to every tenant key — lets multiple lwauth deployments share a Valkey.       |
| `window`     | Sliding-window length. Default 1s.                                                     |
| `timeout`    | Per-call deadline; on expiry the limiter falls back to the local bucket.               |
| `failOpen`   | If true, allow on backend error instead of falling back to the local bucket.           |

**Cluster cap = `perTenant.burst` requests per `window`** (or
`perTenant.rps × window` when `burst` is zero). So
`rps:200, burst:400, window:1s` means "≤ 400 requests/second per
tenant, summed across the entire fleet".

### Semantics under outage

| State                                    | Behaviour                                                       |
|------------------------------------------|-----------------------------------------------------------------|
| Backend healthy, returns admit           | Charge the local bucket too; admit if local burst still has room|
| Backend healthy, returns deny            | **Deny** — cluster cap is authoritative                          |
| Backend errors / circuit open            | Fall back to local bucket (per-replica floor)                   |
| Backend errors / circuit open + failOpen | Allow unconditionally                                            |
| `Request.TenantID == ""`                 | Skip the aggregator; local `default` bucket only                |

The local bucket continues to fire on every admission, so a single
replica still cannot exceed its configured `rps`/`burst` even if the
cluster cap had headroom. This is what makes the failure mode safe:
during a Valkey blip you lose the cluster-wide ceiling but keep the
per-replica floor — a transient `N × rps` worst case, not unbounded.

### Wire protocol

The Valkey backend ([pkg/ratelimit/valkey](../../pkg/ratelimit/valkey/valkey.go))
runs an atomic Lua script per call:

```lua
ZREMRANGEBYSCORE key -inf (now - window)
if ZCARD key >= limit then return 0 end
ZADD key now <unique-member>
PEXPIRE key window
return 1
```

One Valkey round-trip per `Allow`. Per-key memory is bounded by
`limit` (sorted-set entries). Per-key TTL is reset to `window` on
each admission, so idle tenants don't accumulate state on the server.

### Security

The connection inherits the Valkey ACL / password / TLS settings from
the same `addr/username/password/tls` fields the `cache: backend:
valkey` block accepts. Use a dedicated Valkey user with `+EVAL +ZADD
+ZCARD +ZREMRANGEBYSCORE +PEXPIRE -@all` ACL when running on a shared
Valkey deployment.

## Sample dry-run

```bash
$ lwauthctl explain --config tenant-a.yaml \
    --request '{"method":"GET","path":"/api/things","tenantId":"acme"}'
ratelimit  ✓  acme   tokens=199.7  bucket=400
identify   ✓  bearer subject=alice
authorize  ✓  rbac
```

## References

- DESIGN: [DESIGN.md §M11](../DESIGN.md) "per-tenant rate limits".
- Source: [pkg/ratelimit/ratelimit.go](../../pkg/ratelimit/ratelimit.go).
- Tests: [pkg/ratelimit/ratelimit_test.go](../../pkg/ratelimit/ratelimit_test.go).
