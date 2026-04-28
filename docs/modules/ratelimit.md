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
- **Distribution.** Buckets are local to each lwauth replica (token
  count is goroutine-state, not shared via Valkey). With N replicas a
  tenant's effective limit is `N × rps`. Sticky-routing or aggregate
  rate limiting belongs at the L7 proxy in front of lwauth.

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
