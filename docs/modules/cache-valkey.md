# `cache.backend: valkey` — Shared cluster cache

Valkey-/Redis-protocol-compatible shared cache. Used cluster-wide for
introspection results, DPoP `jti` replay, decision cache (M5), and the
M14 revocation lists (when enabled).

**Source:** [pkg/cache](https://github.com/mikeappsec/lightweightauth/tree/main/pkg/cache) — registered as `valkey`.

## When to use

- More than one lwauth replica.
- DPoP enabled: replay rejection must be cluster-wide or it's broken.
- High introspection QPS — one shared cache drastically cuts IdP load.
- Anticipating M14 revocation: revocation lists live in this backend.

## Configuration

```yaml
cache:
  backend: valkey
  addr:    valkey-master.cache.svc.cluster.local:6379
  # username / password / TLS as needed:
  username: lwauth
  password: ${VALKEY_PASSWORD}
  tls: true

  keyPrefix: lwauth/                  # namespacing per-cluster
  ttl: 30s                            # decision cache TTL
  negativeTtl: 5s                     # deny-decision cache TTL
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `backend` | string | `memory` | Set to `valkey` to enable shared cache |
| `addr` | string | *required* | Valkey host:port |
| `username` | string | `""` | Valkey ACL username |
| `password` | string | `""` | Valkey ACL password |
| `tls` | bool | `false` | Enable TLS (min 1.2) |
| `keyPrefix` | string | `"lwauth/"` | Key namespace — lets multiple deployments share a Valkey |
| `ttl` | duration | `30s` | Positive (allow) decision cache TTL |
| `negativeTtl` | duration | `5s` | Negative (deny) decision cache TTL |
| `key` | []string | `["sub","method","path"]` | Fields hashed into the cache key |
| `l1Size` | int | `10000` | L1 LRU size (only for `backend: tiered`) |

Failure mode is **fail-closed for security-critical reads** (DPoP
replay) and **fail-open for performance reads** (decision cache, JWKS
metadata) — so a Valkey outage degrades to "more IdP traffic" rather
than "outage".

## Helm wiring

```yaml
# values.yaml
config:
  inline: |
    cache:
      backend: valkey
      addr: valkey-master.cache.svc:6379
      keyPrefix: lwauth/prod/
      ttl: 30s
      negativeTtl: 5s
extraEnv:
  - name: VALKEY_PASSWORD
    valueFrom: { secretKeyRef: { name: lwauth-secrets, key: valkey } }
```

For Bitnami Valkey:

```bash
helm install valkey bitnami/valkey \
  --namespace cache --create-namespace \
  --set auth.password=$(openssl rand -base64 32)
```

## Worked example

Three lwauth replicas. Alice's opaque token first hits Pod A:

```
A: cache.Get(introspect/<sha>) → MISS
A: POST /introspect → cache.Set(introspect/<sha>, 5m)
```

Two seconds later the same token hits Pod B:

```
B: cache.Get(introspect/<sha>) → HIT (set by A)
```

IdP saw exactly one call.

## Composition

- Required when DPoP is enabled across more than one replica.
- Required for M14 revocation list (token revocation) to be cluster-wide.
- Pair with `valkey-cluster` deploy (Sentinel or Cluster mode) for HA;
  the client retries on `MOVED` / `ASK` automatically.

## References

- Valkey docs: <https://valkey.io>.
- Source: [pkg/cache/valkey.go](https://github.com/mikeappsec/lightweightauth/blob/main/pkg/cache/valkey.go).
- DESIGN.md §5 (decision cache), §M14 (revocation).
