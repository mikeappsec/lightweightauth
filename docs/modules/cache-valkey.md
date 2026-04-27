# `cache.backend: valkey` — Shared cluster cache

Valkey-/Redis-protocol-compatible shared cache. Used cluster-wide for
introspection results, DPoP `jti` replay, decision cache (M5), and the
M14 revocation lists (when enabled).

**Source:** [pkg/cache](../../pkg/cache) — registered as `valkey`.

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
  tls:
    enabled: true
    caFile:  /etc/valkey/ca.pem

  keyPrefix: lwauth/                  # namespacing per-cluster
  poolSize: 16                        # connections per replica
  dialTimeout:  500ms
  readTimeout:  150ms                 # tight; surfaces backend trouble fast
  writeTimeout: 150ms

  # Per-namespace TTLs (default cascade from defaultTtl).
  defaultTtl:        5m
  decisionTtl:       30s
  introspectionTtl:  5m
  dpopReplayTtl:     60s              # 2·dpop.skew
```

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
      decisionTtl: 30s
      introspectionTtl: 5m
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
- Source: [pkg/cache/valkey.go](../../pkg/cache/valkey.go).
- DESIGN.md §5 (decision cache), §M14 (revocation).
