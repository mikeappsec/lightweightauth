# `oauth2-introspection` — Opaque bearer tokens

Verifies opaque OAuth 2.0 access tokens by calling the IdP's RFC 7662
introspection endpoint. The result is cached per-token until `exp` (or
`maxCacheTtl`) so the IdP sees one round-trip per token.

**Source:** [pkg/identity/introspection](../../pkg/identity/introspection/introspection.go) — registered as `oauth2-introspection`.

## When to use

- IdP issues opaque tokens (random strings, no `.` separators).
- IdP exposes `/oauth2/introspect` (Keycloak, Auth0, Hydra, Okta).
- You can tolerate a bounded IdP round-trip per fresh token.

**Don't use** for self-contained JWTs — [`jwt`](jwt.md) is dramatically cheaper.

## Configuration

```yaml
identifiers:
  - name: opaque-bearer
    type: oauth2-introspection
    config:
      url:           https://idp.example.com/oauth2/introspect   # REQUIRED
      clientId:      my-api                                       # for Basic auth to /introspect
      clientSecret:  ${INTROSPECT_SECRET}

      headerName: Authorization    # default
      # cacheSize bounds in-process LRU; cluster-shared cache uses the
      # `valkey` backend selected on AuthConfig.cache.backend.
      cacheSize: 10000
```

The cache key is `sha256(token)`; entries TTL = `min(claims.exp - now, 5m)`.
`active=false` responses are negative-cached for `negativeTtl` (default 30s)
so a poisoned token doesn't hammer the IdP. Concurrent first-misses
collapse to one IdP call via singleflight.

> **Revocation note.** Cached results survive an IdP-side revocation
> until TTL. Use short token TTLs or opt into the M14 revocation surface
> if you need stronger guarantees.

## Helm wiring

```yaml
# values.yaml
config:
  inline: |
    identifiers:
      - name: opaque-bearer
        type: oauth2-introspection
        config:
          url: https://idp.example.com/oauth2/introspect
          clientId: my-api
          clientSecret: ${INTROSPECT_SECRET}    # from a Secret env var
    authorizers:
      - { name: any-auth, type: rbac, config: { allow: ["*"] } }
```

Inject `INTROSPECT_SECRET` from a Kubernetes Secret with the chart's
`extraEnv` (M9 will add a first-class secret-ref helper).

## Worked example

First request with a fresh token:

```
client → lwauth → POST /oauth2/introspect (token=...)
                ← {"active":true,"sub":"alice","exp":1731000000,...}
        → cache.Set(sha256(token), 5m TTL)
        → continue pipeline
```

Subsequent requests with the same token:

```
client → lwauth → cache.Get(sha256(token)) → hit → continue
```

## Composition

- Stack with [`jwt`](jwt.md) under `firstMatch` so signed tokens skip
  the network call entirely.
- Use [`valkey`](cache-valkey.md) cache backend to share introspection
  results across replicas — saves IdP load when the same token hits
  different Pods.

## References

- RFC 7662 (Token Introspection).
- [DESIGN.md §4](../DESIGN.md) — token introspection.
- Source: [pkg/identity/introspection/introspection.go](../../pkg/identity/introspection/introspection.go).
