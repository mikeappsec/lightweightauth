# `cache.backend: memory` — In-process LRU

Default cache backend. A bounded in-process LRU shared across all
modules that consult `cache.Backend` (introspection, JWKS metadata,
DPoP replay, decision cache, ...).

**Source:** [pkg/cache](https://github.com/mikeappsec/lightweightauth/tree/main/pkg/cache) — registered as `memory`.

## When to use

- Single-replica deployments / dev / tests.
- Replicas that don't need to share negative-cached results or DPoP `jti` rejections.
- You want zero external dependencies.

**Don't use** when:
- Multiple lwauth replicas behind a load balancer **and** you've enabled
  DPoP — a stolen `jti` could replay against another Pod. Use
  [`valkey`](cache-valkey.md).
- You want introspection caching shared across replicas to drop IdP QPS.

## Configuration

```yaml
cache:
  backend: memory          # default; can be omitted

  # Optional sizing. Defaults are conservative.
  maxEntries: 50000        # global LRU cap across all keys
  defaultTtl: 5m           # used when a caller doesn't pass an explicit TTL

  # Per-namespace TTL overrides (M5 decision cache, M6 sessions, etc.).
  decisionTtl: 30s
  introspectionTtl: 5m
```

Eviction: simple LRU at `maxEntries`; entries past their TTL are skipped
on read and pruned opportunistically.

## Helm wiring

Default — nothing to set:

```yaml
# values.yaml
config:
  inline: |
    cache:
      backend: memory
      maxEntries: 100000
```

## Worked example

Two replicas, `memory` backend, 5-min introspection TTL. The same opaque
token hitting Pod A and Pod B causes **two** introspection calls (once
per replica). With [`valkey`](cache-valkey.md) it would be one.

## References

- Source: [pkg/cache/memory.go](https://github.com/mikeappsec/lightweightauth/blob/main/pkg/cache/memory.go).
- DESIGN.md §5 — decision cache.
