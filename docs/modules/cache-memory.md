# `cache.backend: memory` — In-process LRU

Default cache backend for the pipeline's decision cache
(`AuthConfig.cache:`, one cache, not a shared multi-namespace pool).
`pkg/cache/memory.go` is a *different*, unrelated pool-cache
subsystem used by the separate `caches:` block (`CachePoolSpec`) —
don't confuse the two when reading source.

**Source:** [internal/cache](https://github.com/mikeappsec/lightweightauth/tree/main/internal/cache) (`decision.go`, `lru.go`), wired via `internal/config/loader.go`'s `buildDecisionCache`.

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

`maxEntries`, `defaultTtl`, `decisionTtl`, and `introspectionTtl` in
the old example below don't exist on `CacheSpec`
(`internal/config/config.go`) — the whole `AuthConfig` decodes via
plain `yaml.Unmarshal` with no unknown-field rejection, so these keys
are silently dropped rather than erroring; an operator following the
old example gets none of the described caps. There's also no
per-namespace TTL split — one `cache:` block backs the single
decision cache, with one `ttl`/`negativeTtl` pair, not separate knobs
per consumer:

```yaml
cache:
  backend: memory          # default; can be omitted
  key: [sub, method, path] # fields hashed into the cache key
  ttl: 30s                 # entry lifetime; 0/omitted disables caching
  negativeTtl: 5s          # how long deny decisions are cached
```

Eviction: simple LRU. The default size when unset is **10,000**
entries (`internal/cache/decision.go`) — there's no config field to
change it for the plain `memory` backend (only `l1Size`, which only
applies when `backend: tiered`).

## Helm wiring

Default — nothing to set:

```yaml
# values.yaml
config:
  inline: |
    cache:
      backend: memory
      key: [sub, method, path]
      ttl: 30s
```

## Worked example

Two replicas, `memory` backend, 5-min introspection TTL. The same opaque
token hitting Pod A and Pod B causes **two** introspection calls (once
per replica). With [`valkey`](cache-valkey.md) it would be one.

## References

- Source: [pkg/cache/memory.go](https://github.com/mikeappsec/lightweightauth/blob/main/pkg/cache/memory.go).
- DESIGN.md §5 — decision cache.
