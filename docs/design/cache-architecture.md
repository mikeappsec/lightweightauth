# Cache Architecture & Design Trade-offs

> LightWeightAuth v1.2 — ENT-CACHE-1 (E1)

## Overview

LightWeightAuth makes an authorization decision on every inbound request.
Each decision may invoke one or more upstream calls:

1. **JWKS fetch** — download the issuer's public keyset to verify JWT signatures
2. **Token introspection** — call the IdP to validate an opaque token
3. **Authorization query** — evaluate policy via OPA, OpenFGA, or CEL

Caching reduces latency and protects upstream services from load. The
project uses a layered caching strategy where each cache tier is tuned to
the data characteristics of the upstream it fronts.

---

## Cache Layers in the Pipeline

```
Request ──► Pipeline.Evaluate()
              │
              ├─► [Identify]
              │     ├─► JWKS Cache (jwx.Cache, in-process)
              │     └─► Introspection Cache (3× LRU, in-process)
              │
              ├─► [Decision Cache] ◄── E1 tiered (L1 + L2)
              │     HIT? → return cached verdict, skip authorize
              │
              └─► [Authorize]
                    ├─► OPA (Rego evaluation)
                    ├─► OpenFGA (relationship check)
                    └─► CEL (expression evaluation)
                          │
                          └─► verdict written to Decision Cache
```

---

## Per-Component Cache Design

### 1. JWKS (Token Signature Verification)

| Property | Value |
|----------|-------|
| Backend | `jwx.Cache` (in-process, auto-refresh) |
| Shared across replicas | No |
| Typical size | 2–5 keys per issuer (~2 KB) |
| Refresh strategy | Background poll every 15 min; immediate on unknown `kid` |
| HTTP optimization | Conditional GET (ETag / If-Modified-Since → 304) |
| Eviction | Replaced atomically on refresh |

**Trade-off: Why no L2?**

- Keysets are tiny and identical across all pods — every pod fetching the
  same URL is negligible load on the IdP (CDN-backed, returns 304).
- Adding Valkey would add a network hop (~1.5 ms) for data that is already
  in-memory and refreshes in the background. Net benefit is negative.
- JWKS endpoints are public, highly available, and rate-limit-friendly.

**When L2 makes sense (future M2):** If an operator runs 500+ pods against
a single issuer with aggressive refresh intervals, sharing the keyset in L2
avoids 499 redundant fetches per cycle. This is tracked for migration via
`cache.Layer.JWKS`.

---

### 2. Token Introspection

| Property | Value |
|----------|-------|
| Backend | 3× `cache.LRU` per identifier (positive, negative, error) |
| Shared across replicas | No (pod-local) |
| Typical size | 10,000 entries per cache × ~500 B = ~5 MB per pod |
| Key | `sha256(token)` |
| Positive TTL | `min(token.exp - now, maxCacheTTL)` (dynamic) |
| Negative TTL | 30 s (token inactive) |
| Error TTL | 5 s (upstream failure) |
| Eviction | TTL expiry (lazy on Get) + LRU size cap |

**Trade-off: Why three separate caches?**

- Different TTL semantics: a positive hit lives for minutes; a negative hit
  must expire quickly (the token may be re-issued with a new `jti`); an
  error must expire in seconds (the IdP may recover).
- Mixing them in one LRU would require per-entry type discrimination on
  every read and complicates eviction priority (errors should be evicted
  first, not LRU-ordered alongside valid claims).

**Trade-off: Why no L2 yet?**

| Concern | Detail |
|---------|--------|
| PII exposure | Introspection responses contain claims (email, name, roles). Writing to shared Valkey requires encryption at rest or field-level redaction. |
| Dynamic TTL | `min(exp - now, max)` varies per entry. Short-lived tokens (negative: 30s, error: 5s) expire before another pod would read them — the L2 network hop is wasted. |
| Revocation prerequisite | Safe sharing requires cross-replica revocation (E2) so a revoked token is invalidated in L2 for all pods atomically. |
| Complexity budget | Introspection caching is already effective pod-local; the marginal hit-rate gain from L2 doesn't justify the security surface until E2 lands. |

**Planned (M2):** After E2 revocation is proven, migrate to
`cache.Layer.Introspect` backed by the tiered backend. Positive entries
will be encrypted with a per-tenant key before L2 write.

---

### 3. Authorization Decision (OPA / OpenFGA / CEL)

| Property | Value |
|----------|-------|
| Backend | `cache.Decision` → pluggable Backend (memory, valkey, **tiered**) |
| Shared across replicas | **Yes** (with `backend: tiered` or `backend: valkey`) |
| Typical size | L1: 10k–20k entries per pod; L2: 500k–1M keys in Valkey |
| Key | `sha256(sub \| tenant \| method \| host \| path \| header:* \| claim:*)` |
| Positive TTL | Configurable (default 60 s) |
| Negative TTL | Configurable (default 5 s) |
| Eviction (L1) | LRU size cap + per-entry TTL |
| Eviction (L2) | TTL expiry + Valkey `maxmemory-policy: allkeys-lru` |
| Singleflight | Yes — concurrent misses on the same key coalesce into one upstream call |

**Trade-off: Why cache at the decision level (not per-authorizer)?**

- A single decision may compose multiple authorizers (`composite: and/or`).
  Caching the final verdict replaces N upstream calls with one cache lookup.
- The cache key includes identity + request dimensions (configurable), so
  different users/paths/methods are correctly isolated.
- Upstream errors are **never cached** — a transient OPA/OpenFGA outage
  cannot freeze a denial in the cache.

**Trade-off: Why short negative TTL (5 s)?**

- A denied user who is then granted access should not wait 60 s for the
  cache to expire. 5 s balances protection (doesn't stampede the authorizer
  on repeated denials) with responsiveness (access is restored quickly).
- Operators can tune `negativeTtl` per AuthConfig based on their access
  change velocity.

---

## E1: Two-Tier (Tiered) Backend

### Design

```
┌──────────────────────────────────────────────────────────┐
│  Tiered Backend                                          │
│                                                          │
│  Get(key):                                               │
│    L1.Get(key) ──► HIT → return (stats: L1 hit)         │
│         │                                                │
│         ▼ MISS                                           │
│    L2.Get(key) ──► HIT → L1.Set(key, val) → return      │
│         │                   (read-through, stats: L2 hit)│
│         ▼ MISS                                           │
│    return miss (stats: both miss)                        │
│                                                          │
│  Set(key, val, ttl):                                     │
│    L1.Set(key, val, ttl)                                 │
│    L2.Set(key, val, ttl)  (write-through)                │
│                                                          │
│  Delete(key):                                            │
│    L1.Delete(key)                                        │
│    L2.Delete(key)                                        │
└──────────────────────────────────────────────────────────┘
```

### Why L1 + L2 (not L2 only)?

| Scenario | L2 only | L1 + L2 |
|----------|---------|---------|
| Repeated request (same pod) | 1.5 ms (network) | **100 ns** (memory) |
| First request after pod start | 1.5 ms | 1.5 ms (then L1 warm) |
| Cross-pod deduplication | ✓ | ✓ (via L2) |
| Memory per pod | 0 | ~5–10 MB (configurable) |
| Valkey load | Every request | Only L1 misses (~15% of traffic) |

L1 reduces Valkey QPS by ~85% at steady state. Without L1, a 100-pod
cluster doing 50k req/s would send 50k×100 = 5M req/s to Valkey. With L1
(85% hit rate), Valkey sees ~750k req/s — a 6.7× reduction.

### Cold-Start Warming

New pods start with an empty L1. Without warming:
- First N requests all miss L1 → hit L2 → 1.5 ms each (acceptable)
- If L2 is also cold (new cluster), all miss → upstream calls (expected)

The `Warm(ctx, keys)` method allows operators to preload hot keys from L2
into L1 at startup. This is optional; organic warming via read-through
achieves steady-state hit rates within seconds under load.

---

## Scaling Characteristics

### Per-Pod Memory Budget

| Cache | Entries | Avg Size | Memory |
|-------|---------|----------|--------|
| JWKS | 5 | 2 KB | 10 KB |
| Introspection (3×) | 30,000 | 500 B | 15 MB |
| Decision (L1) | 20,000 | 200 B | 4 MB |
| **Total per pod** | | | **~20 MB** |

### Valkey Cluster Sizing (L2)

| Metric | Formula | Example (100 pods, 50k req/s) |
|--------|---------|-------------------------------|
| Unique keys | unique(sub × method × path) × TTL window | ~500k keys |
| Memory | keys × (key_size + val_size + overhead) | ~500 MB |
| QPS (with L1) | total_req/s × L1_miss_rate | ~7,500 req/s |
| QPS (without L1) | total_req/s | ~50,000 req/s |

Recommendation: `maxmemory: 1GB`, `maxmemory-policy: allkeys-lru` for a
production cluster. Valkey handles 100k+ ops/sec on a single node.

---

## Eviction & Rotation Summary

| Cache | Primary Eviction | Secondary Eviction | Rotation Trigger |
|-------|-----------------|-------------------|-----------------|
| JWKS | Time-based refresh (15 min) | None (tiny, bounded) | Key rotation at IdP |
| Introspection pos | TTL = min(exp-now, max) | LRU size cap | Token expiry |
| Introspection neg | TTL = 30 s | LRU size cap | Re-introspection |
| Introspection err | TTL = 5 s | LRU size cap | IdP recovery |
| Decision L1 | LRU size cap | Per-entry TTL | Policy change / hot-reload |
| Decision L2 | TTL expiry | `allkeys-lru` at maxmemory | Natural expiry |

---

## Security Considerations

| Concern | Mitigation |
|---------|-----------|
| Cache poisoning (attacker injects false allow) | Cache key includes identity subject — attacker cannot influence another user's cached decision |
| Stale allows after permission revocation | Short positive TTL (60s default); explicit revocation via E2 `POST /v1/admin/revoke` deletes from L1+L2 |
| Upstream errors cached as denials | Errors are **never cached** in the decision cache; `module.ErrUpstream` propagates immediately |
| PII in L2 (introspection claims) | Deferred to M2; decision cache stores only `{allow, status, reason}` — no PII |
| Timing side-channel (cache hit vs miss) | Both paths return the same response structure; latency difference (100ns vs 15ms) is observable but does not leak the *content* of other users' decisions |
| L2 data at rest | Operators enable Valkey TLS + ACLs; optional field-level encryption planned for M2 introspection sharing |

---

## Configuration Reference

```yaml
cache:
  # Key dimensions for the decision cache composite key.
  # A typo here is rejected at load time (fail-closed).
  key: [sub, method, path]

  # How long "allow" decisions are cached.
  ttl: 60s

  # How long "deny" decisions are cached (short = fast unlock).
  negativeTtl: 5s

  # Backend selection:
  #   "memory"  — in-process LRU only (default, single-pod)
  #   "valkey"  — shared Valkey only (no local fast-path)
  #   "tiered"  — L1 in-process LRU + L2 Valkey (recommended for multi-replica)
  backend: tiered

  # L1 size (entries). Only used when backend is "tiered" or "memory".
  l1Size: 20000

  # L2 connection (used by "valkey" and "tiered").
  addr: valkey-master.cache.svc:6379
  username: default
  password: ${VALKEY_PASSWORD}
  tls: true
  keyPrefix: lwauth/prod/
```

---

## Alternatives Considered

### L2 Backend Alternatives

| Alternative | Pros | Cons | Verdict |
|-------------|------|------|---------|
| **Valkey** | OSS (BSD-3), wire-compatible with Redis, cloud-managed, pub/sub for E3 | Requires network hop | ✅ Selected |
| Redis 7.x | Mature, widely deployed | RSALv2/SSPLv1 license (non-OSS), incompatible with Apache-2.0 project | ❌ License conflict |
| Memcached | Simple, battle-tested | No per-key TTL pub/sub (needed for E3 invalidation), no cluster replication | ❌ Missing features |
| DragonflyDB | Redis-compatible, multi-threaded | BSL license (same concern as Redis) | ❌ License conflict |
| Hazelcast | Near-cache built-in | Heavy JVM dependency, overkill for sidecar | ❌ Operational weight |
| Embedded (BadgerDB) | No network hop | Not shared across replicas — defeats L2 purpose | ❌ Wrong model |
| etcd | Already in K8s | Not designed for high-throughput cache; 1.5 MB value limit | ❌ Wrong workload |

### Caching Level Alternatives

| Strategy | Pros | Cons | Verdict |
|----------|------|------|---------|
| Per-authorizer cache (cache each OPA/OpenFGA call) | Fine-grained TTL per backend | N cache lookups per request instead of 1; composite decisions not cacheable | ❌ Higher overhead |
| **Per-decision cache** (cache final verdict) | 1 lookup replaces entire pipeline; simple key model | Coarser granularity (invalidates whole verdict on any policy change) | ✅ Selected |
| HTTP-level cache (Varnish/CDN in front) | Zero code change | Cannot key on identity claims; cache key = URL only | ❌ Insufficient key dimensions |
| Client-side cache (token carries decision) | Zero server-side state | Token bloat; cannot revoke; violates least-privilege | ❌ Security concern |

---

## Metrics Emitted

| Metric | Labels | Purpose |
|--------|--------|---------|
| `lwauth_cache_hits_total` | `cache` | Aggregate hits (L1 or L2) |
| `lwauth_cache_misses_total` | `cache` | Aggregate misses (both layers missed) |
| `lwauth_cache_evictions_total` | `cache` | L1 LRU evictions |
| `lwauth_cache_layer_hits_total` | `cache`, `layer` | Per-layer hits (E1) |
| `lwauth_cache_layer_misses_total` | `cache`, `layer` | Per-layer misses (E1) |

**Alerting examples:**

```promql
# L1 hit rate dropping — consider increasing l1Size
1 - (rate(lwauth_cache_layer_hits_total{layer="l1"}[5m])
   / (rate(lwauth_cache_layer_hits_total{layer="l1"}[5m])
    + rate(lwauth_cache_layer_misses_total{layer="l1"}[5m]))) > 0.3

# L2 miss rate high — cache is ineffective, check TTL/key config
rate(lwauth_cache_layer_misses_total{layer="l2"}[5m])
/ (rate(lwauth_cache_layer_hits_total{layer="l2"}[5m])
 + rate(lwauth_cache_layer_misses_total{layer="l2"}[5m])) > 0.5
```

---

## Roadmap

| Milestone | Feature | Status |
|-----------|---------|--------|
| E1 | Decision cache tiered backend (L1+L2) | ✅ Done |
| E2 | Revocation store (cross-replica token kill) | Next |
| E3 | Tag-based invalidation + stale-while-revalidate | Planned |
| E4 | Cross-replica singleflight (Valkey SETNX locks) | Planned |
| M2 | Introspection + JWKS migration to `cache.Layer` with tiered backend | Future |
