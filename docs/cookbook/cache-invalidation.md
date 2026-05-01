# Invalidate cached decisions and introspection results

lwauth caches aggressively — decision verdicts, introspection
responses, JWKS metadata, DPoP `jti` replay records — because the
alternative is calling the IdP or policy engine on every request. Most
of the time TTL expiry is the right invalidation strategy: short TTLs
(30s decision, 5m introspection) keep staleness bounded without
operator intervention.

Sometimes you need to invalidate **now**: a user's access was revoked,
a policy was wrong, or an introspection cache is serving a stale
`active: true` for a token the IdP has since disabled. This recipe
covers the manual and automated invalidation paths available today and
the tag-based invalidation coming in Tier E.

## What this recipe assumes

- lwauth with the [`valkey` cache backend](../modules/cache-valkey.md)
  for shared invalidation across replicas. The [`memory`
  backend](../modules/cache-memory.md) path is noted where it
  differs.
- `kubectl` access to the lwauth namespace.
- Basic familiarity with Valkey/Redis CLI commands.

## When to invalidate (and when not to)

| Situation | Invalidate? | Why |
|---|---|---|
| User's access revoked at IdP | **Yes** — introspection cache | Cached `active: true` persists until TTL |
| Policy updated via AuthConfig | **No** — automatic | Engine hot-swap compiles new policy; decision cache keys include policy version |
| JWKS key rotated at IdP | **No** — automatic | JWKS cache refreshes on interval; see [rotate-jwks](rotate-jwks.md) |
| Wrong policy shipped, need immediate rollback | **Maybe** | Rollback the AuthConfig first (engine swap is atomic); invalidate the decision cache only if stale cached verdicts from the bad policy are still being served |
| Compromised token needs kill-switch | **Yes** — introspection + decision cache | Short-TTL usually suffices; for guaranteed kill use revocation (Tier E — M14) |

## 1. Invalidate via TTL tuning (no Valkey access needed)

The simplest invalidation is to shorten the TTL so stale entries
expire faster. This works for both `memory` and `valkey` backends:

```yaml
# Tighten decision cache to 5 seconds during an incident.
# Normal: decisionTtl: 30s
cache:
  backend: valkey
  addr: valkey-master.cache.svc:6379
  decisionTtl: 5s          # ← temporary tightening
  introspectionTtl: 30s    # ← tighten if introspection is the problem
```

```bash
lwauthctl validate --config tightened-config.yaml
kubectl apply -f tightened-config.yaml
```

The engine hot-swaps the new TTL immediately. Existing cache entries
keep their original expiry, but new writes use the shorter TTL.
Within `max(old TTL)` seconds, every entry written under the old TTL
has expired.

**Revert** after the incident by restoring the original TTLs.

## 2. Invalidate the Valkey cache directly

For immediate invalidation, delete keys from Valkey. lwauth uses a
predictable key prefix structure:

```
<keyPrefix>/<namespace>/<tenant>/<hash>
```

Where `keyPrefix` defaults to `lwauth/` (configurable in
`cache.keyPrefix`).

### Flush the entire lwauth cache

```bash
# Connect to Valkey
kubectl -n cache exec -it deploy/valkey -- valkey-cli

# Delete all lwauth keys (use SCAN, never KEYS in production)
127.0.0.1:6379> EVAL "local c=0; local r=redis.call('SCAN','0','MATCH','lwauth/*','COUNT',1000); for _,k in ipairs(r[2]) do redis.call('DEL',k); c=c+1 end; return c" 0
# Returns: number of deleted keys

# For large caches, loop until the cursor returns 0:
# (script version)
```

```bash
# Or from outside the pod, one-liner:
kubectl -n cache exec deploy/valkey -- valkey-cli --scan --pattern 'lwauth/*' | \
  xargs -L 100 kubectl -n cache exec -i deploy/valkey -- valkey-cli DEL
```

### Flush only the decision cache for one tenant

```bash
kubectl -n cache exec deploy/valkey -- \
  valkey-cli --scan --pattern 'lwauth/decision/payments/*' | \
  xargs -L 100 kubectl -n cache exec -i deploy/valkey -- valkey-cli DEL
```

### Flush introspection cache for a specific token

If you know the token (or its SHA-256 hash), delete the exact key:

```bash
TOKEN_HASH=$(echo -n "$TOKEN" | sha256sum | cut -d' ' -f1)
kubectl -n cache exec deploy/valkey -- \
  valkey-cli DEL "lwauth/introspect/$TOKEN_HASH"
```

## 3. Invalidate the in-process LRU (memory backend)

The `memory` backend has no external handle. Two options:

### Option A: Restart the pods

```bash
kubectl -n lwauth-system rollout restart deploy/lwauth
```

This is a blunt instrument — every pod drops its entire L1 cache and
starts cold. Use it only when the blast radius is acceptable.

### Option B: Lower TTL + wait

Same as §1 above. The LRU entries expire within the old TTL window.
No restart needed, but not instantaneous.

## 4. Tag-based invalidation (Tier E — ENT-CACHE-2)

When Tier E ships, cache writes will carry tags for tenant, subject,
policy version, and AuthConfig. Invalidation becomes a targeted
operation:

```bash
# Future: invalidate all cached decisions for user alice
# in the payments tenant
lwauthctl cache invalidate \
  --tenant payments \
  --subject alice

# Future: invalidate everything tied to a specific policy version
lwauthctl cache invalidate \
  --policy-version "2026-04-15-prod"
```

This publishes a `cache.invalidate` event over Valkey pub/sub; every
replica drops matching L1 entries and the L2 keys are deleted. Until
then, the manual Valkey key deletion in §2 is the equivalent.

## 5. Verify the invalidation worked

After invalidating, confirm that fresh requests are hitting the
backend (IdP, OPA, OpenFGA) rather than the cache:

```bash
# Check cache hit/miss metrics
kubectl -n lwauth-system exec deploy/lwauth -c lwauth -- \
  curl -s localhost:8080/metrics | grep lwauth_cache

# Look for a spike in cache misses:
#   lwauth_cache_hits_total{cache="decision", outcome="miss"}
#   lwauth_cache_hits_total{cache="introspect", outcome="miss"}

# Confirm upstream calls increased:
#   lwauth_upstream_requests_total{upstream="introspect"}
```

```promql
# PromQL: cache miss rate spike after invalidation
rate(lwauth_cache_hits_total{outcome="miss"}[1m])
```

The miss rate should spike briefly then settle as the cache refills
with fresh entries.

## Operational checklist

```markdown
- [ ] Identify what to invalidate (decision, introspection, or both)
- [ ] Identify the scope (all tenants, one tenant, one user, one token)
- [ ] If Valkey: connect and delete the matching keys (§2)
- [ ] If memory-only: lower TTL (§1) or restart pods (§3)
- [ ] Verify cache misses spiked (§5)
- [ ] Verify the correct behaviour on a test request
- [ ] Restore TTLs if you tightened them
- [ ] Document the incident and what triggered the invalidation
```

## What can still go wrong

- **Deleting DPoP replay keys.** The `lwauth/dpop/*` keys are
  **security-critical** — they prevent token replay. Do NOT delete
  them unless you understand the consequences. A deleted DPoP `jti`
  record means a replayed token will be accepted until TTL re-expires.
  Scope your `SCAN` pattern carefully.
- **Thundering herd after flush.** Deleting the entire cache under
  load causes every request to miss simultaneously, potentially
  overwhelming the IdP or policy engine. Prefer scoped invalidation
  (per-tenant, per-subject) over a full flush. If you must flush
  everything, consider doing it during a low-traffic window.
- **Race between invalidation and cache write.** A request in flight
  during the `DEL` may re-populate the key with stale data. For
  absolute consistency, combine invalidation with a TTL tightening:
  delete the keys, then lower the TTL so any re-populated entry
  expires quickly.
- **Memory backend has no cross-replica story.** Each pod has its own
  LRU. Deleting keys on one pod does not affect others. This is why
  the `valkey` backend is recommended for multi-replica deployments.

## What to look at next

- [Valkey outage drill](valkey-outage-drill.md) — what happens when
  the cache backend itself goes down.
- [`cache-valkey` reference](../modules/cache-valkey.md) — key prefix,
  TTLs, failure modes.
- [`cache-memory` reference](../modules/cache-memory.md) — LRU sizing.
- [DESIGN.md §11.3](../DESIGN.md) — multi-tier cache, tag
  invalidation, stale-while-revalidate design.

## References

- [`cache-valkey`](../modules/cache-valkey.md) — configuration and
  key structure.
- [`cache-memory`](../modules/cache-memory.md) — in-process LRU.
- [`observability`](../modules/observability.md) — cache metrics.
- [DESIGN.md §11.3](../DESIGN.md) — caching improvements design.
- Roadmap: E1 (ENT-CACHE-1), E3 (ENT-CACHE-2), E4 (ENT-CACHE-3).
