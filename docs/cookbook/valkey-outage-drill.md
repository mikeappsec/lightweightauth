# Valkey outage drill — what happens when the cache goes down

lwauth uses Valkey as a shared cache for introspection results,
decision verdicts, DPoP replay detection, and (in future) revocation
lists. Valkey is not in the trust path — lwauth never delegates an
auth *decision* to Valkey — but a Valkey outage changes the
performance and consistency profile of your deployment. This recipe
walks you through a controlled Valkey outage drill so you know exactly
what to expect before it happens at 02:00 on a Saturday.

## What this recipe assumes

- A multi-replica lwauth deployment with
  [`cache.backend: valkey`](../modules/cache-valkey.md).
- A Valkey instance you can safely disrupt (ideally a staging
  cluster; if you must drill in production, use the pod-isolation
  approach in §3).
- `kubectl`, Prometheus, and a way to generate representative
  traffic (a load test, a shadow traffic replay, or simply your
  existing staging workload).
- Familiarity with lwauth's cache failure modes
  ([`cache-valkey`](../modules/cache-valkey.md)).

## The failure model

lwauth treats Valkey failures differently depending on the cache
namespace:

| Cache namespace | Failure mode | Why |
|---|---|---|
| **Decision cache** | **Fail-open** — cache miss, evaluate from scratch | Correctness: a stale cached verdict is worse than a fresh evaluation. Cost: more CPU, more upstream calls, higher p99. |
| **Introspection cache** | **Fail-open** — call the IdP directly | Same logic. Cost: IdP sees N× traffic (one call per replica per request instead of one shared cache hit). |
| **DPoP replay** (`jti` dedup) | **Fail-closed** — reject the request | Security: without the replay store, a stolen DPoP proof can be replayed across replicas. This is the one cache namespace where a Valkey outage causes denials. |
| **Distributed rate limit** (K-DOS-1, v1.1+) | **Configurable** — `failOpen: true` (default) or `failOpen: false` | Default: fall back to per-replica local buckets. Effective limit becomes `N × rps` but no outage. |

**Bottom line:** a Valkey outage degrades performance (more upstream
calls, higher latency) and, if DPoP is enabled, causes hard denials
on replayed proofs. It does **not** cause incorrect allow/deny
verdicts for non-DPoP traffic.

## 1. Baseline — capture steady-state metrics

Before killing Valkey, snapshot the metrics you will compare against:

```bash
# Cache hit rates
kubectl -n lwauth-system exec deploy/lwauth -c lwauth -- \
  curl -s localhost:8080/metrics | \
  grep -E 'lwauth_cache_hits_total|lwauth_upstream_requests_total' \
  > baseline-metrics.txt

# Latency
kubectl -n lwauth-system exec deploy/lwauth -c lwauth -- \
  curl -s localhost:8080/metrics | \
  grep lwauth_request_duration_seconds > baseline-latency.txt
```

```promql
# PromQL: steady-state baselines to compare later
# Decision cache hit ratio
sum(rate(lwauth_cache_hits_total{cache="decision",outcome="hit"}[5m]))
/
sum(rate(lwauth_cache_hits_total{cache="decision"}[5m]))

# Introspection upstream call rate
sum(rate(lwauth_upstream_requests_total{upstream="introspect"}[5m]))

# p99 request latency
histogram_quantile(0.99,
  sum(rate(lwauth_request_duration_seconds_bucket[5m])) by (le))
```

Record these numbers. You will compare them during and after the
outage.

## 2. Kill Valkey

### Option A: Delete the pod (recommended for drills)

```bash
# Scale Valkey to zero. This simulates a clean outage.
kubectl -n cache scale deploy/valkey --replicas=0

# Note the time for metric correlation.
echo "Valkey down at $(date -u +%H:%M:%SZ)"
```

### Option B: Network partition (more realistic)

```bash
# Apply a NetworkPolicy that blocks lwauth → Valkey traffic.
cat <<'EOF' | kubectl apply -f -
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: drill-block-valkey
  namespace: lwauth-system
spec:
  podSelector:
    matchLabels:
      app.kubernetes.io/name: lwauth
  policyTypes: [Egress]
  egress:
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: cache
      ports: []             # empty = block all ports to cache namespace
    - to:
        - namespaceSelector: {}
      ports:
        - port: 443
        - port: 53
          protocol: UDP
EOF
```

This keeps Valkey running but makes it unreachable from lwauth,
simulating a network partition. Lwauth's Valkey client will hit
`dialTimeout` (default 500ms) on every operation.

### Option C: Valkey PAUSE (latency injection)

```bash
# Pause Valkey for 30 seconds at a time. Simulates a GC pause
# or disk I/O stall.
kubectl -n cache exec deploy/valkey -- valkey-cli DEBUG SLEEP 30
```

## 3. Observe the impact

With Valkey down and traffic flowing, watch the metrics change in
real time:

```bash
# Cache metrics should show errors instead of hits
kubectl -n lwauth-system exec deploy/lwauth -c lwauth -- \
  curl -s localhost:8080/metrics | \
  grep -E 'lwauth_cache_hits_total|lwauth_cache_errors_total'
```

### Expected behaviour

| Metric | Expected change |
|---|---|
| `lwauth_cache_hits_total{outcome="hit"}` | Flatlines (no new hits) |
| `lwauth_cache_hits_total{outcome="miss"}` | Spikes (every request misses) |
| `lwauth_cache_errors_total` | Starts counting (Valkey connection errors) |
| `lwauth_upstream_requests_total{upstream="introspect"}` | Spikes (every introspection goes to IdP) |
| `lwauth_request_duration_seconds` (p99) | Increases (no cache shortcut) |
| `lwauth_decisions_total{outcome="deny",reason="dpop_replay"}` | If DPoP enabled: may see false-positive denials |
| `lwauth_ratelimit_backend_errors_total` | If distributed rate limit enabled: counts backend failures |

### What to verify

```bash
# 1. Non-DPoP traffic still gets correct verdicts.
#    A valid JWT should still get 200:
curl -s -o /dev/null -w '%{http_code}' \
  -H "Authorization: Bearer $VALID_TOKEN" \
  https://api.example.com/v1/orders
# expect: 200

# 2. An invalid token still gets 401:
curl -s -o /dev/null -w '%{http_code}' \
  -H "Authorization: Bearer invalid" \
  https://api.example.com/v1/orders
# expect: 401

# 3. If DPoP is enabled, check for replay denials:
kubectl -n lwauth-system logs deploy/lwauth -c lwauth | \
  grep -c "dpop.*replay" | tail -1
```

## 4. Restore Valkey

```bash
# Option A: Scale back up
kubectl -n cache scale deploy/valkey --replicas=1

# Option B: Remove the NetworkPolicy
kubectl -n lwauth-system delete networkpolicy drill-block-valkey

# Option C: Valkey comes back automatically after DEBUG SLEEP
```

## 5. Observe recovery

After Valkey returns, lwauth's cache client reconnects automatically
(the Valkey client retries with backoff). Watch the metrics converge
back to baseline:

```bash
# Cache hits should resume
kubectl -n lwauth-system exec deploy/lwauth -c lwauth -- \
  curl -s localhost:8080/metrics | \
  grep lwauth_cache_hits_total

# Upstream call rate should drop back to baseline
kubectl -n lwauth-system exec deploy/lwauth -c lwauth -- \
  curl -s localhost:8080/metrics | \
  grep lwauth_upstream_requests_total
```

```promql
# PromQL: recovery — cache hit ratio climbing back to steady state
sum(rate(lwauth_cache_hits_total{cache="decision",outcome="hit"}[1m]))
/
sum(rate(lwauth_cache_hits_total{cache="decision"}[1m]))
```

### Recovery timeline

| Phase | Duration | What happens |
|---|---|---|
| Reconnect | 0–5s | Valkey client detects connection is live, re-establishes pool |
| Cache warming | 5s–2min | L1 (in-process) fills from L2 (Valkey) on cache misses |
| Steady state | ~2min | Hit ratios return to baseline |

## 6. Write up the drill

Document the results for your incident runbook:

```markdown
## Valkey outage drill — [DATE]

**Duration:** [start] – [end] ([N] minutes)
**Method:** [pod delete / netpol / debug sleep]

### Impact observed
- Decision cache: hit ratio dropped from [X]% to 0%
- Introspection upstream calls: increased [N]× from baseline
- p99 latency: increased from [X]ms to [Y]ms
- DPoP replay denials: [N] (expected / not expected)
- Rate limiter fallback: [local buckets activated / N/A]

### Correctness
- Valid requests: ✅ continued to receive 200
- Invalid requests: ✅ continued to receive 401
- False positives: [none / N DPoP replay denials]

### Recovery
- Time to reconnect: [N]s
- Time to steady-state cache ratio: [N]s

### Action items
- [ ] [any tuning changes, e.g. adjust dialTimeout, add Valkey Sentinel]
```

## Hardening recommendations

Based on typical drill findings:

1. **Deploy Valkey with Sentinel or Cluster mode** for automatic
   failover. A single Valkey pod is a single point of degradation.

2. **Set tight timeouts** to fail fast rather than blocking:
   ```yaml
   cache:
     backend: valkey
     dialTimeout: 500ms
     readTimeout: 150ms
     writeTimeout: 150ms
   ```

3. **Disable DPoP if you cannot tolerate Valkey-dependent denials.**
   DPoP is the one namespace with fail-closed semantics. If your
   deployment cannot accept DPoP replay denials during a cache
   outage, reconsider whether DPoP is the right fit — or deploy
   Valkey with HA.

4. **Monitor `lwauth_cache_errors_total`.** Alert on a sustained
   non-zero rate. A single transient error is normal; a sustained
   stream means Valkey is unhealthy.

5. **Consider `serveStaleOnUpstreamError`** (Tier E — ENT-CACHE-2).
   When available, this lets lwauth serve stale cached values during
   upstream (IdP, OPA) failures. It does not help with Valkey
   failures directly, but it reduces the cascade when both Valkey
   and an upstream are down simultaneously.

## What to look at next

- [Cache invalidation](cache-invalidation.md) — manually clearing
  cache entries.
- [`cache-valkey` reference](../modules/cache-valkey.md) — timeouts,
  key prefix, pool sizing.
- [DESIGN.md §11.3](../DESIGN.md) — two-tier cache,
  stale-while-revalidate, cross-replica singleflight.
- [`ratelimit`](../modules/ratelimit.md) — distributed rate limiter
  fallback behaviour.

## References

- [`cache-valkey`](../modules/cache-valkey.md) — backend config.
- [`observability`](../modules/observability.md) — cache and upstream
  metrics.
- [DESIGN.md §11.3](../DESIGN.md) — caching design.
- Roadmap: E1 (ENT-CACHE-1), E3 (ENT-CACHE-2), E4 (ENT-CACHE-3).
