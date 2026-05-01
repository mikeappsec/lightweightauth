# Seamless Policy Rotation

This guide explains how to safely migrate from one authorization policy to
another with **zero downtime and zero risk to production traffic**. The
process uses four graduated stages — each one gives you more confidence
before committing.

---

## Overview

| Stage | Mechanism | Risk to production | What you learn |
|---|---|---|---|
| **1. Offline replay** | `lwauthctl replay` | Zero | Which historical requests would change verdict |
| **2. Shadow mode** | `spec.mode: shadow` | Zero | Whether the new policy denies anything on live traffic |
| **3. Canary** | `spec.canary: { ... }` | Zero (observe) or low (enforce on a slice) | Exact disagreement direction on live traffic + path to cutover |
| **4. Promote** | Swap primary authorizer | Full cutover | — |

---

## Stage 1: Offline Replay

Replay your production audit log against both the current and candidate
policies without touching live traffic.

```bash
lwauthctl replay \
  --baseline config-prod.yaml \
  --candidate config-next.yaml \
  --audit /var/log/lwauth/audit.jsonl \
  --out disagreements.jsonl
```

**What happens:**
1. Both YAML files are compiled into pipeline Engines.
2. Each audit event is converted back into a `module.Request`.
3. Both engines evaluate the request independently.
4. Verdict differences are written to `--out` as JSONL.
5. Exit code 2 if any disagreements exist (CI gate).

**What you learn:**
- Exact count of requests where verdicts differ.
- For each disagreement: method, path, subject, prod verdict, candidate verdict.
- Whether the candidate is stricter (denies more) or more permissive (allows more).

**When to move on:** Zero disagreements, or all disagreements are intentional
(e.g., you're deliberately tightening access for a deprecated endpoint).

---

## Stage 2: Shadow Mode

Deploy a second AuthConfig with `mode: shadow`. It runs the full pipeline
on live traffic but **always returns allow** — the real verdict comes from
your production AuthConfig.

### Configuration

```yaml
apiVersion: lwauth.io/v1alpha1
kind: AuthConfig
metadata:
  name: api-shadow
spec:
  version: "opa-v2-candidate"
  mode: shadow
  hosts: ["api.example.com"]
  identifiers:
    - name: jwt
      type: jwt
      config: { issuer: "https://auth.example.com" }
  authorizers:
    - name: opa-next
      type: opa
      config:
        policy: file:///etc/lwauth/abac-next.rego
```

### How it works internally

```
Request arrives
  → Shadow Engine.Evaluate()
    → Identify (normal)
    → Authorize (OPA) → returns DENY
    → Shadow override kicks in:
        • shadowDisagreement = true
        • Metric incremented: lwauth_shadow_disagreement_total
        • Decision overwritten to {Allow: true}
        • Audit event emitted with shadow_disagreement: true
  → Returns allow (no impact on traffic)
```

### Observability

**Throughput** — shadow evaluates 100% of matching traffic:
```promql
rate(lwauth_decisions_total{policy_version="opa-v2-candidate"}[5m])
```

**Disagreement rate:**
```promql
rate(lwauth_shadow_disagreement_total{policy_version="opa-v2-candidate"}[5m])
/
rate(lwauth_decisions_total{policy_version="opa-v2-candidate"}[5m])
```

**Latency of the candidate policy:**
```promql
histogram_quantile(0.99,
  rate(lwauth_decision_latency_seconds_bucket{policy_version="opa-v2-candidate"}[5m])
)
```

**Audit log drill-down:**
```bash
cat audit.jsonl | jq 'select(.shadow_disagreement == true and .policy_version == "opa-v2-candidate")'
```

### Key properties

- **Zero risk:** The shadow verdict never reaches Envoy or the client.
- **Full fidelity:** Runs the real pipeline (identify + authorize + mutate) on real requests.
- **Isolated cache:** Shadow uses its own decision cache; it cannot pollute production's.
- **No special routing:** Every request is evaluated — no sampling config needed.

### When to move on

The disagreement rate is stable at 0% (or only expected intentional
differences remain) for at least 24 hours.

---

## Stage 3: Canary Mode

Add a `canary` block to your **production** AuthConfig. The canary
authorizer runs alongside production on a configurable slice of traffic.
Unlike shadow, canary **knows production's verdict** and reports the
precise agreement classification.

### Configuration (observe-only)

```yaml
apiVersion: lwauth.io/v1alpha1
kind: AuthConfig
metadata:
  name: api-prod
spec:
  version: "rbac-v1"
  authorizers:
    - name: rbac
      type: rbac
      config: { ... }
  canary:
    weight: 100            # % of traffic to evaluate (100 = all)
    sample: ""             # "" = random; "header:x-canary" = opt-in; "hash:sub" = sticky
    enforce: false         # observe-only — canary verdict is logged, not used
    authorizer:
      name: opa-next
      type: opa
      config:
        policy: file:///etc/lwauth/abac-next.rego
```

### How it works internally

```
Request arrives
  → Engine.Evaluate()
    → Identify (normal)
    → Authorize (prod RBAC) → returns ALLOW
    → shouldCanary(request, identity) → true (weight=100)
    → Canary Authorize (OPA) → returns DENY
    → classifyAgreement(prod=ALLOW, canary=DENY)
        → "prod_allow_canary_deny"
    → Metric: lwauth_canary_agreement_total{agreement="prod_allow_canary_deny"}
    → enforce=false → prod verdict stands (ALLOW)
  → Returns ALLOW to client
```

### Agreement classification

| Classification | Meaning | Action |
|---|---|---|
| `match` | Both agree (allow/allow or deny/deny) | Good — policies are equivalent |
| `prod_allow_canary_deny` | Canary is stricter | Investigate — canary may break legitimate access |
| `prod_deny_canary_allow` | Canary is more permissive | Investigate — canary may be too loose |

### Observability

**Agreement breakdown:**
```promql
rate(lwauth_canary_agreement_total{policy_version="rbac-v1"}[5m])
```

**Disagreement percentage:**
```promql
(
  rate(lwauth_canary_agreement_total{agreement!="match"}[5m])
)
/
(
  rate(lwauth_canary_agreement_total[5m])
)
```

**Audit log for canary disagreements:**
```bash
cat audit.jsonl | jq 'select(.canary_agreement != "" and .canary_agreement != "match")'
```

### Sampling strategies

| `sample` value | Behaviour | Best for |
|---|---|---|
| `""` (empty) | Random by `weight`% | General observe-only testing |
| `"header:x-canary"` | Only requests with that header | Internal QA / opt-in testing with `enforce: true` |
| `"hash:sub"` | Sticky by identity subject hash | Consistent per-user experience during enforce rollout |

### Graduating to enforce

Once observe-only shows ≈0 disagreements:

```yaml
  canary:
    weight: 5              # start small
    sample: "hash:sub"     # sticky so same users always get canary
    enforce: true          # canary verdict is now real
    authorizer: { ... }
```

**Ramp-up sequence:**
1. `weight: 5, enforce: true` — 5% of users on new policy. Monitor for 24h.
2. `weight: 25, enforce: true` — broader slice. Monitor.
3. `weight: 100, enforce: true` — full traffic on canary. Equivalent to promoted.
4. Promote: move canary authorizer to primary `authorizers:` list, remove `canary:` block.

### Risks of enforce mode

| Risk | Mitigation |
|---|---|
| False denials on canary slice | Start with low weight; monitor `prod_allow_canary_deny` |
| Sticky routing amplifies blast radius | Use `"header:x-canary"` for initial enforce testing |
| Canary authorizer latency/errors | Canary runs in-line; set timeouts on external policy engines |
| Inconsistent UX across users | Communicate maintenance window or use header-based opt-in |

### When to move on

`weight: 100, enforce: true` has run for ≥24h with 0 disagreements and
no elevated error rate. You're ready to promote.

---

## Stage 4: Promote

Remove the canary block and make the new authorizer primary:

```yaml
apiVersion: lwauth.io/v1alpha1
kind: AuthConfig
metadata:
  name: api-prod
spec:
  version: "opa-v2"       # bump version tag
  authorizers:
    - name: opa
      type: opa
      config:
        policy: file:///etc/lwauth/abac-next.rego
  # canary block removed
```

Delete the shadow AuthConfig if still deployed:
```bash
kubectl delete authconfig api-shadow
```

The controller compiles the new config, atomically swaps the Engine, and
all subsequent requests use the new policy. The `policy_version` label
changes in all metrics/audit from this point forward.

---

## `spec.version` — Tagging Everything

Every AuthConfig should carry an opaque `version` string:

```yaml
spec:
  version: "2026-05-01-opa-v2"
```

This tag propagates to:
- **Prometheus:** `policy_version` label on `lwauth_decisions_total`, `lwauth_shadow_disagreement_total`, `lwauth_canary_agreement_total`
- **Audit logs:** `"policy_version": "2026-05-01-opa-v2"` on every event
- **OTel spans:** `lwauth.policy_version` attribute

During a postmortem, filter by version to instantly isolate whether a
specific policy revision caused an incident:

```promql
rate(lwauth_decisions_total{policy_version="2026-05-01-opa-v2", outcome="deny"}[5m])
```

---

## Shadow vs Canary — When to Use Which

| | Shadow | Canary (observe-only) |
|---|---|---|
| Comparison | "Would my new policy deny anything?" | "Do prod and candidate agree on the same request?" |
| Knows prod's verdict | No | Yes |
| Agreement detail | Binary (disagree or not) | 3-way (match / prod_allow_canary_deny / prod_deny_canary_allow) |
| Traffic selection | 100% always | Configurable weight + sample |
| Path to enforce | None — must promote separately | Flip `enforce: true` for gradual cutover |
| Deployment | Separate AuthConfig | Same AuthConfig, `canary:` block |
| Best for | Initial sanity check | Precise diff + graduated rollout |

**Recommended flow:** Shadow → Canary (observe) → Canary (enforce, low weight) → Canary (enforce, full weight) → Promote.

---

## Rollback

At any stage, rollback is instant:

- **Shadow:** Delete the shadow AuthConfig. Zero impact (it never affected traffic).
- **Canary observe-only:** Remove the `canary:` block. Zero impact.
- **Canary enforce:** Remove the `canary:` block or set `enforce: false`. Traffic immediately reverts to prod authorizer.
- **Post-promote:** `lwauthctl rollback` or revert the AuthConfig YAML to the previous version. The controller recompiles and atomically swaps back.

---

## Summary

```
┌─────────────────────────────────────────────────────────────────┐
│  1. REPLAY (offline)                                            │
│     lwauthctl replay --baseline v1 --candidate v2 --audit log   │
│     → "0 disagreements in 1M historical requests"               │
├─────────────────────────────────────────────────────────────────┤
│  2. SHADOW (live, zero-risk)                                    │
│     Deploy mode:shadow AuthConfig                               │
│     → "0.0% shadow_disagreement for 24h"                       │
├─────────────────────────────────────────────────────────────────┤
│  3. CANARY (live, observe → enforce)                            │
│     canary: { enforce: false } → observe agreement              │
│     canary: { enforce: true, weight: 5 } → real on 5%          │
│     canary: { enforce: true, weight: 100 } → real on all       │
│     → "100% match for 24h"                                     │
├─────────────────────────────────────────────────────────────────┤
│  4. PROMOTE                                                     │
│     Move canary authorizer to primary, remove canary block      │
│     → Done. Zero-downtime policy migration complete.            │
└─────────────────────────────────────────────────────────────────┘
```
