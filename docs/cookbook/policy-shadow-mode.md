# Test a policy change with shadow mode and canary evaluation

You need to ship a policy change — migrating from RBAC to OPA, adding
a new CEL rule, tightening an OpenFGA model — but you cannot risk a
production outage if the new policy denies requests the old one
allowed. lwauth's **shadow mode** and **canary evaluation** let you
deploy the new policy alongside the existing one, compare their
verdicts on live traffic, and promote only when you have evidence they
agree.

This recipe walks the full lifecycle: shadow → audit → canary →
promote. It uses the primitives described in
[DESIGN.md §11.2](../DESIGN.md) and the
[`composite` authorizer](../modules/composite.md).

!!! note "Tier D feature"
    Shadow mode (`spec.mode: shadow`) and canary evaluation
    (`spec.canary`) are **Tier D roadmap items** (D2 / D3). This
    cookbook documents the *operational workflow* so you can plan for
    it now and adopt it the moment the feature ships. The policy
    diffing CLI (`lwauth diff`) is also part of D2.

## What this recipe assumes

- An existing `AuthConfig` with at least one authorizer (e.g. `rbac`)
  serving production traffic.
- A new policy you want to test (e.g. an OPA Rego policy, a revised
  RBAC matrix, a new CEL expression).
- `lwauthctl` v1.2+ (ships with shadow/canary support).
- Prometheus + Grafana or equivalent for metric visualization.
- Audit logging enabled
  ([`observability`](../modules/observability.md)).

## The three-stage rollout

```
  shadow          canary (10%)        promote (100%)
  ┌──────┐       ┌──────────┐        ┌─────────┐
  │ new  │──OK──▶│ new runs │──OK──▶ │ new is  │
  │ logs │       │ on slice │        │ prod    │
  │ only │       │ of traffic│       │         │
  └──────┘       └──────────┘        └─────────┘
     ▲               ▲                    ▲
  audit log      agreement metric     lwauthctl promote
  confirms       confirms             removes old policy
  no surprises   convergence
```

## 1. Deploy the new policy as a shadow AuthConfig

Create a second `AuthConfig` with `spec.mode: shadow`. This tells
lwauth to run the full identify → authorize → mutate pipeline but
**never** return the shadow's verdict to Envoy or Door B. The
production policy continues to serve all traffic.

```yaml
# authconfig-shadow.yaml
apiVersion: lightweightauth.io/v1alpha1
kind: AuthConfig
metadata:
  name: payments-v2-shadow
  namespace: payments
spec:
  version: "2026-05-01-shadow"
  mode: shadow                         # ← key field

  hosts: [payments.example.com]        # same hosts as production
  tenantId: payments

  identifiers:                         # same identifiers
    - name: bearer
      type: jwt
      config:
        issuerUrl: https://idp.example.com
        audiences: [payments-api]

  authorizers:
    - name: next-policy
      type: opa
      config:
        policy: file:///etc/lwauth/policies/payments-v2.rego
        query: data.payments.allow
```

```bash
lwauthctl validate --config authconfig-shadow.yaml
kubectl apply -f authconfig-shadow.yaml
```

Both the production AuthConfig and the shadow run on every request.
The shadow's verdict appears in two places:

1. **Audit log** — tagged with `policy_version: "2026-05-01-shadow"`
   and `mode: shadow`.
2. **Prometheus** — `lwauth_decisions_total{policy_version="2026-05-01-shadow", mode="shadow"}`.

## 2. Analyze shadow disagreements

Let the shadow run for a representative traffic window (typically
24–72 hours covering weekday + weekend patterns). Then query for
disagreements — requests where the shadow's verdict differs from
production:

```bash
# From audit JSONL: find requests where prod=allow but shadow=deny
kubectl -n lwauth-system exec deploy/lwauth -c lwauth -- \
  cat /var/log/lwauth/audit.jsonl | \
  jq 'select(.shadow != null and .decision.allow == true
       and .shadow.allow == false)' | \
  jq '{method, path: .request.path, sub: .identity.sub,
       prod_reason: .decision.reason, shadow_reason: .shadow.reason}' | \
  head -50
```

```promql
# PromQL: shadow disagreement rate (non-zero = investigate)
sum(rate(lwauth_decisions_total{
  mode="shadow",
  agreement="prod_allow_shadow_deny"
}[1h]))
```

Common findings and how to handle them:

| Disagreement | Likely cause | Fix |
|---|---|---|
| Shadow denies requests prod allows | New policy is stricter — may be intentional or a rule bug | Review the denied paths; update the Rego/CEL if unintentional |
| Shadow allows requests prod denies | New policy is more permissive — usually a model gap | Tighten the new policy before promoting |
| Both deny but with different reasons | Cosmetic — both are correct, but the error path differs | Usually safe to ignore; review for debugging clarity |

### Decision diff CLI

For a deeper analysis, replay captured audit logs against both policy
versions offline:

```bash
# Capture a window of audit data
kubectl -n lwauth-system exec deploy/lwauth -c lwauth -- \
  cat /var/log/lwauth/audit.jsonl > audit-window.jsonl

# Replay against both policies
lwauth diff \
  --left  "version=2026-04-15-prod" \
  --right "version=2026-05-01-shadow" \
  --replay audit-window.jsonl

# Output groups divergences by (method, path-template, deny_reason)
# so you can see patterns rather than individual requests.
```

## 3. Promote to canary evaluation

Once the shadow shows zero (or understood) disagreements, promote the
new policy to canary mode. Canary evaluation runs **both** authorizers
on a slice of live traffic and returns the **production** verdict by
default — but logs both:

```yaml
# authconfig-canary.yaml
apiVersion: lightweightauth.io/v1alpha1
kind: AuthConfig
metadata:
  name: payments
  namespace: payments
spec:
  version: "2026-05-01-canary"
  hosts: [payments.example.com]
  tenantId: payments

  identifiers:
    - name: bearer
      type: jwt
      config:
        issuerUrl: https://idp.example.com
        audiences: [payments-api]

  authorizers:
    - name: current-policy
      type: rbac
      config:
        # ...existing production RBAC rules...

  canary:
    weight: 10                           # 10% of traffic
    sample: sticky:hash(sub)             # same user always gets canary
    authorizer:
      name: next-policy
      type: opa
      config:
        policy: file:///etc/lwauth/policies/payments-v2.rego
        query: data.payments.allow
```

```bash
lwauthctl validate --config authconfig-canary.yaml
lwauthctl diff --from authconfig-prod.yaml --to authconfig-canary.yaml
kubectl apply -f authconfig-canary.yaml
```

Monitor the canary metrics:

```promql
# Agreement rate — should converge to 1.0
sum(rate(lwauth_decisions_total{
  policy_track="canary", agreement="match"
}[5m]))
/
sum(rate(lwauth_decisions_total{
  policy_track="canary"
}[5m]))
```

### Ramp the canary

If agreement holds, increase the weight gradually:

```bash
# 10% → 25% → 50% → 100%
kubectl -n payments patch authconfig payments \
  --type merge -p '{"spec":{"canary":{"weight": 25}}}'
```

At each step, let the agreement metric settle for at least one
traffic cycle before ramping further.

## 4. Promote the canary to production

When `agreement=match` is at 100% across all canary traffic for a
sustained period, promote:

```yaml
# authconfig-promoted.yaml
apiVersion: lightweightauth.io/v1alpha1
kind: AuthConfig
metadata:
  name: payments
  namespace: payments
spec:
  version: "2026-05-01-prod"            # new version tag
  hosts: [payments.example.com]
  tenantId: payments

  identifiers:
    - name: bearer
      type: jwt
      config:
        issuerUrl: https://idp.example.com
        audiences: [payments-api]

  authorizers:
    - name: next-policy                   # the canary is now prod
      type: opa
      config:
        policy: file:///etc/lwauth/policies/payments-v2.rego
        query: data.payments.allow

  # canary: block removed — single policy, no dual evaluation
```

```bash
lwauthctl validate --config authconfig-promoted.yaml
kubectl apply -f authconfig-promoted.yaml

# Clean up the shadow AuthConfig if it is still around
kubectl -n payments delete authconfig payments-v2-shadow
```

Verify the promotion stuck:

```bash
kubectl -n payments get authconfig payments \
  -o jsonpath='{.status.appliedVersion}'
# expect: "2026-05-01-prod"
```

## 5. Rollback (if needed)

At any stage, rollback is a `kubectl apply` of the previous config:

```bash
# Re-apply the baseline config. The engine hot-swaps atomically.
kubectl apply -f authconfig-prod.yaml

# Confirm:
kubectl -n payments get authconfig payments \
  -o jsonpath='{.status.appliedVersion}'
# expect: the old version string
```

Shadow and canary modes never affect the production verdict (unless
`canary.enforce: true` is explicitly set), so removing them is always
safe.

## What can still go wrong

- **Shadow performance impact.** Shadow runs the full pipeline, so
  it doubles the authorizer load. If your authorizer calls an
  external service (OPA, OpenFGA), shadow doubles that traffic too.
  Monitor `lwauth_upstream_duration_seconds` during the shadow phase.
- **Canary with `enforce: true` before validation.** Setting
  `canary.enforce: true` makes the canary verdict the real verdict
  for the sampled traffic. Only set this after the observe-only phase
  proves agreement.
- **Decision cache interaction.** The cache keys include
  `policy_version`, so shadow and canary verdicts are cached
  separately from production. A canary verdict is never served as a
  production response. This is by design but means cache hit rates
  drop during canary — plan capacity accordingly.
- **Sticky sampling bias.** `sticky:hash(sub)` ensures a user always
  gets canary or always gets production. If your disagreements are
  user-specific (e.g. a role only certain users have), the canary
  sample may miss them. Use `sample: random` for broader coverage at
  the cost of per-user inconsistency.

## What to look at next

- [DESIGN.md §11.2](../DESIGN.md) — full policy rotation design
  (versioning, canary, shadow, diffing).
- [`composite` authorizer](../modules/composite.md) — the underlying
  machinery that canary evaluation builds on.
- [`observability`](../modules/observability.md) — audit log and
  metrics shape.
- [Rotate HMAC secrets](rotate-hmac.md) — a different kind of
  rotation (key material, not policy).

## References

- [DESIGN.md §11.2](../DESIGN.md) — policy rotation architecture.
- [`composite` authorizer](../modules/composite.md) — dual evaluation.
- [`observability`](../modules/observability.md) — audit + metrics.
- Roadmap: D2 (ENT-POLICY-1), D3 (ENT-POLICY-2).
