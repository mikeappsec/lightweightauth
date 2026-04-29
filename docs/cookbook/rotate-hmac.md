# Rotate HMAC secrets without downtime

You ship CLI tools, webhooks, or service-to-service callers that
authenticate with HMAC-signed requests
([`hmac` identifier](../modules/hmac.md)). The shared secret has been
in production long enough that you want to rotate it — either on a
schedule or because you have evidence it leaked. You need a procedure
that has zero unsigned-window in the middle: every request that was
valid before rotation starts must remain valid throughout, and every
request that becomes valid after rotation finishes must keep working.

The lwauth `hmac` identifier was designed for this: `keys` is a map,
not a single value, so multiple `keyId → secret` pairs coexist. The
verifier looks up the `keyId` parsed from the `Authorization` header
and validates against that one entry. Rotation is therefore a
**three-phase config edit**, not a flag flip:

1. Mint a new key. Add it to `keys` alongside the old one. Roll out.
2. Cut signers over to the new `keyId`. The old `keyId` is still
   accepted, so any client who has not redeployed yet keeps working.
3. Once every signer has rolled, remove the old `keyId` from `keys`.
   Roll out. The old secret is now decommissioned.

This recipe walks each phase, plus a fourth (verification + audit)
that is the part most operators skip and later regret.

## What this recipe assumes

- An existing `AuthConfig` with at least one `hmac` identifier,
  delivered to lwauth either via a Helm-rendered ConfigMap or a CRD
  watched by the controller. Both paths work for this recipe; the
  `kubectl apply` step is the same shape, only the resource kind
  differs.
- The shared secret material lives in a Kubernetes Secret under
  `lwauth-system` (or wherever your daemon runs). Inline secrets in
  ConfigMaps work for development but make rotation auditing harder
  — switch to a Secret first if you have not already.
- `lwauthctl` v1.0+ on your workstation. The CLI today exposes
  `validate`, `diff`, `explain`, and `audit`; this recipe uses all
  four.

This recipe **does not** cover client-side rotation libraries,
changing the canonicalization scheme (`HMAC-SHA256-V1`), or
broadening `requiredSignedHeaders` — those are content-changes that
are not safe under a rolling rotation and need their own write-up.

## 0. Capture the starting state

Before changing anything, snapshot the live config and confirm the
identifier you are about to edit. Two minutes spent here saves you
the "wait, which tenant does this `keyId` belong to?" surprise
mid-rotation:

```bash
# Live config the controller is serving.
kubectl -n lwauth-system get configmap lwauth-config \
  -o jsonpath='{.data.config\.yaml}' > config-baseline.yaml

# OR for CRD mode:
kubectl -n payments get authconfig payments \
  -o yaml > config-baseline.yaml

# Sanity: which keyIds are currently accepted?
yq '.identifiers[] | select(.type == "hmac") | .keys | keys' \
  config-baseline.yaml
# expect: ["abc"]   (or whatever the live keyId is)
```

Keep `config-baseline.yaml` for the duration of the rotation. The
final phase uses `lwauthctl diff` against it to prove you removed
the old key and nothing else.

## 1. Phase 1 — add the new key alongside the old

Mint a fresh 32-byte secret and add it to the `keys` map without
removing the existing entry. The lookup-by-keyId behaviour means
clients still on `abc` keep working unchanged.

```bash
# Generate the new secret. 32 random bytes is the lwauth
# recommendation — HMAC-SHA256 has 256 bits of input space, anything
# shorter wastes the algorithm.
NEW_SECRET=$(openssl rand -base64 32)

# Choose a stable, human-readable keyId. Date-based ids are popular
# because they sort and read naturally in audit logs; do not encode
# anything sensitive into the keyId itself.
NEW_KEY_ID=svc-2026-04

# Update the Secret. --dry-run lets you preview the YAML before
# applying.
kubectl -n lwauth-system get secret lwauth-hmac-secrets \
  -o json | jq --arg id "$NEW_KEY_ID" --arg s "$NEW_SECRET" \
  '.data[$id] = ($s | @base64)' \
  | kubectl apply -f -
```

Then update the AuthConfig so the new `keyId` is wired in. The
edited `hmac` block:

```yaml
identifiers:
  - name: services
    type: hmac
    config:
      requiredSignedHeaders: [host, date]   # unchanged from baseline
      keys:
        # OLD KEY — keep accepting it for the duration of phase 2.
        abc:
          secret: ${HMAC_KEY_ABC}
          subject: service-a
          roles: [machine]
        # NEW KEY — verifier will accept it as soon as this rolls out.
        # No client has switched to it yet.
        svc-2026-04:
          secret: ${HMAC_KEY_SVC_2026_04}
          subject: service-a
          roles: [machine]
```

Validate offline before applying. `lwauthctl validate` compiles the
config end-to-end with the daemon's own loader, so a typo or a
missing env-var binding fails here, not after rollout:

```bash
lwauthctl validate --config new-config.yaml
# expect: "OK: <N> identifiers, <M> authorizers, <K> mutators"

lwauthctl diff --from config-baseline.yaml --to new-config.yaml
# expect: a single addition under
#         identifiers[name="services"].config.keys."svc-2026-04"
```

The `diff` output is the audit trail for this phase — capture it and
attach to the change record. Apply:

```bash
kubectl apply -f new-config.yaml
```

Confirm the engine swap. In file-mode the daemon picks up the new
ConfigMap on its `fsnotify` reload; in CRD-mode the controller
streams the snapshot through the broker
([modules/configstream.md](../modules/configstream.md)):

```bash
kubectl -n lwauth-system logs deploy/lwauth -c lwauth | \
  grep -E 'config: compiled|engine: hot-swap' | tail -3
```

!!! warning "Do NOT cut signers over yet"
    Phase 1 is **only** the verifier-side change. Every signer is
    still using `abc`. The whole point of the overlap is that the
    cutover happens during phase 2 against a verifier that already
    knows about both keys.

## 2. Phase 2 — cut signers over

How long phase 2 lasts is the trade-off you control:

- **Short overlap (hours).** Acceptable when you control every
  signer and can roll them in lockstep — typically internal
  services running in the same cluster.
- **Long overlap (days–weeks).** Required when signers are external
  CLIs, partner integrations, or webhooks under someone else's
  release calendar. The overlap window is exactly the customer
  upgrade window.

The lwauth side does not care; the only invariant is that **no
unsigned window opens** between phases 1 and 3.

For each signer, switch the `keyId` it advertises in the
`Authorization` header (and the secret it signs with). The shape of
the change depends on your signer SDK; the
[`hmac` reference](../modules/hmac.md) shows the canonical-string
format you need to keep stable.

While phase 2 runs, watch the audit log to see which keys are
actually being used. The `audit` subcommand filters lwauth's
JSONL audit stream:

```bash
# Tail the audit log on the lwauth Pod, keep only hmac decisions,
# and group by keyId. Run this for a representative window
# (often 24h) before declaring phase 2 complete.
kubectl -n lwauth-system exec deploy/lwauth -c lwauth -- \
  cat /var/log/lwauth/audit.jsonl \
  | lwauthctl audit --identifier services \
  | jq -r '.identifier_attrs.keyId' | sort | uniq -c | sort -nr
# expect during early phase 2:
#    14823 abc
#       42 svc-2026-04
# expect at end of phase 2:
#       11 abc
#    14854 svc-2026-04
# (a long tail on `abc` is normal; it is a signal that some signer
#  has not redeployed yet, not that rotation is broken.)
```

When the count under `abc` reaches zero **and stays at zero for an
overlap of at least one of your client release cadences**, phase 2
is done. If you remove `abc` while a single signer is still using
it, that signer starts seeing 401s with no path to recover except
deploying the new key — which is the kind of incident you started
this rotation to avoid.

!!! tip "Forced cutover dry-run"
    If you cannot wait, you can force the issue by temporarily
    flipping the affected client's traffic at a load balancer to
    route it through a copy of lwauth that has only the new key.
    Done correctly, it surfaces every still-old signer as a 401 in
    a controlled blast radius. Done incorrectly, it is the same
    "no path to recover" outage. Treat it as a chaos test, not as
    routine procedure.

## 3. Phase 3 — decommission the old key

Remove `abc` from the AuthConfig and from the Kubernetes Secret.
Re-validate, re-diff, re-apply.

```yaml
identifiers:
  - name: services
    type: hmac
    config:
      requiredSignedHeaders: [host, date]
      keys:
        # `abc` removed. Only the new key is accepted from now on.
        svc-2026-04:
          secret: ${HMAC_KEY_SVC_2026_04}
          subject: service-a
          roles: [machine]
```

```bash
lwauthctl validate --config decommissioned-config.yaml
lwauthctl diff --from config-baseline.yaml --to decommissioned-config.yaml
# expect, end-to-end against the original baseline:
#   - removed:  identifiers[name="services"].config.keys."abc"
#   - added:    identifiers[name="services"].config.keys."svc-2026-04"

# Strip the old key from the Secret too.
kubectl -n lwauth-system get secret lwauth-hmac-secrets \
  -o json | jq 'del(.data.abc)' \
  | kubectl apply -f -

kubectl apply -f decommissioned-config.yaml
```

Confirm the engine swap as in phase 1, then re-run the audit
aggregation from phase 2. The expected steady state is **zero**
decisions under `keyId: "abc"` and a healthy stream under the new
key. If you see any non-zero count under `abc`, the secret was not
fully removed and lwauth is logging an unknown-keyId rejection — not
catastrophic, but a signal that your phase 2 overlap was too short.

## 4. Phase 4 — prove it

The part most rotations skip. Three checks, in order:

```bash
# 4.1 Old keyId now produces 401 from a real client. The expected
#     deny reason is "hmac: unknown keyId" on the x-lwauth-reason
#     response header (see Envoy guide §4.4 — strip this at the
#     public edge; it is intended for log joins).
sign-with-old-key.sh /v1/orders | curl -s -o /dev/null -w '%{http_code}\n' \
  -H @/dev/stdin https://services.example.com/v1/orders
# expect: 401

# 4.2 New keyId still serves traffic.
sign-with-new-key.sh /v1/orders | curl -s -o /dev/null -w '%{http_code}\n' \
  -H @/dev/stdin https://services.example.com/v1/orders
# expect: 200

# 4.3 The secret store no longer contains the old material.
kubectl -n lwauth-system get secret lwauth-hmac-secrets \
  -o jsonpath='{.data.abc}'
# expect: empty output. If you see base64 here, the Secret patch
#         in phase 3 did not apply and the old key is still on disk
#         on every replica.
```

The first two map to good CI smoke tests for any future rotation;
keep them around. The third is a one-time check.

## What can still go wrong

- **`requiredSignedHeaders` mismatch.** If a signer does not include
  the headers in the configured list, verification fails with
  `hmac: missing required header` no matter which `keyId` it used.
  Rotation is the wrong tool for that — it is a signer bug. Use
  `lwauthctl explain` to confirm the canonical bytes.
- **Body-cap truncation.** A request whose body exceeds the
  upstream `MaxBytesReader` cap fails as a signature mismatch, not
  as a `413`. If a previously-working CLI starts seeing 401s
  immediately after a rotation, the body cap is the more likely
  culprit than the keys.
- **Clock skew.** `clockSkew` defaults to 5 minutes against the
  signed `Date` header. A signer whose clock has drifted produces
  401s independent of rotation. Same `lwauthctl explain` workflow
  applies — the explain output prints the canonical string and the
  parsed `Date`.
- **Per-tenant key isolation.** If two tenants share one
  `AuthConfig`, removing a `keyId` from `keys` removes it for
  everyone. If you need per-tenant rotation cadences, give each
  tenant its own `AuthConfig` so the rollout granularity matches
  the operational reality.

## What to look at next

- **Multiple identifiers behind `firstMatch`.** Pair `hmac` with
  [`mtls`](../modules/mtls.md) under
  [`firstMatch`](../modules/README.md#identifiers) so service-to-
  service callers without HMAC fall through to mutual TLS.
- **Issuing fresh internal JWTs.** Pair [`jwt-issue`](../modules/jwt-issue.md)
  on the response side so the upstream sees a short-lived internal
  token rather than the HMAC envelope. Keeps the shared secret out
  of east-west traffic and makes future rotations cheaper because
  the blast radius is smaller.
- **Audit retention.** The `audit` step in phase 2 only works if
  lwauth's audit log is persisted. See
  [`observability`](../modules/observability.md) for the chart
  values that route audit JSONL to a sink instead of stdout.

## References

- [`hmac` identifier](../modules/hmac.md) — canonical string,
  `requiredSignedHeaders`, replay-protection contract.
- [`observability`](../modules/observability.md) — audit log shape
  consumed by `lwauthctl audit`.
- [`configstream`](../modules/configstream.md) — how the controller
  streams the rotated `AuthConfig` to every replica without a
  daemon restart.
- [DESIGN.md §4](../DESIGN.md) — identity & credential modules.
