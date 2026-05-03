# Rotate JWKS / IdP signing keys without downtime

Your IdP (Keycloak, Auth0, Entra ID, `lwauth-idp`, or any OIDC
provider) signs JWTs with a private key whose `kid` appears in the
JWKS endpoint. You need to roll that key — either on a schedule, because
the algorithm is being upgraded, or because the old key leaked — without
a window where valid tokens are rejected.

lwauth's [`jwt` identifier](../modules/jwt.md) already supports this
natively: the JWKS cache holds every `kid` the IdP publishes, and
verification picks the JWK whose `kid` matches the token header. The
rotation procedure is therefore about **timing the IdP-side change**
and **proving the fleet has picked up the new key** before retiring the
old one — not about editing the lwauth config at all.

This recipe walks the full lifecycle, including the verification steps
most rotations skip.

## What this recipe assumes

- An existing `AuthConfig` with a `jwt` identifier pointing at a JWKS
  URL (inline or via `IdentityProvider`).
- lwauth refreshes JWKS every 15 minutes by default (or honours the
  IdP's `Cache-Control: max-age` header). You have not overridden
  `jwksRefreshInterval` to something longer than 1 hour.
- `lwauthctl` v1.0+ and `kubectl` on your workstation.
- Prometheus scraping lwauth pods, or at minimum access to the
  `/metrics` endpoint.

This recipe **does not** cover rotating mTLS trust bundles, HMAC shared
secrets (see [rotate-hmac](rotate-hmac.md)), or `jwt-issue` mutator
signing keys — those have different overlap mechanics.

## 0. Capture the starting state

Before touching the IdP, confirm which `kid` lwauth is currently
verifying against:

```bash
# Check the JWKS endpoint directly.
curl -s $(kubectl -n lwauth-system get configmap lwauth-config \
  -o jsonpath='{.data.config\.yaml}' | \
  yq '.identifiers[] | select(.type == "jwt") | .config.jwksUrl') \
  | jq '.keys[].kid'
# expect: ["rsa-2025-11"]   (or whatever the current kid is)

# Confirm lwauth loaded it. The metric shows per-kid verification
# counts (v1.1+):
kubectl -n lwauth-system exec deploy/lwauth -c lwauth -- \
  curl -s localhost:8080/metrics | grep lwauth_jwks_refresh_total
# expect: lwauth_jwks_refresh_total{issuer="...",outcome="ok"} <N>
```

Note the current `kid` — you will use it in phase 3 to prove it has
drained.

## 1. Phase 1 — publish the new key on the IdP (dual-publish)

Add a new signing key to your IdP. The old key stays active for
signing; the new key is **published in JWKS but not yet used for
signing**. This ensures every lwauth replica loads the new `kid` into
its JWKS cache before any token carries it.

How you do this depends on your IdP:

| IdP | How to add a second key |
|---|---|
| **Keycloak** | Realm → Keys → Providers → add an `rsa-generated` provider with higher priority. The old provider stays active until you set its priority lower. |
| **Auth0** | Dashboard → Settings → Signing Keys → Rotate Signing Key. Auth0 publishes both keys in JWKS immediately; the new one becomes the signing key after confirmation. |
| **Entra ID** | Automatic — Microsoft publishes keys ~6 weeks before activation. No action needed; skip to phase 2. |
| **lwauth-idp** | `POST /admin/keys` with the new key material; set `active: false` initially. |

After the IdP publishes both keys, confirm lwauth sees them:

```bash
# Wait for at least one JWKS refresh cycle (default 15 min).
sleep 900

# Verify both kids are in the cache.
curl -s <JWKS_URL> | jq '[.keys[].kid]'
# expect: ["rsa-2025-11", "rsa-2026-05"]
```

!!! warning "Do NOT start signing with the new key yet"
    Phase 1 is about **pre-loading** the verifier. The goal is that
    every lwauth replica already knows the new `kid` before the IdP
    starts minting tokens with it. If you skip this phase, the first
    token signed with the new key will fail verification on any replica
    whose JWKS cache has not refreshed yet.

## 2. Phase 2 — cut the IdP over to the new signing key

Switch the IdP to sign new tokens with the new `kid`. The old key
remains **published in JWKS** (so tokens minted before the cutover
still verify) but is no longer used for new signatures.

| IdP | How to switch the signing key |
|---|---|
| **Keycloak** | Set the new provider's priority higher than the old one. |
| **Auth0** | Confirm the rotation in Dashboard → Settings → Signing Keys. |
| **Entra ID** | Automatic — no action. |
| **lwauth-idp** | `PATCH /admin/keys/<new-kid>` with `active: true`. |

Monitor the transition. Tokens already issued carry the old `kid` and
remain valid until they expire. New tokens carry the new `kid`:

```bash
# Watch the per-kid verification metric. Over time, the old kid's
# rate drops to zero as tokens expire.
kubectl -n lwauth-system exec deploy/lwauth -c lwauth -- \
  curl -s localhost:8080/metrics | grep lwauth_decisions_total | \
  grep 'identifier="jwt"'

# Or via PromQL:
#   rate(lwauth_decisions_total{identifier="jwt"}[5m])
# broken down by the token's kid (available in audit JSONL as
# identifier_attrs.kid).
```

The overlap window length = the maximum `exp - iat` of tokens minted
under the old key. For short-lived tokens (5–15 min) the window is
trivially short. For long-lived refresh tokens, the window may be days
— that is fine; the old key stays in JWKS for the duration.

## 3. Phase 3 — retire the old key from JWKS

Once **all** tokens signed with the old `kid` have expired, remove the
old key from the IdP's JWKS endpoint.

**How to know it is safe:**

```bash
# Option A: Check the audit log for any decision that verified
# using the old kid. Zero hits = safe to retire.
kubectl -n lwauth-system exec deploy/lwauth -c lwauth -- \
  cat /var/log/lwauth/audit.jsonl | \
  jq -r 'select(.identifier == "jwt") | .identifier_attrs.kid' | \
  sort | uniq -c | sort -nr
# expect: only the new kid appears.

# Option B: PromQL — the old kid's verification rate is zero
# across all replicas for at least 2× the max token lifetime.
#   sum(rate(lwauth_decisions_total{identifier="jwt",kid="rsa-2025-11"}[1h])) == 0
```

Remove the old key from the IdP, then confirm lwauth's next JWKS
refresh drops it:

```bash
sleep 600   # wait for refresh
curl -s <JWKS_URL> | jq '[.keys[].kid]'
# expect: ["rsa-2026-05"]   — only the new key
```

## 4. Phase 4 — prove it

```bash
# 4.1 A token signed with the old kid is now rejected.
#     (Craft one with a test tool, or replay a captured JWT.)
OLD_TOKEN="eyJ..."  # a token with kid=rsa-2025-11
curl -s -o /dev/null -w '%{http_code}' \
  -H "Authorization: Bearer $OLD_TOKEN" \
  https://api.example.com/v1/orders
# expect: 401

# 4.2 A fresh token (new kid) still works.
NEW_TOKEN=$(curl -s -X POST "$IDP_URL/oauth/token" \
  -d 'grant_type=client_credentials&...' | jq -r .access_token)
curl -s -o /dev/null -w '%{http_code}' \
  -H "Authorization: Bearer $NEW_TOKEN" \
  https://api.example.com/v1/orders
# expect: 200

# 4.3 The JWKS endpoint no longer serves the old kid.
curl -s <JWKS_URL> | jq '.keys[] | select(.kid == "rsa-2025-11")'
# expect: empty
```

## What lwauth does NOT require during rotation

Unlike HMAC rotation ([rotate-hmac](rotate-hmac.md)), JWKS rotation
does **not** require any `AuthConfig` or `IdentityProvider` edit. The
`jwt` identifier dynamically fetches and caches JWKS; the only config
is `jwksUrl` (or `issuerUrl` for OIDC discovery), which does not
change. This means:

- No `lwauthctl validate` / `diff` / `apply` cycle.
- No engine hot-swap.
- No ConfigMap or CRD edit.
- No Pod restart.

The entire rotation is an IdP-side operation observed passively by
lwauth.

## Accelerating the refresh (optional)

If you cannot wait 15 minutes for the background refresh to pick up a
newly published key, two options:

1. **Lower the refresh interval.** Set `jwksRefreshInterval: 60s` on
   the `jwt` identifier. This increases IdP traffic by 10× but makes
   key publication visible within a minute. Suitable for dev/staging.

2. **Restart the lwauth pods.** Not recommended in production (defeats
   the "no restart" goal), but it forces an immediate JWKS fetch on
   boot. Useful in CI.

For v1.2+ (Tier D — ENT-KEYROT-1), lwauth will expose a
`forceRefresh()` trigger and `lwauth_jwks_refresh_total{issuer,outcome}`
metrics so SREs can push-refresh and prove the new `kid` is loaded
without waiting for the next poll.

## What can still go wrong

- **IdP removes the old key before tokens expire.** Any in-flight
  token whose `kid` is no longer in JWKS gets a `jwt: unknown kid`
  rejection. Wait for `exp` to drain.
- **JWKS endpoint downtime during refresh.** lwauth keeps the last
  successfully fetched JWKS in memory. A transient fetch failure
  does not evict cached keys — it logs a warning and retries on the
  next interval. Extended downtime (> cache TTL) will eventually
  cause the cache to go stale; pair with `serveStaleOnUpstreamError`
  (Tier E — ENT-CACHE-2) when available.
- **Algorithm change (e.g. RS256 → ES256).** This is safe as long as
  both keys are published in JWKS simultaneously. The verifier matches
  by `kid` and reads `alg` from the JWK, so an algorithm switch is
  transparent. Ensure your JWT library on the client side supports the
  new algorithm.
- **Clock skew.** `exp` / `nbf` / `iat` checks use the lwauth host
  clock ± `clockSkew` (default 30s). If your pods have significant
  drift, tokens near their `exp` boundary may reject spuriously during
  the overlap window.

## What to look at next

- [Rotate HMAC secrets without downtime](rotate-hmac.md) — the
  config-edit rotation for symmetric keys.
- [DESIGN.md §11.1](../DESIGN.md) — the full key-rotation design
  covering all six key materials.
- [`jwt` identifier reference](../modules/jwt.md) — `jwksUrl`,
  `issuerUrl`, `audiences`, `clockSkew`, `jwksRefreshInterval`.
- [`observability`](../modules/observability.md) — metrics and audit
  log shape.

## References

- [`jwt` identifier](../modules/jwt.md) — JWKS cache, verification,
  `kid` matching.
- [`observability`](../modules/observability.md) — audit log shape
  consumed by `lwauthctl audit`.
- [DESIGN.md §11.1](../DESIGN.md) — seamless key rotation design.
- [RFC 7517](https://datatracker.ietf.org/doc/html/rfc7517) — JWK
  specification.
