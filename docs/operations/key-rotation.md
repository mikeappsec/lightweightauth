# Key Rotation

LightweightAuth supports seamless verifier-side key rotation for all
credential types without pod restarts. The overlap model ensures old
and new keys are valid simultaneously during a configurable transition
window.

## Supported Credential Types

| Type | Rotation Mechanism | Config Field |
|------|-------------------|--------------|
| **JWT (JWKS)** | Automatic kid-miss refresh from JWKS endpoint | `minRefreshInterval` on the `jwt` identifier |
| **DPoP (pinned keys)** | `pinnedKeys` array with `notBefore`/`notAfter`/`gracePeriod` per kid | `pinnedKeys:` on the `dpop` identifier — see [dpop.md](../modules/dpop.md#proof-key-pinning-optional) |
| **HMAC** | Manual multi-key overlap — add the new key, keep the old one, remove it later | `keys:` on the `hmac` identifier |
| **mTLS** | CA bundle re-read on the identifier's next rebuild (AuthConfig reload) | `trustedCAFiles:`/`trustedCAs:` on the `mtls` identifier |

## HMAC Key Rotation

The `hmac` identifier's config only recognizes `keys:` (a flat map,
no per-key expiry) — a `secrets:` field, or `notBefore`/`notAfter`/
`gracePeriod` on an HMAC key entry, doesn't exist and fails config
validation with `unknown config key(s): secrets`
(`pkg/identity/hmac/hmac.go`'s `KeyEntry` struct only has `Secret`,
`Subject`, `Roles` — no timing fields). There's no automatic
time-bounded expiry for HMAC keys; rotation is the manual
add-then-remove procedure in
[rotate-hmac.md](../cookbook/rotate-hmac.md):

```yaml
identifiers:
  - name: service-auth
    type: hmac
    config:
      keys:
        v2: { secret: "base64...", subject: "service-a", roles: [machine] }
        v1: { secret: "base64...", subject: "service-a", roles: [machine] }
```

If you need `notBefore`/`notAfter`/`gracePeriod`-style automatic
rotation, use the `dpop` identifier's `pinnedKeys` (below) or
`jwt`'s JWKS-based rotation — HMAC doesn't have an equivalent today.

## DPoP Pinned-Key Rotation

The `dpop` identifier's `pinnedKeys` list is the one credential type
that actually has `notBefore`/`notAfter`/`gracePeriod` semantics
(`pkg/identity/dpop/dpop.go`, backed by `pkg/keyrotation.KeySet`). See
[dpop.md](../modules/dpop.md#proof-key-pinning-optional) for the
config shape and the
[DPoP key rotation runbook](dpop-key-rotation-runbook.md)
for the operational procedure — including the current gap that there's
no admin endpoint or metric to introspect key state; it must be
derived from the config's timestamps or tested with a live proof.

## JWKS Force-Refresh on Kid Miss

When a JWT arrives with a `kid` not in the cached JWKS, the `jwt`
identifier's underlying `jwx` JWK cache triggers a force-refresh
(subject to `minRefreshInterval` throttling, default 15 minutes).
This handles IdP-side key rotation without manual intervention.
`pkg/identity/jwt/jwt.go` doesn't emit any metric or log line for
this — it's opaque from lwauth's own observability surface; if you
need to confirm a refresh happened, test with a token signed under
the new `kid` and confirm it verifies.

## mTLS CA Bundle Reload

Configure the mTLS identifier with `trustedCAFiles` (a list of PEM
file paths) or `trustedCAs` (an inline PEM string), plus
`trustForwardedClientCert: true`:

```yaml
identifiers:
  - name: client-cert
    type: mtls
    config:
      trustForwardedClientCert: true
      trustedCAFiles:
        - /etc/lwauth/ca-bundle.pem
```

There's no dedicated `fsnotify` watch on the CA bundle file itself
(`pkg/identity/mtls/mtls.go` has no watch logic) — the file is read
fresh each time the `mtls` identifier is rebuilt, which happens on
every full `AuthConfig` reload (`--watch-config-file`). If the CA
bundle is mounted from a separate Secret/ConfigMap that changes
without the `AuthConfig` YAML itself changing, lwauth will **not**
pick up the new bundle automatically — touch the `AuthConfig`
(even a no-op annotation bump) to force a rebuild after rotating the
CA file.

## Observability

### Prometheus Metrics

There's no per-`kid` metric for any of the identifiers above —
`lwauth_key_verify_total`/`lwauth_key_refresh_total`/`lwauth_key_state`
don't exist (the full metric set is in
[`pkg/observability/metrics/metrics.go`](https://github.com/mikeappsec/lightweightauth/blob/main/pkg/observability/metrics/metrics.go)).
The closest real signal is the coarse, non-`kid`-specific
`lwauth_identifier_total{identifier, outcome}` counter.

### IdentityProvider Status Conditions — not currently wired in

`internal/controller/rotation_conditions.go` defines exactly this
shape (`RotationCondition[T]`/`HealthCondition[T]`, backed by
`pkg/keyrotation.KeySet`, with the `KeyRotation`/`KeysHealthy`
condition types and `RotationInProgress`/`RotationComplete`/
`KeyExpired`/`AllKeysValid`/`KeyPending` reasons shown below), but
nothing calls either function — no controller reconciler in this
repo invokes them. They won't appear on a real `IdentityProvider`
resource today; treat this as the intended future shape once wired
in, not a currently observable status:

```yaml
status:
  conditions:
    - type: KeyRotation
      status: "True"
      reason: RotationInProgress
      message: "keys retiring: [v1]; active: [v2]"
    - type: KeysHealthy
      status: "True"
      reason: AllKeysValid
      message: "2 key(s) healthy"
```

## Rotation Runbook

See [Rotate JWKS](../cookbook/rotate-jwks.md) for a step-by-step
operational procedure.
