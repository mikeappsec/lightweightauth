# Key Rotation

LightweightAuth supports seamless verifier-side key rotation for all
credential types without pod restarts. The overlap model ensures old
and new keys are valid simultaneously during a configurable transition
window.

## Supported Credential Types

| Type | Rotation Mechanism | Config Field |
|------|-------------------|--------------|
| **JWT (JWKS)** | Automatic kid-miss refresh from JWKS endpoint | `minRefreshInterval` on IdentityProvider |
| **HMAC** | `secrets` array with `notBefore`/`notAfter` per kid | `secrets:` on hmac identifier |
| **mTLS** | CA bundle file hot-reload via fsnotify | `caBundlePath` on mtls identifier |

## HMAC Key Rotation

### Legacy format (still supported)

```yaml
identifiers:
  - name: service-auth
    type: hmac
    config:
      keys:
        svc-a: { secret: "base64...", subject: "service-a" }
```

### Rotatable format (D1)

```yaml
identifiers:
  - name: service-auth
    type: hmac
    config:
      secrets:
        - kid: "v2"
          secret: "base64..."
          subject: "service-a"
          roles: [machine]
          notBefore: "2026-05-01T00:00:00Z"
        - kid: "v1"
          secret: "base64..."
          subject: "service-a"
          roles: [machine]
          notAfter: "2026-05-02T00:00:00Z"
          gracePeriod: "10m"
```

**Key lifecycle:**

1. **Pending** — `notBefore` is in the future; key is registered but not used for verification.
2. **Active** — within the `notBefore`..`notAfter` window (or no bounds set).
3. **Retiring** — past `notAfter` but within `gracePeriod` (default 5m); still valid for in-flight tokens.
4. **Retired** — past `notAfter + gracePeriod`; removed from verification set.

## JWKS Force-Refresh on Kid Miss

When a JWT arrives with a `kid` not in the cached JWKS, the module
triggers a force-refresh (subject to `minRefreshInterval` throttling).
This handles IdP-side key rotation without manual intervention.

Metrics emitted:
- `lwauth_key_refresh_total{module="jwt-idp", outcome="kid_miss_trigger"}`
- `lwauth_key_refresh_total{module="jwt-idp", outcome="success"}`
- `lwauth_key_refresh_total{module="jwt-idp", outcome="error"}`

## mTLS CA Bundle Hot-Reload

Configure the mTLS identifier with a `caBundlePath`. The file is
watched via `fsnotify`; changes are picked up within seconds without a
pod restart.

```yaml
identifiers:
  - name: client-cert
    type: mtls
    config:
      caBundlePath: /etc/lwauth/ca-bundle.pem
```

## Observability

### Prometheus Metrics

| Metric | Labels | Description |
|--------|--------|-------------|
| `lwauth_key_verify_total` | `module`, `kid`, `result` | Verification attempts (ok / expired_key / unknown_kid / invalid_sig) |
| `lwauth_key_refresh_total` | `module`, `outcome` | Key material refresh events (success / error / kid_miss_trigger) |
| `lwauth_key_state` | `module`, `state` | Gauge of keys in each lifecycle state |

### IdentityProvider Status Conditions

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

Use `kubectl wait` for rotation completion:

```bash
kubectl wait identityprovider/my-idp \
  --for=condition=KeyRotation=False \
  --timeout=300s
```

## Rotation Runbook

See [Rotate JWKS](../cookbook/rotate-jwks.md) for a step-by-step
operational procedure.
