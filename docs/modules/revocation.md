# Revocation — credential deny-list

A real-time deny-list that short-circuits the pipeline **before**
authorization. If a credential's key (JTI, token hash, session ID) is
in the revocation store, the request is denied immediately — regardless
of what the authorizer would say.

**Source:** [pkg/revocation](https://github.com/mikeappsec/lightweightauth/blob/main/pkg/revocation/) — wired via `revocation:` in the top-level config.

## When to use

- **Immediate logout:** User signs out, token should be invalid
  everywhere within seconds — not after TTL expiry.
- **Credential compromise:** A leaked API key or JWT must be blocked
  before it rotates out naturally.
- **Compliance:** Regulations require the ability to revoke access
  within a bounded time window.

**Not needed** if all tokens are short-lived (< 5 min) and you can
accept that window of exposure.

## Configuration

### In-memory store (single replica)

```yaml
revocation:
  backend: memory
  defaultTTL: "24h"
  maxEntries: 100000
  negativeCache:
    ttl: "2s"
    maxSize: 100000
```

### Valkey store (multi-replica)

```yaml
revocation:
  backend: valkey
  addr: "valkey-master.cache.svc:6379"
  username: "lwauth-revocation"   # Valkey ACL user
  password: "${VALKEY_PASSWORD}"
  tls: true
  keyPrefix: "lwauth/rev/"
  defaultTTL: "24h"
  negativeCache:
    ttl: "2s"
    maxSize: 100000
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `backend` | string | `memory` | Store type: `memory` or `valkey` |
| `addr` | string | — | Valkey host:port (required for valkey backend) |
| `username` | string | — | Valkey ACL username |
| `password` | string | — | Valkey ACL password |
| `tls` | bool | `false` | Enable TLS (min 1.2) to Valkey |
| `keyPrefix` | string | `"lwauth/rev/"` | Key namespace in Valkey |
| `defaultTTL` | duration | `24h` | How long revocations persist |
| `maxEntries` | int | `100000` | Max entries (memory backend) |
| `negativeCache.ttl` | duration | `2s` | Local cache TTL for "not revoked" results |
| `negativeCache.maxSize` | int | `100000` | Max negative cache entries |

## Admin API

Revoke a credential:

```bash
curl -X POST https://lwauth:9000/v1/admin/revoke \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "key": "jti:abc123",
    "reason": "user-logout",
    "ttl": "1h"
  }'
```

| Field | Type | Description |
|-------|------|-------------|
| `key` | string | Opaque identifier (JTI, token hash, session ID) |
| `reason` | string | Audit trail reason |
| `ttl` | duration | Override defaultTTL for this entry (optional) |

The admin endpoint requires authentication — see
[Admin-plane auth](../operations/admin-auth.md).

## Pipeline integration

```text
Request → Rate Limit → Revocation Check → Identify → Authorize → Mutate
                             ↓
                        store.Exists(key)
                             ↓
                   revoked? → 401 Unauthorized
```

The revocation check runs **after** rate limiting but **before**
identification. The key is derived from the raw credential:

| Identifier | Key derivation |
|------------|---------------|
| JWT | `jti:<jti_claim>` |
| API key | `sha256:<hex(sha256(key))>` |
| OAuth2 token | `token:<sha256(access_token)>` |
| Session | `sid:<session_id>` |

## Negative caching

The `negativeCache` wrapper avoids a network round-trip (to Valkey)
for credentials that are **not** revoked — the common case. On a cache
miss it checks the backing store, and if the result is "not revoked",
caches that locally for `ttl` seconds.

When a new revocation is added, the negative cache entry for that key
is **immediately evicted** — ensuring enforcement is near-instantaneous
even with caching enabled.

## Helm wiring

```yaml
# values.yaml
config:
  inline: |
    revocation:
      backend: valkey
      addr: "valkey-master.cache.svc:6379"
      password: "${VALKEY_PASSWORD}"
      tls: true
      defaultTTL: 24h
      negativeCache:
        ttl: 2s
        maxSize: 100000
env:
  - name: VALKEY_PASSWORD
    valueFrom:
      secretKeyRef:
        name: lwauth-valkey
        key: password
```

## Operational notes

- **Memory.** Each in-memory entry is ~200 bytes. At 100k entries
  that's ~20 MB — modest. The background reaper removes expired
  entries every 60 seconds.
- **Valkey.** Uses `SET key reason EX ttl` for add, `EXISTS key` for
  lookup. One round-trip per non-cached check (~0.2ms in-cluster).
- **Federation.** When federation is enabled, revocations are
  automatically broadcast to all peers (see [Federation](federation.md)).
- **Metrics.** `lwauth_revocation_checks_total{result="hit|miss"}` and
  `lwauth_revocation_duration_seconds` track store performance.

## References

- Source: [pkg/revocation/](https://github.com/mikeappsec/lightweightauth/blob/main/pkg/revocation/).
- Admin API: [API.md](../API.md).
- Federation sync: [Federation](federation.md).
