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

Revocation is opt-in and disabled unless `enabled: true` is set
(`internal/config/config.go`'s `RevocationSpec.Enabled`,
`internal/config/loader.go`'s `buildRevocationStore` no-ops when
absent or false). There's no nested `negativeCache: {ttl, maxSize}`
object — the real field is a flat `negCacheTTL` duration string, and
there's no `maxSize`-equivalent knob at all (`WithNegCacheMaxSize`
exists in `pkg/revocation/negcache.go` but is never called from the
loader). `maxEntries` is likewise unwired — `WithMaxEntries` exists in
`pkg/revocation/memory.go` but nothing calls it from config, so the
field is silently ignored if you set it.

### In-memory store (single replica)

```yaml
revocation:
  enabled: true
  backend: memory
  defaultTTL: "24h"
  negCacheTTL: "2s"
```

Note the negative-cache wrap is only applied for the `valkey` backend
(and pool-routed stores) — `backend: memory` gets no negative-cache
wrapper at all today, so `negCacheTTL` has no effect here regardless
of what you set it to.

### Valkey store (multi-replica)

```yaml
revocation:
  enabled: true
  backend: valkey
  addr: "valkey-master.cache.svc:6379"
  username: "lwauth-revocation"   # Valkey ACL user
  password: "${VALKEY_PASSWORD}"   # see warning below
  tls: true
  keyPrefix: "lwauth/rev/"
  defaultTTL: "24h"
  negCacheTTL: "2s"
```

!!! warning "`password` is read literally — no `${VAR}` substitution"
    lwauth does not expand `${VALKEY_PASSWORD}`-style placeholders
    anywhere in `AuthConfig`. `revocation.password` does support the
    real mechanism: `secretRef: "vault://kv/lwauth/valkey#password"`
    (`internal/config/loader.go` checks it specifically, alongside
    `cache.password`/`cache.sharedHmacKey`/`caches[].password`). Or
    template the `AuthConfig` YAML itself at the deployment-pipeline
    layer (Helm, Kustomize, CI) so the real password is already
    inlined before lwauth ever parses it.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `false` | Required to activate revocation checking at all |
| `backend` | string | `memory` | Store type: `memory` or `valkey` |
| `addr` | string | — | Valkey host:port (required for valkey backend) |
| `username` | string | — | Valkey ACL username |
| `password` | string | — | Valkey ACL password |
| `tls` | bool | `false` | Enable TLS (min 1.2) to Valkey |
| `keyPrefix` | string | `"lwauth/rev/"` | Key namespace in Valkey |
| `defaultTTL` | duration | `24h` | How long revocations persist |
| `negCacheTTL` | duration | `2s` | Local cache TTL for "not revoked" results — only applied for `backend: valkey` |

## Admin API

`POST /v1/admin/revoke` has no generic `key` field — it accepts
`jti`, `token_hash`, `subject`, `tenant`, `reason`, `ttl`
(`internal/admin/handler.go`), each mapped to its own fixed key kind
(`jti:`/`hash:`/`sub:[tenant:]`) internally. There's no way to submit
an arbitrary pre-formatted revocation key directly — see
[revocation-immediate-logout.md](../cookbook/revocation-immediate-logout.md#3-revoking-credentials-via-the-admin-api)
for the full picture of what is and isn't reachable this way:

```bash
curl -X POST https://lwauth:9000/v1/admin/revoke \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "jti": "abc123",
    "reason": "user-logout",
    "ttl": "1h"
  }'
```

| Field | Type | Description |
|-------|------|-------------|
| `jti` | string | Revokes by JTI → `jti:<value>` |
| `token_hash` | string | Writes a `hash:<value>` entry — but no identifier module currently checks a `hash:`-prefixed key, so this is presently a no-op |
| `subject` | string | Revokes every credential for this subject → `sub:[tenant:]<value>` |
| `tenant` | string | Scopes `subject` revocation to one tenant |
| `reason` | string | Audit trail reason |
| `ttl` | duration | Override defaultTTL for this entry (optional) |

Response is `202 Accepted` with `{"accepted": true, "keys": [...], "admin": "..."}`.

## Pipeline integration

```text
Request → Rate Limit → Revocation Check → Identify → Authorize → Mutate
                             ↓
                        store.Exists(key)
                             ↓
                   revoked? → 401 Unauthorized
```

The revocation check runs **after** rate limiting but **before**
identification. Each identifier module derives its own keys via
`RevocationKeys()`:

| Identifier | Key derivation |
|------------|---------------|
| JWT | `jti:<jti_claim>` |
| API key / HMAC | `kid:<keyId>` (the entry ID), plus `sub:[tenant:]<subject>` |
| OAuth2 | `sid:<session_id>`, plus `sub:[tenant:]<subject>` |
| mTLS | `serial:<hex_serial>`, plus `sub:[tenant:]<subject>` |
| Introspection | `client:<client_id>` |

Only `jti:` and `sub:` are reachable from the admin API today (see
above) — `kid:`/`sid:`/`serial:`/`client:` exist in the identifier
modules but have no corresponding admin-API field.

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
      enabled: true
      backend: valkey
      addr: "valkey-master.cache.svc:6379"
      password: "vault://kv/lwauth/valkey#password"
      tls: true
      defaultTTL: 24h
      negCacheTTL: 2s
```

## Operational notes

- **Memory.** Each in-memory entry is ~200 bytes. The background
  reaper removes expired entries every **30 seconds**
  (`pkg/revocation/memory.go`).
- **Valkey.** Uses `SET key reason PX <milliseconds>` for add (not
  `EX <seconds>` — millisecond precision), `EXISTS key` for lookup.
  One round-trip per non-cached check (~0.2ms in-cluster).
- **Federation.** [Federation](federation.md) is implemented but not
  wired into any binary today — revocations are **not** automatically
  broadcast to other clusters. Cross-replica propagation *within* one
  cluster does happen, via the admin API's `PeerBroadcaster`
  (`internal/admin/handler.go`), which is a different, already-live
  mechanism.
- **Metrics.** `lwauth_revocation_checks_total{tenant, result}` where
  `result` is `revoked`/`not_revoked`/`error` (not `hit`/`miss`).
  There is no `lwauth_revocation_duration_seconds` metric.

## References

- Source: [pkg/revocation/](https://github.com/mikeappsec/lightweightauth/blob/main/pkg/revocation/).
- Admin API: [API.md](../API.md).
- Federation sync: [Federation](federation.md).
