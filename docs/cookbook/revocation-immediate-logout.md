# Credential revocation & immediate logout

Configure real-time credential revocation to handle immediate logout,
credential compromise, and compliance-driven access termination.
Covers both in-memory (single replica) and Valkey-backed (multi-replica)
stores, with negative caching for performance and optional federation
broadcast.

## What this recipe assumes

- lwauth deployed with at least one identifier (JWT, API key, etc.).
- Credentials have a unique identifier: JTI claim (JWTs), session ID,
  or the key hash (API keys).
- You need sub-second revocation enforcement — not just waiting for
  token expiry.
- Admin API access (port 9000 by default) is network-restricted and
  authenticated.

## 1. In-memory revocation (single replica)

Simplest setup — good for development or single-replica deployments:

```yaml
apiVersion: lightweightauth.io/v1alpha1
kind: AuthConfig
metadata:
  name: api-with-revocation
  namespace: production
spec:
  revocation:
    enabled: true            # required — revocation is opt-in
    backend: memory
    defaultTTL: "24h"        # revocations expire after 24h
    negCacheTTL: "2s"        # cache "not revoked" for 2s

  identifiers:
    - name: bearer
      type: jwt
      config:
        issuerUrl: https://idp.example.com
        audiences: [api]

  authorizers:
    - name: rbac
      type: rbac
      config:
        rolesFrom: claim:roles
        allow: [user, admin]
```

## 2. Valkey-backed revocation (multi-replica)

For production with multiple lwauth replicas. A revocation written to
one replica is immediately visible to all:

```yaml
  revocation:
    enabled: true
    backend: valkey
    addr: "valkey-master.cache.svc:6379"
    username: "lwauth-revocation"
    password: "${VALKEY_PASSWORD}"
    tls: true
    keyPrefix: "lwauth/rev/"
    defaultTTL: "24h"
    negCacheTTL: "2s"
```

## 3. Revoking credentials via the Admin API

`POST /v1/admin/revoke` accepts exactly these body fields: `jti`,
`token_hash`, `subject`, `tenant`, `reason`, `ttl`. At least one of
`jti`, `token_hash`, or `subject` is required. There is no generic
`key` field — you can't hand it a pre-formatted `sid:`/`serial:`/`kid:`
string; the handler builds its own internal keys from the fields
above (`jti` → `jti:<value>`, `token_hash` → `hash:<value>`, `subject`
→ `sub:[tenant:]<value>`).

### Revoke a JWT by JTI

```bash
# Extract the JTI from the token
JTI=$(echo "${TOKEN}" | cut -d. -f2 | base64 -d | jq -r .jti)

# Revoke it
curl -X POST https://lwauth:9000/v1/admin/revoke \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d "{
    \"jti\": \"${JTI}\",
    \"reason\": \"user-logout\",
    \"ttl\": \"1h\"
  }"
# Response (202 Accepted): {"accepted":true,"keys":["jti:abc123"],"admin":"..."}
```

### Revoke all credentials for a subject

The `jwt`/`oauth2`/`mtls`/`hmac`/`apikey` identifiers all key their
subject-level revocation the same way (`sub:[tenant:]<subject>`), so
this is the one body shape that reliably revokes *every* credential a
subject holds, regardless of identifier type:

```bash
curl -X POST https://lwauth:9000/v1/admin/revoke \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "subject": "service-a",
    "tenant": "acme",
    "reason": "credential-compromise",
    "ttl": "24h"
  }'
# Response (202 Accepted): {"accepted":true,"keys":["sub:acme:service-a"],"admin":"..."}
```

### What you *cannot* precisely revoke today

`token_hash` exists as a body field (→ a `hash:<value>` revocation
entry) but no identifier module currently emits a `hash:`-prefixed
`RevocationKeys()` entry to match against it — so submitting
`token_hash` writes a revocation entry that nothing will ever look
up. Similarly, there's no body field for an OAuth2 session ID
(`sid:`, produced internally by the `oauth2` identifier), an API-key
key ID (`kid:`, from `apikey`/`hmac`), or an mTLS certificate serial
(`serial:`, from `mtls`) — those key spaces exist inside the
identifier modules but the admin API has no way to submit them
directly. Until that's added, revoking one specific API key, HMAC
key, OAuth2 session, or certificate without also revoking every other
credential that subject holds isn't possible through this endpoint —
use subject-level revocation (above) instead, which is blunter but
actually works.

## 4. Pipeline integration

The revocation check runs **after** rate limiting but **before**
full identification:

```text
Request → Rate Limit → Revocation Check → Identify → Authorize → Mutate
                             ↓
                        store.Exists(key)
                             ↓
                   revoked? → 401 Unauthorized
                   not revoked? → continue pipeline
```

Key derivation by identifier type (`RevocationKeys()` on each
identifier — see "What you cannot precisely revoke today" above for
which of these the admin API can actually address):

| Identifier | Key format | Source |
|------------|-----------|--------|
| JWT | `jti:<jti_claim>` | Token's `jti` claim |
| JWT / OAuth2 / mTLS / HMAC / API key | `sub:[tenant:]<subject>` | Identity subject — revokes everything |
| API key / HMAC | `kid:<keyId>` | The entry ID in `hashed.entries`/`.file`/`.dir` |
| OAuth2 | `sid:<session_id>` | `sid` claim from the identity provider |
| mTLS cert | `serial:<hex_serial>` | Certificate `serialNumber` claim |
| Introspection | `client:<client_id>` | `client_id` from the introspection response |

## 5. Implementing logout in your application

Wire your application's logout endpoint to call the lwauth admin API:

```python
# Python example — logout handler
import requests
import hashlib

def logout(user_jti: str, admin_token: str):
    """Revoke the user's current token on logout."""
    resp = requests.post(
        "https://lwauth:9000/v1/admin/revoke",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={
            "jti": user_jti,
            "reason": "user-logout",
            "ttl": "1h",  # match remaining token lifetime
        },
    )
    resp.raise_for_status()
```

```go
// Go example — logout handler
func handleLogout(w http.ResponseWriter, r *http.Request) {
    jti := extractJTI(r) // from the user's current token
    body := fmt.Sprintf(`{"jti":%q,"reason":"user-logout","ttl":"1h"}`, jti)
    req, _ := http.NewRequest("POST", "https://lwauth:9000/v1/admin/revoke",
        strings.NewReader(body))
    req.Header.Set("Authorization", "Bearer "+adminToken)
    req.Header.Set("Content-Type", "application/json")
    resp, err := http.DefaultClient.Do(req)
    // ...
}
```

## 6. Negative caching tuning

The negative cache avoids a Valkey round-trip for tokens that are
**not** revoked (the 99.9% case):

| Setting | Trade-off |
|---------|-----------|
| `ttl: 2s` (default) | Revocations take up to 2s to enforce; low IdP load |
| `ttl: 0s` | Instant enforcement; every request hits Valkey |
| `ttl: 10s` | 10s enforcement delay; lowest Valkey load |

When a new revocation is added, the negative cache entry for that key
is **immediately evicted** on the local replica. Cross-replica
propagation depends on the cache TTL (Valkey backend) or federation
broadcast delay.

## 7. Federation broadcast (multi-cluster) — not currently wired in

`pkg/federation` implements exactly this (HMAC-signed snapshot +
revocation fan-out between clusters, see
[its README](https://github.com/mikeappsec/lightweightauth/blob/main/pkg/federation/README.md)
for the real `federation.Config` shape), but nothing in `cmd/lwauth`
or `cmd/lwauth-controlplane` loads it — there's no `federation:` key
on `AuthConfig` (`internal/config/config.go` has no such field), and
no flag wires a `federation.Server`/`federation.Peer` into the
running daemon. Multi-cluster revocation sync is a library that
exists but isn't reachable from configuration today; the only
cross-replica propagation that actually runs in production is the
`PeerBroadcaster` within a single cluster (`internal/admin/handler.go`),
which is what section 8 below covers via Valkey, not federation.

## 8. Helm wiring

```yaml
# values.yaml
config:
  inline: |
    revocation:
      enabled: true
      backend: valkey
      addr: "valkey-master.cache.svc:6379"
      password: "${VALKEY_PASSWORD}"
      tls: true
      keyPrefix: "lwauth/rev/"
      defaultTTL: 24h
      negCacheTTL: 2s
    identifiers:
      - name: bearer
        type: jwt
        config:
          issuerUrl: https://idp.example.com
          audiences: [api]
    authorizers:
      - name: rbac
        type: rbac
        config:
          rolesFrom: claim:roles
          allow: [user, admin]
env:
  - name: VALKEY_PASSWORD
    valueFrom:
      secretKeyRef:
        name: lwauth-valkey
        key: password
```

## 9. Validate

```bash
# Get a valid token
TOKEN=$(get-token-from-idp)
JTI=$(echo "${TOKEN}" | cut -d. -f2 | base64 -d | jq -r .jti)

# Verify it works
curl -H "Authorization: Bearer ${TOKEN}" https://gateway/api/resource
# expect: 200

# Revoke it
curl -X POST https://lwauth:9000/v1/admin/revoke \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -d "{\"jti\":\"${JTI}\",\"reason\":\"test\",\"ttl\":\"5m\"}"
# expect: 202

# Verify it's now rejected (within negCacheTTL seconds)
sleep 2
curl -H "Authorization: Bearer ${TOKEN}" https://gateway/api/resource
# expect: 401

# Check metrics
curl -s https://lwauth:9090/metrics | grep revocation
# lwauth_revocation_checks_total{tenant="...",result="revoked"} 1
# lwauth_revocation_checks_total{tenant="...",result="not_revoked"} 1
```

## Security notes

- **Admin API authentication.** The `/v1/admin/revoke` endpoint
  requires a valid admin token. Restrict network access to the admin
  port (9000) via NetworkPolicy.
- **TTL hygiene.** Set revocation TTL to match or exceed the token's
  remaining lifetime. After the original token expires naturally, the
  revocation entry is wasted memory.
- **Negative cache and instant revocation.** The local cache evicts
  immediately on write, but cross-replica propagation depends on the
  Valkey backend. For truly instant cross-replica enforcement, set
  `negCacheTTL: 0s` (at the cost of a Valkey hit per request).
- **Audit trail.** The `reason` field is logged to the audit log.
  Use meaningful values for incident response.

## Teardown

```bash
kubectl delete authconfig api-with-revocation -n production
```
