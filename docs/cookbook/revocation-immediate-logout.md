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
    backend: memory
    defaultTTL: "24h"        # revocations expire after 24h
    maxEntries: 100000       # cap in-memory entries
    negativeCache:
      ttl: "2s"              # cache "not revoked" for 2s
      maxSize: 100000

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
    backend: valkey
    addr: "valkey-master.cache.svc:6379"
    username: "lwauth-revocation"
    password: "${VALKEY_PASSWORD}"
    tls: true
    keyPrefix: "lwauth/rev/"
    defaultTTL: "24h"
    negativeCache:
      ttl: "2s"
      maxSize: 100000
```

## 3. Revoking credentials via the Admin API

### Revoke a JWT by JTI

```bash
# Extract the JTI from the token
JTI=$(echo "${TOKEN}" | cut -d. -f2 | base64 -d | jq -r .jti)

# Revoke it
curl -X POST https://lwauth:9000/v1/admin/revoke \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d "{
    \"key\": \"jti:${JTI}\",
    \"reason\": \"user-logout\",
    \"ttl\": \"1h\"
  }"
# Response: {"status":"revoked","key":"jti:abc123","expiresAt":"2026-05-03T14:00:00Z"}
```

### Revoke an API key by hash

```bash
# The key derivation for API keys uses sha256
KEY_HASH=$(echo -n "${API_KEY}" | sha256sum | cut -d' ' -f1)

curl -X POST https://lwauth:9000/v1/admin/revoke \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d "{
    \"key\": \"sha256:${KEY_HASH}\",
    \"reason\": \"credential-compromise\",
    \"ttl\": \"24h\"
  }"
```

### Revoke an OAuth2 session

```bash
curl -X POST https://lwauth:9000/v1/admin/revoke \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "key": "sid:session-id-from-idp",
    "reason": "force-logout",
    "ttl": "8h"
  }'
```

### Revoke a certificate by serial

```bash
curl -X POST https://lwauth:9000/v1/admin/revoke \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "key": "serial:ABCDEF1234567890",
    "reason": "compromised-workload",
    "ttl": "24h"
  }'
```

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

Key derivation by identifier type:

| Identifier | Key format | Source |
|------------|-----------|--------|
| JWT | `jti:<jti_claim>` | Token's `jti` claim |
| API key | `sha256:<hex(sha256(key))>` | Raw key hash |
| OAuth2 token | `token:<sha256(access_token)>` | Access token hash |
| Session | `sid:<session_id>` | Session cookie value |
| mTLS cert | `serial:<hex_serial>` | Certificate serial |

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
            "key": f"jti:{user_jti}",
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
    body := fmt.Sprintf(`{"key":"jti:%s","reason":"user-logout","ttl":"1h"}`, jti)
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

## 7. Federation broadcast (multi-cluster)

When federation is enabled, revocations are automatically broadcast
to all configured peers:

```yaml
  revocation:
    backend: valkey
    addr: "valkey-master.cache.svc:6379"
    password: "${VALKEY_PASSWORD}"
    defaultTTL: "24h"

  federation:
    enabled: true
    clusterID: "us-east-1"
    federationKey: "${FEDERATION_PSK}"
    peers:
      - endpoint: "eu-west-1.lwauth.internal:9443"
```

A revocation in `us-east-1` propagates to `eu-west-1` within one
`syncInterval` (default 30s). For faster propagation, lower the
interval — but at the cost of higher inter-cluster traffic.

## 8. Helm wiring

```yaml
# values.yaml
config:
  inline: |
    revocation:
      backend: valkey
      addr: "valkey-master.cache.svc:6379"
      password: "${VALKEY_PASSWORD}"
      tls: true
      keyPrefix: "lwauth/rev/"
      defaultTTL: 24h
      negativeCache:
        ttl: 2s
        maxSize: 100000
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
  -d "{\"key\":\"jti:${JTI}\",\"reason\":\"test\",\"ttl\":\"5m\"}"
# expect: 200

# Verify it's now rejected (within negativeCache.ttl seconds)
sleep 2
curl -H "Authorization: Bearer ${TOKEN}" https://gateway/api/resource
# expect: 401

# Check metrics
curl -s https://lwauth:9090/metrics | grep revocation
# lwauth_revocation_checks_total{result="hit"} 1
# lwauth_revocation_checks_total{result="miss"} 1
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
  `negativeCache.ttl: 0s` (at the cost of a Valkey hit per request).
- **Audit trail.** The `reason` field is logged to the audit log.
  Use meaningful values for incident response.

## Teardown

```bash
kubectl delete authconfig api-with-revocation -n production
```
