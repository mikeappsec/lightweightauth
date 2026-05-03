# OAuth2 token introspection with multi-tier caching

Validate opaque OAuth 2.0 bearer tokens (access tokens that aren't
JWTs) by calling the IdP's RFC 7662 introspection endpoint. Uses
three-tier LRU caching and singleflight deduplication to keep IdP
load manageable even under high traffic.

## What this recipe assumes

- An OAuth 2.0 Authorization Server that issues opaque access tokens
  and exposes a token introspection endpoint (RFC 7662).
- lwauth has network access to the introspection endpoint.
- A client credential (client_id + client_secret) for lwauth to
  authenticate to the introspection endpoint.
- You want to support opaque tokens (not JWTs) — perhaps because your
  IdP issues reference tokens, or you need real-time revocation
  semantics.

## 1. Basic introspection configuration

```yaml
apiVersion: lightweightauth.io/v1alpha1
kind: AuthConfig
metadata:
  name: api-opaque-tokens
  namespace: production
spec:
  identifiers:
    - name: opaque-bearer
      type: oauth2-introspection
      config:
        # RFC 7662 introspection endpoint
        introspectionUrl: https://idp.example.com/oauth2/introspect
        # Client credentials for lwauth to authenticate
        clientId: lwauth-resource-server
        clientSecret: "${INTROSPECTION_CLIENT_SECRET}"
        # Where to find the token in the request
        header: Authorization
        scheme: Bearer
        # Timeout for the introspection call
        timeout: 500ms

  authorizers:
    - name: scope-check
      type: rbac
      config:
        rolesFrom: claim:scope    # introspection returns scope
        allow: [read, write]
```

The introspection response fields are mapped to identity claims:

| Introspection field | Identity claim |
|---------------------|---------------|
| `sub` | `subject` (identity subject) |
| `scope` | `claim:scope` (space-separated → array) |
| `client_id` | `claim:client_id` |
| `username` | `claim:username` |
| `exp` | `claim:exp` |
| `iat` | `claim:iat` |
| All other fields | Available as `claim:<field>` |

## 2. Multi-tier caching

The introspection identifier uses a three-tier LRU cache to minimize
IdP round-trips. Each tier has independent TTLs:

```yaml
    - name: opaque-bearer
      type: oauth2-introspection
      config:
        introspectionUrl: https://idp.example.com/oauth2/introspect
        clientId: lwauth-resource-server
        clientSecret: "${INTROSPECTION_CLIENT_SECRET}"
        timeout: 500ms

        cache:
          # Positive cache: active=true responses
          positiveTTL: 30s
          positiveMaxSize: 50000

          # Negative cache: active=false responses
          negativeTTL: 5s
          negativeMaxSize: 10000

          # Error cache: introspection endpoint failures
          errorTTL: 2s
          errorMaxSize: 1000
```

| Cache tier | Purpose | Recommended TTL |
|-----------|---------|-----------------|
| Positive | Token is valid; avoid re-introspecting | 30s–60s |
| Negative | Token is invalid/revoked; fast-reject | 2s–5s |
| Error | IdP is down; avoid hammering | 1s–5s |

!!! tip "Cache key security"
    The cache key is `sha256(token)` — raw tokens are **never**
    stored in memory. Even if the process memory is dumped, tokens
    cannot be extracted from the cache.

## 3. Singleflight deduplication

When multiple requests arrive with the same token simultaneously,
only one introspection call is made. All concurrent requests for the
same token share the result:

```text
Request A (token X) ─┐
Request B (token X) ──┤── single introspection call ──→ IdP
Request C (token X) ─┘
                    all three get the same result
```

This is automatic — no configuration needed. It prevents thundering
herd on popular tokens (e.g. a service account token used across
many concurrent requests).

## 4. Circuit breaker for IdP resilience

The introspection call goes through the shared `upstream.Guard`,
providing circuit-breaker protection:

```yaml
    - name: opaque-bearer
      type: oauth2-introspection
      config:
        introspectionUrl: https://idp.example.com/oauth2/introspect
        clientId: lwauth-resource-server
        clientSecret: "${INTROSPECTION_CLIENT_SECRET}"
        timeout: 500ms

        resilience:
          breaker:
            failureThreshold: 5
            coolDown: 30s
            halfOpenSuccesses: 2
          retries:
            maxRetries: 1
            backoffBase: 50ms
            backoffMax: 200ms
```

When the circuit opens, cached results continue serving; uncached
tokens fail closed (401).

## 5. Combine with JWT fallback

Support both opaque and JWT tokens — try introspection first, fall
back to JWT validation:

```yaml
spec:
  identifiers:
    # Try introspection first (opaque tokens)
    - name: opaque-bearer
      type: oauth2-introspection
      config:
        introspectionUrl: https://idp.example.com/oauth2/introspect
        clientId: lwauth-resource-server
        clientSecret: "${INTROSPECTION_CLIENT_SECRET}"
        header: Authorization
        scheme: Bearer

    # Fallback to JWT validation (self-contained tokens)
    - name: jwt-bearer
      type: jwt
      config:
        issuerUrl: https://idp.example.com
        audiences: [api]
        header: Authorization
        scheme: Bearer
```

Identifiers are tried in order. If the token is opaque, introspection
succeeds. If introspection returns `active: false` (because it's a
JWT the introspection endpoint doesn't know), the next identifier
(JWT) picks it up.

## 6. Helm wiring

```yaml
# values.yaml
config:
  inline: |
    identifiers:
      - name: opaque-bearer
        type: oauth2-introspection
        config:
          introspectionUrl: https://idp.example.com/oauth2/introspect
          clientId: lwauth-resource-server
          clientSecret: "${INTROSPECTION_CLIENT_SECRET}"
          timeout: 500ms
          cache:
            positiveTTL: 30s
            positiveMaxSize: 50000
            negativeTTL: 5s
            negativeMaxSize: 10000
    authorizers:
      - name: scope-check
        type: rbac
        config:
          rolesFrom: claim:scope
          allow: [read, write, admin]
env:
  - name: INTROSPECTION_CLIENT_SECRET
    valueFrom:
      secretKeyRef:
        name: lwauth-introspection
        key: client-secret
```

## 7. Validate

```bash
# Get an opaque token from your IdP
TOKEN=$(curl -s -X POST https://idp.example.com/oauth2/token \
  -d "grant_type=client_credentials&client_id=myapp&client_secret=..." \
  | jq -r .access_token)

# Authenticate via lwauth
curl -H "Authorization: Bearer ${TOKEN}" https://gateway/api/resource
# expect: 200

# Revoked/expired token
curl -H "Authorization: Bearer expired-token" https://gateway/api/resource
# expect: 401

# Dry-run
lwauthctl explain --config api-opaque-tokens.yaml \
    --request '{"method":"GET","path":"/api/resource","headers":{"authorization":"Bearer '${TOKEN}'"}}'
# identify  ✓  oauth2-introspection  subject=service-account
# authorize ✓  rbac (scope: [read, write])
```

## Operational notes

- **IdP load.** With a 30s positive cache and 10k RPM, you'll see
  ~333 introspection calls/min to the IdP (assuming uniform token
  distribution). Monitor `lwauth_introspection_cache_hit_ratio`.
- **Token hash in logs.** Only the first 8 chars of `sha256(token)`
  appear in debug logs — enough for correlation, not enough for replay.
- **Metric:** `lwauth_introspection_duration_seconds` histogram
  tracks IdP latency; alert on p99 > timeout.

## Teardown

```bash
kubectl delete authconfig api-opaque-tokens -n production
kubectl delete secret lwauth-introspection -n production
```
