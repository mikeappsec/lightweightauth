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
        # RFC 7662 introspection endpoint — field is `url`, not
        # `introspectionUrl` (pkg/identity/introspection's knownKeys).
        url: https://idp.example.com/oauth2/introspect
        # Client credentials for lwauth to authenticate
        clientId: lwauth-resource-server
        clientSecret: "${INTROSPECTION_CLIENT_SECRET}"
        # Where to find the token in the request. There's no separate
        # `scheme:` field — the "Bearer " prefix is stripped
        # unconditionally (case-insensitive), not configurable.
        headerName: Authorization
        # There is no `timeout:` field on this module — per-call
        # timeout is controlled through `resilience:` (see step 4).

  authorizers:
    - name: scope-check
      type: rbac
      config:
        rolesFrom: claim:scope    # introspection returns scope
        allow: [read, write]
```

!!! warning "`clientSecret` is read literally — no `${VAR}` substitution"
    lwauth does not expand `${INTROSPECTION_CLIENT_SECRET}`-style
    placeholders anywhere in `AuthConfig` — every `${VAR}` in this
    recipe's YAML is notation for "your real secret goes here," not
    something lwauth resolves itself. Two ways to actually inject it:
    `clientSecret: "vault://kv/lwauth/introspection#secret"` (resolved
    at compile time — any string field in a module's `config:` is
    checked recursively for a `secretRef`, `internal/config/loader.go`'s
    `resolveMapSecrets`), or template the `AuthConfig` YAML itself at
    the deployment-pipeline layer (Helm, Kustomize, CI) so the real
    secret is already inlined before lwauth ever parses it.

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
IdP round-trips. There's no nested `cache:` block — the three tiers
are flat, top-level fields, and only the positive tier's size is
configurable (`cacheSize` bounds the whole in-process LRU; there's no
per-tier `*MaxSize` knob):

```yaml
    - name: opaque-bearer
      type: oauth2-introspection
      config:
        url: https://idp.example.com/oauth2/introspect
        clientId: lwauth-resource-server
        clientSecret: "${INTROSPECTION_CLIENT_SECRET}"

        cacheSize: 100000     # shared LRU size across all tiers; default 100000
        maxCacheTtl: 30s       # positive tier: cap on min(claims.exp - now, this)
        negativeTtl: 5s        # negative tier: how long "active: false" is remembered
        errorTtl: 2s           # error tier: how long an upstream failure is remembered — 0 disables it
```

| Cache tier | Field | Purpose | Recommended TTL |
|-----------|-------|---------|-----------------|
| Positive | `maxCacheTtl` | Token is valid; avoid re-introspecting | 30s–60s |
| Negative | `negativeTtl` | Token is invalid/revoked; fast-reject | 2s–5s |
| Error | `errorTtl` | IdP is down; avoid hammering | 1s–5s |

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
        url: https://idp.example.com/oauth2/introspect
        clientId: lwauth-resource-server
        clientSecret: "${INTROSPECTION_CLIENT_SECRET}"

        # retries.max, not retries.maxRetries — see pkg/upstream/config.go
        resilience:
          breaker:
            failureThreshold: 5
            coolDown: 30s
            halfOpenSuccesses: 2
          retries:
            max: 1
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
        url: https://idp.example.com/oauth2/introspect
        clientId: lwauth-resource-server
        clientSecret: "${INTROSPECTION_CLIENT_SECRET}"
        headerName: Authorization

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
          url: https://idp.example.com/oauth2/introspect
          clientId: lwauth-resource-server
          clientSecret: "${INTROSPECTION_CLIENT_SECRET}"
          cacheSize: 100000
          maxCacheTtl: 30s
          negativeTtl: 5s
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
# identify:
#   ✓ opaque-bearer (oauth2-introspection) → subject="service-account" claims=N
# authorize: ✓ scope-check (rbac) allow: ...
# decision: allow identifier="opaque-bearer" authorizer="scope-check" upstreamHeaders=0 responseHeaders=0
```

## Operational notes

- **IdP load.** With a 30s positive cache and 10k RPM, you'll see
  ~333 introspection calls/min to the IdP (assuming uniform token
  distribution) — modulo singleflight coalescing on hot tokens.
  There's no `lwauth_introspection_*` metric to monitor this directly
  (no such metric exists in `pkg/observability/metrics`); use IdP-side
  request counts instead.
- **No debug logging in this module.** `pkg/identity/introspection/introspection.go`
  doesn't log anything — there's no token-hash-in-logs behavior to
  rely on for correlation.

## Teardown

```bash
kubectl delete authconfig api-opaque-tokens -n production
kubectl delete secret lwauth-introspection -n production
```
