# CEL expression-based authorization

Build request-aware authorization rules using the Common Expression
Language (CEL). CEL is deterministic, non-Turing-complete, and
type-checked at config load time — making it safe for inline policy
without the operational weight of OPA/Rego.

## What this recipe assumes

- An existing `AuthConfig` with at least one identifier.
- Authorization rules that depend on request attributes (path, method,
  headers) combined with identity claims — too dynamic for static RBAC
  but too simple for a full policy engine.
- Familiarity with CEL syntax (similar to Go/Java expressions).

## 1. Basic path & method authorization

Restrict endpoints by HTTP method and path using CEL expressions:

```yaml
apiVersion: lightweightauth.io/v1alpha1
kind: AuthConfig
metadata:
  name: api-cel-policy
  namespace: production
spec:
  identifiers:
    - name: bearer
      type: jwt
      config:
        issuerUrl: https://idp.example.com
        audiences: [api]

  authorizers:
    - name: endpoint-policy
      type: cel
      config:
        expressions:
          # Admin-only endpoints
          - expr: |
              request.path.startsWith("/api/admin/") ?
                identity.claims["roles"].exists(r, r == "admin") :
                true
            deny_message: "admin role required"

          # Write operations need 'editor' or 'admin'
          - expr: |
              request.method in ["POST", "PUT", "DELETE"] ?
                identity.claims["roles"].exists(r, r == "editor" || r == "admin") :
                true
            deny_message: "editor role required for writes"

          # Block access outside business hours (optional)
          - expr: |
              timestamp(now).getHours() >= 6 &&
              timestamp(now).getHours() < 22
            deny_message: "access restricted outside business hours"
```

All expressions must evaluate to `true` for the request to be
authorized. If any returns `false`, the request is denied with the
corresponding `deny_message`.

## 2. Available variables

CEL expressions have access to:

| Variable | Type | Description |
|----------|------|-------------|
| `identity.subject` | string | Authenticated subject |
| `identity.source` | string | Identifier type ("jwt", "apikey", etc.) |
| `identity.claims` | map[string]any | All identity claims |
| `request.method` | string | HTTP method (GET, POST, etc.) |
| `request.path` | string | Request path |
| `request.host` | string | Host header |
| `request.headers` | map[string]string | Request headers (lowercase keys) |
| `request.query` | map[string]string | Query parameters |
| `request.pathSegments` | list[string] | Path split by `/` |
| `context.tenantId` | string | Resolved tenant ID |
| `context.timestamp` | timestamp | Request timestamp |
| `now` | string | Current time (ISO 8601) |

## 3. Resource-owner authorization

Only allow users to access their own resources:

```yaml
        expressions:
          # /api/users/{userId}/... → user can only access own resources
          - expr: |
              request.path.matches("^/api/users/[^/]+/") ?
                request.pathSegments[2] == identity.subject ||
                identity.claims["roles"].exists(r, r == "admin") :
                true
            deny_message: "cannot access another user's resources"
```

## 4. Multi-tenant data isolation

Ensure tenants can only access their own data:

```yaml
        expressions:
          # Tenant header must match the token's org claim
          - expr: |
              has(request.headers["x-tenant-id"]) ?
                request.headers["x-tenant-id"] == identity.claims["org_id"] :
                true
            deny_message: "tenant mismatch"

          # API key tenants can only access /api/tenant/{their-id}/*
          - expr: |
              identity.source == "apikey" ?
                request.path.startsWith("/api/tenant/" + identity.claims["tenant"] + "/") :
                true
            deny_message: "API key restricted to own tenant path"
```

## 5. IP-based restrictions

Combine identity with network context:

```yaml
        expressions:
          # Privileged operations only from corporate network
          - expr: |
              request.path.startsWith("/api/admin/") ?
                request.headers["x-forwarded-for"].matches("^10\\.0\\.") :
                true
            deny_message: "admin access restricted to corporate network"

          # Service accounts must come from internal CIDRs
          - expr: |
              identity.claims["token_type"] == "service" ?
                request.headers["x-real-ip"].matches("^(10\\.|172\\.(1[6-9]|2[0-9]|3[01])\\.|192\\.168\\.)") :
                true
            deny_message: "service tokens restricted to internal network"
```

## 6. Combining CEL with RBAC (composite)

Use CEL as a secondary check after a fast RBAC pass:

```yaml
  authorizers:
    - name: policy
      type: composite
      config:
        allOf:
          # Fast RBAC check first
          - name: role-check
            type: rbac
            config:
              rolesFrom: claim:roles
              allow: [user, admin]

          # CEL for fine-grained rules
          - name: fine-grained
            type: cel
            config:
              expressions:
                - expr: |
                    request.method == "DELETE" ?
                      identity.claims["roles"].exists(r, r == "admin") :
                      true
                  deny_message: "only admins can delete"
```

## 7. Helm wiring

```yaml
# values.yaml
config:
  inline: |
    identifiers:
      - name: bearer
        type: jwt
        config:
          issuerUrl: https://idp.example.com
          audiences: [api]
    authorizers:
      - name: endpoint-policy
        type: cel
        config:
          expressions:
            - expr: |
                request.path.startsWith("/api/admin/") ?
                  identity.claims["roles"].exists(r, r == "admin") :
                  true
              deny_message: "admin role required"
            - expr: |
                request.method in ["POST", "PUT", "DELETE"] ?
                  identity.claims["roles"].exists(r, r == "editor" || r == "admin") :
                  true
              deny_message: "editor role required for writes"
```

## 8. Validate

```bash
# Admin accessing admin endpoint — allowed
curl -H "Authorization: Bearer ${ADMIN_TOKEN}" \
     https://gateway/api/admin/users
# expect: 200

# Regular user accessing admin endpoint — denied
curl -H "Authorization: Bearer ${USER_TOKEN}" \
     https://gateway/api/admin/users
# expect: 403, body: "admin role required"

# Regular user reading (GET) — allowed
curl -H "Authorization: Bearer ${USER_TOKEN}" \
     https://gateway/api/resources
# expect: 200

# Regular user writing (POST) without editor role — denied
curl -X POST -H "Authorization: Bearer ${USER_TOKEN}" \
     https://gateway/api/resources
# expect: 403, body: "editor role required for writes"

# Dry-run
lwauthctl explain --config api-cel-policy.yaml \
    --request '{"method":"DELETE","path":"/api/admin/users/123","headers":{"authorization":"Bearer ..."}}'
# identify  ✓  jwt      subject=alice  claims.roles=[admin]
# authorize ✓  cel      expr[0]=true  expr[1]=true
```

## Operational notes

- **Type checking.** Expressions are compiled and type-checked at
  config load time. A malformed expression rejects the entire config
  (`Ready=False` on the CRD) — no silent failures at runtime.
- **Performance.** CEL is compiled to an AST and evaluated without
  allocation. Typical expression evaluation is < 1µs. OptOptimize is
  enabled by default.
- **Determinism.** CEL has no loops, no recursion, no side effects.
  The same input always produces the same output. There is no risk
  of infinite loops or resource exhaustion.
- **Composability.** CEL works under `composite` authorizers. Use
  RBAC for the common path and CEL for edge-case rules.

## Teardown

```bash
kubectl delete authconfig api-cel-policy -n production
```
