# Composite authorization patterns

Chain multiple authorizers using `anyOf` (first-allow wins) and `allOf`
(all-must-allow) patterns. The composite meta-authorizer lets you build
tiered evaluation: cheap/fast checks first, expensive checks only when
needed — minimizing latency and external service load.

## What this recipe assumes

- Multiple authorization backends (RBAC, CEL, OpenFGA, SpiceDB, OPA).
- You want to short-circuit expensive checks when a cheaper check can
  decide.
- You understand the difference between `anyOf` (OR — first permit
  wins) and `allOf` (AND — all must permit).

## 1. anyOf — fast RBAC bypass before ReBAC

The most common pattern: admins skip per-resource checks entirely.
Only non-admin requests hit the expensive OpenFGA call:

```yaml
apiVersion: lightweightauth.io/v1alpha1
kind: AuthConfig
metadata:
  name: documents-api
  namespace: documents
spec:
  identifiers:
    - name: bearer
      type: jwt
      config:
        issuerUrl: https://idp.example.com
        audiences: [documents-api]

  authorizers:
    - name: gate
      type: composite
      config:
        # anyOf: stop at the first child that permits.
        # Order: cheap → expensive.
        anyOf:
          # Child 1: RBAC admin bypass (< 1µs, in-process)
          - name: admin-bypass
            type: rbac
            config:
              rolesFrom: claim:roles
              allow: [documents-admin]

          # Child 2: OpenFGA per-resource check (~5ms, network call)
          - name: rebac
            type: openfga
            config:
              apiUrl: http://openfga.openfga.svc:8080
              storeId: 01HX...
              authorizationModelId: 01HX...
              apiToken: "${FGA_TOKEN}"
              timeout: 150ms
              check:
                user: 'user:{{ .Identity.Subject }}'
                relation: |-
                  {{- if eq .Request.Method "GET" -}}viewer
                  {{- else -}}editor
                  {{- end -}}
                object: 'document:{{ index .Request.PathParts 1 }}'
```

Evaluation flow:

```text
admin user → RBAC permits → short-circuit → 200 (no FGA call)
regular user → RBAC denies → try OpenFGA → permits → 200
regular user → RBAC denies → try OpenFGA → denies → 403
```

## 2. allOf — require multiple conditions

All children must permit. Useful for defense-in-depth:

```yaml
  authorizers:
    - name: defense-in-depth
      type: composite
      config:
        # allOf: every child must permit.
        allOf:
          # Must have a valid role
          - name: role-check
            type: rbac
            config:
              rolesFrom: claim:roles
              allow: [user, admin]

          # AND must satisfy fine-grained CEL rules
          - name: resource-rules
            type: cel
            config:
              expressions:
                - expr: |
                    request.method == "DELETE" ?
                      identity.claims["roles"].exists(r, r == "admin") :
                      true
                  deny_message: "only admins can delete"

          # AND must pass the relationship check
          - name: ownership
            type: openfga
            config:
              apiUrl: http://openfga.openfga.svc:8080
              storeId: 01HX...
              authorizationModelId: 01HX...
              check:
                user: 'user:{{ .Identity.Subject }}'
                relation: owner
                object: 'resource:{{ index .Request.PathParts 2 }}'
```

Evaluation flow:

```text
no valid role → RBAC denies → short-circuit → 403 (no CEL, no FGA)
has role + CEL fails → 403 (no FGA call)
has role + CEL passes + FGA denies → 403
has role + CEL passes + FGA permits → 200
```

## 3. Nested composition

Combine `anyOf` and `allOf` for complex policies:

```yaml
  authorizers:
    - name: policy
      type: composite
      config:
        anyOf:
          # Path 1: Super-admins bypass everything
          - name: super-admin
            type: rbac
            config:
              rolesFrom: claim:roles
              allow: [super-admin]

          # Path 2: Regular access requires both RBAC + CEL
          - name: regular-access
            type: composite
            config:
              allOf:
                - name: basic-role
                  type: rbac
                  config:
                    rolesFrom: claim:roles
                    allow: [user, editor, admin]
                - name: tenant-isolation
                  type: cel
                  config:
                    expressions:
                      - expr: |
                          request.headers["x-tenant-id"] == identity.claims["org_id"]
                        deny_message: "cross-tenant access denied"
```

This reads as: "super-admin OR (valid role AND same tenant)".

## 4. Error handling in composite chains

| Mode | On child error | Behavior |
|------|---------------|----------|
| `anyOf` | Error in one child | Try next child; if all error/deny → 403 |
| `allOf` | Error in one child | Short-circuit → 403 |

An error from a child (e.g. OpenFGA timeout) is treated as "not a
permit" — it does not crash the chain. This ensures that a broken
backend doesn't accidentally allow requests.

## 5. Header merging

When multiple children set response or upstream headers, the composite
authorizer merges them:

```yaml
  authorizers:
    - name: gate
      type: composite
      config:
        anyOf:
          - name: admin-bypass
            type: rbac
            config:
              rolesFrom: claim:roles
              allow: [admin]
          - name: check
            type: openfga
            config:
              # ...
```

Headers from the **permitting** child are forwarded. In `anyOf`, only
the first permitting child's headers are used. In `allOf`, headers from
all children are merged (last-writer-wins for conflicts).

## 6. Performance patterns

| Pattern | Use case | Typical p50 |
|---------|----------|-------------|
| `anyOf[RBAC, FGA]` | Admin bypass | < 1µs for admins, ~5ms for others |
| `allOf[RBAC, CEL]` | Role + fine-grained | < 2µs (both in-process) |
| `anyOf[RBAC, allOf[CEL, FGA]]` | Admin bypass, then CEL gate + FGA | < 1µs admins, ~5ms for non-admin FGA path |
| `anyOf[CEL(reject), FGA]` | Reject obvious garbage before FGA | < 1µs for malformed, ~5ms for valid |

Order children by: (1) in-process first, (2) cheap network calls
second, (3) expensive calls last.

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
      - name: gate
        type: composite
        config:
          anyOf:
            - name: admin-bypass
              type: rbac
              config:
                rolesFrom: claim:roles
                allow: [admin]
            - name: rebac
              type: openfga
              config:
                apiUrl: http://openfga.openfga.svc:8080
                storeId: 01HX...
                authorizationModelId: 01HX...
                timeout: 150ms
                check:
                  user: 'user:{{ .Identity.Subject }}'
                  relation: viewer
                  object: 'document:{{ index .Request.PathParts 1 }}'
env:
  - name: FGA_TOKEN
    valueFrom:
      secretKeyRef:
        name: lwauth-fga
        key: token
```

## 8. Validate

```bash
# Admin — hits RBAC, skips FGA
curl -H "Authorization: Bearer ${ADMIN_TOKEN}" https://gateway/api/documents/42
# expect: 200 (RBAC short-circuit)

# Regular user with FGA relationship
curl -H "Authorization: Bearer ${USER_TOKEN}" https://gateway/api/documents/42
# expect: 200 (FGA permits)

# Regular user without relationship
curl -H "Authorization: Bearer ${USER_TOKEN}" https://gateway/api/documents/999
# expect: 403

# Dry-run shows which child decided
lwauthctl explain --config documents-api.yaml \
    --request '{"method":"GET","path":"/api/documents/42","headers":{"authorization":"Bearer '${ADMIN_TOKEN}'"}}'
# identify   ✓  jwt        subject=alice  claims.roles=[admin]
# authorize  ✓  composite  child=admin-bypass (short-circuit)

lwauthctl explain --config documents-api.yaml \
    --request '{"method":"GET","path":"/api/documents/42","headers":{"authorization":"Bearer '${USER_TOKEN}'"}}'
# identify   ✓  jwt        subject=bob  claims.roles=[user]
# authorize  ✓  composite  child=admin-bypass(deny) → child=rebac(permit)
```

## Teardown

```bash
kubectl delete authconfig documents-api -n documents
```
