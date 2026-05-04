# Response header stamping & identity forwarding

Strip raw credentials before they reach upstream services, inject
identity headers (subject, roles, tenant), and optionally mint a
short-lived internal JWT that downstream microservices trust without
re-validating the original token.

## What this recipe assumes

- lwauth running as an `ext_authz` provider.
- At least one identifier configured (JWT, API key, mTLS, etc.).
- Upstream services expect identity in headers (e.g. `X-User`,
  `X-Roles`) rather than re-parsing the original credential.
- Optionally: upstream services validate an internal JWT rather than
  trusting plain headers.

## 1. Strip raw credentials

Remove the original `Authorization` header so upstream services never
see raw tokens. This prevents confused-deputy attacks where a backend
inadvertently forwards the end-user credential to a third party:

```yaml
apiVersion: lightweightauth.io/v1alpha1
kind: AuthConfig
metadata:
  name: api-gateway
  namespace: production
spec:
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

  mutators:
    # Step 1: Strip the raw credential
    - name: strip-auth
      type: header-remove
      config:
        headers:
          - Authorization
          - Cookie    # if session-based auth is also in play
```

## 2. Inject identity headers

Add structured identity information for upstream consumption:

```yaml
  mutators:
    - name: strip-auth
      type: header-remove
      config:
        headers: [Authorization]

    # Step 2: Stamp identity into headers
    - name: identity-headers
      type: header-add
      config:
        upstream:    # headers sent to the upstream service
          X-User-ID: "${sub}"
          X-User-Email: "${claim:email}"
          X-User-Roles: "${claim:roles}"
          X-Tenant-ID: "${claim:tenant_id}"
          X-Auth-Source: "${source}"    # "jwt", "apikey", etc.
        response:    # headers sent back to the client (optional)
          X-Request-ID: "${requestId}"
```

Available placeholders:

| Placeholder | Value |
|-------------|-------|
| `${sub}` | Authenticated subject |
| `${claim:<name>}` | Any claim from the identity |
| `${source}` | Identifier type that matched |
| `${requestId}` | Internal request correlation ID |
| `${header:<name>}` | Inbound request header value |

## 3. Passthrough selected headers

Forward specific inbound headers unchanged (useful for correlation
IDs, trace context, or client-specified metadata):

```yaml
    - name: passthrough
      type: header-passthrough
      config:
        headers:
          - X-Request-ID
          - X-Correlation-ID
          - Traceparent
          - Tracestate
          - X-Forwarded-For
```

## 4. Mint an internal JWT for upstream trust

When plain headers aren't secure enough (any intermediate can forge
`X-User-ID`), mint a short-lived internal JWT that upstreams validate
against a shared HMAC key:

```yaml
    - name: internal-jwt
      type: jwt-issue
      config:
        # Signing key (HS256). Mount from a Secret.
        algorithm: HS256
        key: "${INTERNAL_JWT_KEY}"   # hex-encoded or raw
        # Standard claims
        issuer: lwauth-gateway
        audiences: [internal-services]
        expiry: 60s               # short-lived; re-issued per request
        # Propagate selected claims from the original identity
        copyClaims:
          - sub
          - email
          - roles
          - tenant_id
        # Where to place the minted JWT
        header: X-Internal-Auth
        scheme: Bearer            # upstream sees: X-Internal-Auth: Bearer <jwt>
```

Upstream services validate `X-Internal-Auth` using the shared key:

```go
// In upstream service
claims, err := jwt.Validate(r.Header.Get("X-Internal-Auth"), sharedKey)
if err != nil {
    return http.StatusUnauthorized
}
userID := claims.Subject
roles := claims["roles"]
```

## 5. Complete AuthConfig example

Putting it all together:

```yaml
apiVersion: lightweightauth.io/v1alpha1
kind: AuthConfig
metadata:
  name: api-gateway
  namespace: production
spec:
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

  mutators:
    - name: strip-auth
      type: header-remove
      config:
        headers: [Authorization, Cookie]

    - name: identity-headers
      type: header-add
      config:
        upstream:
          X-User-ID: "${sub}"
          X-User-Email: "${claim:email}"
          X-User-Roles: "${claim:roles}"
          X-Tenant-ID: "${claim:tenant_id}"

    - name: internal-jwt
      type: jwt-issue
      config:
        algorithm: HS256
        key: "${INTERNAL_JWT_KEY}"
        issuer: lwauth-gateway
        audiences: [internal-services]
        expiry: 60s
        copyClaims: [sub, email, roles, tenant_id]
        header: X-Internal-Auth
        scheme: Bearer

    - name: passthrough
      type: header-passthrough
      config:
        headers: [X-Request-ID, Traceparent, Tracestate]
```

## 6. Helm wiring

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
      - name: rbac
        type: rbac
        config:
          rolesFrom: claim:roles
          allow: [user, admin]
    mutators:
      - name: strip-auth
        type: header-remove
        config:
          headers: [Authorization]
      - name: identity-headers
        type: header-add
        config:
          upstream:
            X-User-ID: "${sub}"
            X-User-Roles: "${claim:roles}"
      - name: internal-jwt
        type: jwt-issue
        config:
          algorithm: HS256
          key: "${INTERNAL_JWT_KEY}"
          issuer: lwauth-gateway
          audiences: [internal-services]
          expiry: 60s
          copyClaims: [sub, roles]
          header: X-Internal-Auth
          scheme: Bearer
env:
  - name: INTERNAL_JWT_KEY
    valueFrom:
      secretKeyRef:
        name: lwauth-internal-jwt
        key: signing-key
```

## 7. Validate

```bash
# Verify headers arrive at upstream
curl -v -H "Authorization: Bearer ${TOKEN}" https://gateway/api/whoami

# Upstream should see:
# X-User-ID: alice
# X-User-Roles: ["admin"]
# X-Internal-Auth: Bearer eyJ...
# (No Authorization header)

# Dry-run
lwauthctl explain --config api-gateway.yaml \
    --request '{"method":"GET","path":"/api/whoami","headers":{"authorization":"Bearer '${TOKEN}'"}}'
# identify   ✓  jwt      subject=alice
# authorize  ✓  rbac
# mutate     ✓  strip-auth        removed: [Authorization]
# mutate     ✓  identity-headers  added: X-User-ID=alice
# mutate     ✓  internal-jwt      issued: X-Internal-Auth (exp=60s)
```

## Security notes

- **Always strip raw credentials.** If the upstream doesn't need the
  original token, remove it. This limits blast radius if an upstream
  is compromised.
- **Short expiry on internal JWTs.** 60s or less. These are
  per-request — if they leak, the exposure window is tiny.
- **Rotate internal signing keys.** Use the same dual-key overlap
  pattern from [rotate-hmac](rotate-hmac.md).
- **Header trust boundary.** Envoy's `ext_authz` replaces upstream
  headers with lwauth's response — a malicious client cannot forge
  `X-User-ID` because Envoy overwrites it.

## Teardown

```bash
kubectl delete authconfig api-gateway -n production
kubectl delete secret lwauth-internal-jwt -n production
```
