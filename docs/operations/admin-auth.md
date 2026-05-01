# Admin-plane authentication and authorization

lwauth's admin plane protects operator endpoints —
`/v1/admin/status`, `/v1/admin/cache/invalidate`,
`/v1/admin/revoke`, `/v1/admin/audit` — with a single auth model so
every future admin feature inherits the same trust boundary.

## Authentication

Two mechanisms are supported (composed as OR — the first to succeed
wins):

| Method | How it works |
|--------|-------------|
| **Admin JWT** | A Bearer token in the `Authorization` header, verified against a dedicated JWKS endpoint with its own issuer and audience. Distinct from data-plane JWTs. |
| **mTLS** | The HTTP client presents a TLS client certificate. The middleware maps the certificate's Subject CN (or SAN DNS name) to an admin role. |

You can enable both simultaneously; the middleware tries JWT first,
then falls back to mTLS.

## Authorization (RBAC verbs)

After authentication, the middleware checks that the admin identity
holds the **verb** required by the endpoint. Verbs are coarse-grained
and endpoint-specific:

| Verb | Grants access to |
|------|-----------------|
| `read_status` | `GET /v1/admin/status` |
| `push_config` | (future) config promotion endpoints |
| `invalidate_cache` | `POST /v1/admin/cache/invalidate` |
| `revoke_token` | `POST /v1/admin/revoke` |
| `read_audit` | `GET /v1/admin/audit` |

Verbs are assigned via **roles**. A role is a named set of verbs.
Admin identities receive roles (via JWT claims or mTLS subject
mapping), and the middleware resolves roles to verbs.

## Configuration

Admin auth is configured via the `admin:` block in the lwauth config
or via `Options.Admin` when embedding:

```yaml
# config.yaml (file mode) or values.yaml inline
admin:
  enabled: true

  jwt:
    issuerUrl: https://idp.internal/admin
    audience: lwauth-admin
    jwksUrl: https://idp.internal/admin/.well-known/jwks.json
    rolesClaim: roles    # default; the JWT claim containing role(s)

  mtls:
    subjectMapping:
      # Certificate CN → role name
      admin-bot.lwauth-system.svc: superadmin
      sre-team-cert: operator

  roles:
    superadmin:
      - read_status
      - push_config
      - invalidate_cache
      - revoke_token
      - read_audit
    operator:
      - read_status
      - invalidate_cache
      - revoke_token
    readonly:
      - read_status
      - read_audit
```

### JWT configuration

| Field | Required | Description |
|-------|----------|-------------|
| `issuerUrl` | Yes | Expected `iss` claim value |
| `audience` | Yes | Expected `aud` claim value |
| `jwksUrl` | Yes | URL to fetch admin signing keys |
| `rolesClaim` | No | Claim name containing role(s). Default: `roles`. Value may be a string or `[]string`. |

### mTLS configuration

| Field | Required | Description |
|-------|----------|-------------|
| `subjectMapping` | Yes | Map of certificate CN (or SAN DNS) → role name |

The TLS listener itself must already require client certificates
(via `--tls-client-ca`). The admin middleware does not configure TLS;
it reads the verified peer certificate from the request's
`tls.ConnectionState`.

## Helm wiring

```yaml
# values.yaml
config:
  inline: |
    admin:
      enabled: true
      jwt:
        issuerUrl: https://idp.internal/admin
        audience: lwauth-admin
        jwksUrl: https://idp.internal/admin/.well-known/jwks.json
      mtls:
        subjectMapping:
          sre-cert.cluster.local: operator
      roles:
        operator: [read_status, invalidate_cache, revoke_token]
```

For a **dedicated admin listener** (separate port, separate mTLS CA):
this is not yet implemented but planned. Today admin endpoints share
the main HTTP listener. Operators who want network isolation should
use NetworkPolicy to restrict access to the lwauth pods' HTTP port
from admin sources only.

## CLI usage

`lwauthctl` does not yet talk to the admin API (that's C2 — GitOps
commands). When C2 ships, commands like `lwauthctl cache invalidate`
will authenticate to `/v1/admin/cache/invalidate` using a kubeconfig
token or a service account JWT.

## Endpoints

### `GET /v1/admin/status`

Returns engine and config status. Requires `read_status`.

```bash
curl -s --cert admin.pem --key admin-key.pem \
  https://lwauth.internal:8080/v1/admin/status
# {"status":"ok","admin":"sre-cert.cluster.local"}
```

### `POST /v1/admin/cache/invalidate`

Invalidates cached entries. Requires `invalidate_cache`.

```bash
curl -s -X POST --cert admin.pem --key admin-key.pem \
  -H 'Content-Type: application/json' \
  -d '{"scope":"tenant","tenant":"payments"}' \
  https://lwauth.internal:8080/v1/admin/cache/invalidate
# {"accepted":true,"scope":"tenant","tenant":"payments","subject":""}
```

### `POST /v1/admin/revoke`

Revokes a token or session. Requires `revoke_token`.
(Full implementation in Tier E2 — M14-REVOCATION.)

```bash
curl -s -X POST --cert admin.pem --key admin-key.pem \
  -H 'Content-Type: application/json' \
  -d '{"jti":"abc-123","tenant":"payments"}' \
  https://lwauth.internal:8080/v1/admin/revoke
# {"accepted":true,"note":"revocation store not yet implemented (Tier E2)"}
```

### `GET /v1/admin/audit`

Queries audit logs. Requires `read_audit`.
(Full implementation in Tier D4 — ENT-AUDIT-1.)

## Security considerations

- **Separate issuer/audience.** Admin JWTs must use a different
  issuer and audience than data-plane tokens. A data-plane JWT must
  never grant admin access.
- **Short-lived tokens.** Admin JWTs should have short expiry (5–15
  min). Use refresh tokens or re-auth for longer sessions.
- **Wildcard verb.** The special verb `*` grants all permissions.
  Use sparingly — only for break-glass automation.
- **Audit all admin actions.** Every admin request is logged at INFO
  level with the authenticated subject, verb, and path.

## References

- [DESIGN.md §7 Tier C](../DESIGN.md) — C3 (OPS-ADMIN-1) roadmap
  item.
- [`cache-invalidation` cookbook](../cookbook/cache-invalidation.md) —
  operational cache invalidation guide.
- [TLS configuration](../DEPLOYMENT.md) — `--tls-client-ca` for
  mTLS on the HTTP listener.
