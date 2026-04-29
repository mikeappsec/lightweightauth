# `jwt` — Self-contained signed bearer tokens

Verifies JWT bearers (OIDC ID tokens, OAuth 2.0 self-contained access
tokens) using a JWKS endpoint. The cheapest identifier on the hot path
because verification is a single signature check against an in-memory
keyset.

**Source:** [pkg/identity/jwt](https://github.com/mikeappsec/lightweightauth/blob/main/pkg/identity/jwt/jwt.go) — registered as `jwt`.

## When to use

- IdP issues signed JWTs (Keycloak, Auth0, Okta, Azure AD, Cognito).
- You want stateless verification (no per-request IdP round-trip).
- The token has a JWKS URI you can reach.

**Don't use** for opaque tokens — reach for [`oauth2-introspection`](oauth2-introspection.md) instead.

## Configuration

```yaml
identifiers:
  - name: bearer
    type: jwt
    config:
      # REQUIRED: one of these. issuerUrl auto-discovers JWKS via
      # /.well-known/openid-configuration.
      jwksUrl:   https://idp.example.com/.well-known/jwks.json
      # issuerUrl: https://idp.example.com

      audiences:                  # optional; verify `aud` claim
        - my-api
        - my-api.internal

      header: Authorization       # default
      scheme: Bearer              # default; "" to accept raw token

      # JWKS rotation: the keyset is fetched lazily on first kid miss,
      # but never more often than minRefreshInterval (default 5m). The
      # cache itself never expires — keys disappear when the IdP rotates.
      minRefreshInterval: 5m
```

Verifies (in order): signature against JWKS → `aud` (if configured) →
`exp` / `nbf` with default 0s leeway. Failed checks return `module.ErrNoMatch`
so the next identifier is tried.

## Helm wiring

File mode (default chart):

```yaml
# values.yaml
config:
  inline: |
    identifiers:
      - name: bearer
        type: jwt
        config:
          jwksUrl: https://idp.example.com/.well-known/jwks.json
          audiences: ["my-api"]
    authorizers:
      - { name: gate, type: rbac, config: { rolesFrom: "claim:roles", allow: ["admin"] } }
```

CRD mode adds nothing extra — the same YAML lives under
`spec.identifiers` of an `AuthConfig` CR.

## Worked example

```http
GET /things HTTP/1.1
Authorization: Bearer eyJhbGciOiJSUzI1NiIs...
```

After identification: `Identity{Subject: "alice", Source: "bearer", Claims: {sub, aud, roles, exp, ...}}`.
Subsequent authorizers (`rbac`, `cel`, `opa`) read `Identity.Claims` to
decide.

## Composition

- Pair with [`dpop`](dpop.md) (`dpop.inner.type: jwt`) for sender-constrained bearers.
- Pair with [`mtls`](mtls.md) under `firstMatch` so service-to-service
  callers without a JWT fall through to mutual TLS.
- Use [`jwt-issue`](jwt-issue.md) on the response side to mint a *fresh*
  internal JWT for the upstream — keeps user-facing tokens out of
  east-west traffic.

## References

- RFC 7519 (JWT), RFC 7517 (JWKS), RFC 7515 (JWS).
- [DESIGN.md §4](../DESIGN.md) — identity & credential modules.
- Source: [pkg/identity/jwt/jwt.go](https://github.com/mikeappsec/lightweightauth/blob/main/pkg/identity/jwt/jwt.go).
