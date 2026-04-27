# `oauth2` — Authorization Code + PKCE + sessions

Implements the OAuth 2.0 / OIDC Authorization Code Flow (RFC 6749 §4.1)
with PKCE (RFC 7636), encrypted-cookie sessions, refresh-token rotation,
and the Device Authorization Grant (RFC 8628). Mounts the `/oauth2/*`
HTTP routes lwauth needs to act as an OIDC Relying Party.

**Source:** [pkg/identity/oauth2](../../pkg/identity/oauth2/oauth2.go) — registered as `oauth2`.

## When to use

- Browser-facing apps: lwauth in front of a webapp acts as the OIDC RP.
- CLI / TV / IoT clients via Device Authorization Grant.
- You want logout, refresh rotation, and userinfo built in.

**Don't use** for service-to-service. Use [`jwt`](jwt.md) +
[`pkg/clientauth`](../../pkg/clientauth) instead.

## Configuration

```yaml
identifiers:
  - name: web-login
    type: oauth2
    config:
      issuerUrl:    https://idp.example.com
      clientId:     webapp
      clientSecret: ${OIDC_SECRET}
      redirectUrl:  https://app.example.com/oauth2/callback
      scopes: ["openid", "email", "profile", "offline_access"]

      # Optional: enables /oauth2/device/{start,poll}
      deviceAuthUrl: https://idp.example.com/oauth2/device

      # Encrypted-cookie session store (default).
      cookie:
        name:   lwauth_session
        domain: app.example.com
        secret: ${SESSION_SECRET}    # 32 bytes, base64 or hex
        secure: true
        sameSite: lax
        ttl:    8h
        refreshLeeway: 60s           # opportunistic RT refresh window

      # Optional RP-Initiated Logout (OIDC RP-Initiated Logout 1.0).
      endSessionUrl:        https://idp.example.com/oauth2/logout
      postLogoutRedirectUrl: https://app.example.com/
```

Mounts under the lwauth HTTP server:

| Path | Purpose |
|---|---|
| `/oauth2/start` | Begin auth-code flow (PKCE, state set as cookie). |
| `/oauth2/callback` | Exchange code for tokens, mint session cookie. |
| `/oauth2/userinfo` | Returns `{sub, email, accessTokenExpiry}`; opportunistically refreshes. |
| `/oauth2/refresh` | Explicit refresh-token rotation (RFC 6749 §6). |
| `/oauth2/logout` | Clears session + RP-initiated logout if `endSessionUrl` set. |
| `/oauth2/device/start` | Device Authorization Grant request (M6.5). |
| `/oauth2/device/poll` | Polls IdP `/token` until success / `expired_token`. |

## Helm wiring

The `/oauth2/*` routes need to be reachable from the browser. Either:

- **In Mode A (sidecar):** point Envoy's auth_action at `/oauth2/*` to bypass `ext_authz`.
- **In Mode B (proxy, sibling repo):** the proxy mounts these directly.

```yaml
# values.yaml — Mode A snippet
config:
  inline: |
    identifiers:
      - name: web-login
        type: oauth2
        config: { issuerUrl: https://idp.example.com, ... }
    authorizers:
      - { name: any, type: rbac, config: { allow: ["*"] } }
extraEnv:
  - name: SESSION_SECRET
    valueFrom: { secretKeyRef: { name: lwauth-secrets, key: session } }
  - name: OIDC_SECRET
    valueFrom: { secretKeyRef: { name: lwauth-secrets, key: oidc } }
```

## Worked example (Auth Code + PKCE)

1. Browser → `GET /protected`. No cookie → identifier returns `ErrNoMatch`. Pipeline 302s to `/oauth2/start`.
2. `GET /oauth2/start` → 302 to `https://idp.example.com/authorize?...&code_challenge=...&state=...`.
3. User authenticates; IdP 302s to `/oauth2/callback?code=...&state=...`.
4. lwauth exchanges code → tokens, validates `id_token` against JWKS (audience = clientId), encrypts and stores `{access_token, refresh_token, id_token, exp}` in a cookie.
5. Subsequent requests carry the cookie; identifier decrypts → `Identity{Subject: id_token.sub, Claims: id_token}`.

## Composition

- `firstMatch` with [`jwt`](jwt.md): API clients send Bearer; browsers
  fall through to OAuth2 cookie.
- Pair with [`composite`](composite.md) `anyOf: [rbac, openfga]` for the
  authorize step.
- Switch the cookie store for `MemoryStore` (M6) when you need
  server-side opaque-SID sessions instead of cookie payloads.

## References

- RFC 6749 §4.1, RFC 7636 (PKCE), RFC 8628 (Device Authorization).
- OIDC Core 1.0, OIDC RP-Initiated Logout 1.0.
- Source: [pkg/identity/oauth2/oauth2.go](../../pkg/identity/oauth2/oauth2.go).
