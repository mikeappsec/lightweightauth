# `session` — AES-256-GCM cookie store

Stateless encrypted-cookie store used by the `oauth2` identifier (M3) to
persist OAuth login state across the redirect-back round trip and to
hold a refreshed access token for browser-facing flows. Cookies are
sealed with AEAD (AES-256-GCM), so integrity, confidentiality, and
binding-to-key are all enforced by a single tag.

**Source:** [pkg/session](../../pkg/session/cookie.go) — used internally by `pkg/identity/oauth2`.

## When to use

- Browser-facing OAuth 2.0 Authorization Code + PKCE.
- Any flow where the IdP redirects back to lwauth and you need to
  resume the original request without server-side state.

**Don't use** for tokens that must be revocable independently of the
cookie lifetime — use Valkey ([modules/cache-valkey.md](cache-valkey.md))
for revocation-bearing storage.

## Configuration

`session` is configured under `oauth2.session:` rather than as a
top-level module (it is the OAuth2 identifier's storage, not a
pipeline stage):

```yaml
identifiers:
  - name: web
    type: oauth2
    config:
      issuerUrl: https://idp.example.com
      clientId:  web-app
      clientSecret: { fromEnv: OAUTH_CLIENT_SECRET }
      redirectUrl: https://app.example.com/callback
      scopes: [openid, profile, email]

      session:
        # Cookie name. Default: _lwauth_session
        name: _lwauth_session
        # AES-256 key is SHA-256(secret); ≥32 bytes random recommended.
        secret: { fromEnv: SESSION_SECRET }
        path: /
        domain: app.example.com           # optional
        secure: true                       # default true; false only for local-dev plaintext
        sameSite: Lax                      # Lax | Strict | None
        httpOnly: true                     # default true
        maxAge: 8h                         # default 8h
        cookieMaxBytes: 3500               # default 3500; hard fail above to dodge browser 4KB limit
```

## Helm wiring

```yaml
# values.yaml
secrets:
  sessionSecret: ""                     # rendered into a K8s Secret if non-empty
config:
  inline: |
    identifiers:
      - name: web
        type: oauth2
        config:
          issuerUrl: https://idp.example.com
          clientId:  web-app
          clientSecret: { fromEnv: OAUTH_CLIENT_SECRET }
          redirectUrl: https://app.example.com/callback
          session:
            secret: { fromEnv: SESSION_SECRET }
```

## Wire format

```text
cookie value = base64url( nonce(12) || ciphertext || tag(16) )
plaintext    = JSON-encoded session.Session
```

- 12-byte nonce is fresh `crypto/rand` per `Save` (never reused).
- AEAD tag detects tampering — any modification fails decryption and
  returns `module.ErrCredentialInvalid`.

## Operational notes

- **Rotation.** Bump the secret to invalidate every outstanding
  cookie at once (forced re-login). For graceful rotation, run two
  lwauth replicas with `secret_v2` accepted and `secret_v1` decommissioned
  after `maxAge` elapses (planned, see [DESIGN.md](../DESIGN.md) M14).
- **Size.** Browsers cap cookies near 4 KiB. `cookieMaxBytes` (default
  3500) is a hard fail — the OAuth2 module surfaces a clear error
  rather than silently truncating, so deployments swap to a server-side
  store when sessions outgrow the cookie.
- **Cross-origin.** Set `sameSite: None` + `secure: true` if the lwauth
  callback is served from a different origin than the protected app.

## References

- DESIGN: [DESIGN.md §M3](../DESIGN.md), [DESIGN.md §M11](../DESIGN.md).
- Cryptography review: [security/v1.0-review.md §1](../security/v1.0-review.md).
- Source: [pkg/session/cookie.go](../../pkg/session/cookie.go).
