# `session` — AES-256-GCM cookie store

Stateless encrypted-cookie store used by the `oauth2` identifier (M3) to
persist OAuth login state across the redirect-back round trip and to
hold a refreshed access token for browser-facing flows. Cookies are
sealed with AEAD (AES-256-GCM), so integrity, confidentiality, and
binding-to-key are all enforced by a single tag.

**Source:** [pkg/session](https://github.com/mikeappsec/lightweightauth/blob/main/pkg/session/cookie.go) — used internally by `pkg/identity/oauth2`.

## When to use

- Browser-facing OAuth 2.0 Authorization Code + PKCE.
- Any flow where the IdP redirects back to lwauth and you need to
  resume the original request without server-side state.

**Don't use** for tokens that must be revocable independently of the
cookie lifetime — use Valkey ([modules/cache-valkey.md](cache-valkey.md))
for revocation-bearing storage.

## Configuration

`session` is configured under `oauth2.cookie:` (not `session:` —
that key doesn't exist; `pkg/identity/oauth2/config.go`'s
`knownKeys` only recognizes `cookie`, and using `session:` fails
config validation with `unknown config key(s): session`). It's the
OAuth2 identifier's storage, not a pipeline stage. There is also no
`{ fromEnv: ... }` structured-secret syntax anywhere in this
codebase — `clientSecret`/`cookie.secret` are plain strings; use a
literal value your deployment pipeline substitutes, or a real
`secretRef: vault://...` reference for fields that support secret
resolution (see [pkg/secrets](https://github.com/mikeappsec/lightweightauth/blob/main/pkg/secrets/secrets.go)).
`{ fromEnv: X }` as a YAML mapping fails the `.(string)` type
assertion silently, leaving the field empty:

```yaml
identifiers:
  - name: web
    type: oauth2
    config:
      issuerUrl: https://idp.example.com
      clientId:  web-app
      clientSecret: "${OAUTH_CLIENT_SECRET}"
      redirectUrl: https://app.example.com/oauth2/callback
      scopes: [openid, profile, email]

      cookie:
        # Cookie name. Default: _lwauth_session
        name: _lwauth_session
        # AES-256 key is SHA-256(secret); ≥32 bytes random recommended.
        secret: "${SESSION_SECRET}"
        path: /
        domain: app.example.com           # optional
        secure: true                       # bool; unset defaults per session.CookieStoreConfig
        sameSite: Lax                      # Lax | Strict | None
        httpOnly: true                     # bool
        maxAge: 8h                         # default 8h — NOT "ttl"
        # There is no cookieMaxBytes here — oauth2.CookieConfig doesn't
        # expose it, even though the underlying session.CookieStoreConfig
        # supports it (default 3500, hard-coded when the oauth2 module
        # builds its cookie store).
```

## Helm wiring

```yaml
# values.yaml
config:
  inline: |
    identifiers:
      - name: web
        type: oauth2
        config:
          issuerUrl: https://idp.example.com
          clientId:  web-app
          clientSecret: "${OAUTH_CLIENT_SECRET}"
          redirectUrl: https://app.example.com/oauth2/callback
          cookie:
            secret: "${SESSION_SECRET}"
```

## Wire format

```text
cookie value = base64url( nonce(12) || ciphertext || tag(16) )
plaintext    = JSON-encoded session.Session
```

- 12-byte nonce is fresh `crypto/rand` per `Save` (never reused).
- AEAD tag detects tampering — any modification fails decryption.
  `pkg/session/cookie.go` doesn't import `pkg/module` and returns a
  plain `fmt.Errorf("session: cookie auth failed: %w", err)`, not a
  module sentinel error. The `oauth2` identifier discards this error
  and just falls through to `module.ErrNoMatch` when no session is
  found (`Identify` in `pkg/identity/oauth2/oauth2.go`).

## Operational notes

- **Rotation.** Bump the secret to invalidate every outstanding
  cookie at once (forced re-login). For graceful rotation, run two
  lwauth replicas with `secret_v2` accepted and `secret_v1` decommissioned
  after `maxAge` elapses (planned, see [DESIGN.md](../DESIGN.md) M14).
- **Size.** Browsers cap cookies near 4 KiB. `session.CookieStoreConfig.CookieMaxBytes`
  (default 3500, not overridable through the `oauth2` module's
  `cookie:` block) is a hard fail — an encoded cookie over the limit
  returns an error rather than being silently truncated, so
  deployments swap to a server-side store when sessions outgrow the
  cookie.
- **Cross-origin.** Set `sameSite: None` + `secure: true` if the lwauth
  callback is served from a different origin than the protected app.

## References

- DESIGN: [DESIGN.md §M3](../DESIGN.md), [DESIGN.md §M11](../DESIGN.md).
- Cryptography review: [security/v1.0-review.md §1](../security/v1.0-review.md).
- Source: [pkg/session/cookie.go](https://github.com/mikeappsec/lightweightauth/blob/main/pkg/session/cookie.go).
