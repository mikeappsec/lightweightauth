# pkg/identity/oauth2

Authorization-code + PKCE flow identifier with encrypted session management.

## Usage

```go
import (
    "context"
    _ "github.com/mikeappsec/lightweightauth/pkg/identity/oauth2"
    "github.com/mikeappsec/lightweightauth/pkg/module"
)

identifier, err := module.BuildIdentifier("my-oidc", "oauth2", map[string]any{
    "clientId":    "my-app",
    "clientSecret": "secret",
    "authUrl":     "https://idp.example.com/authorize",
    "tokenUrl":    "https://idp.example.com/token",
    "jwksUrl":     "https://idp.example.com/.well-known/jwks.json",
    "redirectUrl": "https://my-app.example.com/oauth2/callback",
    "cookie": map[string]any{
        "secret": "hex-encoded-32-byte-key",
    },
})
```

## Configuration

```yaml
identifiers:
  - name: my-oidc
    type: oauth2
    config:
      clientId: "my-app"
      clientSecret: "secret"
      authUrl: "https://idp.example.com/authorize"
      tokenUrl: "https://idp.example.com/token"
      jwksUrl: "https://idp.example.com/.well-known/jwks.json"
      redirectUrl: "https://my-app.example.com/oauth2/callback"
      scopes: ["openid", "profile", "email"]
      mountPrefix: "/oauth2/"
      postLoginPath: "/"
      postLogoutPath: "/"
      allowedRedirectHosts: ["my-app.example.com"]
      cookie:
        name: "_lwauth_session"
        secret: "hex-encoded-32-byte-key"
        maxAge: "8h"
        secure: true
        sameSite: "lax"
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `clientId` | string | *required* | OAuth2 client ID |
| `clientSecret` | string | `""` | Client secret (rotatable) |
| `authUrl` | string | *required* | IdP authorize endpoint |
| `tokenUrl` | string | *required* | IdP token endpoint |
| `jwksUrl` | string | *required* | JWKS for id_token verification |
| `issuerUrl` | string | `""` | Optional pinned issuer |
| `scopes` | []string | `nil` | OAuth2 scopes |
| `redirectUrl` | string | *required* | Callback URL |
| `mountPrefix` | string | `"/oauth2/"` | HTTP mount prefix |
| `postLoginPath` | string | `"/"` | Default post-login redirect |
| `postLogoutPath` | string | `"/"` | Default post-logout redirect |
| `endSessionUrl` | string | `""` | RP-Initiated Logout endpoint |
| `deviceAuthUrl` | string | `""` | RFC 8628 device auth endpoint |
| `refreshLeeway` | duration | `""` | Proactive refresh window |
| `allowedRedirectHosts` | []string | `nil` | Open-redirect defense allow-list |
| `cookie.name` | string | `"_lwauth_session"` | Session cookie name |
| `cookie.secret` | string | *required* | Encryption key (hex 32+ bytes) |
| `cookie.maxAge` | duration | `"8h"` | Session lifetime |
| `cookie.secure` | bool | `false` | Secure flag |
| `cookie.sameSite` | string | `"lax"` | SameSite attribute |

## Features

- PKCE mandatory (S256) for all authorization-code flows
- Encrypted stateless session cookies (AES-256-GCM)
- Open-redirect prevention via `allowedRedirectHosts`
- RFC 8628 Device Authorization Grant support
- Client-secret rotation via `keyrotation.KeySet`
- RP-Initiated Logout (OpenID Connect RP-Initiated Logout 1.0)
- Proactive token refresh endpoint

## HTTP Endpoints

| Path | Description |
|------|-------------|
| `/oauth2/start?rd=` | Begins PKCE auth-code flow |
| `/oauth2/callback` | Handles IdP redirect + token exchange |
| `/oauth2/logout` | Clears session |
| `/oauth2/userinfo` | Returns current session as JSON |
| `/oauth2/refresh` | Proactive token refresh |
| `/oauth2/device/start` | Device authorization (RFC 8628) |
| `/oauth2/device/poll` | Polls device-code token exchange |

## How It Works

1. On unauthenticated request, returns 401 with login-hint URL.
2. `/start` generates PKCE code verifier + state, stores in encrypted flow cookie, redirects to IdP.
3. `/callback` validates state, exchanges code for tokens, verifies id_token signature via JWKS, mints session cookie.
4. Subsequent requests: decrypts session cookie, checks expiry, returns identity.
5. `safeRedirect()` rejects `//`, `\`, and non-allowlisted hosts to prevent open-redirect attacks.
