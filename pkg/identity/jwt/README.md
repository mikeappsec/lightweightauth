# pkg/identity/jwt

JWT/OIDC bearer token identifier for LightweightAuth.

## Usage

```go
import (
    "context"
    _ "github.com/mikeappsec/lightweightauth/pkg/identity/jwt"
    "github.com/mikeappsec/lightweightauth/pkg/module"
)

identifier, err := module.BuildIdentifier("my-jwt", "jwt", map[string]any{
    "jwksUrl":  "https://idp.example.com/.well-known/jwks.json",
    "issuerUrl": "https://idp.example.com",
    "audiences": []string{"my-api"},
})
if err != nil {
    log.Fatal(err)
}

identity, err := identifier.Identify(ctx, req)
```

## Configuration

```yaml
identifiers:
  - name: my-jwt
    type: jwt
    config:
      jwksUrl: "https://idp.example.com/.well-known/jwks.json"
      issuerUrl: "https://idp.example.com"
      audiences: ["my-api"]
      header: "Authorization"
      scheme: "Bearer"
      minRefreshInterval: "15m"
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `jwksUrl` | string | *required* | JWKS endpoint URL |
| `issuerUrl` | string | `""` | Optional pinned `iss` claim |
| `audiences` | []string | `nil` | Audience match (any-match) |
| `header` | string | `"Authorization"` | Request header to read |
| `scheme` | string | `"Bearer"` | Token scheme prefix |
| `minRefreshInterval` | duration | `15m` | Bounds kid-miss re-fetch frequency |

## Features

- JWKS auto-refresh with background polling via `lestrrat-go/jwx/v2`
- Force-refresh on kid miss (throttled by `minRefreshInterval`)
- Standard claim enforcement: `exp`, `nbf`, `iat`
- Optional `iss` pinning and `aud` validation (any-of-match)
- Revocation key derivation from `jti` and subject
- Chain-of-responsibility: returns `ErrNoMatch` when no bearer header present

## How It Works

1. Extracts bearer token from the configured header (`Authorization: Bearer <token>`).
2. Parses the JWT header to find the `kid` (key ID).
3. Looks up the signing key from the cached JWKS set; triggers force-refresh on kid miss.
4. Validates signature, `exp`, `nbf`, `iat`, optional `iss`, and optional `aud`.
5. Returns `module.Identity` with subject from `sub` claim and full claims map.
6. Registers itself as `"jwt"` via `module.RegisterIdentifier` in `init()`.
