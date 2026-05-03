# pkg/mutator/jwtissue

Internal JWT minting mutator for upstream service authentication.

## Usage

```go
import (
    "context"
    _ "github.com/mikeappsec/lightweightauth/pkg/mutator/jwtissue"
    "github.com/mikeappsec/lightweightauth/pkg/module"
)

mutator, err := module.BuildMutator("mint-internal", "jwt-issue", map[string]any{
    "issuer":   "lwauth",
    "audience": "backend-api",
    "ttl":      "60s",
    "algorithm": "HS256",
    "key":      "hex:0123456789abcdef0123456789abcdef",
    "header":   "Authorization",
    "scheme":   "Bearer",
    "copyClaims": []string{"email", "role"},
})
```

## Configuration

```yaml
mutators:
  - name: mint-internal
    type: jwt-issue
    config:
      issuer: "lwauth"
      audience: "backend-api"
      ttl: "60s"
      algorithm: "HS256"
      key: "hex:0123456789abcdef0123456789abcdef"
      header: "Authorization"
      scheme: "Bearer"
      copyClaims:
        - email
        - role
        - tenant_id
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `issuer` | string | *required* | JWT `iss` claim |
| `audience` | string | *required* | JWT `aud` claim |
| `ttl` | duration | `"60s"` | Token lifetime |
| `algorithm` | string | `"HS256"` | Signing algorithm (HS256/384/512, RS256/384/512) |
| `key` | string | *required for HS\** | Symmetric key (supports `hex:<bytes>` prefix) |
| `privateKeyFile` | string | *required for RS\** | PEM file path (PKCS#1 or PKCS#8 RSA) |
| `header` | string | `"Authorization"` | Header name for the minted token |
| `scheme` | string | `"Bearer"` | Prefix before the token value |
| `copyClaims` | []string | `[]` | Claims to copy from identity into minted JWT |

## Features

- Mints uniform internal JWTs regardless of original authentication method
- Standard claims set: `iss`, `aud`, `sub`, `iat`, `nbf`, `exp`
- Selective claim propagation via `copyClaims`
- Supports both symmetric (HMAC) and asymmetric (RSA) signing
- Hex-encoded or raw symmetric key input
- No-ops silently if identity is nil or subject is empty
- Uses `lestrrat-go/jwx/v2` for JWT construction and signing

## How It Works

1. Checks that the identity has a non-empty subject (no-ops otherwise).
2. Builds JWT claims: `iss`, `aud`, `sub` from identity, `iat`/`nbf` = now, `exp` = now + TTL.
3. Copies any listed claims from `Identity.Claims` into the token.
4. Signs the token with the configured algorithm and key material.
5. Sets the signed token in `Decision.UpstreamHeaders` as `{header}: {scheme} {token}`.
