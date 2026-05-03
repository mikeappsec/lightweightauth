# pkg/identity/dpop

RFC 9449 DPoP (Demonstrating Proof of Possession) sender-constrained token identifier.

## Usage

```go
import (
    "context"
    _ "github.com/mikeappsec/lightweightauth/pkg/identity/dpop"
    "github.com/mikeappsec/lightweightauth/pkg/module"
)

identifier, err := module.BuildIdentifier("dpop-jwt", "dpop", map[string]any{
    "required": true,
    "skew":     "30s",
    "inner": map[string]any{
        "type": "jwt",
        "config": map[string]any{
            "jwksUrl": "https://idp.example.com/.well-known/jwks.json",
        },
    },
})
```

## Configuration

```yaml
identifiers:
  - name: dpop-jwt
    type: dpop
    config:
      required: true
      skew: "30s"
      replayCacheSize: 10000
      proofHeader: "DPoP"
      inner:
        type: jwt
        config:
          jwksUrl: "https://idp.example.com/.well-known/jwks.json"
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `required` | bool | `true` | Whether DPoP proof is mandatory |
| `skew` | duration | `30s` | Allowed clock drift on `iat` |
| `replayCacheSize` | int | `10000` | LRU entries for jti replay prevention |
| `proofHeader` | string | `"DPoP"` | Header carrying the DPoP proof JWS |
| `bearerHeader` | string | `"Authorization"` | Header for `ath` computation |
| `inner` | object | *required* | Wrapped identifier spec (type + config) |

## Features

- Full RFC 9449 §4.3 verification (typ, alg, jwk, htm, htu, iat, jti, cnf.jkt, ath)
- Wraps any inner identifier (JWT, introspection, etc.)
- LRU-based `jti` replay prevention with TTL
- Rejects symmetric algorithms and `none` in DPoP proofs
- Rejects private keys in the proof header (only public JWKs accepted)
- `X-Forwarded-Proto` aware for scheme comparison behind proxies
- Optional mode: missing DPoP header falls through to inner identifier when `required: false`

## How It Works

1. Extracts the DPoP proof JWS from the configured header.
2. Validates proof structure: `typ=dpop+jwt`, asymmetric `alg`, embedded public `jwk`.
3. Verifies JWS signature under the embedded JWK.
4. Validates payload claims: `htm` matches method, `htu` matches URL, `iat` within ±skew.
5. Checks `jti` uniqueness against the replay cache.
6. Delegates to the inner identifier (e.g., JWT validation).
7. Binds proof to token: `cnf.jkt` (RFC 7638 thumbprint) must match, `ath` must equal `base64url(sha256(access_token))`.
