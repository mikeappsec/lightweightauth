# pkg/identity/dpop

RFC 9449 DPoP (Demonstrating Proof of Possession) sender-constrained token identifier.

## Usage

```go
import (
    "context"
    _ "github.com/mikeappsec/lightweightauth/pkg/identity/dpop"
    "github.com/mikeappsec/lightweightauth/pkg/module"
)

identifier, err := module.BuildIdentifier("dpop", "dpop-jwt", map[string]any{
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
| `proofHeader` | string | `"DPoP"` | Header carrying the DPoP proof JWS |
| `bearerHeader` | string | `"Authorization"` | Header for `ath` computation |
| `inner` | object | *required* | Wrapped identifier spec (type + config) |
| `pinnedKeys` | []object | — | Optional server-side proof-key pinning with `notBefore`/`notAfter`/`gracePeriod` rotation lifecycle per key (see `pkg/identity/dpop/dpop.go` and `pkg/identity/dpop/rotatable.go`) — unlike the apikey/hmac/oauth2/introspection "rotatable" variants elsewhere in this codebase, this one **is** wired into the live factory |

The `jti` replay cache is not a per-identifier field — it's sized via
the top-level `caches:` block under the pool name `"replay"` (see
`docs/cookbook/dpop-sender-binding.md`).

## Features

- Full RFC 9449 §4.3 verification (typ, alg, jwk, htm, htu, iat, jti, cnf.jkt, ath)
- Wraps any inner identifier (JWT, introspection, etc.)
- LRU-based `jti` replay prevention with TTL
- Rejects symmetric algorithms and `none` in DPoP proofs
- Rejects private keys in the proof header (only public JWKs accepted)
- `X-Forwarded-Proto` aware for scheme comparison behind proxies
- `htu` comparison strips query from the request path for ext_authz compatibility (DPOP-VULN-02 fix)
- `cnf.jkt` is mandatory when `required: true` and a bearer token is present — prevents token replay with any key (DPOP-VULN-01 fix)
- Optional mode: missing DPoP header falls through to inner identifier when `required: false`

## How It Works

1. Extracts the DPoP proof JWS from the configured header.
2. Validates proof structure: `typ=dpop+jwt`, asymmetric `alg`, embedded public `jwk`.
3. Verifies JWS signature under the embedded JWK.
4. Validates payload claims: `htm` matches method, `htu` matches URL (path only, query stripped), `iat` within ±skew.
5. Checks `jti` uniqueness against the replay cache.
6. Delegates to the inner identifier (e.g., JWT validation).
7. Enforces proof-of-possession binding:
   - `cnf.jkt` (RFC 7638 thumbprint) **must** match the proof JWK — mandatory when `required: true` and a bearer token is present (DPOP-VULN-01 fix).
   - `ath` **must** equal `base64url(sha256(access_token))` when an access token is present.
