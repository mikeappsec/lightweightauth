# pkg/identity/hmac

AWS-SigV4-style HMAC request signing identifier.

## Usage

```go
import (
    "context"
    _ "github.com/mikeappsec/lightweightauth/pkg/identity/hmac"
    "github.com/mikeappsec/lightweightauth/pkg/module"
)

identifier, err := module.BuildIdentifier("hmac-auth", "hmac", map[string]any{
    "keys": map[string]any{
        "service-a": map[string]any{
            "secret":  "base64-encoded-secret",
            "subject": "service-a",
        },
    },
})
```

## Configuration

```yaml
identifiers:
  - name: hmac-auth
    type: hmac
    config:
      header: "Authorization"
      scheme: "HMAC-SHA256"
      dateHeader: "Date"
      clockSkew: "5m"
      requiredSignedHeaders: ["host", "date"]
      keys:
        service-a:
          secret: "base64-encoded-secret"
          subject: "service-a"
          roles: ["reader"]
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `header` | string | `"Authorization"` | Header containing HMAC signature |
| `scheme` | string | `"HMAC-SHA256"` | Authorization scheme prefix |
| `dateHeader` | string | `"Date"` | Header for clock-skew enforcement |
| `clockSkew` | duration | `5m` | Allowed clock drift |
| `requiredSignedHeaders` | []string | `["host", "date"]` | Headers the signer MUST include |
| `keys` | map | *required* | Named HMAC keys with secrets + identity |

## Features

- Constant-time signature comparison via `subtle.ConstantTimeCompare`
- Clock-skew-based replay protection via `Date` header
- Configurable required signed headers (prevents header-stripping attacks)
- Canonical request format with deterministic query param ordering
- Key rotation via `keyrotation.KeySet[KeyEntry]`
- Body hashing (SHA-256) included in canonical request

## Authorization Header Format

```
Authorization: HMAC-SHA256 keyId="abc", signedHeaders="date;host;content-type", signature="<base64>"
```

## How It Works

1. Parses the authorization header for `keyId`, `signedHeaders`, and `signature`.
2. Validates that all `requiredSignedHeaders` are included in the signed set.
3. Checks the `Date` header is within `clockSkew` of current time (replay protection).
4. Builds a canonical request string: method, host, path, sorted query, signed header values, body hash.
5. Computes `HMAC-SHA256(key.secret, canonicalRequest)` and compares to provided signature.
6. On match, returns identity with the key's subject and configured roles/claims.
