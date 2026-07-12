# pkg/identity/scim

SCIM 2.0 provisioning callback identifier module (G9 — ID-SAML-1).

## Usage

```go
import (
    "context"
    _ "github.com/mikeappsec/lightweightauth/pkg/identity/scim"
    "github.com/mikeappsec/lightweightauth/pkg/module"
)

id, err := module.BuildIdentifier("scim", "scim-provisioning", map[string]any{
    "bearerToken":  "secret-provisioning-token",
    "subjectClaim": "userName",
    "groupsClaim":  "groups",
})
```

## Configuration

```yaml
identifiers:
  - name: scim-provisioning
    type: scim
    config:
      bearerToken: "secret-provisioning-token"
      header: Authorization
      scheme: Bearer
      subjectClaim: userName
      groupsClaim: groups
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `bearerToken` | string | *required* | Shared secret token the IdP uses to authenticate provisioning requests |
| `header` | string | `"Authorization"` | HTTP header containing the token |
| `scheme` | string | `"Bearer"` | Authentication scheme prefix (e.g. `Bearer`) |
| `subjectClaim` | string | `"userName"` | JSON field in the SCIM body to extract as subject |
| `groupsClaim` | string | `"groups"` | JSON field in the SCIM body to extract as groups claim |
| `subjectPrefix` | string | `"scim:"` | Prepended to the extracted subject (SCIM-VULN-02) — set to `""` to opt out (not recommended) |

## Features

- Bearer token validation with constant-time comparison (G9-VULN-10)
- Token stored as SHA-256 hash — plaintext never held in memory after construction
- SCIM user identity extraction from JSON request body
- Extracts: userName, groups, schemas, id, displayName, active status
- Request body size limit of 1 MiB to prevent memory exhaustion (G9-VULN-05)
- Case-insensitive scheme matching
- Falls back to `"scim-provisioner"` subject when body has no user identity

## How It Works

1. Reads the bearer token from the configured header (default: `Authorization: Bearer <token>`).
2. Computes SHA-256 hash of the presented token.
3. Constant-time compares the hash against the stored hash — rejects on mismatch.
4. If the request body is present and within the size limit, parses it as JSON.
5. Extracts the subject from the configured `subjectClaim` field
   (default: `userName`) and prepends `subjectPrefix` (default
   `"scim:"`) — so by default the resulting subject is namespaced,
   e.g. `scim:alice`, not the raw claim value.
6. Extracts groups, SCIM schemas, display name, and active status into claims.
7. Returns an `Identity` with the extracted subject and claims.

## Thread Safety

| Type | Safe for concurrent use? | Notes |
|------|--------------------------|-------|
| `Identifier` | ✅ Yes | All fields immutable after construction; no shared mutable state |

The `Identifier` is safe for concurrent use from the pipeline hot path. The `tokenHash` field is a fixed-size array set once at construction. Each `Identify` call operates on its own stack-local variables with no shared state.
