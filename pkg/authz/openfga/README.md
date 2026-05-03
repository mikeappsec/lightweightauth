# pkg/authz/openfga

OpenFGA Zanzibar-style ReBAC authorizer.

## Usage

```go
import (
    "context"
    _ "github.com/mikeappsec/lightweightauth/pkg/authz/openfga"
    "github.com/mikeappsec/lightweightauth/pkg/module"
)

authorizer, err := module.BuildAuthorizer("fga", "openfga", map[string]any{
    "apiUrl":  "http://openfga:8080",
    "storeId": "01HXYZ...",
    "check": map[string]any{
        "user":     "user:{{.Identity.Subject}}",
        "relation": "{{.Request.Method | lower}}",
        "object":   "endpoint:{{.Request.Path}}",
    },
})
```

## Configuration

```yaml
authorizers:
  - name: fga
    type: openfga
    config:
      apiUrl: "http://openfga:8080"
      storeId: "01HXYZ..."
      authorizationModelId: ""
      timeout: "2s"
      apiToken: ""
      check:
        user: "user:{{.Identity.Subject}}"
        relation: "{{.Request.Method | lower}}"
        object: "endpoint:{{.Request.Path}}"
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `apiUrl` | string | *required* | OpenFGA service URL |
| `storeId` | string | *required* | OpenFGA store ID |
| `authorizationModelId` | string | `""` (latest) | Pin to model version |
| `timeout` | duration | `"2s"` | HTTP call timeout |
| `apiToken` | string | `""` | Optional Bearer token |
| `check.user` | template | *required* | User tuple field |
| `check.relation` | template | *required* | Relation tuple field |
| `check.object` | template | *required* | Object tuple field |

## Template Functions

| Function | Description |
|----------|-------------|
| `lower` | Lowercase |
| `upper` | Uppercase |

## Template Variables

- `.Identity` — subject, claims, source
- `.Request` — method, host, path, pathParts, tenantId, headers

## Features

- Go template-based tuple mapping for flexible schema adaptation
- Circuit breaker via `upstream.Guard` for OpenFGA resilience
- Response body capped at 64 KiB (prevents memory exhaustion)
- Empty rendered tuple fields → immediate 403 (no network call)
- Composable under `composite` authorizer

## How It Works

1. Renders user/relation/object strings from Go templates using identity and request data.
2. POSTs a `Check` request to `{apiUrl}/stores/{storeId}/check`.
3. If `allowed: true` → allow; `allowed: false` → deny (403).
4. Network failures handled by circuit breaker → 503.
