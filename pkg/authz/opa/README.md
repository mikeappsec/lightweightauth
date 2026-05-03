# pkg/authz/opa

Embedded OPA/Rego policy engine authorizer.

## Usage

```go
import (
    "context"
    _ "github.com/mikeappsec/lightweightauth/pkg/authz/opa"
    "github.com/mikeappsec/lightweightauth/pkg/module"
)

authorizer, err := module.BuildAuthorizer("opa-policy", "opa", map[string]any{
    "rego": `package authz
default allow = false
allow { input.identity.claims.role == "admin" }`,
    "query": "data.authz.allow",
})
```

## Configuration

```yaml
authorizers:
  - name: opa-policy
    type: opa
    config:
      rego: |
        package authz
        default allow = false
        allow {
          input.identity.claims.role == "admin"
        }
        allow {
          input.request.method == "GET"
          input.identity.claims.role == "viewer"
        }
      query: "data.authz.allow"
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `rego` | string | *required* | Rego policy source |
| `query` | string | `"data.authz.allow"` | Rego query to evaluate |

## Input Document

```json
{
  "identity": { "subject": "...", "claims": {...}, "source": "..." },
  "request":  { "method": "GET", "host": "...", "path": "/...", "headers": {...}, "tenantId": "..." },
  "context":  { ... }
}
```

## Features

- Rego compiled once at config time — zero hot-path compilation
- Prepared query evaluation for maximum per-request performance
- Full OPA input document: identity, request, and pipeline context
- Headers flattened to first-value strings for Rego ergonomics
- Errors wrapped as `module.ErrUpstream` for proper 503 handling

## How It Works

1. At factory time, compiles the Rego source and prepares a query.
2. On each request, builds the `input` document from identity, request, and context.
3. Evaluates the prepared query — expects a boolean result.
4. `true` → allow; `false` → deny (403); evaluation error → 503.
