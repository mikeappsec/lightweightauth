# pkg/authz/cel

CEL expression authorizer for lightweight attribute-based access control.

## Usage

```go
import (
    "context"
    _ "github.com/mikeappsec/lightweightauth/pkg/authz/cel"
    "github.com/mikeappsec/lightweightauth/pkg/module"
)

authorizer, err := module.BuildAuthorizer("cel-check", "cel", map[string]any{
    "expression": `identity.claims.role == "admin" || request.method == "GET"`,
})
```

## Configuration

```yaml
authorizers:
  - name: cel-check
    type: cel
    config:
      expression: |
        identity.claims.role == "admin" ||
        (request.method == "GET" && request.path.startsWith("/public/"))
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `expression` | string | *required* | CEL expression yielding `bool` |

## Variables

| Variable | Type | Contents |
|----------|------|----------|
| `identity` | `map<string, dyn>` | subject, claims, source |
| `request` | `map<string, dyn>` | method, host, path, headers, tenantId |
| `context` | `map<string, dyn>` | Pipeline scratch map |

## Features

- CEL environment compiled and type-checked at config time
- `OptOptimize` enabled for maximum evaluation performance
- Zero external dependencies at runtime (embedded CEL engine)
- Return type enforced to `bool` at compile time (config error otherwise)
- Composable under `composite` authorizer

## How It Works

1. At factory time, compiles the CEL expression with the environment containing `identity`, `request`, and `context` variables.
2. Type-checks that the expression output is `bool`.
3. On each request, evaluates the expression with flattened headers (first-value `map[string]string`).
4. `true` → allow; `false` → deny (403); evaluation error → 503.
