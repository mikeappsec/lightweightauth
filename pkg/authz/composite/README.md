# pkg/authz/composite

Meta-authorizer that combines multiple authorizers with allOf/anyOf logic.

## Usage

```go
import (
    "context"
    _ "github.com/mikeappsec/lightweightauth/pkg/authz/composite"
    "github.com/mikeappsec/lightweightauth/pkg/module"
)

authorizer, err := module.BuildAuthorizer("multi", "composite", map[string]any{
    "anyOf": []any{
        map[string]any{"name": "rbac", "type": "rbac", "config": map[string]any{"allow": []string{"admin"}}},
        map[string]any{"name": "cel", "type": "cel", "config": map[string]any{"expression": `request.method == "GET"`}},
    },
})
```

## Configuration

```yaml
authorizers:
  - name: multi
    type: composite
    config:
      anyOf:
        - name: role-check
          type: rbac
          config:
            allow: ["admin", "editor"]
        - name: public-read
          type: cel
          config:
            expression: 'request.method == "GET" && request.path.startsWith("/public/")'
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `anyOf` | []child | — | At least one child must allow (mutually exclusive with `allOf`) |
| `allOf` | []child | — | Every child must allow (mutually exclusive with `anyOf`) |

Each child is `{ name, type, config }` — built recursively via `module.BuildAuthorizer`.

## Features

- Exactly one of `anyOf`/`allOf` required (validated at config time)
- Arbitrary nesting (composites within composites)
- `anyOf`: first Allow wins; `ErrUpstream` short-circuits for safety
- `allOf`: first Deny wins; no children = deny (no implicit allow)
- `mergeAllow` unions ResponseHeaders and UpstreamHeaders from multiple allowed children
- Composable with all authorizer types (rbac, opa, cel, openfga, spicedb, grpc-plugin, wasm)

## How It Works

1. Builds each child authorizer recursively at config time.
2. **anyOf mode**: evaluates children until one allows; short-circuits on upstream errors.
3. **allOf mode**: evaluates all children; first deny terminates.
4. Merges response/upstream headers from all allowed children into the final decision.
