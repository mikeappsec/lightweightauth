# pkg/authz/rbac

Role-based access control authorizer with O(1) hash-lookup decisions.

## Usage

```go
import (
    "context"
    _ "github.com/mikeappsec/lightweightauth/pkg/authz/rbac"
    "github.com/mikeappsec/lightweightauth/pkg/module"
)

authorizer, err := module.BuildAuthorizer("my-rbac", "rbac", map[string]any{
    "rolesFrom": "claim:roles",
    "allow":     []string{"admin", "editor"},
})
```

## Configuration

```yaml
authorizers:
  - name: my-rbac
    type: rbac
    config:
      rolesFrom: "claim:roles"
      allow:
        - admin
        - editor
        - viewer
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `rolesFrom` | string | `"claim:roles"` | Where to read roles (format: `claim:<name>`) |
| `allow` | []string | *required* | Roles permitted access |

## Features

- Zero external dependencies — pure in-process evaluation
- O(1) role lookup via `map[string]struct{}`
- Supports claims typed as `[]string`, `[]any`, or single `string`
- Clear 403 reason identifying the denied subject
- Composable under `composite` authorizer (allOf/anyOf)

## How It Works

1. Extracts the subject's roles from `Identity.Claims` using the `claim:<key>` syntax.
2. Checks each role against the allow-set (stored as a hash map).
3. If any role matches, returns `Allow: true`.
4. Otherwise returns 403 with reason: `"subject '<sub>' has no allowed role"`.
