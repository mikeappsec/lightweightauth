# pkg/authz/spicedb

SpiceDB / Zanzibar-style ReBAC authorizer via gRPC CheckPermission.

## Usage

```go
import (
    "context"
    _ "github.com/mikeappsec/lightweightauth/pkg/authz/spicedb"
    "github.com/mikeappsec/lightweightauth/pkg/module"
)

authorizer, err := module.BuildAuthorizer("spicedb", "spicedb", map[string]any{
    "endpoint": "spicedb:50051",
    "token":    "my-preshared-key",
    "check": map[string]any{
        "resourceType": "document",
        "resourceId":   "{{.Request.Path | sanitize}}",
        "permission":   "{{.Request.Method | lower}}",
        "subjectType":  "user",
        "subjectId":    "{{.Identity.Subject}}",
    },
})
```

## Configuration

```yaml
authorizers:
  - name: spicedb
    type: spicedb
    config:
      endpoint: "spicedb:50051"
      token: "my-preshared-key"
      insecure: false
      timeout: "2s"
      consistency: "minimize_latency"
      check:
        resourceType: "document"
        resourceId: "{{.Request.Path | sanitize}}"
        permission: "{{.Request.Method | lower}}"
        subjectType: "user"
        subjectId: "{{.Identity.Subject}}"
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `endpoint` | string | *required* | SpiceDB gRPC address |
| `token` | string | *required* | Pre-shared key |
| `insecure` | bool | `false` | Disable TLS (warns if true) |
| `timeout` | duration | `"2s"` | Per-check timeout |
| `consistency` | string | `"minimize_latency"` | `minimize_latency` or `fully_consistent` |
| `check.resourceType` | template | *required* | Resource object_type |
| `check.resourceId` | template | *required* | Resource object_id |
| `check.permission` | template | *required* | Permission name |
| `check.subjectType` | template | *required* | Subject object_type |
| `check.subjectId` | template | *required* | Subject object_id |

## Template Functions

| Function | Description |
|----------|-------------|
| `lower` | Lowercase |
| `upper` | Uppercase |
| `sanitize` | Restricts to SpiceDB-safe chars `[a-zA-Z0-9/_|@.-]` |

## Features

- gRPC CheckPermission with `authzed-go` SDK
- Template-based resource/permission mapping with panic recovery
- 1024-char input cap on rendered template values
- Circuit breaker via `upstream.Guard` for SpiceDB resilience
- Conditional (caveated) permissions treated as `ErrUpstream` for safe fallthrough
- gRPC recv buffer capped at 256 KiB
- TLS with system certs by default; insecure mode logs warning

## How It Works

1. Renders resource type/id, permission, and subject type/id from Go templates.
2. Calls `CheckPermission` RPC on the SpiceDB endpoint via gRPC.
3. `PERMISSIONSHIP_HAS_PERMISSION` → allow; `NO_PERMISSION` → deny (403).
4. Conditional permissions → `ErrUpstream` (allows composite fallthrough).
5. Network failures handled by circuit breaker → 503.
