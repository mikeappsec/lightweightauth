# pkg/plugin/grpc

Out-of-process gRPC plugin runtime for all pipeline stages.

## Usage

```go
import (
    "context"
    _ "github.com/mikeappsec/lightweightauth/pkg/plugin/grpc"
    "github.com/mikeappsec/lightweightauth/pkg/module"
)

authorizer, err := module.BuildAuthorizer("external-policy", "grpc-plugin", map[string]any{
    "address": "unix:///run/lwauth/plugins/policy.sock",
    "timeout": "1s",
})
```

## Configuration

```yaml
authorizers:
  - name: external-policy
    type: grpc-plugin
    config:
      address: "unix:///run/lwauth/plugins/policy.sock"
      timeout: "1s"
      insecure: false
      tls:
        caFile: "/etc/lwauth/plugin-ca.pem"
        certFile: "/etc/lwauth/plugin-client.pem"
        keyFile: "/etc/lwauth/plugin-client-key.pem"
      signing:
        mode: "verify"
        keys:
          - id: "key-1"
            secret: "hex:0123456789abcdef..."
      lifecycle:
        command: "/usr/local/bin/my-plugin"
        args: ["--port", "50051"]
        healthCheck:
          interval: "5s"
          timeout: "2s"
          failureThreshold: 3
        restart:
          backoff: "1s"
          maxRestarts: 5
        startTimeout: "30s"
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `address` | string | *required* | Unix socket or host:port |
| `timeout` | duration | `"1s"` | Per-call deadline |
| `insecure` | bool | `false` | Opt-in plaintext for non-loopback |
| `tls.caFile` | string | — | CA for server verification |
| `tls.certFile` | string | — | mTLS client cert |
| `tls.keyFile` | string | — | mTLS client key |
| `signing.mode` | string | `"disabled"` | `disabled`, `verify`, or `require` |
| `signing.keys` | []key | — | HMAC-SHA256 keys (≥16 bytes, hex-encoded) |
| `lifecycle.command` | string | — | Plugin binary path (optional supervisor) |
| `lifecycle.startTimeout` | duration | `"30s"` | Max wait for first health probe |

## Features

- Single type name `"grpc-plugin"` registers for all three stages (identifier/authorizer/mutator)
- TLS required by default for non-loopback TCP connections
- F-PLUGIN-2 HMAC-SHA256 response signature verification (verified BEFORE response inspection)
- Optional process lifecycle management with health checks and restart backoff
- Fail-closed: RPC failures → `ErrUpstream` → 503
- Peer certificates NOT forwarded in request body (security)
- Connection pooling: same `poolKey` reused by multiple modules targeting one plugin

## How It Works

1. At config time, dials the gRPC endpoint (with optional mTLS credentials).
2. If `lifecycle` is configured, spawns the plugin binary and waits for health probe.
3. On each request, translates `module.Request` + `module.Identity` to proto, calls the plugin.
4. If signing is enabled, verifies the HMAC-SHA256 signature on the response before processing.
5. Translates the proto response back to `module.Identity` / `module.Decision` / mutation.
