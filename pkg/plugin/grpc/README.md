# pkg/plugin/grpc

Out-of-process gRPC plugin runtime for all pipeline stages.

## Usage

```go
import (
    "context"
    _ "github.com/mikeappsec/lightweightauth/pkg/plugin/grpc"
    "github.com/mikeappsec/lightweightauth/pkg/module"
)

authorizer, err := module.BuildAuthorizer("grpc-plugin", "external-policy", map[string]any{
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
            hmacSecret: "0123456789abcdef0123456789abcdef"
      lifecycle:
        command: "/usr/local/bin/my-plugin"
        args: ["--port", "50051"]
        healthCheck:
          interval: "5s"
          timeout: "2s"
          failureThreshold: 3
        restart:
          initialBackoff: "1s"
          maxBackoff: "30s"
          jitter: "0.2"
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
| `signing.mode` | string | `"disabled"`, but see note below | `disabled`, `verify`, or `require` |
| `signing.keys[].hmacSecret` | string | — | HMAC-SHA256 key, bare hex string — **not** `secret`, and **no** `"hex:"` prefix (`hex.DecodeString` is called directly on the value) |
| `lifecycle.command` | string | — | Plugin binary path (optional supervisor) |
| `lifecycle.restart.initialBackoff` / `.maxBackoff` / `.jitter` / `.maxRestarts` | — | — | Restart backoff — there is no `backoff` field |
| `lifecycle.startTimeout` | duration | `"30s"` | Max wait for first health probe |

**`signing.mode` default nuance:** for any TCP `host:port` address
(not a Unix socket) configured without `insecure: true` and with no
`signing:` block at all, `client.go` silently bumps the effective
default to `verify` instead of `disabled` — a security-hardening
override for the higher-risk TCP case. Only Unix-socket addresses or
explicit `insecure: true` TCP addresses actually default to `disabled`.

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

## Thread Safety

| Type | Safe for concurrent use? | Notes |
|------|--------------------------|-------|
| `Identifier` | ✅ Yes | Immutable config + gRPC `ClientConn` (goroutine-safe) |
| `Authorizer` | ✅ Yes | Immutable config + gRPC `ClientConn` (goroutine-safe) |
| `Mutator` | ✅ Yes | Immutable config + gRPC `ClientConn` (goroutine-safe) |

Internally, the connection pool (`sync.Mutex`) and supervisor pool (`sync.Mutex`) are process-wide singletons with mutex protection. Signing verification is stateless per-call — keys are read-only after construction.
