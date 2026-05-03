# pkg/lwauthd

Public embedding surface for the lwauth daemon (decision engine).

## Usage

```go
import (
    "context"
    "github.com/mikeappsec/lightweightauth/pkg/lwauthd"
)

// Minimal embedded usage
err := lwauthd.Run(ctx, lwauthd.Options{
    ConfigPath: "/etc/lwauth/config.yaml",
    HTTPAddr:   ":9000",
    GRPCAddr:   ":9001",
})
```

## Options

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `ConfigPath` | string | `""` | File path to initial config |
| `HTTPAddr` | string | `":9000"` | HTTP listener address (Door A) |
| `GRPCAddr` | string | `":9001"` | gRPC listener address (Door B) |
| `MetricsAddr` | string | `":9090"` | Prometheus /metrics endpoint |
| `HealthAddr` | string | `":9091"` | Health probe endpoint |
| `CRDWatch` | bool | `false` | Watch Kubernetes CRD for config |
| `TLS` | *TLSConfig | `nil` | TLS settings for listeners |
| `Logger` | *slog.Logger | default | Structured logger |

## Engine Sources

The daemon resolves its auth engine from one of three sources (priority order):

1. **CRD watch** — Kubernetes AuthConfig custom resource (when `CRDWatch: true`)
2. **File config** — YAML file at `ConfigPath` (with optional fsnotify hot-reload)
3. **Error engine** — Returns 503 for all requests (when no config is available)

## Features

- `Run()` blocks until context is cancelled (graceful shutdown)
- Hot-reload: config changes re-compile the engine with zero downtime
- Dual-door architecture: HTTP reverse-proxy (Door A) + gRPC decision API (Door B)
- `LoadEngine()` compiles a config spec into a ready-to-serve engine
- Health endpoint reports `ready` only after first engine compilation
- Graceful drain: in-flight requests complete before shutdown

## How It Works

1. `Run()` parses options, starts listeners (HTTP, gRPC, metrics, health).
2. Loads initial config from file or CRD; compiles into an auth engine.
3. Engine is atomically swapped on config change (new requests use new engine immediately).
4. On context cancellation: stops accepting new connections, drains in-flight requests, shuts down.
