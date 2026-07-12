# pkg/lwauthd

Public embedding surface for the lwauth daemon (decision engine).

## Usage

```go
import (
    "github.com/mikeappsec/lightweightauth/pkg/lwauthd"
)

// Minimal embedded usage — Run takes no context; it blocks internally
// on SIGINT/SIGTERM (signal.Notify), not a caller-supplied context.
err := lwauthd.Run(lwauthd.Options{
    ConfigPath: "/etc/lwauth/config.yaml",
    HTTPAddr:   ":8080", // default when omitted
    GRPCAddr:   ":9001", // default when omitted
})
```

## Options

`Options` has roughly 30 fields (`pkg/lwauthd/lwauthd.go`) — most
undocumented here previously. There is no `MetricsAddr`, `HealthAddr`,
`CRDWatch`, or `TLS` field; those don't exist. The real shape:

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `ConfigPath` | string | `""` | File path to initial config (file mode) |
| `HTTPAddr` | string | `":8080"` | HTTP listener address (Door A) — **not** `:9000` |
| `GRPCAddr` | string | `":9001"` | gRPC listener address (Door B) |
| `TLSCertFile` / `TLSKeyFile` / `TLSClientCAFile` | string | `""` | TLS/mTLS for the HTTP listener — no `TLSConfig` struct |
| `GRPCTLSCertFile` / `GRPCTLSKeyFile` / `GRPCTLSClientCAFile` | string | `""` | Same for the gRPC listener |
| `EnableReflection` | bool | `false` | gRPC server reflection |
| `DisableHTTPAuthorize` / `DisableHTTPMetrics` / `DisableHTTPOpenAPI` | bool | `false` | Remove `/v1/authorize`, `/metrics`, `/openapi.*` from the HTTP listener — metrics and health share this listener, there's no separate address |
| `Admin` | `admin.Config` | zero value | Admin-plane auth/RBAC (`/v1/admin/*`) |
| `MaxRequestBytes` | int64 | `1 MiB` | Cap on `/v1/authorize` request bodies |
| `HTTPReadHeaderTimeout` / `HTTPReadTimeout` / `HTTPWriteTimeout` / `HTTPIdleTimeout` / `HTTPMaxHeaderBytes` | — | 10s / 30s / 30s / 120s / 1 MiB | HTTP server timeouts |
| `GRPCKeepalive*` / `GRPCMaxConnection*` / `GRPCMaxConcurrentStreams` | — | see source | gRPC connection-management knobs (F14) |
| `WatchConfigFile` | bool | `false` | fsnotify hot-reload of `ConfigPath` (file mode) |
| `WatchNamespace` | string | `""` | Non-empty switches to CRD mode — **not** a `CRDWatch bool` |
| `AuthConfigName` | string | — | Which `AuthConfig` CR to reconcile in CRD mode |
| `LeaderElection*` / `LeaseDuration` / `RenewDeadline` / `RetryPeriod` | — | see source | Controller-runtime leader election (ENT-HA-1) |
| `ConfigStreamAddr` / `ConfigStreamNodeID` | string | — | Follower configstream subscription for active/active HA |
| `Logger` | `*slog.Logger` | default | Structured logger |

## Engine Sources

The daemon resolves its auth engine from one of two sources:

1. **File config** — YAML file at `ConfigPath`, with optional
   `WatchConfigFile` fsnotify hot-reload.
2. **CRD watch** — Kubernetes `AuthConfig` custom resource, when
   `WatchNamespace` is non-empty. `ConfigPath` is ignored in this mode.

## Features

- `Run()` blocks on OS signals (SIGINT/SIGTERM), not a caller-supplied
  context — it builds its own internal context and listens via
  `signal.Notify`
- Hot-reload: config changes re-compile the engine with zero downtime
- Dual-door architecture: HTTP (Door A) + gRPC ext_authz/native (Door B)
- `LoadEngine()` compiles a config spec into a ready-to-serve engine
- Graceful drain: in-flight requests complete before shutdown

## How It Works

1. `Run()` parses options, starts listeners (HTTP, gRPC — metrics and
   health share the HTTP listener unless disabled).
2. Loads initial config from file or CRD; compiles into an auth engine.
3. Engine is atomically swapped on config change (new requests use new engine immediately).
4. On SIGINT/SIGTERM: stops accepting new connections, drains in-flight requests, shuts down.
