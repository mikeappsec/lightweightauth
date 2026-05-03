# pkg/configstream

xDS-style config snapshot streaming with conflation and multi-writer support.

## Usage

```go
import (
    "github.com/mikeappsec/lightweightauth/pkg/configstream"
)

// Publisher side (controller)
broker := configstream.NewBroker()
broker.Publish(&configstream.Snapshot{
    Spec:    compiledAuthConfig,
    Version: 1,
})

// Subscriber side (pod)
ch := broker.Subscribe()
for snap := range ch {
    engine.Swap(snap.Spec)
}

// gRPC server
srv := configstream.NewServer(broker, myAuthorizer)
srv.Register(grpcServer)

// gRPC client
configstream.Stream(ctx, conn, "node-1", func(snap *configstream.Snapshot) error {
    return engine.Swap(snap.Spec)
})
```

## Configuration

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `maxSnapshotBytes` | int | `4 MiB` | Max snapshot size on server |
| Authorizer | callback | *required* | Gates each inbound stream (fail-closed) |

## Features

- **Conflation**: slow subscribers only see the latest snapshot (depth-1 buffer)
- **Multi-writer**: multiple publishers can fan in safely (per B2: M12-BROKER-MW)
- **Late join**: new subscribers immediately receive the current snapshot
- `highWater` tracking prevents version regression under concurrent publishers
- Server enforces max snapshot size (4 MiB)
- Authorizer is fail-closed: nil panics at construction
- `Stream()` is one-shot; caller handles backoff/reconnect
- Version assignment serialized inside broker mutex; delivery happens outside

## How It Works

1. **Broker.Publish()** atomically installs a new snapshot, assigns a monotonic version, and notifies all subscribers.
2. **Broker.Subscribe()** returns a channel primed with the latest snapshot. Subsequent publishes conflate: if the subscriber hasn't read yet, the pending slot is overwritten with the newer version.
3. **Server** wraps the broker as a gRPC `StreamAuthConfig` service. Each stream is authorized on connect; snapshots push to clients as they arrive.
4. **Stream()** client opens the RPC, receives snapshots, and calls the handler for each.
