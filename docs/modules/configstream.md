# `configstream` — xDS-style streaming config push (M11)

Server-streaming gRPC service that pushes compiled `AuthConfig`
snapshots to many subscribers with **latest-wins conflation** — slow
consumers can never block `Publish`. Late subscribers are primed with
the current snapshot so a mid-flight pod restart catches up
immediately.

**Source:** [pkg/configstream](../../pkg/configstream/broker.go).
**Service:** `lightweightauth.v1.ConfigDiscovery` /
`StreamAuthConfig` (one server-streaming RPC).

## When to use

- Sidecar / fleet topologies where one lwauth control-plane pushes to
  many lwauth data-plane replicas.
- Embedders building their own Compile-and-Swap path (e.g. a custom
  proxy) that need an authoritative push channel rather than periodic
  polling of a ConfigMap.

**Not needed** for the standard CRD/file deployment — the controller
swaps engines in-process.

## Server side

The reconciler optionally publishes to a `Broker` after each
successful Compile-and-Swap:

```go
import "github.com/mikeappsec/lightweightauth/pkg/configstream"

br := configstream.NewBroker()                // 1 publisher, N subscribers
gs := grpc.NewServer()
configstream.Register(gs, br)                 // mounts ConfigDiscovery
go gs.Serve(lis)

// In your reconciler, after a successful Compile():
br.Publish(snapshot)                          // []byte JSON, version-tagged
```

`Broker.Publish` is the **single-writer** path. Calling Publish from
multiple goroutines is supported but has a known caveat (an older
snapshot can win against a newer one under contention) — multi-writer
support is tracked as a v1.1 follow-up. See
[DESIGN.md §M12 follow-ups](../DESIGN.md).

## Client side

```go
import "github.com/mikeappsec/lightweightauth/pkg/configstream"

conn, _ := grpc.NewClient("control-plane:9001", grpc.WithTransportCredentials(...))
defer conn.Close()

err := configstream.Stream(ctx, conn, "node-id-here", func(snap []byte, version uint64) error {
    cfg, err := config.Parse(snap)
    if err != nil { return err }
    return engineHolder.Swap(cfg)              // your Compile-and-Swap path
})
```

The helper:
- Sends an initial `StreamAuthConfigRequest{nodeId}` so the server can
  scope the snapshot to the caller.
- Calls `handler` synchronously per snapshot — return non-nil to abort
  the stream.
- Reconnects automatically with bounded backoff on transport errors.

## Wire shape

```protobuf
service ConfigDiscovery {
  rpc StreamAuthConfig(StreamAuthConfigRequest)
      returns (stream StreamAuthConfigResponse);
}

message StreamAuthConfigResponse {
  bytes  snapshot = 1;   // JSON-encoded AuthConfig
  uint64 version  = 2;   // monotonic per-Broker
}
```

JSON over the wire is deliberate: module-specific free-form `config`
maps round-trip cleanly through it but not through protobuf's
struct/Any. The cost is one JSON round-trip per snapshot — negligible
versus push frequency.

## Conflation contract

```text
Publish(v=1)        →  Publish(v=2)  →  Publish(v=3)
                     ↘                     ↓
   slow subscriber  ←——————————————— sees v=3 only
```

A subscriber that hasn't drained its channel by the time `Publish(v=3)`
arrives loses v=2 — by design. The contract is "eventually converge to
latest", never "every snapshot delivered".

## Storm resilience (M12 slice 5)

Validated under reconnect storms in
[pkg/configstream/grpc_storm_test.go](../../pkg/configstream/grpc_storm_test.go):

- 16 clients × 3 reconnects + 1 long-lived over single HTTP/2 conn vs
  100-publish stream — runs <250 ms under `-race`.
- Server-cancel (`gs.Stop()`) closes all client streams cleanly with
  zero goroutine leaks.

## Operational notes

- **Versioning.** `version` is a monotonic counter per Broker
  instance. On control-plane restart, the counter resets to 0 — clients
  must treat version comparison as "snapshot bytes != prior snapshot"
  rather than "version > prior version".
- **Authorization.** The service has no built-in authn. Operators
  protect it via mTLS at the listener level (the helm chart's
  `controlPlane.tls` block) or by fronting it with the standard
  `lwauth` data plane.
- **Multi-tenant.** A single Broker pushes the cluster-wide snapshot;
  tenant filtering is the subscriber's responsibility (the `nodeId`
  argument lets the server scope replies in custom builds).

## References

- DESIGN: [DESIGN.md §M11](../DESIGN.md) "xDS-style push".
- Stress + storm tests: [pkg/configstream/stress_test.go](../../pkg/configstream/stress_test.go),
  [pkg/configstream/grpc_storm_test.go](../../pkg/configstream/grpc_storm_test.go).
- Source: [pkg/configstream/broker.go](../../pkg/configstream/broker.go).
