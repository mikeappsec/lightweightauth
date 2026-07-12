# pkg/connpool

Process-wide connection pool singletons for shared infrastructure clients.

## Purpose

Eliminates TCP connection churn during config hot-reloads and allows multiple
subsystems (cache, revocation, event bus, authz) targeting the same server to
share a single multiplexed client.

Connections are keyed by `(address + credentials hash)`, created on first
request, and live for the process lifetime.

## Pools

### Valkey

```go
client, err := connpool.GetValkey(connpool.ValkeyConfig{
    Addr:     "valkey:6379",
    Username: "lwauth",
    Password: "secret",
    TLS:      true,
})
```

Shared across cache and revocation subsystems. Uses the valkey-go library's
built-in connection multiplexing.

### HTTP

`GetHTTP` takes an `HTTPConfig`, not a bare string:

```go
httpClient := connpool.GetHTTP(connpool.HTTPConfig{
    BaseURL: "https://idp.example.com",
})
```

Returns a shared `*http.Client` keyed by base URL, configured with sensible
timeouts (30s overall, 10s TLS handshake, 5s response header wait).

### gRPC

`GetGRPC` takes a `GRPCConfig`, not a bare target string — extra dial
options are variadic after it:

```go
conn, err := connpool.GetGRPC(connpool.GRPCConfig{
    Target: "spicedb:50051",
}, grpc.WithTransportCredentials(creds))
```

Returns a shared `*grpc.ClientConn` keyed by target + credentials. Used by
SpiceDB, OpenFGA, and plugin gRPC adapters.

## Testing

`SetValkeyOverride` takes a **factory function**, not a client
instance, and returns its own cleanup closure — there is no separate
`ClearValkeyOverride` function:

```go
// Override Valkey client for tests
restore := connpool.SetValkeyOverride(func(cfg connpool.ValkeyConfig) (valkey.Client, error) {
    return fakeClient, nil
})
defer restore()
```

## Design

Follows the singleton pattern established in `pkg/plugin/grpc/connPool`. Each
pool uses `sync.Mutex` + map for thread-safe lazy initialization. The key
includes a hash of credentials so that configurations targeting different
servers (or the same server with different auth) remain isolated.
