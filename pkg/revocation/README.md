# pkg/revocation

Credential revocation store with pluggable backends and negative caching.

## Usage

```go
import (
    "github.com/mikeappsec/lightweightauth/pkg/revocation"
)

// In-process store
store := revocation.NewMemoryStore(
    revocation.WithDefaultTTL(24 * time.Hour),
    revocation.WithMaxEntries(100000),
)

// Add a revocation
store.Add(ctx, &revocation.Entry{
    Key:    "jti:abc123",
    Reason: "user-logout",
    TTL:    1 * time.Hour,
})

// Check if revoked
exists, err := store.Exists(ctx, "jti:abc123")

// Valkey (Redis-compatible) for multi-replica
vStore, err := revocation.NewValkeyStore(revocation.ValkeyConfig{
    Addr:       "valkey:6379",
    KeyPrefix:  "lwauth/rev/",
    DefaultTTL: 24 * time.Hour,
})
```

## Configuration

### MemoryStore Options

| Option | Default | Description |
|--------|---------|-------------|
| `WithDefaultTTL(d)` | `24h` | Default entry TTL |
| `WithMaxEntries(n)` | `0` (unlimited) | Max stored entries |

### ValkeyConfig

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `Addr` | string | *required* | Valkey host:port |
| `Username` | string | `""` | ACL username |
| `Password` | string | `""` | ACL password |
| `TLS` | bool | `false` | Enable TLS (min 1.2) |
| `KeyPrefix` | string | `"lwauth/rev/"` | Key namespace |
| `DefaultTTL` | duration | `24h` | Entry lifetime |

### NegCache Options

| Option | Default | Description |
|--------|---------|-------------|
| `WithNegCacheTTL(d)` | `2s` | Negative cache entry lifetime |
| `WithNegCacheMaxSize(n)` | `100000` | Max negative cache entries |

## Features

- **MemoryStore**: in-process map with lazy eviction + background reaper goroutine
- **ValkeyStore**: shared storage via SET+EX/EXISTS for multi-replica deployments
- **NegCache**: local negative-result cache wrapper to avoid network round-trips
- Key-agnostic: stores any opaque string (JTI, sha256(token), session ID, etc.)
- TTL-based automatic expiry (no manual cleanup needed)
- Pagination support for List operations
- Evict API for cross-replica invalidation via event bus

## How It Works

1. Pipeline calls `store.Exists(ctx, key)` before evaluating the authorizer.
2. If key exists → credential is revoked → request denied.
3. `NegCache` wraps the backing store: on "not revoked" result, caches locally for `negCacheTTL` to skip network calls.
4. On `Add`, NegCache evicts the local entry to ensure immediate enforcement.
5. ValkeyStore uses Redis `SET key reason EX ttl` for add, `EXISTS key` for lookup.
