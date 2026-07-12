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

// Add a revocation — Add takes Entry by value, not a pointer
store.Add(ctx, revocation.Entry{
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
- **ValkeyStore**: shared storage via `SET ... PX <ms>`/`EXISTS` for multi-replica deployments
- **CacheStore**: folds revocation onto a shared `pkg/cache` pool backend (`NewCacheStore`) — a third real backend, undocumented here previously
- **NegCache**: local negative-result cache wrapper to avoid network round-trips
- **ParallelChecker**: bounded goroutine pool for concurrent multi-key revocation checks
- Key-agnostic: stores any opaque string (JTI, sha256(token), session ID, etc.)
- TTL-based automatic expiry (no manual cleanup needed)
- Pagination support for List operations
- Evict API for cross-replica invalidation via event bus

## Parallel Revocation Checking

The `ParallelChecker` wraps a `Store` and checks multiple revocation keys concurrently
using a bounded worker pool via `errgroup`. For the common case of 2 keys (jti + sub)
this eliminates sequential round-trips to the backing store.

```go
pc := revocation.NewParallelChecker(store,
    revocation.WithConcurrency(4), // default: 4 goroutines
)

// Returns true as soon as any key is found revoked.
revoked, err := pc.ExistsAny(ctx, []string{"jti:abc123", "sub:acme:alice"})
```

| Option | Default | Description |
|--------|---------|-------------|
| `WithConcurrency(n)` | `4` | Max concurrent goroutines for key checks |

For 0–1 keys, `ExistsAny` inlines the call without spawning goroutines.

## How It Works

1. Pipeline calls `store.Exists(ctx, key)` before evaluating the authorizer.
2. If key exists → credential is revoked → request denied.
3. `NegCache` wraps the backing store: on "not revoked" result, caches locally for `negCacheTTL` to skip network calls.
4. On `Add`, NegCache evicts the local entry to ensure immediate enforcement.
5. ValkeyStore uses Redis `SET key reason PX <milliseconds>` for add
   (millisecond precision, not `EX <seconds>`), `EXISTS key` for lookup.

## Thread Safety

| Type | Safe for concurrent use? | Notes |
|------|--------------------------|-------|
| `Store` (interface) | ✅ Yes | Contract mandates implementations be safe from the pipeline hot path |
| `MemoryStore` | ✅ Yes | `sync.RWMutex` protects entries (RLock for reads, Lock for writes) |
| `ValkeyStore` | ✅ Yes | Stateless wrapper around goroutine-safe Valkey client |
| `NegCache` | ✅ Yes | `sync.RWMutex` protects local cache map; reaper goroutine stopped via channel |
| `ParallelChecker` | ✅ Yes | Stateless; uses bounded errgroup for parallel `Exists` checks |
| `Entry` | ✅ Yes | Plain value type |
