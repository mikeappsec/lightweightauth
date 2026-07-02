// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package cache

import (
	"fmt"
	"sort"
	"sync"
	"sync/atomic"
)

// Stats are the per-pool counters a backend updates and the runtime exposes
// via Prometheus. Per the redesign, capacity events (Evictions, size) are
// per-pool, while per-call counters (Hits, Misses, StaleServed) are surfaced
// with {pool, module, layer} labels at the metrics boundary.
type Stats struct {
	Hits           atomic.Uint64
	Misses         atomic.Uint64
	Evictions      atomic.Uint64
	StaleServed    atomic.Uint64 // stale entries served during upstream outages
	DistSFWon      atomic.Uint64 // this replica won the distributed lock
	DistSFWaited   atomic.Uint64 // this replica waited for another replica's result
	DistSFFallback atomic.Uint64 // TryLock errors forced fallback to local singleflight
}

// BackendSpec is the resolved, backend-agnostic shape that selects and
// configures a [Cache] implementation for a single pool. It carries only
// infrastructure ("where/how bytes are stored"); per-module behavior such
// as TTLs lives on the module config, not here (design §6).
type BackendSpec struct {
	// Type names a registered backend ("memory", "valkey", "tiered", ...).
	// Empty defaults to "memory".
	Type string `json:"type,omitempty" yaml:"type,omitempty"`

	// Size bounds an in-process backend's entry count (memory/L1).
	Size int `json:"size,omitempty" yaml:"size,omitempty"`

	// Remote backend connection settings.
	Addr      string `json:"addr,omitempty" yaml:"addr,omitempty"`
	Username  string `json:"username,omitempty" yaml:"username,omitempty"`
	Password  string `json:"password,omitempty" yaml:"password,omitempty"`
	KeyPrefix string `json:"keyPrefix,omitempty" yaml:"keyPrefix,omitempty"`
	TLS       bool   `json:"tls,omitempty" yaml:"tls,omitempty"`

	// MaxTTL is the pool-level ceiling (design §6). A module's effective TTL
	// is min(module.ttl, MaxTTL). Zero means "no ceiling".
	MaxTTL string `json:"maxTtl,omitempty" yaml:"maxTtl,omitempty"`

	// AllowPII permits caching values flagged as carrying PII to this pool.
	// Deny-by-default; see the security section of the design.
	AllowPII bool `json:"allowPII,omitempty" yaml:"allowPII,omitempty"`

	// Encrypt enables at-rest value encryption (AES-GCM) for this pool. Only
	// meaningful together with AllowPII for remote backends.
	Encrypt bool `json:"encrypt,omitempty" yaml:"encrypt,omitempty"`

	// Codec selects the value codec for [Typed] handles drawn from this pool
	// ("gob" default, "json" opt-in). Pool-scoped so a single backend can't
	// be read with mismatched encodings.
	Codec string `json:"codec,omitempty" yaml:"codec,omitempty"`

	// Extra carries backend-specific settings not modeled above.
	Extra map[string]any `json:"extra,omitempty" yaml:"extra,omitempty"`
}

// BackendFactory builds a [Cache] from spec. The provided Stats pointer is
// non-nil; backends that evict locally (LRU) update its Evictions counter,
// while remote backends rely on server-side eviction and leave it at zero.
type BackendFactory func(spec BackendSpec, stats *Stats) (Cache, error)

var (
	backendRegistryMu sync.RWMutex
	backendRegistry   = map[string]BackendFactory{}
)

// RegisterBackend installs a factory under the given type name (e.g.
// "memory", "valkey"). It panics on duplicate registration so init-time
// mistakes surface immediately. An out-of-tree backend registers here
// identically to a built-in.
func RegisterBackend(typeName string, f BackendFactory) {
	if f == nil {
		panic("cache: RegisterBackend called with nil factory")
	}
	backendRegistryMu.Lock()
	defer backendRegistryMu.Unlock()
	if _, dup := backendRegistry[typeName]; dup {
		panic(fmt.Sprintf("cache: backend %q already registered", typeName))
	}
	backendRegistry[typeName] = f
}

// BuildBackend constructs a [Cache] from spec, defaulting to "memory" when
// spec.Type is empty.
func BuildBackend(spec BackendSpec, stats *Stats) (Cache, error) {
	t := spec.Type
	if t == "" {
		t = "memory"
	}
	backendRegistryMu.RLock()
	f, ok := backendRegistry[t]
	backendRegistryMu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("%w: unknown backend %q (registered: %v)", ErrConfig, t, RegisteredBackends())
	}
	if stats == nil {
		stats = &Stats{}
	}
	return f(spec, stats)
}

// RegisteredBackends returns the sorted names of registered backends, useful
// for diagnostics and error messages.
func RegisteredBackends() []string {
	backendRegistryMu.RLock()
	defer backendRegistryMu.RUnlock()
	out := make([]string, 0, len(backendRegistry))
	for k := range backendRegistry {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
