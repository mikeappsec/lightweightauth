package cache

import (
	"fmt"
	"sync"
)

// BackendSpec is the YAML/CRD shape that selects a Backend at compile
// time. It is consumed by [BuildBackend], which dispatches to the factory
// previously registered under [BackendSpec.Type].
//
//	cache:
//	  backend: valkey            # "memory" (default) or "valkey"
//	  addr: valkey-master:6379
//	  password: ${VALKEY_PASSWORD}
//	  keyPrefix: lwauth/
//	  tls: false
//	  size: 100000               # only used by "memory"
//
// The Stats pointer is filled in by the caller (the decision/introspection
// cache) so eviction counters from the LRU backend land in the correct
// per-cache Stats struct.
type BackendSpec struct {
	Type      string         `json:"type,omitempty" yaml:"type,omitempty"`
	Size      int            `json:"size,omitempty" yaml:"size,omitempty"`
	Addr      string         `json:"addr,omitempty" yaml:"addr,omitempty"`
	Password  string         `json:"password,omitempty" yaml:"password,omitempty"`
	Username  string         `json:"username,omitempty" yaml:"username,omitempty"`
	KeyPrefix string         `json:"keyPrefix,omitempty" yaml:"keyPrefix,omitempty"`
	TLS       bool           `json:"tls,omitempty" yaml:"tls,omitempty"`
	Extra     map[string]any `json:"extra,omitempty" yaml:"extra,omitempty"`
}

// BackendFactory builds a Backend from the spec. The provided Stats
// pointer is non-nil; backends that evict (LRU) update its Evictions
// counter, while remote backends (Valkey, Redis) leave it at zero and
// rely on the server-side eviction policy.
type BackendFactory func(spec BackendSpec, stats *Stats) (Backend, error)

var (
	backendRegistryMu sync.RWMutex
	backendRegistry   = map[string]BackendFactory{}
)

// RegisterBackend installs a factory under the given type name (e.g.
// "memory", "valkey"). Panics on duplicate registration so init-time
// mistakes are caught immediately.
func RegisterBackend(typeName string, f BackendFactory) {
	backendRegistryMu.Lock()
	defer backendRegistryMu.Unlock()
	if _, dup := backendRegistry[typeName]; dup {
		panic(fmt.Sprintf("cache: backend %q already registered", typeName))
	}
	backendRegistry[typeName] = f
}

// BuildBackend constructs a Backend from spec, defaulting to "memory" when
// spec.Type is empty.
func BuildBackend(spec BackendSpec, stats *Stats) (Backend, error) {
	t := spec.Type
	if t == "" {
		t = "memory"
	}
	backendRegistryMu.RLock()
	f, ok := backendRegistry[t]
	backendRegistryMu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("cache: unknown backend %q (registered: %v)", t, RegisteredBackends())
	}
	if stats == nil {
		stats = &Stats{}
	}
	return f(spec, stats)
}

// RegisteredBackends returns the names of registered backends. Useful
// for `lwauthctl modules` and error messages.
func RegisteredBackends() []string {
	backendRegistryMu.RLock()
	defer backendRegistryMu.RUnlock()
	out := make([]string, 0, len(backendRegistry))
	for k := range backendRegistry {
		out = append(out, k)
	}
	return out
}

// init wires the in-process LRU as the default "memory" backend so plain
// AuthConfigs (`cache: {ttl: 30s}`) keep working with no `backend` field.
func init() {
	RegisterBackend("memory", func(spec BackendSpec, stats *Stats) (Backend, error) {
		size := spec.Size
		if size <= 0 {
			size = 10_000
		}
		return NewLRU(size, 0, stats)
	})
}
