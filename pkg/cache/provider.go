// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package cache

import (
	"fmt"
	"sort"
	"strings"
)

// DefaultPool is the pool name used when no caches are declared and when a
// module does not select a pool.
const DefaultPool = "default"

// Provider hands out namespaced caches to modules. The runtime builds one
// per module instance and passes it through the module's dependencies. A
// module asks for a cache by logical name; the provider resolves it to a
// configured pool, applies the module's namespace, and returns a ready
// [Cache]. Because pool references are validated at config load (see
// [ValidatePools]), Cache never has to fail.
type Provider interface {
	// Cache returns a namespaced handle for a logical name. The handle is
	// auto-prefixed by the requesting module's identity, so two modules
	// using the same logical name never collide.
	Cache(name string) Cache

	// Names lists the configured cache pools, for diagnostics.
	Names() []string
}

// Pools is the root set of constructed cache backends keyed by pool name. It
// is built once per pipeline instance from the operator's caches: config and
// shared by every module's [Provider].
type Pools struct {
	byName map[string]Cache
}

// PoolConfig is one entry in the operator's caches: list: a pool name plus
// the backend infrastructure that implements it.
type PoolConfig struct {
	Name        string `json:"name" yaml:"name"`
	BackendSpec `json:",inline" yaml:",inline"`
}

// BuildPools constructs every declared pool. When no "default" pool is
// declared, an implicit in-memory default is synthesized so plain configs
// keep working. Each pool name must be unique and non-empty.
func BuildPools(cfgs []PoolConfig) (*Pools, error) {
	byName := make(map[string]Cache, len(cfgs)+1)
	for _, c := range cfgs {
		name := strings.TrimSpace(c.Name)
		if name == "" {
			return nil, fmt.Errorf("%w: cache pool with empty name", ErrConfig)
		}
		if _, dup := byName[name]; dup {
			return nil, fmt.Errorf("%w: duplicate cache pool %q", ErrConfig, name)
		}
		backend, err := BuildBackend(c.BackendSpec, &Stats{})
		if err != nil {
			return nil, fmt.Errorf("cache pool %q: %w", name, err)
		}
		byName[name] = backend
	}
	if _, ok := byName[DefaultPool]; !ok {
		def, err := BuildBackend(BackendSpec{Type: "memory"}, &Stats{})
		if err != nil {
			return nil, fmt.Errorf("cache: synthesize default pool: %w", err)
		}
		byName[DefaultPool] = def
	}
	return &Pools{byName: byName}, nil
}

// Names returns the sorted pool names.
func (p *Pools) Names() []string {
	out := make([]string, 0, len(p.byName))
	for k := range p.byName {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Has reports whether a pool with the given name exists.
func (p *Pools) Has(name string) bool {
	_, ok := p.byName[name]
	return ok
}

// For returns a [Provider] scoped to a single module. moduleID is the
// module's identity (e.g. "i/jwt/my-jwt") used as the key namespace.
// defaultPool is the pool the module selected via cache.pool; an empty value
// falls back to [DefaultPool]. routes optionally maps logical names to pool
// names for modules that draw from more than one pool.
func (p *Pools) For(moduleID, defaultPool string, routes map[string]string) Provider {
	if defaultPool == "" {
		defaultPool = DefaultPool
	}
	return &moduleProvider{
		pools:       p,
		moduleID:    strings.TrimRight(moduleID, "/"),
		defaultPool: defaultPool,
		routes:      routes,
	}
}

type moduleProvider struct {
	pools       *Pools
	moduleID    string
	defaultPool string
	routes      map[string]string
}

func (m *moduleProvider) Cache(name string) Cache {
	poolName := m.defaultPool
	if p, ok := m.routes[name]; ok && p != "" {
		poolName = p
	} else if m.pools.Has(name) {
		// Allow addressing a pool directly by name.
		poolName = name
	}
	backend, ok := m.pools.byName[poolName]
	if !ok {
		// ValidatePools guarantees this never happens in normal operation;
		// fall back to default rather than panic to stay available.
		backend = m.pools.byName[m.defaultPool]
	}
	prefix := m.moduleID + "/" + name + "/"
	return Namespaced(backend, prefix)
}

func (m *moduleProvider) Names() []string { return m.pools.Names() }

// ValidatePools enforces fail-fast pool references at config load. referenced
// is every pool name named by a module's cache.pool; declared is every pool
// in the caches: block (the implicit default is always considered declared).
// Any reference missing from declared yields ErrConfig.
func ValidatePools(declared, referenced []string) error {
	have := make(map[string]struct{}, len(declared)+1)
	have[DefaultPool] = struct{}{}
	for _, d := range declared {
		have[d] = struct{}{}
	}
	var missing []string
	seen := make(map[string]struct{}, len(referenced))
	for _, r := range referenced {
		if r == "" {
			continue
		}
		if _, ok := have[r]; ok {
			continue
		}
		if _, dup := seen[r]; dup {
			continue
		}
		seen[r] = struct{}{}
		missing = append(missing, r)
	}
	if len(missing) == 0 {
		return nil
	}
	sort.Strings(missing)
	return fmt.Errorf("%w: undeclared cache pool(s) %v (declared: %v)", ErrConfig, missing, declared)
}
