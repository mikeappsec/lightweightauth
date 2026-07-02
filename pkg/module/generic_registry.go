// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package module

import (
	"fmt"
	"sort"
	"sync"
)

// ModuleFactory is the generic, dependency-aware factory signature. Every
// built-in module registers one (directly, or via the legacy [SimpleFactory]
// shim) in its init(). The deps argument carries host-provided capabilities
// such as cache pools (see [Deps]); modules that need none can register a
// [SimpleFactory] instead and ignore it.
type ModuleFactory[T any] func(name string, cfg map[string]any, deps Deps) (T, error)

// SimpleFactory is the legacy, no-dependencies factory signature. It is kept
// so modules that do not consume host dependencies can register without
// boilerplate; [Registry.RegisterSimple] adapts it to a [ModuleFactory].
type SimpleFactory[T any] func(name string, cfg map[string]any) (T, error)

// Registry is a type-safe, concurrency-safe registry of module factories
// keyed by type name (e.g. "jwt", "apikey", "cel"). It replaces the
// three hand-coded parallel maps that previously existed in registry.go.
//
// Usage:
//
//	var Identifiers = NewRegistry[Identifier]("identifier")
//	Identifiers.Register("jwt", jwtFactory)
//	id, err := Identifiers.Build("jwt", "my-jwt", cfg)
type Registry[T any] struct {
	mu        sync.RWMutex
	kind      string
	factories map[string]ModuleFactory[T]
}

// NewRegistry creates an empty registry for the given module kind.
func NewRegistry[T any](kind string) *Registry[T] {
	return &Registry[T]{
		kind:      kind,
		factories: make(map[string]ModuleFactory[T]),
	}
}

// Register installs a deps-aware factory under the given type name. It
// panics on duplicate registration so that init-time wiring mistakes surface
// immediately at process start.
func (r *Registry[T]) Register(typeName string, f ModuleFactory[T]) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, dup := r.factories[typeName]; dup {
		panic(fmt.Sprintf("module: %s %q already registered", r.kind, typeName))
	}
	r.factories[typeName] = f
}

// RegisterSimple installs a legacy no-dependencies factory, adapting it to a
// deps-aware [ModuleFactory] by discarding the injected [Deps]. Use it for
// modules that do not consume host capabilities.
func (r *Registry[T]) RegisterSimple(typeName string, f SimpleFactory[T]) {
	r.Register(typeName, func(name string, cfg map[string]any, _ Deps) (T, error) {
		return f(name, cfg)
	})
}

// Build looks up a factory by type name, invokes it with the given instance
// name, config, and host dependencies, and returns the constructed module.
func (r *Registry[T]) Build(typeName, instanceName string, cfg map[string]any, deps Deps) (T, error) {
	r.mu.RLock()
	f, ok := r.factories[typeName]
	r.mu.RUnlock()
	if !ok {
		var zero T
		return zero, fmt.Errorf("%w: unknown %s type %q", ErrConfig, r.kind, typeName)
	}
	return f(instanceName, cfg, deps)
}

// Types returns the registered type names in sorted order.
func (r *Registry[T]) Types() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	names := make([]string, 0, len(r.factories))
	for n := range r.factories {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// Has reports whether a factory is registered under the given type name.
func (r *Registry[T]) Has(typeName string) bool {
	r.mu.RLock()
	_, ok := r.factories[typeName]
	r.mu.RUnlock()
	return ok
}

// Global registries — one per pipeline stage. These are the canonical
// singletons that modules register into via their init() functions.
var (
	Identifiers = NewRegistry[Identifier]("identifier")
	Authorizers = NewRegistry[Authorizer]("authorizer")
	Mutators    = NewRegistry[ResponseMutator]("mutator")
)
