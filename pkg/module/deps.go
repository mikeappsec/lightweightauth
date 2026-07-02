// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package module

import (
	"context"
	"log/slog"

	"github.com/mikeappsec/lightweightauth/pkg/cache"
)

// Deps carries the runtime capabilities the host injects into every module
// at construction time. It is passed to deps-aware factories (see
// [ModuleFactory] and RegisterIdentifierWithDeps) so modules receive their
// dependencies through the constructor rather than via post-construction
// setters.
//
// Deps is a struct so new capabilities can be added as fields without
// re-breaking the factory signature. Today's fields:
//
//   - Caches  — the cache pools a module may draw named handles from.
//   - Logger  — the structured logger scoped to the engine.
//   - Ctx     — the engine-lifecycle context. Modules that start background
//     goroutines (JWKS pollers, refreshers) MUST bind them to Ctx so they
//     are cancelled when the engine is swapped on hot-reload; this closes
//     the leak where jwx.Cache pollers used context.Background().
//
// Future additive fields (Metrics, Clock, Tracer, Secrets) extend this
// struct without breaking existing factories.
type Deps struct {
	// Caches provides namespaced cache handles. May be nil when caching is
	// not configured; modules MUST treat a nil Caches as "no cache" and fall
	// back to cache.NoOpCache() rather than panicking.
	Caches cache.Provider

	// Logger is the engine-scoped structured logger. May be nil; modules
	// should default to slog.Default() when so.
	Logger *slog.Logger

	// Ctx is the engine-lifecycle context. May be nil for legacy callers;
	// modules that start goroutines should default to context.Background()
	// only as a last resort.
	Ctx context.Context
}

// CacheProvider returns d.Caches, or a no-op provider when none was injected,
// so callers never need a nil check before requesting a handle.
func (d Deps) CacheProvider() cache.Provider {
	if d.Caches != nil {
		return d.Caches
	}
	return noopProvider{}
}

// noopProvider is the zero-dependency fallback returned when no cache pools
// are configured. Every handle it returns is a no-op cache.
type noopProvider struct{}

func (noopProvider) Cache(string) cache.Cache { return cache.NoOpCache() }
func (noopProvider) Names() []string          { return nil }
