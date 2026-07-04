// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package config_test

import (
	"errors"
	"testing"

	"github.com/mikeappsec/lightweightauth/internal/config"
	"github.com/mikeappsec/lightweightauth/pkg/module"

	_ "github.com/mikeappsec/lightweightauth/pkg/builtins"
)

// cachePoolBaseConfig is a minimal apikey+rbac AuthConfig used to exercise the
// caches: block wiring without depending on transport adapters.
func cachePoolBaseConfig() *config.AuthConfig {
	return &config.AuthConfig{
		Identifier: config.IdentifierFirstMatch,
		Identifiers: []config.ModuleSpec{{
			Name: "dev-apikey",
			Type: "apikey",
			Config: map[string]any{
				"headerName": "X-Api-Key",
				"static": map[string]any{
					"dev-admin-key": map[string]any{"subject": "alice", "roles": []any{"admin"}},
				},
			},
		}},
		Authorizers: []config.ModuleSpec{{
			Name: "rbac",
			Type: "rbac",
			Config: map[string]any{
				"rolesFrom": "claim:roles",
				"allow":     []any{"admin"},
			},
		}},
	}
}

// TestCompile_NoCachesBlock confirms configs that predate the module-native
// cache layer still compile (an implicit default pool is synthesized).
func TestCompile_NoCachesBlock(t *testing.T) {
	t.Parallel()
	eng, err := config.Compile(cachePoolBaseConfig())
	if err != nil {
		t.Fatalf("Compile without caches: %v", err)
	}
	t.Cleanup(eng.Close)
}

// TestCompile_ValidMemoryPool confirms a declared in-memory pool compiles.
func TestCompile_ValidMemoryPool(t *testing.T) {
	t.Parallel()
	ac := cachePoolBaseConfig()
	ac.Caches = []config.CachePoolSpec{
		{Name: "tokens", Backend: "memory", Size: 1024},
	}
	eng, err := config.Compile(ac)
	if err != nil {
		t.Fatalf("Compile with memory pool: %v", err)
	}
	t.Cleanup(eng.Close)
}

// TestCompile_DuplicatePoolName fails fast on a duplicate pool name.
func TestCompile_DuplicatePoolName(t *testing.T) {
	t.Parallel()
	ac := cachePoolBaseConfig()
	ac.Caches = []config.CachePoolSpec{
		{Name: "tokens", Backend: "memory"},
		{Name: "tokens", Backend: "memory"},
	}
	_, err := config.Compile(ac)
	if !errors.Is(err, module.ErrConfig) {
		t.Fatalf("expected ErrConfig for duplicate pool, got %v", err)
	}
}

// TestCompile_UnknownBackend fails fast on an unregistered backend.
func TestCompile_UnknownBackend(t *testing.T) {
	t.Parallel()
	ac := cachePoolBaseConfig()
	ac.Caches = []config.CachePoolSpec{
		{Name: "tokens", Backend: "does-not-exist"},
	}
	_, err := config.Compile(ac)
	if !errors.Is(err, module.ErrConfig) {
		t.Fatalf("expected ErrConfig for unknown backend, got %v", err)
	}
}

// TestCompile_EmptyPoolName fails fast on a blank pool name.
func TestCompile_EmptyPoolName(t *testing.T) {
	t.Parallel()
	ac := cachePoolBaseConfig()
	ac.Caches = []config.CachePoolSpec{
		{Name: "  ", Backend: "memory"},
	}
	_, err := config.Compile(ac)
	if !errors.Is(err, module.ErrConfig) {
		t.Fatalf("expected ErrConfig for empty pool name, got %v", err)
	}
}

// TestCompile_ModuleSelectsDeclaredPool confirms a module may route its caches
// to a declared pool via the cache.pool selector, and that the loader strips
// the cache key so the module's own CheckUnknownKeys guard stays intact.
func TestCompile_ModuleSelectsDeclaredPool(t *testing.T) {
	t.Parallel()
	ac := cachePoolBaseConfig()
	ac.Caches = []config.CachePoolSpec{
		{Name: "tokens", Backend: "memory", Size: 1024},
	}
	ac.Identifiers[0].Config["cache"] = map[string]any{"pool": "tokens"}
	eng, err := config.Compile(ac)
	if err != nil {
		t.Fatalf("Compile with module pool selector: %v", err)
	}
	t.Cleanup(eng.Close)
}

// TestCompile_UndeclaredPoolReference fails fast when a module selects a pool
// that was never declared in the caches: block.
func TestCompile_UndeclaredPoolReference(t *testing.T) {
	t.Parallel()
	ac := cachePoolBaseConfig()
	ac.Identifiers[0].Config["cache"] = map[string]any{"pool": "ghost"}
	_, err := config.Compile(ac)
	if !errors.Is(err, module.ErrConfig) {
		t.Fatalf("expected ErrConfig for undeclared pool reference, got %v", err)
	}
}

// TestCompile_DefaultPoolAlwaysSelectable confirms a module may explicitly
// select the implicit "default" pool without declaring it.
func TestCompile_DefaultPoolAlwaysSelectable(t *testing.T) {
	t.Parallel()
	ac := cachePoolBaseConfig()
	ac.Identifiers[0].Config["cache"] = map[string]any{"pool": "default"}
	eng, err := config.Compile(ac)
	if err != nil {
		t.Fatalf("Compile selecting default pool: %v", err)
	}
	t.Cleanup(eng.Close)
}

// TestCompile_CacheSelectorNotAMapping rejects a malformed cache: selector.
func TestCompile_CacheSelectorNotAMapping(t *testing.T) {
	t.Parallel()
	ac := cachePoolBaseConfig()
	ac.Identifiers[0].Config["cache"] = "tokens"
	_, err := config.Compile(ac)
	if !errors.Is(err, module.ErrConfig) {
		t.Fatalf("expected ErrConfig for non-mapping cache selector, got %v", err)
	}
}

// TestCompile_CachePoolNotAString rejects a non-string cache.pool value.
func TestCompile_CachePoolNotAString(t *testing.T) {
	t.Parallel()
	ac := cachePoolBaseConfig()
	ac.Identifiers[0].Config["cache"] = map[string]any{"pool": 42}
	_, err := config.Compile(ac)
	if !errors.Is(err, module.ErrConfig) {
		t.Fatalf("expected ErrConfig for non-string cache.pool, got %v", err)
	}
}
