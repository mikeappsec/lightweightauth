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

// TestCompile_DecisionCacheFromPool confirms the decision cache can draw its
// backend from a declared pool via cache.pool instead of inline backend fields.
func TestCompile_DecisionCacheFromPool(t *testing.T) {
	t.Parallel()
	ac := cachePoolBaseConfig()
	ac.Caches = []config.CachePoolSpec{
		{Name: "decisions", Backend: "memory", Size: 1024},
	}
	ac.Cache = &config.CacheSpec{
		TTL:  "1m",
		Key:  []string{"sub"},
		Pool: "decisions",
	}
	eng, err := config.Compile(ac)
	if err != nil {
		t.Fatalf("Compile with pool-routed decision cache: %v", err)
	}
	t.Cleanup(eng.Close)
}

// TestCompile_DecisionCachePoolUndeclared fails fast when cache.pool names a
// pool that was never declared in the caches: block.
func TestCompile_DecisionCachePoolUndeclared(t *testing.T) {
	t.Parallel()
	ac := cachePoolBaseConfig()
	ac.Cache = &config.CacheSpec{
		TTL:  "1m",
		Key:  []string{"sub"},
		Pool: "ghost",
	}
	_, err := config.Compile(ac)
	if !errors.Is(err, module.ErrConfig) {
		t.Fatalf("expected ErrConfig for undeclared decision-cache pool, got %v", err)
	}
}

// TestCompile_DecisionCachePoolConflictsWithBackend rejects mixing cache.pool
// with the inline backend fields it supersedes.
func TestCompile_DecisionCachePoolConflictsWithBackend(t *testing.T) {
	t.Parallel()
	ac := cachePoolBaseConfig()
	ac.Caches = []config.CachePoolSpec{
		{Name: "decisions", Backend: "memory"},
	}
	ac.Cache = &config.CacheSpec{
		TTL:     "1m",
		Key:     []string{"sub"},
		Pool:    "decisions",
		Backend: "memory",
	}
	_, err := config.Compile(ac)
	if !errors.Is(err, module.ErrConfig) {
		t.Fatalf("expected ErrConfig for cache.pool + cache.backend, got %v", err)
	}
}
