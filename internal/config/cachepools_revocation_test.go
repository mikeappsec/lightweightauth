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

// TestCompile_RevocationStoreFromPool confirms the revocation store can draw
// its backend from a declared pool via revocation.pool (P6).
func TestCompile_RevocationStoreFromPool(t *testing.T) {
	t.Parallel()
	ac := cachePoolBaseConfig()
	ac.Caches = []config.CachePoolSpec{
		{Name: "revs", Backend: "memory", Size: 1024},
	}
	ac.Revocation = &config.RevocationSpec{
		Enabled: true,
		Pool:    "revs",
	}
	eng, err := config.Compile(ac)
	if err != nil {
		t.Fatalf("Compile with pool-routed revocation store: %v", err)
	}
	t.Cleanup(eng.Close)
}

// TestCompile_RevocationPoolUndeclared fails fast when revocation.pool names a
// pool that was never declared in the caches: block.
func TestCompile_RevocationPoolUndeclared(t *testing.T) {
	t.Parallel()
	ac := cachePoolBaseConfig()
	ac.Revocation = &config.RevocationSpec{
		Enabled: true,
		Pool:    "ghost",
	}
	_, err := config.Compile(ac)
	if !errors.Is(err, module.ErrConfig) {
		t.Fatalf("expected ErrConfig for undeclared revocation pool, got %v", err)
	}
}

// TestCompile_RevocationPoolConflictsWithBackend rejects mixing revocation.pool
// with the inline backend fields it supersedes.
func TestCompile_RevocationPoolConflictsWithBackend(t *testing.T) {
	t.Parallel()
	ac := cachePoolBaseConfig()
	ac.Caches = []config.CachePoolSpec{
		{Name: "revs", Backend: "memory"},
	}
	ac.Revocation = &config.RevocationSpec{
		Enabled: true,
		Pool:    "revs",
		Backend: "memory",
	}
	_, err := config.Compile(ac)
	if !errors.Is(err, module.ErrConfig) {
		t.Fatalf("expected ErrConfig for revocation.pool + revocation.backend, got %v", err)
	}
}
