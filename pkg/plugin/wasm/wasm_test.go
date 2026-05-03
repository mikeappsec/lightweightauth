// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package wasm

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// testWASM is a minimal WASM module (WAT format compiled).
// For real tests we'd compile a guest, but for unit tests we verify
// error paths and config parsing.

func TestConfig_Defaults(t *testing.T) {
	c := Config{Path: "/tmp/test.wasm"}
	c.defaults()

	if c.MaxMemoryMB != 16 {
		t.Errorf("MaxMemoryMB = %d, want 16", c.MaxMemoryMB)
	}
	if c.MaxFuel != 1_000_000 {
		t.Errorf("MaxFuel = %d, want 1000000", c.MaxFuel)
	}
	if c.Timeout != 100*time.Millisecond {
		t.Errorf("Timeout = %v, want 100ms", c.Timeout)
	}
}

func TestConfig_CustomValues(t *testing.T) {
	c := Config{
		Path:        "/tmp/test.wasm",
		MaxMemoryMB: 32,
		MaxFuel:     5_000_000,
		Timeout:     500 * time.Millisecond,
	}
	c.defaults()

	if c.MaxMemoryMB != 32 {
		t.Errorf("MaxMemoryMB = %d, want 32", c.MaxMemoryMB)
	}
	if c.MaxFuel != 5_000_000 {
		t.Errorf("MaxFuel = %d, want 5000000", c.MaxFuel)
	}
	if c.Timeout != 500*time.Millisecond {
		t.Errorf("Timeout = %v, want 500ms", c.Timeout)
	}
}

func TestNewRuntime(t *testing.T) {
	ctx := context.Background()
	rt, err := NewRuntime(ctx)
	if err != nil {
		t.Fatalf("NewRuntime: %v", err)
	}
	defer rt.Close(ctx)
}

func TestLoad_MissingFile(t *testing.T) {
	ctx := context.Background()
	rt, err := NewRuntime(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Close(ctx)

	_, err = rt.Load(ctx, "missing", Config{Path: "/nonexistent/module.wasm"})
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLoad_InvalidWasm(t *testing.T) {
	ctx := context.Background()
	rt, err := NewRuntime(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Close(ctx)

	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.wasm")
	os.WriteFile(bad, []byte("not a wasm module"), 0644)

	_, err = rt.Load(ctx, "bad", Config{Path: bad})
	if err == nil {
		t.Fatal("expected error for invalid wasm")
	}
}

func TestParseConfig_Valid(t *testing.T) {
	cfg := map[string]any{
		"path":        "/opt/plugins/check.wasm",
		"maxMemoryMB": float64(32),
		"maxFuel":     float64(2000000),
		"timeout":     "200ms",
		"kind":        "identifier",
	}
	c, err := parseConfig(cfg)
	if err != nil {
		t.Fatalf("parseConfig: %v", err)
	}
	if c.Path != "/opt/plugins/check.wasm" {
		t.Errorf("Path = %q", c.Path)
	}
	if c.MaxMemoryMB != 32 {
		t.Errorf("MaxMemoryMB = %d", c.MaxMemoryMB)
	}
	if c.MaxFuel != 2_000_000 {
		t.Errorf("MaxFuel = %d", c.MaxFuel)
	}
	if c.Timeout != 200*time.Millisecond {
		t.Errorf("Timeout = %v", c.Timeout)
	}
	if c.Kind != "identifier" {
		t.Errorf("Kind = %q", c.Kind)
	}
}

func TestParseConfig_MissingPath(t *testing.T) {
	_, err := parseConfig(map[string]any{})
	if err == nil {
		t.Fatal("expected error for missing path")
	}
}

func TestParseConfig_InvalidTimeout(t *testing.T) {
	_, err := parseConfig(map[string]any{
		"path":    "/tmp/x.wasm",
		"timeout": "not-a-duration",
	})
	if err == nil {
		t.Fatal("expected error for invalid timeout")
	}
}

// TestCall_NoAllocExport verifies error when module lacks alloc export.
func TestCall_NoAllocExport(t *testing.T) {
	ctx := context.Background()
	rt, err := NewRuntime(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Close(ctx)

	// Minimal valid wasm module (empty, no exports).
	// Magic + version + empty sections.
	minWasm := []byte{
		0x00, 0x61, 0x73, 0x6d, // magic
		0x01, 0x00, 0x00, 0x00, // version 1
	}
	dir := t.TempDir()
	p := filepath.Join(dir, "empty.wasm")
	os.WriteFile(p, minWasm, 0644)

	mod, err := rt.Load(ctx, "empty", Config{Path: p})
	if err != nil {
		t.Fatal(err)
	}

	_, err = mod.Call(ctx, "identify", []byte(`{}`))
	if err == nil {
		t.Fatal("expected error for missing alloc export")
	}
}
