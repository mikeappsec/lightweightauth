// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package module_test

import (
	"context"
	"errors"
	"testing"

	"github.com/mikeappsec/lightweightauth/pkg/module"
)

// ─── Generic Registry Tests ──────────────────────────────────────

type fakeIdentifier struct{ n string }

func (f *fakeIdentifier) Name() string { return f.n }
func (f *fakeIdentifier) Identify(context.Context, *module.Request) (*module.Identity, error) {
	return &module.Identity{Subject: "test"}, nil
}

func TestRegistry_RegisterAndBuild(t *testing.T) {
	r := module.NewRegistry[module.Identifier]("test-ident")
	r.Register("fake", func(name string, cfg map[string]any) (module.Identifier, error) {
		return &fakeIdentifier{n: name}, nil
	})

	id, err := r.Build("fake", "my-fake", nil)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if id.Name() != "my-fake" {
		t.Errorf("Name() = %q, want %q", id.Name(), "my-fake")
	}
}

func TestRegistry_Build_UnknownType(t *testing.T) {
	r := module.NewRegistry[module.Identifier]("test-ident")
	_, err := r.Build("nonexistent", "x", nil)
	if err == nil {
		t.Fatal("expected error for unknown type")
	}
	if !errors.Is(err, module.ErrConfig) {
		t.Errorf("expected ErrConfig, got: %v", err)
	}
}

func TestRegistry_Register_PanicOnDuplicate(t *testing.T) {
	r := module.NewRegistry[module.Identifier]("test-ident")
	factory := func(name string, cfg map[string]any) (module.Identifier, error) {
		return &fakeIdentifier{n: name}, nil
	}
	r.Register("dup", factory)

	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic on duplicate registration")
		}
	}()
	r.Register("dup", factory) // should panic
}

func TestRegistry_Types(t *testing.T) {
	r := module.NewRegistry[module.Identifier]("test-ident")
	r.Register("beta", func(string, map[string]any) (module.Identifier, error) {
		return &fakeIdentifier{}, nil
	})
	r.Register("alpha", func(string, map[string]any) (module.Identifier, error) {
		return &fakeIdentifier{}, nil
	})

	types := r.Types()
	if len(types) != 2 {
		t.Fatalf("Types() len = %d, want 2", len(types))
	}
	if types[0] != "alpha" || types[1] != "beta" {
		t.Errorf("Types() = %v, want [alpha beta]", types)
	}
}

func TestRegistry_Has(t *testing.T) {
	r := module.NewRegistry[module.Identifier]("test-ident")
	r.Register("exists", func(string, map[string]any) (module.Identifier, error) {
		return &fakeIdentifier{}, nil
	})
	if !r.Has("exists") {
		t.Error("Has(exists) = false, want true")
	}
	if r.Has("missing") {
		t.Error("Has(missing) = true, want false")
	}
}

// ─── DecodeConfig Tests ──────────────────────────────────────────

type sampleConfig struct {
	Name    string   `yaml:"name" json:"name"`
	Port    int      `yaml:"port" json:"port"`
	Enabled bool     `yaml:"enabled" json:"enabled"`
	Tags    []string `yaml:"tags" json:"tags"`
}

func TestDecodeConfig_Success(t *testing.T) {
	raw := map[string]any{
		"name":    "test",
		"port":    8080,
		"enabled": true,
		"tags":    []any{"a", "b"},
	}
	var cfg sampleConfig
	if err := module.DecodeConfig(raw, &cfg); err != nil {
		t.Fatalf("DecodeConfig: %v", err)
	}
	if cfg.Name != "test" {
		t.Errorf("Name = %q, want %q", cfg.Name, "test")
	}
	if cfg.Port != 8080 {
		t.Errorf("Port = %d, want 8080", cfg.Port)
	}
	if !cfg.Enabled {
		t.Error("Enabled = false, want true")
	}
	if len(cfg.Tags) != 2 || cfg.Tags[0] != "a" || cfg.Tags[1] != "b" {
		t.Errorf("Tags = %v, want [a b]", cfg.Tags)
	}
}

func TestDecodeConfig_UnknownKeys(t *testing.T) {
	raw := map[string]any{
		"name":    "test",
		"typo":   "oops",
	}
	var cfg sampleConfig
	err := module.DecodeConfig(raw, &cfg)
	if err == nil {
		t.Fatal("expected error for unknown key")
	}
	if !errors.Is(err, module.ErrConfig) {
		t.Errorf("expected ErrConfig, got: %v", err)
	}
}

func TestDecodeConfig_FloatToInt(t *testing.T) {
	// YAML unmarshals numbers as float64; DecodeConfig should coerce.
	raw := map[string]any{
		"name": "svc",
		"port": float64(9090),
	}
	var cfg sampleConfig
	if err := module.DecodeConfig(raw, &cfg); err != nil {
		t.Fatalf("DecodeConfig: %v", err)
	}
	if cfg.Port != 9090 {
		t.Errorf("Port = %d, want 9090", cfg.Port)
	}
}

func TestDecodeConfig_EmptyMap(t *testing.T) {
	raw := map[string]any{}
	var cfg sampleConfig
	if err := module.DecodeConfig(raw, &cfg); err != nil {
		t.Fatalf("DecodeConfig: %v", err)
	}
	// All zero values.
	if cfg.Name != "" || cfg.Port != 0 || cfg.Enabled {
		t.Errorf("expected zero values, got: %+v", cfg)
	}
}

// ─── Decorated Registry Tests ────────────────────────────────────

func TestDecoratedRegistry_AppliesDecorators(t *testing.T) {
	r := module.NewDecoratedRegistry[module.Identifier]("test-ident")
	r.Register("base", func(name string, cfg map[string]any) (module.Identifier, error) {
		return &fakeIdentifier{n: name}, nil
	})

	// Decorator that prefixes the name.
	r.AddDecorator(func(id module.Identifier) module.Identifier {
		return &fakeIdentifier{n: "decorated-" + id.Name()}
	})

	id, err := r.Build("base", "original", nil)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if id.Name() != "decorated-original" {
		t.Errorf("Name() = %q, want %q", id.Name(), "decorated-original")
	}
}
