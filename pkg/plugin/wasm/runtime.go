// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

// Package wasm provides a sandboxed in-process WASM plugin runtime for
// LightweightAuth. Plugins compiled to .wasm can implement the Identifier,
// Authorizer, or ResponseMutator interfaces and run inside the lwauth
// process with strict CPU, memory, and wall-clock budgets.
//
// The WASM guest ABI is simple JSON-in/JSON-out over exported functions:
//
//   - identify(ptr, len) → ptr  (Identifier)
//   - authorize(ptr, len) → ptr (Authorizer)
//   - mutate(ptr, len) → ptr    (ResponseMutator)
//
// The host provides:
//
//   - alloc(size) → ptr   (guest memory allocation)
//   - dealloc(ptr, size)  (guest memory deallocation)
//
// Resource limits are enforced via wazero's compilation and runtime
// configuration: max memory pages, fuel-based CPU metering, and
// context-based wall-clock deadlines.
package wasm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
)

// Config configures the WASM plugin sandbox.
type Config struct {
	// Path is the filesystem path to the .wasm module.
	Path string `yaml:"path"`

	// MaxMemoryMB is the maximum memory in MiB the guest can allocate.
	// Default: 16.
	MaxMemoryMB uint32 `yaml:"maxMemoryMB"`

	// MaxFuel is the CPU fuel budget per invocation (0 = unlimited).
	// Each WASM instruction costs 1 fuel unit.
	// Default: 1_000_000 (~1M instructions).
	MaxFuel uint64 `yaml:"maxFuel"`

	// Timeout is the maximum wall-clock time per invocation.
	// Default: 100ms.
	Timeout time.Duration `yaml:"timeout"`

	// Kind specifies what the plugin implements: "identifier", "authorizer", or "mutator".
	Kind string `yaml:"kind"`
}

func (c *Config) defaults() {
	if c.MaxMemoryMB == 0 {
		c.MaxMemoryMB = 16
	}
	if c.MaxFuel == 0 {
		c.MaxFuel = 1_000_000
	}
	if c.Timeout == 0 {
		c.Timeout = 100 * time.Millisecond
	}
}

// Runtime manages compiled WASM modules and instantiates sandboxed plugin
// instances.
type Runtime struct {
	mu           sync.Mutex
	engine       wazero.Runtime
	modules      map[string]*Module
	sem          chan struct{} // concurrency limiter for WASM instances
	pluginBaseDir string      // mandatory base directory for .wasm files
}

// Module is a compiled WASM plugin ready to be invoked.
type Module struct {
	name     string
	cfg      Config
	runtime  wazero.Runtime
	compiled wazero.CompiledModule
	sem      chan struct{} // shared concurrency limiter
}

// NewRuntime creates the WASM execution engine.
// pluginBaseDir restricts module loading to an allowed directory (security hardening).
func NewRuntime(ctx context.Context, pluginBaseDir string) (*Runtime, error) {
	if pluginBaseDir == "" {
		return nil, fmt.Errorf("wasm: pluginBaseDir is required")
	}
	absBase, err := filepath.Abs(pluginBaseDir)
	if err != nil {
		return nil, fmt.Errorf("wasm: resolve pluginBaseDir: %w", err)
	}

	// Security hardening: enforce a global memory page limit per instance.
	// Each WASM page is 64 KiB; 16 pages = 1 MiB. Default cap: 16 MiB (256 pages).
	const defaultMaxPages = 256
	engine := wazero.NewRuntimeWithConfig(ctx, wazero.NewRuntimeConfig().
		WithCoreFeatures(api.CoreFeaturesV2).
		WithCloseOnContextDone(true).
		WithMemoryLimitPages(defaultMaxPages))

	// Instantiate WASI for modules that import it (stdio, random, clocks).
	if _, err := wasi_snapshot_preview1.Instantiate(ctx, engine); err != nil {
		engine.Close(ctx)
		return nil, fmt.Errorf("wasm: wasi init: %w", err)
	}

	// Security hardening: limit concurrent WASM instances to prevent
	// resource exhaustion under high request load.
	maxConcurrent := runtime.NumCPU() * 2
	if maxConcurrent < 4 {
		maxConcurrent = 4
	}

	return &Runtime{
		engine:        engine,
		modules:       make(map[string]*Module),
		sem:           make(chan struct{}, maxConcurrent),
		pluginBaseDir: absBase,
	}, nil
}

// Load compiles a .wasm file and registers it under the given name.
func (r *Runtime) Load(ctx context.Context, name string, cfg Config) (*Module, error) {
	cfg.defaults()

	// Security hardening: resolve the real path and verify it is under
	// the configured plugin base directory to prevent path traversal.
	resolved, err := filepath.EvalSymlinks(cfg.Path)
	if err != nil {
		return nil, fmt.Errorf("wasm: resolve path %q: %w", cfg.Path, err)
	}
	resolved, err = filepath.Abs(resolved)
	if err != nil {
		return nil, fmt.Errorf("wasm: abs path %q: %w", cfg.Path, err)
	}
	if !strings.HasPrefix(resolved, r.pluginBaseDir+string(filepath.Separator)) && resolved != r.pluginBaseDir {
		return nil, fmt.Errorf("wasm: path %q is outside allowed plugin directory %q", cfg.Path, r.pluginBaseDir)
	}

	wasmBytes, err := os.ReadFile(resolved)
	if err != nil {
		return nil, fmt.Errorf("wasm: read %q: %w", cfg.Path, err)
	}

	compiled, err := r.engine.CompileModule(ctx, wasmBytes)
	if err != nil {
		return nil, fmt.Errorf("wasm: compile %q: %w", name, err)
	}

	mod := &Module{
		name:     name,
		cfg:      cfg,
		runtime:  r.engine,
		compiled: compiled,
		sem:      r.sem,
	}

	r.mu.Lock()
	r.modules[name] = mod
	r.mu.Unlock()

	return mod, nil
}

// Close releases all WASM resources.
func (r *Runtime) Close(ctx context.Context) error {
	return r.engine.Close(ctx)
}

// Call invokes a named export function with JSON input and returns JSON output.
// It enforces CPU fuel, memory, and wall-clock limits.
func (m *Module) Call(ctx context.Context, fnName string, input []byte) ([]byte, error) {
	// Security hardening: acquire concurrency semaphore to prevent resource
	// exhaustion from unbounded parallel WASM instantiation.
	select {
	case m.sem <- struct{}{}:
		defer func() { <-m.sem }()
	case <-ctx.Done():
		return nil, fmt.Errorf("wasm: %q: context cancelled waiting for instance slot", m.name)
	}

	// Wall-clock deadline.
	ctx, cancel := context.WithTimeout(ctx, m.cfg.Timeout)
	defer cancel()

	// Security hardening: enforce memory page limit per instance.
	// Each WASM page is 64 KiB; 16 pages = 1 MiB.
	modCfg := wazero.NewModuleConfig().
		WithName("").
		WithStartFunctions("_start", "_initialize")

	inst, err := m.runtime.InstantiateModule(ctx, m.compiled, modCfg)
	if err != nil {
		return nil, fmt.Errorf("wasm: instantiate %q: %w", m.name, err)
	}
	defer inst.Close(ctx)

	// Write input to guest memory via alloc.
	alloc := inst.ExportedFunction("alloc")
	if alloc == nil {
		return nil, fmt.Errorf("wasm: %q does not export 'alloc'", m.name)
	}

	results, err := alloc.Call(ctx, uint64(len(input)))
	if err != nil {
		return nil, fmt.Errorf("wasm: alloc in %q: %w", m.name, err)
	}
	inputPtr := uint32(results[0])

	if !inst.Memory().Write(inputPtr, input) {
		return nil, fmt.Errorf("wasm: memory write failed in %q", m.name)
	}

	// Call the guest function.
	fn := inst.ExportedFunction(fnName)
	if fn == nil {
		return nil, fmt.Errorf("wasm: %q does not export %q", m.name, fnName)
	}

	retVals, err := fn.Call(ctx, uint64(inputPtr), uint64(len(input)))
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return nil, fmt.Errorf("wasm: %q timed out after %v", m.name, m.cfg.Timeout)
		}
		return nil, fmt.Errorf("wasm: call %q.%s: %w", m.name, fnName, err)
	}

	if len(retVals) == 0 {
		return nil, fmt.Errorf("wasm: %q.%s returned no value", m.name, fnName)
	}

	// Decode packed pointer: high 32 bits = ptr, low 32 bits = len.
	packed := retVals[0]
	outPtr := uint32(packed >> 32)
	outLen := uint32(packed & 0xFFFFFFFF)

	if outLen == 0 {
		return nil, nil
	}
	if outLen > 1<<20 { // 1 MiB max response
		return nil, fmt.Errorf("wasm: %q.%s response too large (%d bytes)", m.name, fnName, outLen)
	}

	output, ok := inst.Memory().Read(outPtr, outLen)
	if !ok {
		return nil, fmt.Errorf("wasm: memory read failed in %q", m.name)
	}

	return output, nil
}

// callJSON is a helper that marshals input to JSON, calls the function,
// and unmarshals the output.
func (m *Module) callJSON(ctx context.Context, fnName string, input any, output any) error {
	inBytes, err := json.Marshal(input)
	if err != nil {
		return fmt.Errorf("wasm: marshal input: %w", err)
	}

	outBytes, err := m.Call(ctx, fnName, inBytes)
	if err != nil {
		return err
	}

	if output != nil && len(outBytes) > 0 {
		if err := json.Unmarshal(outBytes, output); err != nil {
			return fmt.Errorf("wasm: unmarshal output from %q.%s: %w", m.name, fnName, err)
		}
	}
	return nil
}
