# pkg/plugin/wasm

Sandboxed in-process WASM plugin runtime using wazero.

## Usage

```go
import (
    "context"
    _ "github.com/mikeappsec/lightweightauth/pkg/plugin/wasm"
    "github.com/mikeappsec/lightweightauth/pkg/module"
)

identifier, err := module.BuildIdentifier("wasm", "custom-check", map[string]any{
    "path":        "/etc/lwauth/plugins/wasm/check.wasm",
    "maxMemoryMB": 32,   // parsed but NOT enforced — see below
    "maxFuel":     2000000, // parsed but NOT enforced — see below
    "timeout":     "200ms", // the only real budget
})
```

## Configuration

`.wasm` files must live under a plugin base directory — default
`/etc/lwauth/plugins/wasm`, overridable only via the
`LWAUTH_WASM_PLUGIN_DIR` environment variable, not a config field.

```yaml
identifiers:
  - name: custom-header-check
    type: wasm
    config:
      path: /etc/lwauth/plugins/wasm/check.wasm
      maxMemoryMB: 32
      maxFuel: 2000000
      timeout: 200ms
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `path` | string | *required* | Filesystem path to `.wasm` module — must resolve under the plugin base directory |
| `maxMemoryMB` | uint32 | `16` | **Parsed but not enforced.** The real limit is a hardcoded, engine-wide 16 MiB (`WithMemoryLimitPages(256)`), applied once for every module regardless of this value |
| `maxFuel` | uint64 | `1000000` | **Parsed but not enforced.** No `WithFuel`/fuel-related wazero API call exists anywhere in `runtime.go` — fuel metering has no effect |
| `timeout` | duration | `100ms` | Wall-clock deadline per invocation — the only real budget |
| `kind` | string | — | Plugin kind (identifier/authorizer/mutator) |

## Guest ABI

Plugins must export the following functions:

| Export | Signature | Description |
|--------|-----------|-------------|
| `alloc(size) → ptr` | `(i32) → i32` | Allocate guest memory |
| `identify(ptr, len) → packed_ptr` | `(i32, i32) → i64` | Identifier entry point |
| `authorize(ptr, len) → packed_ptr` | `(i32, i32) → i64` | Authorizer entry point |
| `mutate(ptr, len) → packed_ptr` | `(i32, i32) → i64` | Mutator entry point |

Return value is a packed pointer: `(outPtr << 32) | outLen`.

Input/output format: JSON.

## Features

- Pure-Go WASM runtime via wazero (no CGO, no system dependencies)
- CPU budget via fuel metering: **not implemented** — `maxFuel` has no effect
- Memory cap: **not per-module** — a single hardcoded 16 MiB engine-wide limit applies regardless of `maxMemoryMB`
- Wall-clock deadline with `context.WithTimeout` + `WithCloseOnContextDone`
- 1 MiB max response size cap
- WASI preview1 available for stdlib needs (clocks, random)
- Module compiled once at load; fresh instance per invocation (no cross-request state leakage)
- Registers as type `"wasm"` for all three pipeline stages

## How It Works

1. At config time, reads `.wasm` file, compiles it via wazero (validates structure, AOT compiles).
2. On each request, creates a fresh module instance with resource limits.
3. Writes JSON input to guest memory via the `alloc` export.
4. Calls the appropriate guest function (`identify`/`authorize`/`mutate`).
5. Reads the JSON output from guest memory using the returned packed pointer.
6. Deserializes the response into the appropriate module interface type.
7. Instance is closed after each call (no state persistence across requests).

## Thread Safety

| Type | Safe for concurrent use? | Notes |
|------|--------------------------|-------|
| `Runtime` | ✅ Yes | `sync.Mutex` protects modules map; channel-based concurrency limiter bounds WASM instances |
| `Module` | ✅ Yes | Channel semaphore bounds concurrent invocations; each `Call` instantiates a fresh WASM instance |
| `Identifier` | ✅ Yes | Stateless wrapper; delegates to `Module.Call` |
| `Authorizer` | ✅ Yes | Stateless wrapper; delegates to `Module.Call` |
| `Mutator` | ✅ Yes | Stateless wrapper; delegates to `Module.Call` |

The global `Runtime` singleton is initialized via `sync.Once`. Each `Module.Call` creates a fresh WASM instance (no shared instance state), so after acquiring a semaphore slot, execution is fully isolated.
