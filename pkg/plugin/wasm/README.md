# pkg/plugin/wasm

Sandboxed in-process WASM plugin runtime using wazero.

## Usage

```go
import (
    "context"
    _ "github.com/mikeappsec/lightweightauth/pkg/plugin/wasm"
    "github.com/mikeappsec/lightweightauth/pkg/module"
)

identifier, err := module.BuildIdentifier("custom-check", "wasm", map[string]any{
    "path":        "/opt/plugins/check.wasm",
    "maxMemoryMB": 32,
    "maxFuel":     2000000,
    "timeout":     "200ms",
})
```

## Configuration

```yaml
identifiers:
  - name: custom-header-check
    type: wasm
    config:
      path: /opt/plugins/check.wasm
      maxMemoryMB: 32
      maxFuel: 2000000
      timeout: 200ms
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `path` | string | *required* | Filesystem path to `.wasm` module |
| `maxMemoryMB` | uint32 | `16` | Maximum guest memory (MiB) |
| `maxFuel` | uint64 | `1000000` | CPU fuel budget per invocation |
| `timeout` | duration | `100ms` | Wall-clock deadline per invocation |
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
- CPU budget via fuel metering (per-instruction accounting)
- Memory cap enforced per module instance
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
