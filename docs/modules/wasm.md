# `wasm` — sandboxed WASM plugin runtime

Runs a WebAssembly module **in-process** via the pure-Go
[wazero](https://wazero.io/) runtime. Each invocation gets a fresh
instance with CPU, memory, and wall-clock budgets — no guest can
escape the sandbox or affect other requests.

**Source:** [pkg/plugin/wasm](https://github.com/mikeappsec/lightweightauth/tree/main/pkg/plugin/wasm/) — registered as `wasm` under all three module kinds.

## When to use

- You want **sandboxed extensibility** without the operational cost of
  a separate gRPC process per plugin.
- The logic is simple enough to express in a language that compiles to
  WASM (Rust, TinyGo, AssemblyScript, C).
- You need **deterministic resource limits** per invocation — fuel
  metering, memory cap, timeout.

**Don't use** if the plugin needs long-lived state, network access, or
file I/O — use [`grpc-plugin`](plugin-grpc.md) instead. WASM guests
run in a one-shot sandbox with no persistent state between invocations.

## Configuration

```yaml
identifiers:
  - name: custom-header-check
    type: wasm
    config:
      path: /opt/plugins/header-check.wasm
      maxMemoryMB: 32        # guest memory cap (MiB)
      maxFuel: 2000000       # CPU fuel budget per invocation
      timeout: 200ms         # wall-clock deadline
```

```yaml
authorizers:
  - name: policy-wasm
    type: wasm
    config:
      path: /opt/plugins/policy.wasm
      maxMemoryMB: 64
      maxFuel: 5000000
      timeout: 500ms
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `path` | string | *required* | Filesystem path to `.wasm` module |
| `maxMemoryMB` | uint32 | `16` | Maximum guest memory (MiB) |
| `maxFuel` | uint64 | `1000000` | CPU fuel budget (instructions) |
| `timeout` | duration | `100ms` | Wall-clock deadline per invocation |

## Guest ABI

Every WASM module must export:

| Export | Signature | Description |
|--------|-----------|-------------|
| `alloc(size) → ptr` | `(i32) → i32` | Allocate guest memory for input |
| `identify(ptr, len) → packed` | `(i32, i32) → i64` | Identifier entry point |
| `authorize(ptr, len) → packed` | `(i32, i32) → i64` | Authorizer entry point |
| `mutate(ptr, len) → packed` | `(i32, i32) → i64` | Mutator entry point |

Only export the function(s) matching the module kind you intend.

### Input/Output format

**Input** (JSON written to guest memory):

```json
{
  "request": {
    "method": "GET",
    "host": "api.example.com",
    "path": "/users/123",
    "headers": {"authorization": ["Bearer ..."]},
    "query": {"page": ["1"]}
  },
  "identity": {
    "subject": "alice",
    "source": "jwt",
    "claims": {"roles": ["admin"]}
  }
}
```

**Output** (JSON read from guest memory):

For identifiers:
```json
{"subject": "alice", "claims": {"roles": ["admin"]}}
```

For authorizers:
```json
{"allow": true}
```

For mutators:
```json
{"setHeaders": {"X-User": "alice"}, "removeHeaders": ["X-Internal"]}
```

### Return value encoding

The return value is a packed `i64`: `(outPtr << 32) | outLen`.
The host reads `outLen` bytes from `outPtr` in guest memory to get the
JSON response. Maximum response size is **1 MiB**.

## Helm wiring

```yaml
# values.yaml
config:
  inline: |
    authorizers:
      - name: policy-wasm
        type: wasm
        config:
          path: /opt/plugins/policy.wasm
          maxMemoryMB: 64
          maxFuel: 5000000
          timeout: 500ms
extraVolumes:
  - name: wasm-plugins
    configMap: { name: lwauth-wasm-plugins }
extraVolumeMounts:
  - name: wasm-plugins
    mountPath: /opt/plugins
    readOnly: true
```

## Operational notes

- **Compilation.** The `.wasm` file is compiled (AOT) once at config
  load time. Subsequent invocations instantiate from the compiled
  module — startup cost is < 100µs per request.
- **Isolation.** Each invocation is a fresh instance. No memory leaks
  or state carries between requests. The instance is closed after each
  call.
- **Fuel.** Each WASM instruction consumes one unit of fuel. When fuel
  runs out, the guest traps and the host returns an error (deny).
- **WASI.** WASI preview1 is available for stdlib needs (clocks,
  random). Filesystem and network access are **not** provided.
- **Pure Go.** wazero requires no CGO, no system libraries — builds
  on any `GOOS`/`GOARCH` the Go toolchain supports.

## Writing a guest plugin

Minimal Rust example:

```rust
#[no_mangle]
pub extern "C" fn alloc(size: i32) -> i32 {
    let mut buf = Vec::with_capacity(size as usize);
    let ptr = buf.as_mut_ptr() as i32;
    std::mem::forget(buf);
    ptr
}

#[no_mangle]
pub extern "C" fn authorize(ptr: i32, len: i32) -> i64 {
    let input = unsafe {
        std::slice::from_raw_parts(ptr as *const u8, len as usize)
    };
    let response = b"{\"allow\":true}";
    let out_ptr = alloc(response.len() as i32);
    unsafe {
        std::ptr::copy_nonoverlapping(
            response.as_ptr(),
            out_ptr as *mut u8,
            response.len(),
        );
    }
    ((out_ptr as i64) << 32) | (response.len() as i64)
}
```

Compile with: `cargo build --target wasm32-wasi --release`

## References

- DESIGN: [DESIGN.md](../DESIGN.md).
- Source: [pkg/plugin/wasm/](https://github.com/mikeappsec/lightweightauth/tree/main/pkg/plugin/wasm/).
- Guest SDK: [lightweightauth-plugins](https://github.com/mikeappsec/lightweightauth-plugins).
