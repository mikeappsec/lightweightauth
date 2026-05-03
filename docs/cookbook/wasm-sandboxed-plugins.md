# WASM sandboxed plugins

Write custom identifiers, authorizers, or mutators in Rust (or TinyGo)
compiled to WebAssembly. Runs in-process via the wazero runtime with
per-invocation CPU, memory, and wall-clock budgets — no guest can
escape the sandbox or affect other requests.

## What this recipe assumes

- Rust toolchain with `wasm32-wasi` target (or TinyGo with WASI
  support).
- Logic that doesn't need persistent state, network access, or file
  I/O between invocations.
- You want sandboxed extensibility without operating a separate gRPC
  sidecar.

## 1. Write a WASM authorizer (Rust)

A minimal authorizer that checks a custom claim:

```rust
// src/lib.rs
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
struct Input {
    identity: Identity,
    request: Request,
}

#[derive(Deserialize)]
struct Identity {
    subject: String,
    claims: std::collections::HashMap<String, serde_json::Value>,
}

#[derive(Deserialize)]
struct Request {
    method: String,
    path: String,
    headers: std::collections::HashMap<String, Vec<String>>,
}

#[derive(Serialize)]
struct Output {
    allow: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    deny_message: Option<String>,
}

#[no_mangle]
pub extern "C" fn alloc(size: i32) -> i32 {
    let mut buf = Vec::with_capacity(size as usize);
    let ptr = buf.as_mut_ptr() as i32;
    std::mem::forget(buf);
    ptr
}

#[no_mangle]
pub extern "C" fn authorize(ptr: i32, len: i32) -> i64 {
    let input_bytes = unsafe {
        std::slice::from_raw_parts(ptr as *const u8, len as usize)
    };
    let input: Input = serde_json::from_slice(input_bytes).unwrap();

    // Custom authorization logic: require "internal" claim for /admin paths
    let output = if input.request.path.starts_with("/admin") {
        match input.identity.claims.get("department") {
            Some(val) if val == "engineering" => Output {
                allow: true,
                deny_message: None,
            },
            _ => Output {
                allow: false,
                deny_message: Some("engineering department required for /admin".into()),
            },
        }
    } else {
        Output { allow: true, deny_message: None }
    };

    let response = serde_json::to_vec(&output).unwrap();
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

## 2. Build the WASM module

```bash
# Add the target
rustup target add wasm32-wasi

# Build (release for size + performance)
cargo build --target wasm32-wasi --release

# Output: target/wasm32-wasi/release/my_plugin.wasm

# Optional: strip debug info for smaller binary
wasm-opt -Os target/wasm32-wasi/release/my_plugin.wasm -o policy.wasm
```

For TinyGo:

```bash
tinygo build -o policy.wasm -target wasi -no-debug ./main.go
```

## 3. Configure lwauth to load the WASM module

```yaml
apiVersion: lightweightauth.io/v1alpha1
kind: AuthConfig
metadata:
  name: api-with-wasm
  namespace: production
spec:
  identifiers:
    - name: bearer
      type: jwt
      config:
        issuerUrl: https://idp.example.com
        audiences: [api]

  authorizers:
    - name: custom-policy
      type: wasm
      config:
        path: /opt/plugins/policy.wasm
        maxMemoryMB: 32        # guest memory cap (MiB)
        maxFuel: 2000000       # CPU fuel budget per invocation
        timeout: 200ms         # wall-clock deadline
```

## 4. Resource budgets

Each invocation gets a fresh sandbox with strict limits:

| Budget | Default | Purpose |
|--------|---------|---------|
| `maxMemoryMB` | 16 MiB | Maximum guest memory allocation |
| `maxFuel` | 1,000,000 | CPU instruction budget (1 fuel = 1 instruction) |
| `timeout` | 100ms | Wall-clock deadline |

When any budget is exhausted:

- **Memory exceeded** → guest traps, host returns deny
- **Fuel exhausted** → guest traps, host returns deny
- **Timeout** → context cancelled, host returns deny

No infinite loops, no OOM — the sandbox guarantees termination.

## 5. WASM identifier (custom token format)

Parse a proprietary token format:

```rust
#[derive(Serialize)]
struct IdentifyOutput {
    subject: String,
    claims: std::collections::HashMap<String, serde_json::Value>,
}

#[no_mangle]
pub extern "C" fn identify(ptr: i32, len: i32) -> i64 {
    let input_bytes = unsafe {
        std::slice::from_raw_parts(ptr as *const u8, len as usize)
    };
    let input: Input = serde_json::from_slice(input_bytes).unwrap();

    // Extract custom token from X-Custom-Auth header
    let token = input.request.headers.get("x-custom-auth")
        .and_then(|v| v.first());

    let output = match token {
        Some(t) if validate_proprietary_token(t) => {
            let claims = parse_token_claims(t);
            IdentifyOutput { subject: claims.sub, claims: claims.extra }
        }
        _ => return 0, // return 0 = no match, try next identifier
    };

    let response = serde_json::to_vec(&output).unwrap();
    let out_ptr = alloc(response.len() as i32);
    unsafe {
        std::ptr::copy_nonoverlapping(response.as_ptr(), out_ptr as *mut u8, response.len());
    }
    ((out_ptr as i64) << 32) | (response.len() as i64)
}
```

Config:

```yaml
  identifiers:
    - name: custom-token
      type: wasm
      config:
        path: /opt/plugins/custom-identifier.wasm
        maxMemoryMB: 16
        maxFuel: 1000000
        timeout: 50ms
```

## 6. WASM mutator (response enrichment)

Add custom headers based on identity:

```rust
#[derive(Serialize)]
struct MutateOutput {
    #[serde(rename = "setHeaders")]
    set_headers: std::collections::HashMap<String, String>,
    #[serde(rename = "removeHeaders")]
    remove_headers: Vec<String>,
}

#[no_mangle]
pub extern "C" fn mutate(ptr: i32, len: i32) -> i64 {
    let input_bytes = unsafe {
        std::slice::from_raw_parts(ptr as *const u8, len as usize)
    };
    let input: Input = serde_json::from_slice(input_bytes).unwrap();

    let mut headers = std::collections::HashMap::new();
    headers.insert("X-User-Tier".into(),
        input.identity.claims.get("tier")
            .map(|v| v.to_string())
            .unwrap_or_else(|| "free".into()));

    let output = MutateOutput {
        set_headers: headers,
        remove_headers: vec!["X-Internal-Debug".into()],
    };

    let response = serde_json::to_vec(&output).unwrap();
    let out_ptr = alloc(response.len() as i32);
    unsafe {
        std::ptr::copy_nonoverlapping(response.as_ptr(), out_ptr as *mut u8, response.len());
    }
    ((out_ptr as i64) << 32) | (response.len() as i64)
}
```

## 7. Deploy via ConfigMap or OCI

### ConfigMap (small modules < 1 MiB)

```bash
kubectl -n lwauth-system create configmap lwauth-wasm-plugins \
  --from-file=policy.wasm=./target/wasm32-wasi/release/policy.wasm
```

### OCI artifact (recommended for production)

```bash
# Push to OCI registry
oras push ghcr.io/myorg/lwauth-plugins/policy:v1.0.0 \
  --artifact-type application/wasm \
  policy.wasm:application/wasm

# Reference in config (requires bundle module)
# See docs/modules/bundle.md for OCI bundle loading
```

## 8. Helm wiring

```yaml
# values.yaml
config:
  inline: |
    identifiers:
      - name: bearer
        type: jwt
        config:
          issuerUrl: https://idp.example.com
          audiences: [api]
    authorizers:
      - name: custom-policy
        type: wasm
        config:
          path: /opt/plugins/policy.wasm
          maxMemoryMB: 32
          maxFuel: 2000000
          timeout: 200ms
extraVolumes:
  - name: wasm-plugins
    configMap:
      name: lwauth-wasm-plugins
extraVolumeMounts:
  - name: wasm-plugins
    mountPath: /opt/plugins
    readOnly: true
```

## 9. Validate

```bash
# Test the custom authorizer
curl -H "Authorization: Bearer ${TOKEN_WITH_ENGINEERING_DEPT}" \
     https://gateway/admin/settings
# expect: 200

curl -H "Authorization: Bearer ${TOKEN_WITHOUT_ENGINEERING_DEPT}" \
     https://gateway/admin/settings
# expect: 403, "engineering department required for /admin"

# Non-admin path — always allowed
curl -H "Authorization: Bearer ${ANY_TOKEN}" \
     https://gateway/api/public
# expect: 200

# Dry-run
lwauthctl explain --config api-with-wasm.yaml \
    --request '{"method":"GET","path":"/admin/settings","headers":{"authorization":"Bearer ..."}}'
# identify  ✓  jwt   subject=alice  claims.department=engineering
# authorize ✓  wasm  (policy.wasm → allow)
```

## Operational notes

- **AOT compilation.** The `.wasm` file is compiled once at config
  load time. Per-request cost is only instantiation (< 100µs).
- **No state between requests.** Each invocation is a fresh instance.
  Memory is freed after each call — no leaks possible.
- **WASI preview1.** Clocks and random are available. Filesystem and
  network access are **not** provided.
- **Pure Go runtime.** wazero requires no CGO — deploys on any
  platform the Go toolchain supports.
- **Maximum response: 1 MiB.** Larger responses are truncated.

## Teardown

```bash
kubectl delete authconfig api-with-wasm -n production
kubectl delete configmap lwauth-wasm-plugins -n lwauth-system
```
