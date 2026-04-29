# `module.Request` invariants — one canonical shape, two doors

> **Audience:** anyone touching the transport adapters
> ([internal/server/grpc.go](../../internal/server/grpc.go),
> [internal/server/native.go](../../internal/server/native.go),
> [internal/server/http.go](../../internal/server/http.go),
> [pkg/plugin/grpc/translate.go](../../pkg/plugin/grpc/translate.go))
> or writing a new identifier / authorizer / mutator.

---

## 1. The problem this solves

`lightweightauth` accepts the same authorization decision through four
entry points:

| Door / surface              | Wire type                                  | Adapter function                                                    |
|-----------------------------|--------------------------------------------|---------------------------------------------------------------------|
| Door A (Envoy ext_authz)    | `envoy.service.auth.v3.CheckRequest`       | [requestFromCheck](../../internal/server/grpc.go)                   |
| Door B (native gRPC SDK)    | `lightweightauth.v1.AuthorizeRequest`      | [requestFromAuthorize](../../internal/server/native.go)             |
| HTTP JSON                   | `POST /v1/authorize` body                  | [HTTPHandler.authorize](../../internal/server/http.go)              |
| Out-of-process plugin host  | `*module.Request` → `authv1.AuthorizeRequest` | [reqToProto](../../pkg/plugin/grpc/translate.go)                 |

All four feed `pipeline.Engine.Evaluate(ctx, *module.Request)`. The
engine and every shipped module read **only** from `module.Request` —
they don't know which adapter built it.

The risk: each adapter could shape the same logical input differently,
so the verdict would depend on which door the request came through. A
user allowed via Envoy would be denied via the SDK, or a signature
that verifies on the HTTP path would fail on the gRPC path.

We can't change Envoy. So **every other adapter must produce the same
canonical shape Envoy does.** That shape is the `module.Request`
invariant.

---

## 2. The invariant

For every `*module.Request` that reaches `Engine.Evaluate`:

1. **Header keys are lowercase.**
   HTTP/2 mandates lowercase on the wire; Envoy already complies.
   The other three adapters explicitly lowercase before storing.
   → Modules MAY use `r.Headers["authorization"]` directly.
   → `r.Header(name)` remains case-insensitive for backward compat.
2. **`Method` is uppercase.**
   All four adapters call `strings.ToUpper`.
3. **`Host` is the HTTP authority** (the `:authority` / `Host` header
   value), **not** the gRPC peer's TCP address.
   - Door A: `envoy.HttpRequest.Host`.
   - Door B: prefers the `host` header; falls back to
     `peer.RemoteAddr` only when no header was sent (non-HTTP gRPC
     callers, mostly tests).
   - HTTP JSON: client-supplied `host` field.
   - Plugin: `r.Host` is forwarded as the synthetic `host` header.
4. **`PeerCerts` carries DER bytes only.**
   The mTLS-via-XFCC path (Envoy forwarding `x-forwarded-client-cert`)
   leaves the raw header in `Headers["x-forwarded-client-cert"]`; the
   `mtls` module parses it from there. `PeerCerts` is reserved for
   the in-process TLS termination path where lwauth itself produced
   verified DER bytes.
5. **`Path` is the resource the request targets.**
   - Door A: HTTP path.
   - Door B / plugin: `Resource` field (free-form: HTTP path, gRPC
     FQN, Kafka topic, …) — surfaced as `Path` so RBAC/OPA/CEL configs
     are identical across doors.

Modules constructing a `*module.Request` directly in tests SHOULD use
lowercase header keys to match real traffic. The case-insensitive
`Header()` helper still works, but new code should not rely on it.

---

## 3. Why we chose normalization over a parity matrix

An earlier slice of B1 shipped a Door A vs Door B parity matrix that
walked every (identifier × authorizer) combination through both doors
and asserted the verdicts agreed. It worked, but it was the wrong
tool: it caught **symptoms** (a verdict diverged) rather than
**causes** (the adapters disagreed on shape).

Normalizing at the adapter boundary is strictly stronger:

- **The bug becomes unrepresentable.** A module that reads
  `r.Headers["X-Tenant"]` directly cannot accidentally work on one
  door and fail on the other — it either works on all doors (because
  the key isn't lowercase, so it fails everywhere → the unit test
  catches it) or works on none.
- **Per-module unit tests now suffice.** With one canonical input
  shape, a module's own tests cover both doors at once.
- **No O(n × m) test runtime.** The parity matrix booted a real
  engine + bufconn gRPC server per cell; normalization tests are pure
  function calls.
- **The contract is documented.** The
  [module.Request.Headers](../../pkg/module/module.go) godoc spells
  out the invariant; new contributors see it before they reach for a
  case-sensitive lookup.

The parity matrix was deleted in this slice. The few asymmetries it
had surfaced (host plumbing, XFCC handling, header casing) became
explicit normalization rules in the adapters, fenced by
[internal/server/normalize_test.go](../../internal/server/normalize_test.go).

---

## 4. The normalization tests

[internal/server/normalize_test.go](../../internal/server/normalize_test.go)
asserts the invariant directly at the adapter boundary:

| Test                                                  | Asserts                                                                                  |
|-------------------------------------------------------|------------------------------------------------------------------------------------------|
| `TestRequestFromCheck_LowercasesHeaderKeys`           | Door A drops mixed-case keys into lowercase slots.                                       |
| `TestRequestFromCheck_DoesNotPolluteCertWithXFCCString` | Door A leaves `PeerCerts` nil when the input is an XFCC string (not DER).              |
| `TestRequestFromAuthorize_LowercasesHeaderKeys`       | Door B drops mixed-case keys into lowercase slots.                                       |
| `TestRequestFromAuthorize_HostFromHeaderNotPeer`      | Door B prefers the `host` header over `peer.RemoteAddr`.                                 |
| `TestRequestFromAuthorize_HostFallsBackToPeer`        | Door B falls back to peer address only when no host header is set.                       |

Each test is a pure function call against the adapter — no engine, no
gRPC server, no fixtures. They fail loudly if a future contributor
strips one of the rules in isolation.

---

## 5. The path-of-least-resistance for new contributors

If you're writing a new identifier, authorizer, or mutator:

```go
// PREFERRED: direct lowercase map lookup. Works on every door because
// the adapter normalizes before the engine ever sees the Request.
v := r.Headers["authorization"]

// Also fine: case-insensitive helper. Older code uses it; new code
// can too. Keeps working even if a test author forgets to lowercase.
v := r.Header("Authorization")

// FORBIDDEN in production code (will pass on Door A, fail on a
// hand-built test fixture, fail on every adapter that ever forgets
// to lowercase): direct lookup with a non-lowercase key.
v := r.Headers["Authorization"]
```

If you're writing a new transport adapter:

1. Lowercase every header key before assigning to `out.Headers`.
2. Uppercase the method.
3. Populate `Host` from the HTTP authority semantic source for your
   transport — not from a TCP-level peer address unless that's all
   you have.
4. Only put DER bytes in `PeerCerts`. If your transport gives you a
   string-encoded cert (XFCC, base64, PEM), put it in the appropriate
   header and let the `mtls` module parse it.
5. Add a couple of cases to `normalize_test.go` for your adapter.

---

## 6. Why the `Path` vs `Resource` rename is part of this contract

Door A receives an HTTP path. Door B / plugin / HTTP JSON callers may
send any opaque string as the resource — a gRPC FQN, a Kafka topic, a
queue name. The adapters all surface that string in
`module.Request.Path` so a single `rbac` / `cel` / `opa` policy works
across all four entry points without conditional logic.

This is not a normalization in the casing sense, but it lives in the
same contract: every adapter agrees on which `Request` field carries
"the thing the request targets," and every module reads it from one
place.

---

## 7. TL;DR

- One canonical `*module.Request` shape, four adapters, each
  responsible for normalizing into it.
- Modules can ignore the difference between Envoy, native gRPC, HTTP
  JSON, and plugin invocations — the engine sees the same input from
  all four.
- The invariant is fenced by
  [internal/server/normalize_test.go](../../internal/server/normalize_test.go)
  as pure-function tests at the adapter boundary, no end-to-end
  parity matrix required.
- This is strictly stronger than the parity-matrix approach the
  earlier B1 slice shipped, so the matrix was deleted.
