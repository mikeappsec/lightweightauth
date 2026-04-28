# M12-CONF-MATRIX — Door A vs Door B Conformance Matrix

> **Audience:** contributors who need to understand what
> [internal/server/matrix_test.go](../../internal/server/matrix_test.go)
> is asserting and why. If you've ever asked "why does this test exist
> at all?" or "why aren't there 35 cells?" — read on.

---

## 1. The architectural fact this test defends

`lightweightauth` exposes the **same authorization decision** through
**two separate transports**:

```
                          ┌──────────────────────┐
   Envoy sidecar ────────►│  Door A              │
   (ext_authz v3 gRPC)    │  envoy.service.auth.v3│
                          │  AuthorizationServer  │──┐
                          └──────────────────────┘  │
                                                    │
                                                    ▼
                                          ┌──────────────────┐
                                          │  one shared      │
                                          │  pipeline.Engine │
                                          │  (identifier →   │
                                          │   authorizer →   │
                                          │   mutator)       │
                                          └──────────────────┘
                                                    ▲
                          ┌──────────────────────┐  │
   Native Go/Rust SDK ───►│  Door B              │──┘
   (lightweightauth.v1)   │  authv1.AuthServer    │
                          └──────────────────────┘
```

Both doors register on **the same gRPC server** in production. They
funnel into **the same `pipeline.Engine`**. The only thing that differs
is the **adapter** that turns the wire-format request into the
internal `module.Request`:

| Door  | Wire type                    | Adapter                                                  |
|-------|------------------------------|----------------------------------------------------------|
| A     | `envoy.CheckRequest`         | [extauthz.toRequest](../../internal/server/extauthz.go)  |
| B     | `lightweightauth.v1.AuthorizeRequest` | [native.toRequest](../../internal/server/native.go) |

> **The contract:** for any logically equivalent input, both adapters
> must produce a `module.Request` that the engine cannot tell apart.
> If they don't, the same user gets allowed through Envoy and denied
> through the SDK (or vice versa). That's the bug class M12-CONF-MATRIX
> exists to catch.

---

## 2. The bug class, in one picture

Suppose someone refactors header plumbing and accidentally lower-cases
the `Authorization` header value only on Door B:

```
        SAME logical request:
        ┌──────────────────────────────────────────────┐
        │ method=GET, path=/things                     │
        │ Authorization: Bearer eyJhbGciOiJSUzI1NiIs… │
        └──────────────────────────────────────────────┘
               │                              │
       Door A  │                              │  Door B
               ▼                              ▼
   module.Request{                    module.Request{
     Headers: {                         Headers: {
       "authorization":                   "authorization":
         "Bearer eyJhbGc…"                  "bearer eyjhbgc…"   ◄── MUTATED
     }                                  }
   }                                  }
               │                              │
               ▼                              ▼
        jwt.Identify()                 jwt.Identify()
        ──► Identity{alice, admin}     ──► ErrInvalidCredential
               │                              │
               ▼                              ▼
        rbac.Authorize()               (engine returns 401)
        ──► Allow:true
               │                              │
               ▼                              ▼
          HTTP 200                       HTTP 401  ◄── PARITY BROKEN
```

Per-module unit tests don't catch this because they call `Identify()`
directly with a hand-built `module.Request`. The Envoy-only integration
test doesn't catch it either. **Only a parity test that drives the
same input through both doors catches it.**

---

## 3. What `TestConformance_Matrix` actually executes

For **every cell** in the table, the test does this:

```mermaid
sequenceDiagram
    participant T as t.Run("apikey+opa")
    participant Build as tc.build(t)
    participant Boot as bootBothDoors
    participant Eng as pipeline.Engine
    participant DA as Door A client<br/>(envoy authv3)
    participant DB as Door B client<br/>(lwauth authv1)
    participant Assert as assertParity

    T->>Build: 1. Build per-cell AuthConfig
    Note over Build: apikey identifier +<br/>opa authorizer +<br/>any httptest.Server<br/>(JWKS / OpenFGA / etc.)
    Build-->>T: *config.AuthConfig

    T->>Boot: 2. Boot ONE engine,<br/>BOTH doors
    Boot->>Eng: config.Compile(ac)
    Note over Boot: bufconn gRPC server<br/>register Door A handler<br/>register Door B handler
    Boot-->>T: (envoyCli, nativeCli)

    T->>Assert: 3. ALLOW input
    Assert->>DA: Check(CheckRequest{x-api-key:dev-admin-key})
    Assert->>DB: Authorize(AuthorizeRequest{x-api-key:dev-admin-key})
    DA-->>Assert: Status.Code == OK
    DB-->>Assert: Allow=true
    Note over Assert: assert doorA.allow == doorB.allow<br/>assert doorA.allow == wantAllow

    T->>Assert: 4. DENY input
    Assert->>DA: Check(CheckRequest{x-api-key:dev-viewer-key})
    Assert->>DB: Authorize(AuthorizeRequest{x-api-key:dev-viewer-key})
    DA-->>Assert: Status.Code == PermissionDenied
    DB-->>Assert: Allow=false, HttpStatus=403
    Note over Assert: assert doorA.allow == doorB.allow<br/>assert doorB.HttpStatus == wantHTTP
```

Every cell does steps 1–4. **The cells differ only in what config they
build and what credential they send.**

---

## 4. The shape of one cell, line-by-line

This is the simplest cell from
[matrix_test.go](../../internal/server/matrix_test.go):

```go
{
    name:    "apikey+opa",
    build:   func(t *testing.T) *config.AuthConfig {
        return apikeyConfigWith(opaAdminInRoles())
    },
    allow:   func(t *testing.T) matrixRequest {
        return apikeyReq("dev-admin-key")
    },
    deny:    func(t *testing.T) matrixRequest {
        return apikeyReq("dev-viewer-key")
    },
    denyTTP: 403,
},
```

What each field means:

| Field    | Purpose                                                                                     |
|----------|---------------------------------------------------------------------------------------------|
| `name`   | Sub-test name. CI failure shows `TestConformance_Matrix/apikey+opa` so you know which pair regressed. |
| `build`  | Returns a real `AuthConfig` for this cell. Spins up any per-cell httptest.Server (JWKS, OpenFGA, introspection) and registers `t.Cleanup` itself. |
| `allow`  | Returns the request that **must be allowed**. Will be sent through both doors. |
| `deny`   | Returns the request that **must be denied**. Will be sent through both doors. |
| `denyTTP`| Expected HTTP status from Door B's `AuthorizeResponse.HttpStatus` on the deny input (403 for forbidden, 401 for missing credentials). |

`build`, `allow`, `deny` are **functions, not values**, so per-cell
infrastructure (servers, signing keys) is created lazily inside the
parallel sub-test goroutine.

---

## 5. Why the matrix is sparse, not 7 × 5 = 35

The pipeline structure determines what's worth testing:

```
                                  ┌─── communicates ONLY via
   ┌────────────┐    Identity{   │    this struct. No back-channel.
   │ identifier │───►  Subject,  │
   └────────────┘     Claims,   ◄┘
        ▲             Source }       ┌────────────┐
        │                       ───► │ authorizer │ ───► Decision
        │                            └────────────┘
   reads transport
   (headers, body,
    peer certs)
```

**Identifier** and **authorizer** are independent layers:

- An identifier transport bug shows up regardless of which authorizer
  runs after it (the bug corrupts the `Identity` before the authorizer
  ever sees it).
- An authorizer transport bug shows up regardless of which identifier
  ran before it (the bug is in how the authorizer reads
  `module.Request`, not in how `Identity` was built).

So you don't need every (id × authz) pair. You need:

> **Every module to appear on at least one row.**

That's `O(n + m)` cells, not `O(n · m)`.

### How the matrix achieves that

```
                AUTHORIZERS  ──────────────────────────────────►
                ┌─────┬─────┬─────┬─────────────┬─────────┐
                │ rbac│ cel │ opa │ composite   │ openfga │
   ┌────────────┼─────┼─────┼─────┼─────────────┼─────────┤
 I │ apikey     │  ✓  │  ✓  │  ✓  │      ✓      │    ✓    │ ◄── apikey
 D │            │     │     │     │             │         │     is the
 E │            │     │     │     │             │         │     "carrier"
 N │            │     │     │     │             │         │     for every
 T │            │     │     │     │             │         │     authorizer
 I ├────────────┼─────┼─────┼─────┼─────────────┼─────────┤
 F │ jwt        │  ✓  │  -  │  -  │      -      │    -    │
 I │            │     │     │     │             │         │ ◄── rbac is
 E │ introspect │  ✓  │  -  │  -  │      -      │    -    │     the
 R │            │     │     │     │             │         │     "carrier"
 S │ hmac       │ N/A │ N/A │ N/A │     N/A     │   N/A   │     for every
   │ mtls       │ TODO│ TODO│ TODO│    TODO     │  TODO   │     extra
   │ dpop       │ TODO│ TODO│ TODO│    TODO     │  TODO   │     identifier
   │ oauth2     │ TODO│ TODO│ TODO│    TODO     │  TODO   │
   ▼            └─────┴─────┴─────┴─────────────┴─────────┘
```

- **Row 1 (`apikey × all 5`)** — `apikey` is the **cheapest**
  identifier (single header lookup, no signing, no upstream). Use it as
  the carrier so each of the 5 authorizers gets exercised once through
  both doors. Catches authorizer-side transport bugs.
- **Rows 2–3 (`{jwt, introspection} × rbac`)** — `rbac` is the
  **cheapest** authorizer (in-memory hash lookup). Use it as the
  carrier so each non-apikey identifier gets exercised once through
  both doors. Catches identifier-side transport bugs.
- **`opa + jwt`?** — Redundant. If `apikey + opa` passes, OPA reads
  `Identity` correctly through both doors. If `jwt + rbac` passes, JWT
  builds `Identity` correctly through both doors. The composition is
  just (already-tested) + (already-tested), with no shared state.

### N/A rows (the matrix surfaced a real architectural finding)

- **`hmac`** — Permanently N/A until **M12-PROTO-HOST** lands. The
  HMAC signature is bound to the request's `Host` header and body
  hash. Door A receives `Host` via
  `envoy.AttributeContext_HttpRequest.Host`. Door B's
  `lightweightauth.v1.AuthorizeRequest` proto has no `host` field, so
  Door B fills `module.Request.Host` from the gRPC peer's remote
  address. **Same input → different canonical strings → different
  verdicts. That is the correct behaviour.** The matrix isn't broken
  here; it discovered that HMAC is currently a Door A-only identifier.
  Tracked as M12-PROTO-HOST in [DESIGN.md §1](../DESIGN.md).

### TODO rows (slice 2)

- **`mtls`** — Door A receives the cert as a string in the
  `x-forwarded-client-cert` header (Envoy XFCC format). Door B
  receives it as raw DER bytes in `module.Request.PeerCerts`. Needs a
  shared XFCC↔PeerCerts test helper.
- **`dpop`** — DPoP wraps an *inner* identifier (e.g. `dpop` wrapping
  `jwt`). The current `matrixCase` shape doesn't compose
  inner-fixtures. Needs a small refactor.
- **`oauth2`** (redirect flow) — Needs a fake IdP doing the full
  authorization-code dance. Out of scope for a transport-parity test;
  covered end-to-end in
  [pkg/identity/oauth2](../../pkg/identity/oauth2/oauth2_test.go).

---

## 6. Why the assertion compares allow-bool + status, not reasons

The two doors return different envelope shapes:

```
Door A response                      Door B response
──────────────                       ──────────────
google.rpc.Status {                  AuthorizeResponse {
  Code:    OK | PermissionDenied       Allow:      bool
  Message: string  // shown to user    HttpStatus: int32
}                                      DenyReason: string  // for SDK callers
                                     }
```

`assertParity` translates them onto a common axis:

```go
doorAAllow := codes.Code(cresp.Status.Code) == codes.OK
// then:
if doorAAllow != aresp.Allow { … }                // <-- the parity check
if !aresp.Allow && aresp.HttpStatus != wantHTTP { … }  // <-- status sanity
```

Reason strings are **not** compared because they have different
audiences:
- Door A's `Status.Message` becomes the HTTP body Envoy returns to the
  end-user — must be terse and redacted.
- Door B's `DenyReason` is consumed programmatically by an SDK caller
  — can be more structured.

Both originate from the same `Decision.Reason` inside the engine, so
the parity that *matters* (was the request allowed? what status?) is
fully covered.

---

## 7. Why all the `httptest.Server` plumbing in fixtures

Three of the eight cells need a live HTTP upstream:

| Cell                  | Upstream needed                                |
|-----------------------|------------------------------------------------|
| `apikey + openfga`    | Fake OpenFGA `/check` endpoint                 |
| `jwt + rbac`          | In-memory JWKS endpoint serving the public key |
| `introspection + rbac`| Fake RFC 7662 `/introspect` endpoint           |

These are spun up **inside** the cell's `build` function and registered
with `t.Cleanup(srv.Close)` so each parallel sub-test owns its own
isolated upstream. Nothing leaks between cells; no port collisions; no
shared mutable state.

The JWT fixture is slightly special because the `build` callback
creates the server, but the `allow` and `deny` callbacks need to
**re-mint tokens against the same signing key**. That's why
`jwtFixturesByTest` exists — a `*testing.T`-keyed map that lets the
allow/deny callbacks find the same fixture `build` created. The
`t.Cleanup` evicts the entry when the sub-test ends.

---

## 8. Where to add the next cell

When **M12-PROTO-HOST** ships and `AuthorizeRequest` gains `host` /
`body_sha256` fields, adding `hmac + rbac` is roughly:

1. Add a `hmacReq(t, secret, keyID)` helper that builds the canonical
   string (see
   [pkg/identity/hmac/hmac.go](../../pkg/identity/hmac/hmac.go)
   `canonical()`).
2. Extend `matrixRequest` with `host` and `body` fields.
3. Extend `assertParity` to plumb them onto **both** doors:
   - Door A: `Http.Host = req.host`, `Http.Body = req.body`.
   - Door B: `AuthorizeRequest.Host = req.host`, `.Body = req.body`
     (new fields).
4. Add the cell to `matrixCases()`.
5. Delete the long N/A comment block.

For **mtls** the same pattern applies — add `peerCerts [][]byte` to
`matrixRequest`, plumb into Door A's XFCC header and Door B's
`PeerCerts` field. For **dpop**, generalise `matrixCase` to allow
nested identifier specs.

---

## 9. TL;DR

- **What it tests:** that Door A (Envoy ext_authz) and Door B (native
  gRPC) produce the *same* allow/deny verdict for the *same* logical
  input, for *every shipped module*.
- **Why it's sparse:** the identifier↔authorizer boundary is a clean
  `module.Identity` struct, so every module needs to appear on **at
  least one** row, not on every row.
- **What "carrier" means:** the cheapest module on the *other* axis,
  used purely to keep that axis stable while we vary the module under
  test.
- **What it discovered:** HMAC parity is structurally impossible until
  the proto is extended (M12-PROTO-HOST). That's not a test bug; it's
  a real product gap the matrix was built to surface.
