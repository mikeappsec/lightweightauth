# LightweightAuth Security Hardening — 2026-04-29

## Scope

Targeted hardening pass over trust boundaries, upstream parsing, controller
trust material, request lifecycle, and JWKS bootstrap. All changes are
in-tree fixes; no behavioural changes were preserved for backwards
compatibility where the legacy behaviour was itself the issue.

This document describes the engineering changes only. It is not a
vulnerability disclosure and does not assign severities.

## Summary

Six items were closed:

| Area                         | Change                                                                 |
| ---------------------------- | ---------------------------------------------------------------------- |
| Native gRPC peer identity    | `module.Request.PeerCerts` is sourced exclusively from the verified TLS handshake. |
| Pipeline FirstMatch          | Non-`ErrNoMatch` errors from an identifier are terminal for the request. |
| OpenFGA / introspection      | Success-path JSON responses are read through `io.LimitReader` caps.    |
| Controller IdP merge         | Tenant `idpRef` cannot override cluster-authoritative trust material.  |
| HTTP authorize               | The handler honours client cancellation instead of detaching context.  |
| JWKS startup                 | Initial JWKS refresh runs under an explicit 30 s deadline.             |

A second pass closed two further items:

| Area                         | Change                                                                 |
| ---------------------------- | ---------------------------------------------------------------------- |
| Decision-cache key fields    | Unknown `cache.key` entries are rejected at config-load time.          |
| ConfigDiscovery gRPC server  | Constructor requires an explicit `Authorizer`; nil panics, errors return `Unauthenticated`. |

## Changes in detail

### 1. Native gRPC peer identity

**Files:** `api/proto/lightweightauth/v1/auth.proto`,
`api/proto/lightweightauth/v1/auth.pb.go`,
`internal/server/native.go`,
`pkg/client/go/client.go`,
`pkg/plugin/grpc/translate.go`,
`tests/golden/plugin-v1/plugin.descriptor`.

`PeerInfo.cert_chain` (field 3) was a caller-supplied byte blob that the
server treated as already-verified DER. The mtls identifier reads
`module.Request.PeerCerts` as trusted, so any caller that could reach the
gRPC `Authorize` could synthesise a "verified" client identity.

The field is removed from the proto and its number is `reserved` so it
cannot be re-introduced for any purpose:

```proto
message PeerInfo {
  string remote_addr = 1;
  string spiffe_id   = 2;
  reserved 3;
  reserved "cert_chain";
}
```

The Go SDK `Peer` struct no longer carries `CertChain`. The plugin gRPC
shim no longer forwards peer certs to plugin processes.

The server populates `PeerCerts` only from the verified TLS handshake on
the gRPC connection, via two new helpers in `internal/server/native.go`:

- `isTLSConnVerified` — confirms `credentials.TLSInfo.State.HandshakeComplete`
  and that at least one verified chain is present.
- `verifiedPeerCertFromContext` — returns the leaf certificate's DER from
  `VerifiedChains[0][0].Raw`, and only that.

This is a v1.x wire break taken under the security carve-out documented in
`tests/golden/plugin_descriptor_test.go`. The wire-lock golden was
regenerated in the same change.

### 2. Pipeline FirstMatch fall-through

**File:** `internal/pipeline/engine.go`.

The FirstMatch identifier loop previously continued to the next identifier
on any error, including hard authentication failures. An invalid token
seen by the first identifier could therefore fall through to a second,
weaker identifier (e.g. an API-key backend that ignored the bearer header
entirely) and authenticate the request anyway.

The loop now treats only `module.ErrNoMatch` as fall-through. Any other
error is terminal for the request.

### 3. Upstream JSON size caps

**Files:** `pkg/authz/openfga/openfga.go`,
`pkg/identity/introspection/introspection.go`.

OpenFGA `Check` and RFC 7662 introspection success responses were decoded
straight from the upstream `http.Response.Body` with no size bound. A
hostile or compromised upstream could pin large amounts of memory inside
the request lifetime.

Both call sites now wrap the success body in `io.LimitReader`:
- OpenFGA: 64 KiB (a Check response is ≤ a few hundred bytes).
- Introspection: 1 MiB (large JWT-shaped responses still fit).

### 4. Controller IdP trust-material merge

**File:** `internal/controller/idp_resolve.go`.

The tenant CRD `idpRef` block could override cluster-scoped IdP fields
that constitute trust material — most importantly `issuerUrl` and
`jwksUrl`. A tenant operator could therefore redirect token verification
to an IdP they controlled.

The merge is split:

- `setAuthoritative` — `issuerUrl`, `jwksUrl`. Cluster value wins; tenant
  cannot override.
- `setIfMissing` — operational defaults (`header`, `scheme`,
  `minRefreshInterval`). Tenant value wins if set; cluster fills the gap.

### 5. HTTP authorize cancellation

**File:** `internal/server/http.go`.

The HTTP authorize handler used `context.WithoutCancel(r.Context())` when
calling the engine. A client that disconnected mid-evaluation could not
release backend work; under load this turned client-side timeouts into
server-side amplification.

The handler now passes `r.Context()` directly. Engine-internal deadlines
remain in place, so a stuck upstream is still capped.

### 6. JWKS startup deadline

**Files:** `pkg/identity/jwt/jwt.go`, `pkg/identity/oauth2/oauth2.go`.

The initial `jwk.Cache.Refresh` at module construction used the parent
background context with no deadline. A non-responsive IdP could stall
daemon startup indefinitely.

Both call sites now wrap the refresh in `context.WithTimeout(ctx, 30s)`.
Steady-state refreshes already had their own deadline and are unchanged.

### 7. Decision-cache key validation

**Files:** `internal/cache/decision.go`,
`internal/config/config.go`,
`tests/golden/authconfig/05-cache-and-ratelimit.yaml`,
`examples/config.yaml`,
`docs/DESIGN.md`.

`cache.key` previously skipped any value `resolveField` did not
recognise, with the comment "future fields don't break old configs". The
documented golden example used `pathTemplate`, which is not implemented,
so the operator-facing string `[sub, method, pathTemplate]` silently
became the cache key `sub|method`. A single allow decision could then
replay across every path the same subject hit with the same HTTP method.

`NewDecision` now rejects unknown fields and returns `module.ErrConfig`.
The recognised set is the one `resolveField` actually implements: `sub`,
`tenant`, `method`, `host`, `path`, `header:<Name>`, `claim:<Name>`.
DESIGN.md, the example config, and the golden are corrected to use
`path`. A future path-template normaliser can be added as a recognised
field; it is not silently aliased now.

### 8. ConfigDiscovery requires an Authorizer

**File:** `pkg/configstream/grpc.go`.

`AuthConfigSnapshot` bytes are trust material: every consumer pod
compiles them into its live `Engine`, and a malicious snapshot can flip
the entire policy surface. The stock daemon does not register the
`ConfigDiscovery` server on a public listener, but the convenience
`NewServer(b)` constructor allowed an embedder to attach it to any
`grpc.ServiceRegistrar` with no authentication.

`NewServer` now requires an `Authorizer func(ctx context.Context) error`
and panics on nil. `StreamAuthConfig` runs the authorizer against the
stream context before any snapshot is sent. A `status.Error` from the
authorizer is preserved verbatim; any other error is normalised to
`codes.Unauthenticated`. Embedders who genuinely want an open endpoint
must pass an explicit allow-everything function so the choice is
visible in their own code review.

## Verification

- `go test ./... -race -count=1 -timeout=300s` — all packages green.
- `tests/golden/plugin_descriptor_test.go` — wire-lock regenerated and
  passing; `protoc` will reject any future attempt to reuse field 3 on
  `PeerInfo`.
- New focused tests:
  - `internal/server/native_security_test.go`
  - `internal/pipeline/engine_security_test.go`
  - `internal/controller/idp_resolve_security_test.go`
  - `internal/cache/decision_security_test.go`
  - `pkg/configstream/grpc_security_test.go`

## Out of scope

- Decision-cache key field set. The recognised list (`sub`, `tenant`,
  `method`, `host`, `path`, `header:<Name>`, `claim:<Name>`) is now
  enforced at config-load time. New dimensions (e.g. a real
  path-template normaliser) are an additive change for a later release.