# Milestones M1–M12 — v1.0 feature inventory

This document is the canonical "what landed when" reference for
LightweightAuth v1.0. Every feature listed below is on `main` and
documented in [docs/modules/](modules/README.md) with a YAML sample. Use this
page when you want to locate a capability by milestone; use
[docs/modules/README.md](modules/README.md) when you want to locate it
by `type:` string.

The architectural rationale lives in [DESIGN.md](DESIGN.md). The v1.0
security review is in [security/v1.0-review.md](security/v1.0-review.md).

---

## M0 — Skeleton

- Repo layout, module interfaces (`pkg/module`), pipeline shell.
- Zero functional surface; sets the contracts every later milestone
  fills in.

## M1 — Local mode

| Feature                                       | Lives in                                   | Doc |
|-----------------------------------------------|--------------------------------------------|-----|
| HTTP server (Door A) + `/v1/authorize`        | `internal/server/http.go`                  | [DESIGN §5](DESIGN.md) |
| `jwt` identifier (jwx/v2 + JWKS)              | `pkg/identity/jwt`                         | [modules/jwt.md](modules/jwt.md) |
| `apikey` identifier (static + argon2id)       | `pkg/identity/apikey`                      | [modules/apikey.md](modules/apikey.md) |
| `rbac` authorizer                             | `pkg/authz/rbac`                           | [modules/rbac.md](modules/rbac.md) |
| `header-add` / `header-remove` mutators       | `pkg/mutator/headers`                      | [modules/header-add.md](modules/header-add.md), [modules/header-remove.md](modules/header-remove.md) |
| `firstMatch` / `allMust` identifier chains    | `internal/pipeline`                        | [DESIGN §2](DESIGN.md) |
| Inline-YAML + file-watch reload               | `internal/config`                          | [DEPLOYMENT.md](DEPLOYMENT.md) |

### Sample

```yaml
# config.yaml — minimal M1 setup
identifiers:
  - name: bearer
    type: jwt
    config: { jwksUrl: https://idp.example.com/.well-known/jwks.json, audiences: [my-api] }
authorizers:
  - { name: gate, type: rbac, config: { rolesFrom: "claim:roles", allow: [admin] } }
mutators:
  - { name: stamp, type: header-add, config: { headers: { "X-User": "${identity.subject}" } } }
```

## M2 — Envoy ext_authz (Door A — gRPC variant)

- `envoy.service.auth.v3.Authorization` server on `:9001`
  (`internal/server/grpc.go`).
- Same pipeline as Door A HTTP — one `EngineHolder`, two doors.
- Worked Envoy config: [examples/envoy/](https://github.com/mikeappsec/lightweightauth/tree/main/examples/envoy/) and
  [DEPLOYMENT.md](DEPLOYMENT.md).

## M3 — OAuth2 authorization-code + sessions

| Feature                                       | Lives in                  | Doc |
|-----------------------------------------------|---------------------------|-----|
| `oauth2` identifier (auth-code + PKCE)        | `pkg/identity/oauth2`     | [modules/oauth2.md](modules/oauth2.md) |
| AES-256-GCM cookie-backed session store       | `pkg/session`             | [modules/session.md](modules/session.md) |
| `header-passthrough` mutator                  | `pkg/mutator/headers`     | [modules/header-passthrough.md](modules/header-passthrough.md) |

## M4 — Kubernetes (CRDs + controller)

- `lightweightauth.io/v1alpha1` CRDs: `AuthConfig`, `IdentityProvider`,
  `Plugin` (descriptor lock — see M12).
- `internal/controller` reconciler watches `AuthConfig` and resolves
  `IdPRef` references; atomic Compile-and-Swap on every change.
- Helm chart [deploy/helm/lightweightauth/](https://github.com/mikeappsec/lightweightauth/tree/main/deploy/helm/lightweightauth/)
  with both file-mode and CRD-mode wiring.
- Pinned to `controller-runtime` aligned with `k8s.io/* v0.35.x`.

```yaml
# CRD sample — drops directly into `kubectl apply`
apiVersion: lightweightauth.io/v1alpha1
kind: AuthConfig
metadata: { name: tenant-a, namespace: default }
spec:
  identifiers:
    - name: bearer
      type: jwt
      idpRef: corp-idp                  # cluster-scoped IdentityProvider
  authorizers:
    - { name: gate, type: rbac, config: { rolesFrom: "claim:roles", allow: [admin] } }
```

## M5 — Policy expansion + decision cache

| Feature                                | Lives in                       | Doc |
|----------------------------------------|--------------------------------|-----|
| `opa` authorizer (embedded Rego)       | `pkg/authz/opa`                | [modules/opa.md](modules/opa.md) |
| `cel` authorizer (Google CEL)          | `pkg/authz/cel`                | [modules/cel.md](modules/cel.md) |
| `composite` authorizer (allOf/anyOf)   | `pkg/authz/composite`          | [modules/composite.md](modules/composite.md) |
| In-memory decision cache (LRU + TTL)   | `internal/cache/decision`      | [modules/cache-memory.md](modules/cache-memory.md) |
| Negative cache (denies; default off)   | `internal/cache/decision`      | [modules/cache-memory.md](modules/cache-memory.md) |

```yaml
authorizers:
  - name: gate
    type: composite
    config:
      allOf:
        - { type: rbac, config: { rolesFrom: "claim:roles", allow: [admin] } }
        - { type: cel,  config: { expr: 'request.headers["x-region"] == "us-east-1"' } }
cache:
  backend: memory
  ttl: 60s
  negativeTtl: 0s        # opt-in: cache denies for N seconds
```

## M6 — Remaining credential modules

| Feature                                       | Lives in                       | Doc |
|-----------------------------------------------|--------------------------------|-----|
| `mtls` identifier (X.509 + XFCC)              | `pkg/identity/mtls`            | [modules/mtls.md](modules/mtls.md) |
| `hmac` identifier (SigV4-style)               | `pkg/identity/hmac`            | [modules/hmac.md](modules/hmac.md) |
| `oauth2-introspection` identifier (RFC 7662)  | `pkg/identity/introspection`   | [modules/oauth2-introspection.md](modules/oauth2-introspection.md) |
| `jwt-issue` mutator (mint internal JWTs)      | `pkg/mutator/jwtissue`         | [modules/jwt-issue.md](modules/jwt-issue.md) |
| Refresh-token rotation + RP-initiated logout  | `pkg/identity/oauth2`          | [modules/oauth2.md](modules/oauth2.md) |

## M6.5 — Device Authorization Grant + DPoP

- RFC 8628 device flow on the `oauth2` identifier.
- `dpop` identifier (RFC 9449) — sender-constrained bearers wrapping
  any other identifier. See [modules/dpop.md](modules/dpop.md).

```yaml
identifiers:
  - name: dpop-bearer
    type: dpop
    config:
      inner:
        type: jwt
        config: { jwksUrl: https://idp.example.com/.well-known/jwks.json }
      replayWindow: 60s
      nonceStore: { backend: valkey, address: valkey:6379 }   # optional
```

## M7 — ReBAC + shared cache backend

| Feature                                  | Lives in                 | Doc |
|------------------------------------------|--------------------------|-----|
| `openfga` authorizer (Zanzibar ReBAC)    | `pkg/authz/openfga`      | [modules/openfga.md](modules/openfga.md) |
| Valkey/Redis cache backend               | `internal/cache/valkey`  | [modules/cache-valkey.md](modules/cache-valkey.md) |
| Shared decision / introspection / DPoP-replay caches | `internal/cache/valkey` | [modules/cache-valkey.md](modules/cache-valkey.md) |

```yaml
cache:
  backend: valkey
  ttl: 5m
  valkey:
    address:   valkey.lwauth.svc.cluster.local:6379
    keyPrefix: lwauth/decision/
    tls:       { enabled: true, caFile: /etc/lwauth/tls/ca.pem }
```

## M8 — Native gRPC (Door B) + SDKs

- Native `lightweightauth.v1.Auth` service: `Authorize` (unary) +
  `AuthorizeStream` (bidi).
- Generated proto bindings in [api/proto/lightweightauth/v1/](https://github.com/mikeappsec/lightweightauth/tree/main/api/proto/lightweightauth/v1/).
- Go SDK: [pkg/client/go](https://github.com/mikeappsec/lightweightauth/tree/main/pkg/client/go) — `Client.Authorize`,
  `UnaryServerInterceptor`, `HTTPMiddleware`.
- Outbound helper for service-to-service callers: [pkg/clientauth](https://github.com/mikeappsec/lightweightauth/tree/main/pkg/clientauth)
  (RFC 6749 §4.4 client-credentials with auto-refresh + Guard).

```go
// Go SDK quickstart
cli, _ := lwauthclient.New("dns:///lwauth:9001")
defer cli.Close()
mw := cli.HTTPMiddleware(myUpstream)
http.ListenAndServe(":8080", mw)
```

## M9 — Observability + audit

| Surface                          | Package                            | Doc |
|----------------------------------|------------------------------------|-----|
| Prometheus metrics (5 emitters)  | `pkg/observability/metrics`        | [modules/observability.md](modules/observability.md) |
| OpenTelemetry tracing            | `pkg/observability/tracing`        | [modules/observability.md](modules/observability.md) |
| Structured audit log (slog JSON) | `pkg/observability/audit`          | [modules/observability.md](modules/observability.md) |
| `lwauthctl audit` tail subcommand| `cmd/lwauthctl`                    | [modules/observability.md](modules/observability.md) |

Hot-path overhead: one `time.Now()`, two atomic loads, three OTel
no-op-tracer span calls. Free until an exporter is wired.

## M10 — Sibling repos + plugin runtime

- Out-of-process plugin host: `pkg/plugin/grpc` registers the single
  type `grpc-plugin` under all three module kinds.
- Sibling repos: `lightweightauth-proxy`, `lightweightauth-idp`,
  `lightweightauth-plugins` (Go / Python / Rust SDKs + reference
  plugins).

```yaml
identifiers:
  - name: saml-bridge
    type: grpc-plugin
    config: { address: unix:///var/run/lwauth/saml.sock, timeout: 200ms }
```

See [modules/plugin-grpc.md](modules/plugin-grpc.md) for the full
dial / mTLS / auth-token / reconnect surface.

## M11 — Multi-tenancy hardening + xDS push

| Feature                                    | Lives in                  | Doc |
|--------------------------------------------|---------------------------|-----|
| Outbound resilience (breaker + budget)     | `pkg/upstream`            | [modules/upstream.md](modules/upstream.md) |
| Per-tenant rate limits (token bucket)      | `pkg/ratelimit`           | [modules/ratelimit.md](modules/ratelimit.md) |
| Per-tenant key-material via `idpRef`       | `internal/controller`     | [modules/jwt.md](modules/jwt.md) |
| xDS-style streaming config push            | `pkg/configstream`        | [modules/configstream.md](modules/configstream.md) |
| `lwauthctl validate / diff / explain`      | `cmd/lwauthctl`           | [DEPLOYMENT.md](DEPLOYMENT.md) |

```yaml
# Tenant-A AuthConfig — full M11 surface in one block
spec:
  rateLimit:
    perTenant: { rps: 200, burst: 400 }
    default:   { rps: 50,  burst: 100 }
  identifiers:
    - name: bearer
      type: jwt
      idpRef: corp-idp                   # cluster-scoped IdentityProvider
  authorizers:
    - name: rebac
      type: openfga
      config:
        address: openfga.svc:8081
        storeId: 01HX...
        resilience:
          breaker:  { failureThreshold: 5, coolDown: 30s }
          retries:  { maxRetries: 2, backoffBase: 50ms, backoffMax: 1s }
```

## M12 — v1.0 release stabilization

No new runtime features. Stabilization, lock-down, and review:

| Slice | Deliverable                                    | Doc / location |
|-------|------------------------------------------------|----------------|
| 1     | Golden config + plugin descriptor lock         | [tests/golden/](https://github.com/mikeappsec/lightweightauth/tree/main/tests/golden/) |
| 2     | Plugin-author conformance suite                | [pkg/module/conformance](https://github.com/mikeappsec/lightweightauth/tree/main/pkg/module/conformance/) |
| 3     | Hot-reload concurrency stress + goleak         | `pkg/configstream/stress_test.go` |
| 4     | Envtest e2e against real kube-apiserver        | [tests/envtest/](https://github.com/mikeappsec/lightweightauth/tree/main/tests/envtest/) |
| 5     | Multi-client xDS reconnect storm tests         | `pkg/configstream/grpc_storm_test.go` |
| 6     | Fuzzing on credential parsers (jwt/hmac/dpop/mtls) | `pkg/identity/*/fuzz_test.go` |
| 7     | Soak/load harness (Door A + Door B)            | [tests/soak/](https://github.com/mikeappsec/lightweightauth/tree/main/tests/soak/) — `make soak` |
| 8     | Chaos suite (upstream fault injection)         | [tests/chaos/](https://github.com/mikeappsec/lightweightauth/tree/main/tests/chaos/) — `make chaos` |
| 9     | Secure code review + otel DoS fix              | [security/v1.0-review.md](security/v1.0-review.md) |

Plus dependency refresh: every direct dep at HEAD as of v1.0 cut
(see `go.mod`); container bases on current minor; `make vuln` clean
under Go 1.26.2.

### M12 dev commands

```bash
make test              # default suite (33 packages, ~90s)
make envtest           # CRD reconcile against real kube-apiserver
make soak              # 1k RPS / 10s; nightly: SOAK_DURATION=30m SOAK_RPS=10000
make chaos             # upstream fault injection
make fuzz              # 30s per parser; FUZZTIME=10m for nightly
make vuln              # govulncheck ./... pinned to repo toolchain
```

---

## Where to go next

- **Verifying it runs:** [QUICKSTART.md](QUICKSTART.md).
- **Calling it:** [API.md](API.md) — every HTTP path + gRPC service.
- **Operating it:** [DEPLOYMENT.md](DEPLOYMENT.md).
- **Designing against it:** [ARCHITECTURE.md](ARCHITECTURE.md), [DESIGN.md](DESIGN.md).
- **Writing a plugin:** [modules/plugin-grpc.md](modules/plugin-grpc.md) +
  [pkg/module/conformance](https://github.com/mikeappsec/lightweightauth/tree/main/pkg/module/conformance/).
- **Securing a deployment:** [security/v1.0-review.md](security/v1.0-review.md).
- **What's planned after v1.0:** [DESIGN.md §7](DESIGN.md) — the
  post-v1 roadmap (multi-writer Broker, OpenAPI doc, FIPS mode,
  distributed rate-limit, plugin lifecycle, SpiceDB adapter, …).
