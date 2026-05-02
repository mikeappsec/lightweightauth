# LightweightAuth — Design Document

> Audience: contributors and operators evaluating the project.
> Purpose: turn the five high-level requirements into concrete technical
> recommendations, and make the trade-offs explicit so we can revisit them.

---

## 0. TL;DR architecture

```
                ┌─────────────────────────────────────────┐
                │                lwauth                   │
   request ──►  │  ┌────────┐  ┌────────────┐  ┌───────┐  │ ──► allow / deny
   (HTTP /      │  │ server │─►│  pipeline  │─►│ cache │  │     (+ headers)
   ext_authz)   │  └────────┘  └─────┬──────┘  └───────┘  │
                │                    │                    │
                │   ┌────────────────┼────────────────┐   │
                │   ▼                ▼                ▼   │
                │ Identify       Authorize       Mutate   │
                │ (JWT/mTLS/     (OPA / RBAC)    (inject  │
                │  HMAC/APIKey/                    JWT)   │
                │  OAuth2)                                │
                └─────────────────────────────────────────┘
```

Three transports talk to the same `pipeline`:

1. **HTTP** — local dev / sidecar.
2. **gRPC native** — typed Go/other-language clients.
3. **gRPC `envoy.service.auth.v3.Authorization`** — Envoy `ext_authz` filter.

A fourth optional transport — a **built-in reverse proxy** — is discussed in
§3 as an alternative to Envoy.

---

## 1. Authn/Authz service: local API + gRPC routing

### Requirement recap
> A lightweight oauth2-proxy + Authorino combined; runnable locally as an API
> service, ideally exposing gRPC so requests can be routed through it before
> reaching the upstream.

### Recommendation
- Ship **one binary** (`cmd/lwauth`) that serves **HTTP + gRPC concurrently**
  on separate listeners, sharing the same in-process pipeline.
- Use **`grpc-go` with `grpc.ServerOption(MaxConcurrentStreams)`** plus the
  `protovalidate` interceptor for input validation.

### The two gRPC services, visually

The `lwauth` gRPC port registers **two services on the same listener**.
Think of it as one process with two "front doors" that lead to the same
pipeline:

```
              ┌──────────────────────────────────────────────────────────┐
              │                  lwauth (gRPC :9001)                     │
              │                                                          │
  Envoy /     │   Door A:  envoy.service.auth.v3.Authorization           │
  Istio /  ──►│            rpc Check(CheckRequest) → CheckResponse       │
  Gateway     │            (industry-standard ext_authz contract)        │
  API         │                          │                               │
              │                          ▼                               │
              │                  ┌──────────────┐                        │
  Your Go ──► │   Door B:        │  pipeline    │                        │
  service     │   lightweight    │  (Identify → │                        │
  (interceptor│   auth.v1.Auth   │   Authorize →│                        │
   or SDK)    │   rpc Authorize  │   Mutate)    │                        │
              │   →AuthorizeReply└──────────────┘                        │
              │                          │                               │
              │                          ▼                               │
              │                     allow / deny                         │
              └──────────────────────────────────────────────────────────┘
```

#### Door A — `envoy.service.auth.v3.Authorization` (ext_authz)

What it is: the **same protobuf** Envoy and every Envoy-based product
(Istio, Kuadrant, Contour, Emissary, Consul, AWS App Mesh, Gloo) already
speaks. We *implement* it; we don't define it.

- **Request shape:** `CheckRequest` carries an `AttributeContext` with
  `Request.Http` (method, host, path, headers, optional body) and the peer's
  TLS info. Headers are capped (~8 KiB by default in Envoy) and the body is
  only present if the route opts in.
- **Response shape:** `CheckResponse` with `OkHttpResponse` (headers to
  inject upstream / overwrite) or `DeniedHttpResponse` (status + body).
- **Why we adopt it as-is:** any operator who already wrote an Istio
  `AuthorizationPolicy` with `provider: lwauth` gets working auth with zero
  client code. Authorino uses the same pattern.

```
  client ─► Envoy ──► [Check RPC] ──► lwauth (Door A)
                ◄── allow + headers ─┘
           └──► upstream
```

#### Door B — `lightweightauth.v1.Auth` (native)

What it is: **our own, smaller protobuf** for callers who don't want to
pull in `envoyproxy/go-control-plane` (a heavy dep tree) and who want a
request shape that maps cleanly to non-HTTP transports (gRPC method names,
Kafka topics, internal queues, custom protocols).

Sketch (final shape lives in `api/proto/lightweightauth/v1/auth.proto`):

```proto
service Auth {
  // One-shot decision (most common).
  rpc Authorize(AuthorizeRequest) returns (AuthorizeResponse);

  // Streaming for long-lived sessions / WebSocket re-checks.
  rpc AuthorizeStream(stream AuthorizeRequest)
      returns (stream AuthorizeResponse);
}

message AuthorizeRequest {
  string method = 1;          // "GET", "grpc.health.v1.Health/Check", ...
  string resource = 2;        // free-form: URL path, gRPC FQN, topic, ...
  map<string, string> headers = 3;
  bytes  body = 4;            // optional, opt-in
  PeerInfo peer = 5;          // mTLS cert chain, IP, SPIFFE ID
  map<string, string> context = 6; // tenant id, trace id, etc.
}

message AuthorizeResponse {
  bool   allow = 1;
  int32  http_status = 2;             // hint for HTTP callers
  map<string, string> upstream_headers = 3;
  map<string, string> response_headers = 4;
  Identity identity = 5;              // so the caller can log / audit
  string deny_reason = 6;
}
```

Why this exists alongside Door A:

| Concern | Door A (ext_authz) | Door B (native) |
|---|---|---|
| Dep weight on caller | Heavy (`go-control-plane`) | Light (single small proto) |
| Non-HTTP transports (gRPC, Kafka, MQTT) | Awkward (everything pretends to be HTTP) | First-class |
| Streaming re-auth | No | Yes (`AuthorizeStream`) |
| Multi-language SDKs we'll publish | Inherits Envoy's protos | We own the surface, can keep it stable |
| Operator familiarity | High (industry standard) | Has to learn ours |

#### Concrete usage examples

**Door A — Envoy snippet:**
```yaml
http_filters:
- name: envoy.filters.http.ext_authz
  typed_config:
    "@type": type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthz
    grpc_service:
      envoy_grpc: { cluster_name: lwauth }
```

**Door B — Go interceptor inside another service:**
```go
conn, _ := grpc.Dial("lwauth:9001", grpc.WithTransportCredentials(creds))
client := authv1.NewAuthClient(conn)

srv := grpc.NewServer(grpc.UnaryInterceptor(
    func(ctx context.Context, req any, info *grpc.UnaryServerInfo,
         handler grpc.UnaryHandler) (any, error) {
        md, _ := metadata.FromIncomingContext(ctx)
        resp, err := client.Authorize(ctx, &authv1.AuthorizeRequest{
            Method:   info.FullMethod,
            Resource: info.FullMethod,
            Headers:  flatten(md),
        })
        if err != nil || !resp.Allow {
            return nil, status.Error(codes.PermissionDenied, resp.GetDenyReason())
        }
        return handler(ctx, req)
    },
))
```

#### Internally: one pipeline, two thin adapters

```
  Door A handler ──► extauthz.toRequest()  ─┐
                                            ├─► pipeline.Evaluate() ──► Decision
  Door B handler ──► nativev1.toRequest() ─┘                                │
                                                                            │
  Door A handler ◄── extauthz.toCheckResponse() ◄──────────────────────────┤
  Door B handler ◄── nativev1.toAuthorizeResponse() ◄──────────────────────┘
```

Each adapter is ~150–200 LOC. The pipeline never sees protobuf — it works
on `module.Request` / `module.Decision` (see
[pkg/module/module.go](https://github.com/mikeappsec/lightweightauth/blob/main/pkg/module/module.go)). That's what makes adding a
third door (HTTP REST, MQTT, …) cheap later.

### Modes of deployment for "routing through the service"

| Mode | How requests reach lwauth | Best for |
|------|---------------------------|----------|
| **Sidecar ext_authz** (recommended K8s default) | Envoy/Istio sends a *check* RPC to lwauth; the request body never transits lwauth. | High throughput, large bodies, service mesh users. |
| **Native gRPC middleware** | App's gRPC server runs `lwauth.UnaryInterceptor` that calls lwauth's gRPC API. | Pure-gRPC stacks, no proxy. |
| **Reverse proxy mode** | lwauth is itself a small `httputil.ReverseProxy` in front of the upstream. | Local dev, edge cases, simple deployments. |
| **Library mode** | Import `pkg/pipeline` directly. | Embedding inside another Go service. |

### Trade-offs

- **Sharing the pipeline across HTTP + gRPC** keeps logic identical but means
  the `Request` abstraction (see [pkg/module/module.go](https://github.com/mikeappsec/lightweightauth/blob/main/pkg/module/module.go))
  must be transport-agnostic. We pay a small marshalling cost in the Envoy
  adapter — acceptable.
- **Ext_authz vs native gRPC**: ext_authz is *check-only* (no body access by
  default, capped headers); native API can carry richer payloads but is
  proprietary. Supporting both is cheap (~200 LOC adapter) and avoids picking.
- **Alternative considered: reuse OAuth2 Proxy as a library.** Rejected —
  oauth2-proxy is HTTP-only, has a monolithic config, and isn't designed for
  embedding. We can lift its OIDC code paths conceptually, not as a dep.

---

## 2. Minimalistic, pluggable module system

### Requirement recap
> Minimalistic endpoint with multiple modules. Default plugins for everything,
> but users can implement their own (e.g. swap the IdP).

### Recommendation
A **three-stage pipeline** with narrow Go interfaces (already sketched in
[pkg/module/module.go](https://github.com/mikeappsec/lightweightauth/blob/main/pkg/module/module.go)):

```
Identifier(s)  →  Authorizer(s)  →  ResponseMutator(s)
```

- `Identifier`: produces an `Identity` from credentials. Multiple may be
  configured; first non-nil wins (or "all must succeed" for layered auth).
- `Authorizer`: takes the `Identity` and request, returns `Decision`.
- `ResponseMutator`: post-allow tweaks (e.g. mint a downstream JWT, redact
  headers).

Modules are wired via **config**, not code. Two plugin mechanisms:

| Mechanism | When to use | Trade-offs |
|-----------|-------------|------------|
| **Compile-time registry** (`init()` calls `module.Register`) | All built-ins, and users who fork & build. | Zero overhead, type-safe, but requires a rebuild to add a module. **Recommended default.** |
| **Out-of-process gRPC plugins** (go-plugin / Hashicorp style or a thin gRPC contract) | Closed-source or non-Go modules. | Adds an RPC hop and crash isolation; users can write modules in Python/Rust. |
| Go `plugin` package (`.so`) | — | **Not recommended.** Brittle on Linux only, version-skew nightmares. |
| WASM (e.g. wazero) | Future: untrusted user code. | Sandbox, but ecosystem for auth libs in WASM is thin today. |

**Recommendation:** ship compile-time registry now, design the plugin
interface so that an out-of-process gRPC plugin host can be added later
without breaking existing users. Defer WASM until there's demand.

### Out-of-process gRPC plugins — deeper dive

#### What it actually is

The core of `lwauth` already speaks gRPC. An **out-of-process plugin** is
simply *another* small gRPC service — typically running as a sibling
container in the same Pod (or another Unix-socket peer locally) — that
implements one of three plugin services:

```proto
// api/proto/lightweightauth/plugin/v1/plugin.proto (sketch)
service IdentifierPlugin {
  rpc Identify(IdentifyRequest) returns (IdentifyResponse);
}
service AuthorizerPlugin {
  rpc Authorize(AuthorizeRequest) returns (AuthorizeResponse);
}
service MutatorPlugin {
  rpc Mutate(MutateRequest) returns (MutateResponse);
}
```

Inside `lwauth`, an adapter implements the same Go interfaces from
[pkg/module/module.go](https://github.com/mikeappsec/lightweightauth/blob/main/pkg/module/module.go) but forwards each call
over gRPC. The pipeline cannot tell the difference between a built-in
identifier and an out-of-process one.

```
  request ──► pipeline ──► remoteAdapter ──gRPC──► your-plugin (any language)
                                              ◄── identity / decision
```

Config wires it in by URL:

```yaml
identifiers:
  - name: corp-saml-bridge
    type: grpc-plugin
    address: unix:///var/run/lwauth/saml.sock
    timeout: 100ms
```

#### Concrete use cases / benefits

1. **Closed-source / proprietary credential validators.** A bank has an
   in-house token format and can't open-source the validator. They build a
   private container that implements `IdentifierPlugin` and ship it
   alongside the upstream `lwauth` image — no fork, no rebuild on every
   `lwauth` release.
2. **Non-Go languages.** Your security team has a Python library for a
   custom HMAC scheme, or a Rust crate for a post-quantum signature. Wrap
   it in a tiny gRPC server; lwauth calls it. No need to port crypto to Go.
3. **Heavy or stateful authorizers.** A homegrown ABAC engine that loads
   100 MB of policy data and connects to three databases shouldn't live
   in-process with a latency-critical auth proxy. Run it as its own
   Deployment, scale it independently, and let lwauth stay small.
4. **Crash / blast-radius isolation.** A bug in a third-party module
   (panic, memory leak, slow loop) takes down only the plugin pod, not
   every auth request. The pipeline marks the plugin unhealthy and can
   fail open or closed per config.
5. **Independent release cadence.** Security teams update the JWT
   validator weekly; SREs only want to touch the auth proxy quarterly.
   Out-of-process plugins decouple those release trains.
6. **Bridging to existing services.** Many orgs already run a homegrown
   "auth service". Wrapping it as a `grpc-plugin` lets `lwauth` adopt it
   immediately — useful for migrations.
7. **Hot-swap / canary of policy logic.** Roll out a new authorizer
   plugin at v2, route 5% of traffic to it via config, compare decisions
   side-by-side, then promote — all without redeploying `lwauth`.

#### Trade-offs vs compile-time

| Axis | Compile-time | Out-of-process gRPC |
|------|--------------|---------------------|
| Latency overhead | ~0 | +50–500 µs (loopback gRPC), +1–5 ms (cross-pod) |
| Crash isolation | ❌ panic in plugin = crash | ✅ plugin can die independently |
| Language | Go only | Any language with gRPC |
| Distribution | Rebuild + redeploy `lwauth` | Independent container |
| Type safety | Full | Proto-validated only |
| Resource accounting | Shared with core | Separate cgroup |
| Ops complexity | One process | Two+ processes per Pod |

#### When NOT to use it

- For a built-in module we ship — it'd just add latency.
- When sub-millisecond p99 matters and you can't afford even loopback gRPC.
- For trivial logic (header rename, claim copy) — compile-time wins.

#### Implementation plan

We'll define the plugin proto and the adapter early (so the pipeline
interface stays plugin-friendly), but defer the *plugin host runtime*
(lifecycle: spawning, health-checking, restarting) to milestone **M10**.
Until then, users who want this can run their plugin as a separate Pod
and point lwauth at it via a static address.

### Config shape

```yaml
auth:
  identifiers:
    - name: corp-jwt
      type: jwt
      jwksUrl: https://idp.corp/.well-known/jwks.json
      audiences: [api.corp]
    - name: legacy-apikey
      type: apikey
      headerName: X-Api-Key
      store: secrets:redis
  authorizers:
    - name: rbac
      type: rbac
      rolesFrom: claim:roles
    - name: opa
      type: opa
      policy: file:///etc/lwauth/policy.rego
  response:
    - type: jwt-issue   # mint internal token for upstream
      issuer: lwauth
      ttl: 60s
```

### Why this beats a single "AuthProvider" interface
A monolithic interface forces every plugin to re-implement caching, header
parsing, error handling. Splitting by **pipeline phase** keeps each module
~50–150 LOC and lets the pipeline share cross-cutting concerns (caching,
metrics, tracing) once.

---

## 3. Kubernetes deployment, CRDs, Helm, and the data-plane question

### Requirement recap
> Deploy on K8s using Envoy (Authorino-style), support CRDs and a Helm chart.
> Is it possible to avoid Envoy and bring our own proxy?

### Decision: support **three data-plane modes** as first-class options

We explicitly do **not** lock to Envoy. The pipeline is the product; the
data plane is a deployment choice. Users will pick whichever fits their
environment, and we provide all three with documented support tiers:

| Mode | Status at v1.0 | What we ship | Best for |
|------|----------------|--------------|----------|
| **A. Envoy via ext_authz** | ✅ **Tier 1 (GA)** | Helm chart + sample Envoy config + ext_authz gRPC service | Existing service-mesh / Istio / Gateway API users |
| **B. eBPF redirection** | 🔬 **Tier 3 (experimental, post-v1)** | A separate `lwauth-ebpf` agent (own repo) that uses sockops/sk_msg to redirect connections to lwauth | High-density east-west enforcement, ambient-mesh-style deployments |

"Tier 1" = full docs, Helm support, CI matrix, security review.
"Tier 3" = published, but operators are expected to engage actively.

The key architectural point: **all modes drive the same pipeline.**
Mode A and C produce a `module.Request` via the ext_authz adapter; Mode B
(direct HTTP/gRPC or library embedding) produces it from the built-in
server handler. Adding or replacing a data plane never touches
policy/identifier code.

```
  ┌─────────── Mode A ──────────┐    ┌── Mode B ──────────┐    ┌── Mode C (future) ──┐
  │  Envoy ── ext_authz gRPC ── │    │  Direct HTTP/gRPC  │    │  eBPF agent ──────  │
  │                             │    │  or library embed   │    │  (sockops redirect) │
  └─────────────┬───────────────┘    └─────────┬──────────┘    └─────────┬───────────┘
                │                              │                         │
                └──────────► same module.Request ◄───────────────────────┘
                                       │
                                       ▼
                                  pipeline (one impl)
```

### Mode A — Envoy + ext_authz (Tier 1)

**How it works.** Envoy terminates the connection, holds the request body,
and calls `lwauth.Check()` over gRPC. On allow, Envoy forwards (with any
headers we injected); on deny, Envoy responds directly.

**Implementation cost for us:** small — we implement the ext_authz proto
(see §1, Door A) and ship a sample Envoy config + Helm chart.

**Benefits**
- Battle-tested L7 proxy (HTTP/1.1, HTTP/2, HTTP/3, gRPC, WebSockets).
- Free integration with Istio, Kuadrant, Contour, Emissary, Consul, App Mesh.
- Body never transits lwauth → high throughput, smaller blast radius.
- Operators can keep their existing Envoy tuning, telemetry, fleet tooling.

**Costs**
- Two processes to run / observe / upgrade per Pod.
- Envoy is heavy (~100 MB image, ~30–50 MB RSS minimum).
- Configuring Envoy is its own learning curve.

### Mode C — eBPF (Tier 3, experimental, future)

**How it works.** A privileged DaemonSet (`lwauth-ebpf`) attaches eBPF
programs (`sockops` / `sk_msg` / `cgroup_skb`) to redirect outbound or
inbound connections from selected workloads to a local `lwauth` Unix
socket, where the pipeline decides allow/deny. On allow, the kernel
splices the socket through to the real destination; on deny, the
connection is dropped.

```
  app ──connect()──► [eBPF hook] ──► lwauth (UDS) ──pipeline──► allow?
                                                    │
                                                    ├── yes: splice ──► upstream
                                                    └── no:  RST
```

**Benefits**
- No proxy in the data path → near-zero added latency, no extra hops.
- Transparent to the application; works for non-HTTP protocols.
- Plays well with ambient-mesh-style deployments (Cilium, Istio Ambient).

**Costs**
- Linux-only, kernel ≥ 5.10 for the features we'd want.
- Requires `CAP_BPF` / `CAP_SYS_ADMIN`; many regulated environments forbid this.
- Far less protocol awareness — for HTTP routing decisions you still want
  L7 parsing, which means tee-ing payloads to userspace. At that point,
  Mode A or B is usually simpler.
- Maintenance burden is high: kernel upgrades break BPF programs.

**Plan.** Defer to **post-v1.0**. Maintain in a separate repository
(`lightweightauth-ebpf`) so the core stays portable and dependency-free.
Design the pipeline now to accept connection-level (4-tuple + SPIFFE)
requests, not just HTTP, so Mode C doesn't require a refactor when we
build it.

### Service-mesh-without-Envoy (Linkerd, etc.)

Noted, not implemented by us. Linkerd's policy plane is closed; the
integration would be "call lwauth as an external authorizer" — same as
Mode A in spirit. We'll accept community contributions but won't lead.

### What we ship in K8s

1. **Helm chart** at `deploy/helm/lightweightauth/` (in this repo):
   - `lwauth` Deployment + Service (gRPC + HTTP).
   - ServiceAccount + RBAC for the controller.
   - HPA, PDB, NetworkPolicy, optional ServiceMonitor.
   - Optional sub-chart dependency on an Envoy Deployment, depending on
     the chosen data-plane mode.
3. **CRDs** under [api/crd](https://github.com/mikeappsec/lightweightauth/tree/main/api/crd/):
   - `AuthConfig` — main resource: identifiers, authorizers, response mutators
     (mirrors the YAML in §2). Namespaced.
   - `AuthPolicy` — binds an `AuthConfig` to a route/host pattern.
   - `IdentityProvider` — cluster-scoped IdP definitions reusable across
     namespaces.
4. A **controller** (controller-runtime) that watches the CRDs and pushes
   compiled config into the running `lwauth` pods via:
   - mounted ConfigMap + SIGHUP reload (simple), or
   - a small xDS-style gRPC stream lwauth pulls from the controller (scales
     better, recommended once we exceed a few dozen `AuthConfig`s).

### Bottom line for this requirement

- **Mode A (Envoy)** is the recommended default for service-mesh users.
- **Mode B (direct HTTP/gRPC or library embed)** covers standalone and
  embedded use cases without requiring an external proxy.
- **Mode C (eBPF)** is on the roadmap as a post-v1 experiment, kept in a
  separate repo to avoid bloating the core.

### CRD design sketch

```yaml
apiVersion: lightweightauth.io/v1alpha1
kind: AuthConfig
metadata:
  name: api-corp
spec:
  hosts: ["api.corp.example.com"]
  identifiers:
    - name: corp-jwt
      jwt:
        issuerUrl: https://idp.corp
        audiences: [api.corp]
  authorizers:
    - name: opa
      opa:
        rego: |
          package authz
          default allow = false
          allow { input.identity.claims.role == "admin" }
  response:
    - jwtIssue:
        issuer: lwauth
        ttl: 60s
status:
  ready: true
  observedGeneration: 7
```

This shape is intentionally close to Authorino's `AuthConfig` so users coming
from there have a short learning curve, but flatter (no `when`/`patterns`
indirection — keep §2's "minimalistic" promise).

---

## 4. Identity & credential modules

### Requirement recap
> JWT validation (default), OAuth2 flows (client credentials, auth code,
> implicit), mTLS, HMAC, API key.

Recommended built-ins, all under [pkg/identity](https://github.com/mikeappsec/lightweightauth/tree/main/pkg/identity/):

| Module | Library | Notes & trade-offs |
|--------|---------|--------------------|
| **JWT** | `github.com/lestrrat-go/jwx/v2` | Best maintained Go JWT lib; native JWKS cache, JWE/JWS support. Alternative `golang-jwt/jwt` is simpler but lacks JWKS rotation. **Pick jwx.** |
| **OAuth2 — client credentials** | `golang.org/x/oauth2/clientcredentials` | Standard. We mostly *consume* tokens here, not issue. |
| **OAuth2 — authorization code (+ PKCE)** | Built on `golang.org/x/oauth2` + state/nonce store | Needed for browser flows à la oauth2-proxy. Requires a session store (cookie-encrypted by default, Redis optional). |
| **OAuth2 — implicit** | — | **Recommend deprecating in design.** OAuth 2.1 drops it. Implement only if a customer needs it; document as legacy. |
| **OAuth2 — device code** | Add as bonus; cheap once auth-code is built. |
| **mTLS** | stdlib `crypto/tls` + SPIFFE ID parsing | Two ingestion paths: (a) lwauth itself terminates TLS (proxy mode), (b) Envoy forwards client cert via `x-forwarded-client-cert`. Support both; (b) is the K8s default. |
| **HMAC** | stdlib `crypto/hmac` | Spec the canonical request format up-front (AWS SigV4-style is well-trodden). Trade-off: SigV4 is verbose; a simpler "HMAC over method+path+date+body-hash" is enough for most. Make the canonicalizer a sub-plugin. |
| **API key** | — | Storage backends as sub-modules: in-memory (tests), file, Redis, K8s `Secret`, external secret manager. Always store **hashed** (argon2id) keys; the wire key is the only plaintext. |

### Cross-cutting recommendation
Every Identifier returns the same `Identity` shape (subject + claims map) so
Authorizers don't need to know which one fired. The pipeline stamps
`Identity.Source` for audit logs.

### Token introspection
For opaque OAuth2 tokens (RFC 7662), add an `oauth2-introspection`
identifier that calls the IdP's introspection endpoint and **caches** the
response keyed by token hash with a TTL bounded by `exp`. This is essential
for performance — see §5.

> **Note on revocation.** Caching introspection results means an early
> revocation by the IdP is invisible until the cached entry's TTL
> expires (default ≤ token `exp`). The "short TTLs + refresh rotation"
> story handles this for most deployments; operators who need stronger
> guarantees can opt into the revocation surface in
> **M14-REVOCATION** (§7, Tier E).

---

## 5. Policy enforcement & caching (design now, implement later)

### Requirement recap
> OPA or RBAC authorization, with caching, designed early even if implemented
> later.

### Models we support (or plan to)

The `Authorizer` interface is policy-model-agnostic. Out of the box we plan
to cover the four models that account for ~all real-world authz needs:

| Model | What it is | Sweet spot | Built-in? |
|-------|------------|------------|-----------|
| **RBAC** | Subject → Role → Permission. | Coarse-grained APIs, admin/user/viewer-style. | ✅ Default, zero-config. |
| **ABAC** | Decision = f(subject attrs, resource attrs, action, environment). | Multi-tenant, time/region/clearance rules, claim-driven decisions. | ✅ Via embedded OPA (Rego is our ABAC engine) and a lighter CEL option. |
| **ReBAC** | Decision derived from a graph of relationships ("user X is editor of doc Y because X is member of team Z which owns Y"). | Docs/files/orgs (Google-Drive-style), GitHub-style repo perms, multi-tenant SaaS. | ✅ Via a Zanzibar-style adapter (see below). |
| **Custom / hybrid** | Anything else (PBAC, risk-based, etc.) | Bespoke needs. | ✅ Via the `Authorizer` plugin interface. |

### Engine choices

| Engine | Models it covers | Pros | Cons |
|--------|------------------|------|------|
| **RBAC built-in** (roles → permissions, bindings via claims) | RBAC | Zero deps, fast hash lookups. Covers ~50–70% of real-world policies. | Not expressive for attribute or relationship rules. |
| **OPA / Rego** (`github.com/open-policy-agent/opa/rego`, embedded) | RBAC + ABAC | Full Rego, hot-reload, mature ecosystem, partial-eval, decision logs. | ~5–10 MB binary bloat, cold compile on policy change. |
| **OPA sidecar over HTTP** | RBAC + ABAC | Decouples policy lifecycle, language-agnostic. | Extra hop, extra process. |
| **Cedar** (`cedar-policy/cedar-go`) | RBAC + ABAC | Designed for authz, formally analyzable, small. | Smaller community than OPA today. |
| **CEL** | Lightweight ABAC | Tiny, used by K8s admission. | Less expressive than Rego for set-based rules. |
| **OpenFGA** (`openfga/openfga`) — Zanzibar-style | **ReBAC** | Production-grade Zanzibar implementation, fast check API, model store. | Requires a backing datastore (Postgres/MySQL); extra service to run. |
| **SpiceDB** (`authzed/spicedb`) | **ReBAC** | Mature Zanzibar implementation with strong consistency primitives. | Same: separate service + datastore. |
| **Built-in mini-ReBAC** | ReBAC | No external service for small graphs. | Won't scale past tens of thousands of relations; we shouldn't reinvent Zanzibar. |

### Recommendation

1. **RBAC** — built-in default, ships at M1.
2. **ABAC** — embedded **OPA/Rego** as the advanced default at M5; expose
   `policy` as inline Rego, a URL, or a ConfigMap reference. Add **CEL** as
   a lighter alternative for users who want a smaller dependency surface.
3. **ReBAC** — ship as a first-class **adapter to OpenFGA / SpiceDB**
   (whichever the user runs); the `Authorizer` issues `Check(user, relation,
   object)` RPCs and caches the result. We do **not** plan to build our own
   Zanzibar — it is a multi-year project and excellent open-source
   implementations exist.
4. **Custom** — the `Authorizer` interface (see
   [pkg/module/module.go](https://github.com/mikeappsec/lightweightauth/blob/main/pkg/module/module.go)) plus the out-of-process
   plugin mechanism (§2) covers anything we don't ship.

### Composing models

Real policies often mix models ("admin role *or* member-of relation grants
edit"). The pipeline supports a **composite authorizer** that runs a list
of authorizers with `allOf` / `anyOf` semantics:

```yaml
authorizers:
  - name: combined
    type: composite
    anyOf:
      - { type: rbac, rolesFrom: claim:roles, allow: ["admin"] }
      - { type: openfga,
          server: openfga.svc:8081,
          check: { user: "user:{{.sub}}", relation: "editor",
                   object: "doc:{{.path[2]}}" } }
      - { type: opa, policy: file:///etc/lwauth/abac.rego }
```

This lets users adopt ReBAC incrementally without ripping out existing RBAC.

### Cache design (the important part to lock in early)

Three distinct caches, each with a different invalidation story:

1. **JWKS / IdP metadata cache**
   - Keyed by issuer URL.
   - Refreshed on `Cache-Control: max-age` or every 10 min, whichever is shorter.
   - Background refresh (singleflight + jittered timer) so request-path
     never blocks on JWKS fetch.

2. **Token introspection / userinfo cache**
   - Keyed by `sha256(token)`.
   - TTL = `min(token.exp - now, configured max)`.
   - LRU with a hard size cap (default 100k entries, ~50 MB).

3. **Authorization decision cache**
   - This is the contentious one. Two choices:

     **a. Cache full decisions** keyed by a hash of the *cache key spec*
     defined in policy (e.g. `subject + method + path-template`). Fast, but
     wrong if policy depends on time, request body, or external data — needs
     explicit opt-in per `AuthConfig`.

     **b. Cache only intermediate inputs** (parsed JWT, fetched user attrs)
     and re-evaluate the policy each time. Safer, less speedup.

   - **Recommendation:** support both. Default = (b). Allow operators to
     declare `cache: { key: ["sub", "method", "path"], ttl: 30s }`
     in `AuthConfig` to opt into (a). Unknown field names are rejected
     at config-load time so a typo (e.g. `pathTemplate`) cannot silently
     collapse the key and let an allow decision replay across requests
     that differed only on the missing dimension.

### Cache implementation choices

| Option | Notes |
|--------|-------|
| **In-house `lru`** (`internal/cache/lru_internal.go`) | `container/list` + `map`, ~80 LOC, generic, eviction callback. **Default in-process backend.** Per-entry TTL is enforced by the wrapping `cache.LRU` so we don't need an "expirable" variant. |
| **`ristretto`** | Higher throughput, admission policy; more complex. Use if benchmarks demand it. |
| **Valkey (`valkey-io/valkey-go`) / Redis** | Shared `cache.Backend` for multi-replica decision / introspection / DPoP-replay caches; landed in M7 (`internal/cache/valkey`). Same client also speaks Redis 7.x. `groupcache` rejected (no `Delete` → no revocation; upstream in maintenance). |
| **`singleflight.Group`** | Mandatory in front of every cache to coalesce stampedes. Cheap, do this from day one. |

### Negative caching
Cache **deny** decisions too (shorter TTL, e.g. 5s). Stops a misbehaving
client from hammering OPA on every request.

### Observability hooks
The pipeline emits Prometheus metrics for every cache layer:
`lwauth_cache_hits_total{cache="jwks|introspect|decision"}`,
`..._misses_total`, `..._evictions_total`, plus a `decision_latency_seconds`
histogram split by allow/deny and by authorizer name. Designing this now
costs nothing and is invaluable when tuning later.

---

## 6. Cross-cutting concerns (worth deciding once)

| Concern | Recommendation |
|---------|----------------|
| **Config format** | YAML for files, CRD for K8s. Single Go struct shared by both via `sigs.k8s.io/yaml`. |
| **Hot reload** | File watcher (`fsnotify`) for local; CRD informers for K8s. The pipeline is rebuilt atomically and swapped via `atomic.Pointer`. |
| **Logging** | `log/slog` (stdlib, structured). |
| **Tracing** | OpenTelemetry. Propagate `traceparent` from Envoy. |
| **Metrics** | Prometheus via `promhttp`; OTel metrics behind a build tag. |
| **Testing** | Table-driven unit tests per module + an integration suite that boots Envoy in a container and runs real ext_authz flows. |
| **Security baseline** | Distroless image, non-root, read-only rootfs, no shell. SBOM via `syft`, signed with `cosign`. |
| **Versioning** | API (`pkg/module`) is SemVer. CRDs use `v1alpha1` until we have ≥3 production users. |

---

## 7. Roadmap

The roadmap is the authoritative checklist for everything §1–§8 promise.
Items marked ✅ are merged on `main`; everything else is ordered roughly
by dependency, not by calendar.

### Done

1. **M0 – skeleton ✅** — repo layout, module interfaces (`pkg/module`),
   design docs, `lwauth` + `lwauthctl` binaries, Helm chart skeleton,
   sample Envoy config, Dockerfile, plugin proto sketch.
2. **M1 – local mode ✅** — HTTP server, JWT identifier (`jwx/v2` + JWKS
   cache), API-key identifier (in-memory static map only), RBAC
   authorizer, in-process LRU cache layer, file-based AuthConfig YAML
   loader, `httptest` JWT round-trip + cache + RBAC tests.
3. **M2 – Envoy ext_authz ✅** — `envoy.service.auth.v3.Authorization`
   gRPC service (`internal/server/grpc.go`), dual HTTP+gRPC listeners
   in `pkg/lwauthd`, bufconn integration tests, sample Envoy config at
   `deploy/envoy/sample.yaml` and compose stack vs Envoy 1.37.x.
4. **M3 – OAuth2 auth-code + sessions ✅** — AES-256-GCM encrypted
   cookie session store (`pkg/session`), oauth2 identifier with PKCE +
   state + JWKS-verified id_token (`pkg/identity/oauth2`), HTTP flow
   endpoints `/oauth2/{start,callback,logout,userinfo}` mounted via the
   new `module.HTTPMounter` interface, full e2e flow test against an
   in-process fake IdP.

5. **M4 – Kubernetes ✅** — `lightweightauth.io/v1alpha1` CRDs
   (`AuthConfig`, `AuthPolicy`, `IdentityProvider`) at
   `api/crd/v1alpha1` with hand-written DeepCopy + scheme registration;
   single-CR `controller-runtime` reconciler (`internal/controller`)
   that compiles `AuthConfig.Spec` and atomically swaps the engine via
   `*server.EngineHolder`; compile errors recorded on `.status.message`
   never crash the manager; CR deletion preserves the last good engine.
   `fsnotify` hot-reload path for non-K8s deployments
   (`pkg/lwauthd/watch.go`, 100 ms debounce, re-arms on atomic editor
   replace). Helm chart hardened with ServiceAccount + RBAC,
   ClusterRole on `lightweightauth.io/*`, CRD manifests (Helm
   `keep` policy), HPA (autoscaling/v2), PDB, NetworkPolicy with
   peer selectors, optional `ServiceMonitor`. xDS-style controller→pod
   streaming push remains **deferred to M11**; ConfigMap + atomic
   reload is the M4 mechanism. Pinned to `controller-runtime v0.21.0`
   + `k8s.io/* v0.34.1` (newer combinations broke the cache build).

6. **M5 – Policy expansion + decision cache ✅** — embedded **OPA/Rego**
   authorizer (`pkg/authz/opa`, prepared queries on the hot path);
   **CEL** authorizer (`pkg/authz/cel`, `google/cel-go`, bool-typed
   expressions over `identity` / `request` / `context`); **composite**
   authorizer (`pkg/authz/composite`) with `allOf` / `anyOf` semantics
   that builds children via `module.BuildAuthorizer` so RBAC + ABAC +
   ReBAC compose recursively. **Decision cache**
   (`internal/cache/decision.go`) wraps `Authorizer.Authorize` with
   `golang.org/x/sync/singleflight` stampede coalescing, positive +
   negative TTLs, hash-truncated keys built from declared fields
   (`sub`, `tenant`, `method`, `host`, `path`, `header:*`, `claim:*`),
   and never caches `ErrUpstream`. Wired in via `AuthConfig.cache`
   (`{ key: [...], ttl: 30s, negativeTtl: 5s }`); zero TTL or absent
   stanza disables it. **Token introspection** identifier
   (`pkg/identity/introspection`, RFC 7662) with per-identifier LRU
   keyed by `sha256(token)`, TTL bounded by `min(exp - now, maxCacheTtl)`,
   negative cache for `active=false`, and an in-package singleflight
   so concurrent first-misses collapse to one IdP round-trip. Cache
   observability counters (`Stats.Hits` / `.Misses` / `.Evictions`)
   wired through every backend; the concrete Prometheus surface
   ships in M9.

7. **M6 – Remaining credential modules ✅** — shipped:
   - **OAuth 2.0 Bearer Token (RFC 6750)** — already covered by two
     identifiers; M6 confirms the surface is complete:
     - `jwt` (`pkg/identity/jwt`) for self-contained signed bearers
       (JWKS verify, `iss`/`aud`/`exp`/`nbf`).
     - `oauth2-introspection` (`pkg/identity/introspection`) for opaque
       bearers (RFC 7662 with per-identifier LRU + singleflight).
     Both consume `Authorization: Bearer <token>` with configurable
     `header` / `scheme`. No third "bearer" module is needed —
     every OAuth 2.0 bearer is either signed or opaque, and each
     case has a dedicated identifier.
   - **mTLS** identifier (`pkg/identity/mtls`) with two ingestion paths:
     in-process `Request.PeerCerts` and Envoy
     `x-forwarded-client-cert` parsing. SPIFFE URI-SAN takes
     precedence over CN; optional `trustedIssuers` Subject-DN
     allow-list.
   - **HMAC** identifier (`pkg/identity/hmac`) with a pluggable
     `Canonicalizer` function value. Default canonicalizes
     `method|path|date|sha256(body)`; both
     `keyId="...", signature="..."` and compact `keyId:sig`
     `Authorization` formats are accepted; clock-skew (default 5m)
     enforced via the `Date` header; constant-time compare.
   - **API-key** upgrades: argon2id (RFC 9106 §4 interactive params)
     storage (`pkg/identity/apikey/store.go`) with three backends —
     in-process `hashed.entries`, flat-file `hashed.file`, and
     K8s-Secret-volume `hashed.dir` (skips `..data` symlinks). The
     plaintext `static` map from M1 is retained as the test backend.
     `keyId` lands on `Identity.Claims["keyId"]` for audit
     attribution. Redis / Vault backends remain in
     lightweightauth-plugins.
   - **Response mutators**: `jwt-issue` (`pkg/mutator/jwtissue`,
     HS256/384/512 + RS256/384/512, `copyClaims`, configurable header
     + scheme), `header-add` / `header-remove` / `header-passthrough`
     (`pkg/mutator/headers`, `${sub}` / `${claim:foo}` expansion +
     `subjectHeader` shortcut + ext_authz delete-via-empty-value
     semantics).
   - **OAuth2 follow-ups** deferred from M3: refresh-token rotation
     (per-request opportunistic refresh inside `/oauth2/userinfo` plus
     an explicit `/oauth2/refresh` endpoint, `RefreshLeeway`
     configurable, RFC 6749 §6 rotated-RT handling), RP-initiated
     single-logout (`endSessionUrl` + OIDC RP-Initiated Logout 1.0
     `id_token_hint` + `post_logout_redirect_uri`), and a server-side
     `MemoryStore` (`pkg/session/memory.go`) implementing
     `session.Store` with 256-bit opaque SIDs and a TTL janitor.
   - **OAuth2 Client Credentials Grant** (RFC 6749 §4.4) is deferred
     to **M8**: it is the **caller** side of the `jwt` identifier —
     services run the grant themselves to obtain a bearer and hand
     the result to lwauth, where `jwt` already validates it. The
     only useful artefact is a small outbound helper
     (`pkg/clientauth`) for service-to-service callers of
     lwauth-protected upstreams; lands alongside the Door B SDKs.
   - **OAuth2 Device Authorization Grant** (RFC 8628) and **DPoP**
     (RFC 9449) are split into a small follow-up release **M6.5**
     (see below) so M6 can ship without their additional surface.

8. **M6.5 – Device Authorization Grant + DPoP ✅** _(branch
   `m6.5-device-grant-and-dpop`)_.

   *Device Authorization Grant (RFC 8628).* New interactive flow shape
   parallel to auth-code, for CLIs / TVs / IoT. Mounted under the
   existing `oauth2` HTTP surface (gated by `deviceAuthUrl` so the
   routes don't appear when the IdP doesn't support the grant):
   - `/oauth2/device/start` — proxies to the IdP's device authorization
     endpoint and returns the JSON body verbatim
     (`device_code`, `user_code`, `verification_uri`,
     `verification_uri_complete`, `expires_in`, `interval`).
   - `/oauth2/device/poll` — the caller POSTs `{ device_code }` (JSON
     or form-urlencoded). lwauth exchanges via
     `urn:ietf:params:oauth:grant-type:device_code` and returns:
     - 200 + `Set-Cookie` + `{subject, email, accessTokenExpiry}` on
       success (mints the same `Session` shape as `/oauth2/callback`),
     - 202 + `{error: authorization_pending|slow_down}` for non-terminal
       polls so vanilla HTTP clients don't throw on a 4xx,
     - 4xx with the IdP's body for terminal errors (`expired_token`,
       `access_denied`).
     Refresh-token rotation and RP-initiated logout from M6 apply
     unchanged.

   *DPoP (RFC 9449) — sender-constrained bearers.* New
   `pkg/identity/dpop` wrapper-style identifier registered as `dpop`.
   Resolves its inner identifier via `module.BuildIdentifier` so it
   composes with `jwt`, `oauth2-introspection`, or any future bearer
   verifier. Per-request verification (RFC 9449 §4.3):
   - protected header carries `typ=dpop+jwt` and an embedded public
     `jwk`; signature verifies under that JWK,
   - asymmetric-only `alg` allow-list (RS/PS/ES/EdDSA) — HMAC and
     `none` are rejected before signature work,
   - `htm` matches the request method (case-insensitive),
   - `htu` matches host + path of the request, ignoring query and
     fragment per §4.3 step 9; scheme cross-checked against
     `X-Forwarded-Proto` when present,
   - `iat` within ±`skew` (default 30 s),
   - `jti` not seen recently — replay cache backed by
     `internal/cache.LRU` (default 10 000 entries, TTL = 2·skew),
     so M7's Redis backend slots in for free,
   - confirmation-claim binding: when the inner identity surfaces
     `cnf.jkt` (RFC 7800), it MUST equal the RFC 7638 SHA-256
     thumbprint of the embedded JWK,
   - access-token binding: when the request carries a bearer (or
     `DPoP`-typed) `Authorization` header, the proof's `ath` claim
     MUST equal `base64url(sha256(token))`.
   Opt-in via `dpop: { required: true, skew: 30s }` on the wrapped
   identifier; `required: false` falls through to the inner identifier
   when no `DPoP` header is present, preserving the chained-identifier
   story.

9. **M7 – ReBAC + shared cache backend ✅** _(branch
   `m7-rebac-and-shared-cache`)_.

   *OpenFGA adapter authorizer* (`pkg/authz/openfga`) — registered as
   `openfga`. Adapts an external OpenFGA Pod (operator-run alongside
   lwauth) by mapping each authorize call to a `POST
   {apiUrl}/stores/{storeId}/check` with a `tuple_key:{user, relation,
   object}` body. The three tuple components are produced by Go
   `text/template` snippets evaluated against `{Identity, Request}`,
   so AuthConfigs derive them from request metadata
   (`user: "user:{{ .Identity.Subject }}"`,
   `relation: "{{ .Request.Method | lower }}"`,
   `object: "doc:{{ index .Request.PathParts 1 }}"`). Empty rendered
   tuples deny without a network round-trip; non-2xx responses surface
   as `module.ErrUpstream` (so M5's negative cache skips them);
   per-request timeout (`timeout`, default 2 s); optional
   `apiToken` becomes `Authorization: Bearer …`; optional
   `authorizationModelId` pins a model version. Composes under the
   M5 `composite` authorizer — the recommended pattern is
   `anyOf: [rbac, openfga]` so cheap role checks short-circuit before
   the network hop. SpiceDB stays a future adapter at the same
   surface; we picked OpenFGA first because of the simpler HTTP
   `Check` API and CNCF sandbox status.

   *Shared cache backend — Valkey* (`internal/cache/valkey`). New
   `cache.BackendSpec`/`BackendFactory`/`RegisterBackend` registry
   (`internal/cache/registry.go`) lets `AuthConfig.cache.backend`
   select between `memory` (in-process LRU, default) and `valkey`
   without touching the `Decision` cache call sites. The Valkey
   backend uses `github.com/valkey-io/valkey-go` (auto-pipelining
   RESP3 client by the Valkey core team) and binds to the standard
   `cache.Backend` interface (`Get/Set/Delete` with TTL). `keyPrefix`
   isolates multiple AuthConfigs sharing one Valkey deployment;
   factory pings on construction so misconfiguration surfaces at
   `AuthConfig` compile time. We chose **Valkey over Redis** because
   it is BSD-3 (Apache-2.0-friendly) post the Redis Inc.
   re-licensing, is wire-compatible (RESP2/3 unchanged), and is the
   default in-cloud option (AWS ElastiCache for Valkey, GCP
   Memorystore for Valkey). The same backend connects to plain Redis
   if an operator prefers it. `groupcache` is deferred — its lack of
   `Delete` makes revocation impossible, and the upstream is in
   maintenance mode. Tests use `github.com/alicebob/miniredis/v2`
   (RESP2-compatible) with `DisableCache: true` + `AlwaysRESP2: true`
   on the client; production Valkey speaks RESP3 so client-side
   tracking stays available there. The `dpop` replay cache from M6.5
   already routes through `cache.Backend`, so opting into Valkey
   makes it shared across replicas for free.

10. **M8 – Native gRPC (Door B) + SDKs ✅** _(branch
    `m8-native-grpc-and-sdks`)_.

    *Native `lightweightauth.v1.Auth` service* (`internal/server/native.go`).
    `Authorize` (unary, the common case) and `AuthorizeStream`
    (bidirectional, for long-lived sessions / WebSocket re-auth) land on
    the same `:9001` listener that already serves Door A
    (`envoy.service.auth.v3.Authorization`); both are registered against
    the same `EngineHolder` so a config swap takes effect on both
    surfaces atomically. The native adapter is ~150 LOC mirroring
    `internal/server/grpc.go`: a `requestFromAuthorize` that produces
    the same `*module.Request` ext_authz emits, plus a
    `responseFromDecision` that returns `Allow=false` in the body
    (rather than via gRPC status) so callers can read both the
    `deny_reason` and any `response_headers` in one round trip.
    `AuthorizeStream` is independent — a deny on message N does NOT
    close the stream; the *caller* decides when to disconnect.
    Streamed health is advertised as `lightweightauth.v1.Auth` in the
    standard `grpc.health.v1` service.

    *Generated proto bindings* (`api/proto/lightweightauth/v1/*.pb.go`,
    `*_grpc.pb.go`). Generated with **buf** (`buf.yaml`,
    `buf.gen.yaml`, `make proto`); both the .proto and the generated
    code are committed so consumers don't need a toolchain. The lint
    config disables `SERVICE_SUFFIX` and the unique-RPC-message rules
    so `Auth.Authorize` / `AuthorizeStream` can share
    `Authorize{Request,Response}` (both directions of the bidi stream
    use the same shape — that is the whole point).

    *Go SDK* (`pkg/client/go`, importable as `lwauthclient`). Three
    surfaces from one tiny client:
    - `Client.Authorize(ctx, *Request) (*Response, error)` — direct
      one-shot calls; `Request` and `Response` are SDK structs that
      hide the generated proto types so callers don't depend on
      `api/proto/...` directly.
    - `Client.UnaryServerInterceptor()` — drop into
      `grpc.NewServer(grpc.UnaryInterceptor(cli.UnaryServerInterceptor()))`
      and every inbound RPC is authorized using `info.FullMethod` as
      the resource, with incoming gRPC metadata flattened into headers.
      Deny → `codes.PermissionDenied` (or `Unauthenticated` for 401),
      with the lwauth `deny_reason` as the gRPC status message.
    - `Client.HTTPMiddleware(next)` — net/http middleware. Allow →
      `UpstreamHeaders` are stamped on the inbound request before
      `next` sees them; deny → `http_status` from lwauth + body
      carrying `deny_reason`. `HTTPStatusOnError` (default 503) is the
      single knob for fail-closed-vs-open when lwauth itself is
      unreachable; we ship 503 so the default is conservative.

    *Conformance tests* (`internal/server/conformance_test.go`). One
    `EngineHolder` serves both Door A (ext_authz) and Door B (native)
    on a single bufconn server; a fixture table walks
    `{admin allowed, viewer denied, missing credential}` and asserts
    the allow/deny verdict and HTTP status hint match across the two
    doors. We deliberately don't compare deny reason strings byte-for-
    byte (Door A's reason is the body Envoy sends to the client; Door
    B's is consumed programmatically), but both originate from the
    same `Decision.Reason`.

    *Outbound helper for service-to-service callers* (`pkg/clientauth`).
    The M6 deferral: this is the *caller* side of the `jwt` identifier.
    A small RFC 6749 §4.4 client-credentials helper —
    `NewClientCredentialsSource(cfg)` returns a goroutine-safe Source
    with lazy fetch + automatic refresh (configurable `Leeway`,
    default 30 s). `Source.HTTPClient(ctx)` wraps any
    `*http.Client` with `Authorization: Bearer <tok>` injection on
    every outbound request, so a service can call an
    lwauth-protected upstream in one line. `AuthStyle` covers the
    three common shapes: HTTP Basic, body params, or auto-detect with
    Basic→body fallback on 401 (Auth0 / Keycloak / generic OAuth 2.0
    parity). mTLS-to-IdP is supported by passing a pre-configured
    `HTTPClient` so `ClientSecret` can be empty.

11. **M9 – Observability + audit ✅** _(branch
    `m9-observability-and-audit`)_.

    *Prometheus metrics surface* (`pkg/observability/metrics`). New
    `Recorder` type with its own `*prometheus.Registry` so tests get an
    isolated surface; the process-wide `Default()` is what the pipeline
    reads on the hot path. Five emitters land at v1.0:

    | Metric | Type | Labels |
    |---|---|---|
    | `lwauth_decisions_total` | counter | `outcome`, `authorizer`, `tenant` |
    | `lwauth_decision_latency_seconds` | histogram (16 exp buckets, 100µs…3.3s) | `outcome`, `authorizer`, `tenant` |
    | `lwauth_identifier_total` | counter | `identifier`, `outcome` (`match`/`no_match`/`error`) |
    | `lwauth_cache_hits_total` / `_misses_total` / `_evictions_total` | `CounterFunc` | `cache` |

    Cache stats use `prometheus.CounterFunc` so the registry pulls the
    live `atomic.Uint64` values from `cache.Stats` at scrape time —
    zero polling, and a hot-reload that builds a new `*cache.Decision`
    just changes what the registered closure dereferences.
    `pkg/lwauthd` calls `RegisterCacheStats("decision", ...)` once at
    startup; the closure goes through `EngineHolder.Load()` so it
    survives every reload. `MustRegister` panics on duplicate are
    swallowed so tests can boot `Run` repeatedly. The `/metrics` route
    is mounted on the existing HTTP listener
    (`internal/server/http.go`) — no new port to expose.

    *OpenTelemetry tracing* (`pkg/observability/tracing`). Thin wrapper
    around the OTel global tracer. `pipeline.Engine.Evaluate` opens
    `pipeline.Evaluate` as the outer span and `pipeline.Identify` /
    `pipeline.Mutate` as children, with attributes
    `lwauth.{method,host,path,tenant,decision,cache_hit,identity.subject,identity.source,mutator}`.
    No exporter is wired in core: operators register their own
    `TracerProvider` (OTLP HTTP/gRPC, stdout, …) at process start;
    until they do, every span call resolves to the OTel no-op tracer
    and costs ~5 ns. Trace context propagation in/out of lwauth is
    expected via the standard `otelhttp` / `otelgrpc` server handlers,
    which operators wrap around the listeners themselves.
    `tracing.TraceIDFromContext(ctx)` exposes the W3C trace-id to the
    audit sink so audit lines and distributed traces correlate.

    *Structured audit log* (`pkg/observability/audit`). One `Event`
    struct per terminal decision, emitted via a `Sink` interface. The
    default `NewSlogSink` writes one JSON line per decision through a
    caller-supplied `*slog.Logger` under the message `audit`, with
    keys `ts, tenant, subject, identity_source, authorizer, decision,
    deny_reason, http_status, method, host, path, latency_ms,
    cache_hit, trace_id`. `audit.Discard` is the default until
    `lwauthd.Run` upgrades it to a slog sink at startup. Headers and
    request bodies are deliberately *not* logged — operators who need
    them enable trace context propagation and read the request span
    instead.

    *`lwauthctl audit` subcommand*. Tail mode: reads JSONL audit
    records from `--file` (default stdin), filters with
    `--tenant`/`--subject`/`--decision`, and re-emits matching lines.
    Pipes cleanly off `kubectl logs deploy/lwauth -f` since the JSONL
    handler reuses the operational stdout. Non-audit slog records
    (anything without `"msg":"audit"`) are skipped so a mixed stream
    works. `--follow` keeps reading past EOF for tailing a rotated
    file. The deferred admin-streaming endpoint becomes M14's
    `POST /v1/admin/...` audit feed.

    *Engine integration* lives in `internal/pipeline/engine.go`:
    `Evaluate` is now `start := time.Now(); ... evaluate(); report()`
    where `report` fans out to metrics/audit/span via the package
    defaults. The hot-path overhead is one extra `time.Now()`, two
    atomic loads (`metrics.Default()`, `audit.Default()`), and three
    span-API calls — the OTel no-op tracer makes those last three
    free until an operator wires a real provider. Identifier outcomes
    are recorded inside `identify` so the `lwauth_identifier_total`
    counter reflects every probe across `firstMatch`/`allMust`.

12. **M10 – Sibling repos + plugin runtime ✅** _(branch
    `m10-plugin-host-runtime`, sibling repos
    `lightweightauth-idp`, `lightweightauth-plugins`)_.
    - Bootstrap `lightweightauth-idp` (OIDC issuer, token endpoint,
      minimal admin UI).
    - Bootstrap `lightweightauth-plugins` (SDKs in Go / Python / Rust +
      reference plugins: SAML bridge, Vault-backed API keys, custom
      HMAC).
    - ✅ **Out-of-process plugin host runtime** (`pkg/plugin/grpc`,
      branch `m10-plugin-host-runtime`). The package registers a single
      type name `grpc-plugin` under all three module kinds; a config
      entry of the form
      ```yaml
      type: grpc-plugin
      config:
        address: unix:///var/run/lwauth/saml.sock   # or "host:port"
        timeout: 200ms
      ```
      dials the plugin (insecure today; mTLS lands in M11 alongside
      circuit-breaking) and returns a thin remote adapter satisfying
      `module.Identifier` / `Authorizer` / `ResponseMutator`. The
      pipeline cannot tell built-ins from plugins apart — same caching,
      same observability, same audit emission.

      Wire mapping:
      - `module.Request` → `authv1.AuthorizeRequest` (Path → Resource,
        []string headers comma-joined, Host surfaced as a synthetic
        `Host` header, Context map JSON-stringified). The plugin sees
        exactly what a Door B caller would.
      - `IdentifyResponse{no_match=true}` → `module.ErrNoMatch` so the
        host moves to the next configured identifier, matching built-in
        semantics. `error != ""` → `module.ErrUpstream`.
      - `AuthorizePluginResponse` → `*module.Decision` verbatim
        (allow / status / deny_reason / both header maps).
      - `MutateResponse` headers are *merged* on top of any existing
        decision headers, never replacing — composes cleanly with
        chained mutators.

      Connection pool: a process-wide `sync.Map` keyed by address de-dups
      `*grpc.ClientConn` so two identifiers + an authorizer + a mutator
      all wired to the same socket share one HTTP/2 stream pool.

      Lifecycle (spawn / health-check / restart) is **deferred to
      M11**; today the host assumes the plugin process is supervised
      externally (systemd unit or sidecar container), which is the
      documented topology in `docs/modules/plugin-grpc.md`.

      Tests: `pkg/plugin/grpc/grpc_test.go` boots a bufconn fake
      implementing all three plugin services and round-trips OK /
      no_match / plugin-error / RPC-error / config-error paths.

### Next

13. **M11 – Multi-tenancy hardening + xDS push ✅** _(branch
    `m11-multitenancy-xds`, merged in #8)._
    - **Outbound resilience** (`pkg/upstream`). Centralized circuit
      breaker (closed → open → half-open after a configurable
      cool-down) plus a token-bucket retry budget, composed by
      `Guard.Do(ctx, fn)` with bounded exponential back-off. Wired
      into every network-touching built-in: `openfga` Check,
      `oauth2-introspection`, `clientauth` token fetch, and the
      `valkey` cache backend (Get/Set/Delete each guarded). Each
      module exposes a uniform `resilience: { breaker: {...}, retries:
      {...} }` block parsed by `upstream.FromMap`. Sentinel errors
      `ErrCircuitOpen` / `ErrRetryBudgetExceeded` map to
      `module.ErrUpstream` so the pipeline returns deterministic
      503-class denies under upstream pressure rather than chewing
      worker goroutines.
    - **Per-tenant rate limits** (`pkg/ratelimit`). Token-bucket keyed
      by `Request.TenantID` with per-tenant overrides and a Default
      bucket. Wired into `pipeline.Engine` via `Options.RateLimiter`
      so the limit check fires *before* identifier work — exhausted
      tenants short-circuit to a `429` deny without spending JWKS
      fetches or OPA evaluations. Disabled by default; the limiter is
      a typed nil when `rateLimit:` is absent so cost is one branch
      per request.
    - **Per-tenant key-material isolation.** Cluster-scoped
      `IdentityProvider` CR (now carrying `header`, `scheme`,
      `minRefreshInterval` in addition to issuer/jwks/audiences). A
      tenant `AuthConfig` references one with `idpRef: <name>` on a
      jwt identifier; the controller's `ResolveIdPRefs` expands the
      reference before `Compile` so the identifier sees a
      fully-materialized config. Tenant-set scalar fields win;
      `audiences` is a deduplicated set-union so an API gateway
      shared between two services can extend the cluster list
      without forking. Reconciler now `Watches` `IdentityProvider`
      and re-enqueues the AuthConfig on every change, so a
      cluster-wide JWKS rotation propagates without touching tenant
      CRs.
    - **xDS-style push** (`pkg/configstream`). A `Broker` fans
      compiled snapshots to many subscribers with latest-wins
      conflation (slow consumers can never block `Publish`); late
      subscribers are primed with the current snapshot so a
      mid-flight pod restart catches up immediately. Wrapped by the
      `lightweightauth.v1.ConfigDiscovery` gRPC service — one
      server-streaming RPC `StreamAuthConfig` that pushes
      JSON-encoded snapshots tagged with a monotonic version. The
      reconciler optionally publishes to a `Broker` after each
      successful Compile-and-Swap; a `Stream(ctx, conn, nodeID,
      handler)` client helper drives any embedder's
      Compile-and-Swap path. JSON over the wire (rather than a
      schemafull message) is deliberate: module-specific free-form
      `config` maps round-trip cleanly through it but not through
      protobuf's struct/Any. Bufconn round-trip tests cover
      initial-snapshot delivery, mid-stream updates, and
      multi-client fan-out.
    - **`lwauthctl` dev-loop**. `lwauthctl validate --config <f>`
      compiles a YAML offline and prints a one-line summary
      (`OK hosts=… identifiers=N authorizers=N mutators=N
      cache=bool rateLimit=bool`). `lwauthctl diff --from --to`
      surfaces module-level structural diffs (`+` / `-` / `~`) plus
      scalar / cache / rateLimit changes; both files are `Compile()`d
      first so unparsable inputs are rejected before diff. `lwauthctl
      explain --config --request` dry-runs a request through the
      pipeline and prints `✓` / `·` / `✗` markers for each stage's
      verdict. Six binary-level tests boot the actual `lwauthctl` so
      the integration with `cmd/`'s flag wiring stays honest.
    - Bug fix uncovered late: `audit.Discard` was a `SinkFunc` (a
      function type, uncomparable in Go), and `lwauthd.Run` does
      `audit.Default() == audit.Discard` to detect operator overrides.
      Process boot panicked with `comparing uncomparable type
      audit.SinkFunc`, killing the lwauth container in
      `compose up --wait`. Replaced with a named zero-sized struct
      so interface-wrapped equality is well-defined; regression test
      pinned in `pkg/observability/audit/audit_test.go`.

      Tests: every new package ships a `_test.go` (race-clean) and
      the suite remained 30/30 green at every slice. The
      `pkg/configstream` tests in particular cover slow-subscriber
      conflation under N=16 concurrent goroutines and full bufconn
      gRPC round-trips against the generated stubs.

### Next

14. **M12 – v1.0 release.** This is the stabilization milestone — no new
    runtime features; the goal is to lock the surface, audit the
    codebase end-to-end, and close the testing gaps that accumulated
    while we were shipping.

    *API freeze.*
    - `pkg/module` API frozen under SemVer; CRDs promoted from
      `v1alpha1` to `v1`.
    - Plugin contract `plugin/v1` declared stable; future evolution
      through `plugin/v2`.
    - Native `lightweightauth.v1.Auth` and
      `lightweightauth.v1.ConfigDiscovery` protos declared stable.
    - Documented promotion criteria for tier 2 → tier 1 plugins.
    - Published Go SDK + Python/Rust plugin SDKs at 1.0.

    *Feature inventory frozen for v1.0 (recap of M1–M11).* Every line
    here is something we ship and support; the list is the contract.

    | Area | Surface |
    |---|---|
    | **Servers** | HTTP `/v1/authorize`, native gRPC Door B (`lightweightauth.v1.Auth.Authorize` + `AuthorizeStream`), Envoy ext_authz Door A (`envoy.service.auth.v3.Authorization.Check`), `/healthz`, `/metrics`, OAuth2 endpoints (`/oauth2/{start,callback,logout,refresh,userinfo,device/start,device/poll}`). |
    | **Identifiers** | `jwt`, `oauth2-introspection`, `oauth2` (auth-code + PKCE + device grant), `apikey` (plaintext + argon2id file/dir backends), `hmac`, `mtls`, `dpop` wrapper, `grpc-plugin` adapter. |
    | **Authorizers** | `rbac`, `opa` (embedded Rego), `cel`, `composite` (`allOf`/`anyOf`), `openfga` (HTTP `Check`), `grpc-plugin` adapter. |
    | **Mutators** | `jwt-issue` (HS/RS 256/384/512), `header-add` / `header-remove` / `header-passthrough`, `grpc-plugin` adapter. |
    | **Caches** | In-process LRU + per-entry TTL, `valkey` shared backend (also speaks Redis 7.x). Decision cache with positive + negative TTL + singleflight; per-identifier introspection cache; DPoP replay cache; JWKS via jwx. |
    | **Resilience** | `pkg/upstream` Guard (breaker + retry budget + bounded back-off) wired into every network-touching module. |
    | **Multi-tenancy** | `Request.TenantID` carried through the pipeline; per-tenant rate limits (`pkg/ratelimit`); cluster-scoped `IdentityProvider` with tenant overrides. |
    | **Config plane** | YAML files (fsnotify hot-reload), Kubernetes CRDs (`AuthConfig`, `AuthPolicy`, `IdentityProvider`) reconciled by an in-process `controller-runtime` manager, gRPC `ConfigDiscovery` push (`pkg/configstream`). |
    | **Observability** | Prometheus metrics (`lwauth_decisions_total`, `_decision_latency_seconds`, `_identifier_total`, `_cache_*`), OpenTelemetry tracing (no-op until an exporter is wired), structured audit log via `slog`. |
    | **CLI** | `lwauth` daemon, `lwauthctl validate / diff / explain / audit`. |
    | **SDKs** | Go (`pkg/client/go`), plus Python and Rust in `lightweightauth-plugins`. |
    | **Sibling repos** | `lightweightauth-idp`, `lightweightauth-plugins`. |
    | **Outbound helper** | `pkg/clientauth` client-credentials Source for service-to-service callers. |

    *Testing already in place.* The `go test ./... -count=1` matrix
    runs 30 packages green and is gated on every PR via
    `.github/workflows/build.yaml`. What's already covered:

    - **Unit**: every module has table-driven coverage of its happy
      path and its sentinel-error paths (`ErrNoMatch`,
      `ErrInvalidCredential`, `ErrConfig`, `ErrUpstream`). DPoP, HMAC,
      JWT, mTLS, introspection, OPA/CEL/RBAC/OpenFGA all carry
      explicit negative cases.
    - **Race**: the test matrix runs under `-race`; concurrency-heavy
      packages (`pkg/configstream`, `internal/cache/valkey`,
      `pkg/ratelimit`) exercise N≥16 goroutine fan-outs.
    - **Integration / transport conformance**:
      `internal/server/conformance_test.go` boots Door A and Door B
      on a single bufconn server and asserts the same allow/deny
      verdict + HTTP status hint across both. The OpenFGA tests
      stand up an `httptest` server impersonating the
      `/stores/{id}/check` endpoint; introspection tests do the same
      for RFC 7662; OAuth2 auth-code and device-grant flows have
      end-to-end tests against an in-process fake IdP.
    - **gRPC plugin host**: `pkg/plugin/grpc/grpc_test.go` boots a
      bufconn fake implementing all three plugin services and
      round-trips OK / no_match / plugin-error / RPC-error /
      config-error paths.
    - **Controller**: `internal/controller` tests reconcile fake
      `AuthConfig` + `IdentityProvider` CRs (envtest-free) covering
      Compile success, Compile error → status, idpRef resolution,
      tenant overrides, and ConfigDiscovery `Broker.Publish`.
    - **CLI**: `cmd/lwauthctl/main_test.go` builds the actual binary
      and drives `validate / diff / explain / audit` end-to-end so
      flag wiring stays honest.
    - **Compose smoke test** (`.github/workflows/build.yaml` job
      `e2e`): `docker compose up --build --wait` brings up Envoy +
      lwauth + an echo upstream; `curl` exercises healthz and a
      real ext_authz allow.

    *Additional testing planned for v1.0.* These are the gaps M12
    closes before tagging:

    1. **End-to-end Kubernetes test** with `envtest` /
       `controller-runtime`'s test harness: install the CRDs into a
       real apiserver, post an `AuthConfig`, observe the engine swap
       through `EngineHolder`, then mutate an `IdentityProvider`
       referenced via `idpRef` and assert the swap propagates. Today
       we test the reconciler's pure-function paths but not the
       envtest round-trip.
    2. **xDS-style push integration**: spin up a controller with a
       `Broker` and N gRPC `Stream()` clients in the same process,
       assert ordering + de-dup-by-version under reconnect storms.
       Single-client tests already exist; this is multi-client +
       reconnect.
    3. **Soak / load**: a `make bench` target that drives ~10k RPS
       through Door A and Door B for 30 minutes against a synthetic
       JWT identifier + RBAC + decision cache, asserts p99 < 5 ms
       and zero-error invariants. Current benchmarks are micro-only
       (table-driven `-bench` per module).
    4. **Chaos**: introduce upstream faults (slow IdP, 500-ing
       OpenFGA, packet-loss to Valkey) under load and confirm the
       `pkg/upstream` breaker opens, the retry budget bounds the
       pain, and the pipeline returns deterministic 503s rather
       than chewing goroutines. We have unit tests for each fault
       primitive; we don't yet have a "all of them at once" run.
    5. **Fuzzing** (`go test -fuzz`) on the credential parsers most
       at risk: `jwt` token splitting, `hmac` `Authorization` parsing,
       `dpop` proof header decoding, `mtls` x-forwarded-client-cert
       parsing, native gRPC `AuthorizeRequest` decoding. These are
       the inputs an attacker most directly controls.
    6. **Concurrency stress on hot reloads**: 1000 reconciles/sec on
       an `AuthConfig` while serving traffic; assert no torn reads,
       no leaked goroutines (`goleak`), and metrics counters stay
       monotonic.
    7. **Backwards-compat lock**: vendor a v1.0-RC AuthConfig YAML
       and a v1.0-RC plugin proto into `tests/golden/` and assert
       every subsequent build still parses them. This is the
       contract that turns the API freeze into something we can
       enforce in CI rather than just promise.

    *Known follow-up: multi-writer `configstream.Broker`.* The
    M12 broker stress test surfaced an implicit single-writer
    contract on `Broker.Publish`: under concurrent publishers a
    snapshot from publisher A may iterate the subscriber list
    behind publisher B's, and write an older snapshot into a
    slow subscriber's pending slot *after* B's newer snapshot
    landed. The reconciler is single-writer in production today
    (one reconcile loop per controller), so this is documented
    on `Broker.Publish` rather than fixed for v1.0. Lifting the
    contract is straightforward — compare versions in
    `subscription.deliver` so the pending slot only moves
    forwards — and is planned for the post-v1.0 line where
    per-tenant push and federation may legitimately produce
    multiple publishers. Tracked separately so it doesn't gate
    v1.0.

    *Secure code review.* Before tagging v1.0 we run a focused
    review of the codebase. Scope:

    - **Cryptography**: every code path that signs, verifies, hashes,
      or compares secrets (`jwt`, `hmac`, `dpop`, `mtls`,
      `apikey/store.go`, `pkg/session` cookie sealing,
      `pkg/mutator/jwtissue`). Confirm constant-time compares
      everywhere, no string-equality on secret material, no logging
      of token contents, no `none` / weak-alg acceptance, JWKS
      rotation under key compromise.
    - **AuthN/AuthZ correctness**: every `Identifier` honors the
      `firstMatch` / `allMust` contract, sentinel-error mapping is
      correct end-to-end (a network failure in OpenFGA must NOT be
      cached as a deny), pipeline can never accidentally allow on
      error.
    - **Untrusted-input parsing**: HTTP / gRPC adapters, CRD
      validation, gRPC proto deserialization, YAML loading. Confirm
      every parser has an upper bound (header count, body size,
      claim count) and that bounded denies happen *before*
      unbounded work.
    - **Resource exhaustion**: caches have hard size caps,
      goroutine fan-outs are bounded (e.g. controller `Watches`
      enqueue but never spawn unbounded), the `pkg/upstream` breaker
      really does shed load rather than just reorder it.
    - **Container / supply chain (lite)**: image runs as non-root,
      read-only rootfs, no shell; `examples/` configs do not embed
      production-looking secrets. (Full hardened-image work is M13;
      this pass just confirms we're not regressing today.)
    - **Plugin trust boundary**: the `grpc-plugin` adapter is the
      one place untrusted-language code returns into core. Confirm
      we don't pass through unbounded slices, never trust plugin
      timestamps, and surface plugin errors uniformly.
    - **Multi-tenancy isolation**: cache keys, audit lines, metric
      labels, rate-limit buckets are all tenant-scoped — no
      cross-tenant leak via shared state.
    - **Dependencies**: `govulncheck` clean on every release; pin
      versions; remove any unused imports.

    The review's output is a checklist in
    `docs/security/v1.0-review.md` plus follow-up issues for
    anything unfixable in M12 itself (those gate v1.0).

    *Documentation site + cookbook.* A `docs/cookbook/` of
    end-to-end recipes ("protect a gRPC service with Istio + lwauth
    + RBAC", "add OpenFGA to an existing Envoy deployment", "rotate
    HMAC secrets without downtime"). The per-module references in
    `docs/modules/` (added on the design/* branch in 2026-04) become
    the foundation; v1.0 surfaces them on a docs site.

    *Plugin-author conformance suite* (`pkg/module/conformance`):
    a Go test harness third-party module authors can vendor that
    asserts their `Identifier` / `Authorizer` / `Mutator` honors the
    contract (concurrent-safe, no Context retention, sentinel
    errors, `nil`-safety). Published alongside
    `lightweightauth-plugins`.

    *Dependency refresh — what landed and why some deps stayed pinned.*
    Run as a final M12 sweep: `go get -u ./...` followed by
    `go mod tidy` and a full test + `govulncheck` run. Outcomes:

    - **Bumped to current minor/patch:**
      - `go.opentelemetry.io/otel` family (`otel`, `trace`, `metric`,
        `sdk/metric`) **1.41.0 → 1.43.0** — also closes dependabot
        alert #1 (high) for the multi-value `baggage` header
        allocation DoS (GHSA-r3pj-fc6c-r6j8).
      - `golang.org/x/{crypto, net, sys, text, term}` to current.
      - `sigs.k8s.io/controller-runtime` **v0.21.0 → v0.23.3**.
      - `sigs.k8s.io/structured-merge-diff/v6` **6.3.2 → 6.4.0**.
      - `github.com/lestrrat-go/jwx/v3` **3.0.13 → 3.1.0** (and the
        v2 line consumed by `pkg/identity/oauth2` is at v2.1.6).
      - All Prometheus, go-openapi, fxamacker/cbor, goccy/go-json,
        mailru/easyjson, vektah/gqlparser, valyala/fastjson, and
        gomodules.xyz/jsonpatch indirects to current.
    - **k8s.io/* held at v0.35.4** (was 0.34.1, target was 0.36.0).
      The k8s 0.36 release added a new method
      (`HasSyncedChecker`) to the `client-go`
      `ResourceEventHandlerRegistration` interface, which
      controller-runtime v0.23.3 (the latest at v1.0 cut) does not
      yet implement on its `multi_namespace_cache.handlerRegistration`
      type. Building against k8s 0.36 + controller-runtime 0.23.3
      therefore breaks compilation of the indirect dependency chain
      we don't own. We pin to v0.35.4 (the highest k8s minor
      controller-runtime 0.23.3 builds against) and will revisit on
      the next controller-runtime minor.
    - **Container bases unchanged at v1.0:** `golang:1.26.2-alpine`
      (matches the repo's `go` directive), `alpine:3.22.4`,
      `envoyproxy/envoy:v1.37.2`, `ealen/echo-server:0.9.2`. All
      are on their current minor lines; bumping them is a no-op
      change tracked separately so a base-image refresh does not
      gate a code release.
    - **Verification gates the upgrade ran clean through:**
      `go build ./...`, `go test ./...` (33/33 packages green),
      `govulncheck ./...` (zero called vulnerabilities), and the
      build-tag-gated suites (`make envtest`, `make soak`,
      `make chaos`, `make fuzz`).

    The `make vuln` Makefile target (added in slice 9) reproduces
    the scan against the repo's pinned toolchain so contributors
    can replay the v1.0 result locally.

Items previously numbered 15 (M13 – Supply-chain hardening) and 16
(M14 – Revocation) have been relocated into the tiered post-v1.0
queue below — see **F1. M13-SUPPLY-CHAIN** and **E2. M14-REVOCATION**.
The relocation reflects that neither item is on a v1.0.x patch line
nor a Tier-A hardening slice: M13 remains demand-driven ecosystem work,
and M14 now belongs with the enterprise HA/cache line because revocation
depends on admin auth, audit retention, and cross-replica state.

### Post-v1.0 queue (reprioritized 2026-05-01)

The post-v1.0 list is now ordered by **risk**, not by milestone number:
security and bug-fix work runs first, then hardening that closes known
DoS / trust gaps, then quality / coverage gaps, and only then new
feature surface area. The original numeric IDs (16–27) are preserved
where they still apply; new enterprise recommendations use `OPS-*`,
`ENT-*`, and `F-*` IDs so they can be tracked independently.

#### Tier S — security & correctness (next patch line, v1.0.x)

These are open security findings or known bugs against shipped code.
They MUST land before any tier-A feature work begins.

S1. _(Removed — no longer applicable.)_

S2. **SEC-MTLS-1 — XFCC trust requires an anchor.** ✅ shipped.
    Factory-time guard in
    [pkg/identity/mtls/mtls.go](https://github.com/mikeappsec/lightweightauth/blob/main/pkg/identity/mtls/mtls.go) now
    fails closed when `trustXFCC == true && pool == nil &&
    len(trustedIssuers) == 0`, closing the symmetric mistake of
    the slice-1 fix where an XFCC-enabled config without an anchor
    silently re-enabled blind-trust behaviour. Regression test:
    `TestMTLS_TrustFlagRequiresAnchor`.

S3. **TEST-RACE-1 — Race-mode flake in `configstream`.** ✅ shipped.
    `pkg/configstream/TestGRPC_MultiClientReconnectStorm` passed in
    isolation but flaked intermittently under `go test -race ./...`.
    Investigated: the original `goleak` allow-list covered only
    *server-side* gRPC transport helpers
    (`http2Server.{keepalive,HandleStreams}`, etc.). The client-side
    counterparts (`http2Client.{reader,keepalive}`,
    `addrConn.resetTransport`, the resolver/balancer
    `CallbackSerializer`) can outlive `cc.Close()` and
    `GracefulStop()` by a few scheduler ticks under `-race ./...`,
    and trip the leak check before they unwind. Not a `Broker`
    correctness bug. Fix: mirror the server-side allow-list with the
    symmetric client-side helpers and wrap the goleak call in a
    50 ms settle window. A real `Broker` subscription-pump leak does
    not exit on its own, so it still fails the check after the
    settle.

#### Tier A — hardening (v1.1)

These close known DoS / trust gaps and reduce operator footguns.
Each is a self-contained slice, ordered roughly by impact.

A1. **F-PLUGIN-2 (was 24) — Signature on plugin replies.** Slice 8
    landed mTLS dial credentials for `grpc-plugin`, but the host
    still trusts the *payload* of a reply by virtue of having
    dialed the right address. On a shared host or a multi-tenant
    plugin sidecar that's a weaker boundary than we'd like. Add
    an optional `plugin/v1.1` extension that lets a plugin sign
    its `IdentifyResponse` / `AuthorizePluginResponse` body with
    a pre-shared key (HMAC) or X.509 cert; the host verifies
    before surfacing the result to the pipeline.

    ✅ v1.1 ships the HMAC half on `v1.1-tier-a`. Application-layer
    signature carried as gRPC trailing metadata
    (`lwauth-sig` / `lwauth-kid` / `lwauth-alg`) over a deterministic
    length-prefixed canonical encoding of the response. Modes:
    `disabled` (v1.0 default — zero-config compat), `verify` (accept
    signed or unsigned, reject *bad* signatures), `require` (every
    response must be signed). Alg/kid are bound into the protected
    bytes so a downgrade attempt invalidates the signature instead of
    silently degrading. X.509 / asymmetric is a forward-compatible
    follow-up; the trailer scheme already routes alg through to the
    host. New package
    [pkg/plugin/sign](https://github.com/mikeappsec/lightweightauth/tree/main/pkg/plugin/sign/) and the
    [signing config block](https://github.com/mikeappsec/lightweightauth/blob/main/pkg/plugin/grpc/sign.go) on every
    `grpc-plugin` factory.

A2. **K-AUTHN-2 (was 22) — Negative-cache invalid introspection.**
    ✅ shipped on `v1.1-tier-a`. The `oauth2-introspection`
    identifier already negative-cached `active=false`; v1.1 adds
    a third cache line for `ErrUpstream` outcomes (network
    failure, 5xx, circuit-open) keyed on `sha256(token)`,
    TTL = `errorTtl` (default 5s, set to 0 to disable). A flood
    of identical-token retries during an IdP blip now coalesces
    to one upstream call per token per window instead of fanning
    out. The Guard circuit-breaker still owns the per-(tenant,
    upstream) coarse policy; this cache adds per-credential
    coalescing on top. See
    [pkg/identity/introspection/introspection.go](https://github.com/mikeappsec/lightweightauth/blob/main/pkg/identity/introspection/introspection.go).

A3. **K-DOS-1 (was 23) — Distributed rate-limit aggregation.**
    `pkg/ratelimit` was per-replica through v1.0; under N pods a
    tenant could spend `N × limit` before any replica tripped.

    ✅ v1.1 ships the optional Valkey-backed aggregator on
    `v1.1-tier-a`. New `rateLimit.distributed:` block selects a
    registered backend (v1.1 ships `valkey`); per-tenant bucket
    becomes a sliding-window counter atomic across the fleet via
    Lua `ZREMRANGEBYSCORE` → `ZCARD` → `ZADD` → `PEXPIRE`.
    Per-replica buckets stay the default and continue to act as a
    safety floor: on backend success the local bucket is also
    charged so a single replica still can't exceed its `rps`; on
    backend error the limiter falls back to local (or, with
    `failOpen: true`, allows). New backend abstraction
    [pkg/ratelimit/backend.go](https://github.com/mikeappsec/lightweightauth/blob/main/pkg/ratelimit/backend.go) keeps
    the core package dependency-free; concrete impl in
    [pkg/ratelimit/valkey](https://github.com/mikeappsec/lightweightauth/tree/main/pkg/ratelimit/valkey/) registers via
    `init()` from the `pkg/builtins` blank-import.

A4. **M10-PLUGIN-LIFECYCLE (supervisor half, was 25) — Plugin
    process supervision.** Slice 8 closed the dial-credentials
    half (TLS / mTLS / fail-closed for non-loopback plaintext);
    the supervisor half ships in v1.1.

    ✅ v1.1 ships the opt-in supervisor on `v1.1-tier-a`. New
    package [pkg/plugin/supervisor](https://github.com/mikeappsec/lightweightauth/tree/main/pkg/plugin/supervisor/)
    spawns the child via `os/exec`, probes
    `grpc.health.v1.Health.Check` every `interval` over the same
    transport credentials the data plane uses, and after
    `failureThreshold` consecutive failures sends SIGTERM (Kill on
    Windows), waits up to `gracefulTimeout`, then SIGKILL. Restart
    is exponential backoff (`initial * 2^n` capped at `maxBackoff`)
    with uniform ±`jitter`; `maxRestarts: 0` = unlimited. New
    `lifecycle:` block on the `grpc-plugin` config opts in;
    operators on Kubernetes / systemd leave it unset and the v1.0
    "platform owns the sidecar" model is unchanged. Supervisor and
    connection pool share the same `poolKey` so multiple modules
    pointed at one plugin reuse one child. Config-time readiness:
    `startTimeout` bounds how long engine construction waits for
    the first successful health probe; failure surfaces as
    `ErrConfig` at boot.

A5. **K-CRYPTO-2 (was 21) — FIPS 140-3 build mode.** Optional
    `make fips` target so regulated deployments can ship a
    FIPS-validated lwauth binary alongside the stock image.

    ✅ v1.1 ships on `v1.1-tier-a`. Build path uses Go 1.24+'s
    in-tree FIPS module (selected via `GOFIPS140=v1.0.0`) rather
    than the older `GOEXPERIMENT=boringcrypto` route — pure-Go,
    no CGO, ~3 % overhead instead of the legacy 10–20 %. New
    Makefile targets `fips`, `fips-test`, `fips-verify`,
    `docker-fips`. New [Dockerfile.fips](https://github.com/mikeappsec/lightweightauth/blob/main/Dockerfile.fips)
    publishes `<image>:<tag>-fips` with the
    `org.lightweightauth.fips140=enabled` OCI label so
    image-policy admission webhooks have two independent ways
    (tag suffix + label) to refuse a stock image landing in a
    regulated namespace. New [pkg/buildinfo](https://github.com/mikeappsec/lightweightauth/tree/main/pkg/buildinfo/)
    surfaces `Version`, `Commit`, `GoVersion()`, `FIPSEnabled()`;
    the metrics recorder exposes `lwauth_fips_enabled` (always
    present, value 0/1) and `lwauth_build_info` (constant
    labelled gauge). lwauthd logs the build identity at startup
    and accepts `--print-build-info` for a deterministic
    single-line probe; the FIPS Dockerfile self-asserts
    `fips_enabled=true` at build time so a toolchain regression
    fails the image build instead of a deployment. CI gains
    `fips-test` and `build-fips` jobs in
    [.github/workflows/build.yaml](https://github.com/mikeappsec/lightweightauth/blob/main/.github/workflows/build.yaml).
    Operator-facing docs:
    [docs/operations/fips.md](operations/fips.md) lists which
    primitives switch backends and gives admission-webhook /
    Prometheus / runtime verification recipes.

#### Tier B — quality / coverage (v1.1)

Not user-visible features, but they catch whole classes of
regressions before users do.

B1. **M12-REQUEST-NORM (was M12-CONF-MATRIX) — Canonical
    `module.Request` invariants.** Originally framed as a
    Door A × Door B conformance *matrix* that would assert
    parity for every (identifier, authorizer) cell. While
    drafting that matrix we caught the underlying problem:
    parity tests can only catch the asymmetries we anticipate;
    the right fix is to make the asymmetries *unrepresentable*
    by normalizing at the adapter boundary.

    *Status: shipped on `v1.1-tier-b`* — see the full rule set
    and rationale in
    [docs/testing/request-invariants.md](testing/request-invariants.md).

    Canonical `module.Request` shape, enforced at every entry
    point ([requestFromCheck](https://github.com/mikeappsec/lightweightauth/blob/main/internal/server/grpc.go) for
    Door A, [requestFromAuthorize](https://github.com/mikeappsec/lightweightauth/blob/main/internal/server/native.go)
    for Door B, [HTTPHandler.authorize](https://github.com/mikeappsec/lightweightauth/blob/main/internal/server/http.go)
    for Door C, [reqToProto](https://github.com/mikeappsec/lightweightauth/blob/main/pkg/plugin/grpc/translate.go)
    for Door D):

    - `Method` uppercase ASCII;
    - `Headers` keys always lowercase (HTTP/2 normal form);
    - `Host` = HTTP authority (preferred from the `host`
      header), never the gRPC peer's TCP address;
    - `PeerCerts` = DER bytes of the verified leaf cert, or
      nil — never an XFCC string. The previous Door A code
      stuffed XFCC into `PeerCerts` which made
      `x509.ParseCertificate` fail on every in-process
      request; the mtls module now relies solely on the
      header path, which it always supported.

    Modules are authored against `module.Request` without
    branching on the transport. Adding Door E (e.g. an HTTP
    `/authorize` endpoint, a CLI shim, a WASM host) means
    writing one decoder that obeys the invariants — no module
    code or test changes required.

    Unit tests fence each invariant in
    [internal/server/normalize_test.go](https://github.com/mikeappsec/lightweightauth/blob/main/internal/server/normalize_test.go);
    the existing single-fixture parity self-test in
    [internal/server/conformance_test.go](https://github.com/mikeappsec/lightweightauth/blob/main/internal/server/conformance_test.go)
    remains as a smoke check that Door A and Door B agree end-
    to-end.

B2. **M12-BROKER-MW (was 19) — Multi-writer `configstream.Broker`.**
    Lift the implicit single-writer contract on `Broker.Publish`
    so per-tenant publishers and federated control planes can
    fan in safely. Compare versions in `subscription.deliver` so
    a slow subscriber's pending slot only ever moves forwards.
    Small change but it shifts a documented invariant, hence
    v1.1 rather than a v1.0 patch.

    *Status: shipped (v1.1).* Version assignment stays serialised
    under the broker mutex; delivery moved outside it. Each
    `subscription` carries a `highWater uint64` that `deliver`
    consults to drop any snapshot `<= highWater`, so two
    concurrent writers can race past each other without ever
    regressing a subscriber's pending slot. `Subscribe` seeds
    `highWater` from `b.current.Version` at prime time to fence
    the new-subscriber-versus-concurrent-Publish race. Fenced by
    `TestBrokerStress_MultiWriter` (8 writers × 500 publishes ×
    16 subscribers, asserts final version, per-subscriber
    monotonicity, drain-to-final, goleak) and the deterministic
    `TestBrokerDeliver_RejectsStaleVersion` in
    [pkg/configstream/stress_test.go](https://github.com/mikeappsec/lightweightauth/blob/main/pkg/configstream/stress_test.go).

B3. **DOC-OPENAPI-1 (was 18) — Machine-readable API contract.**
    Generate an OpenAPI 3.1 doc for the HTTP surface (`POST
    /v1/authorize`, `/healthz`, `/readyz`, `/metrics`, and
    `module.HTTPMounter` prefixes such as `/oauth2/*`) checked
    in at `api/openapi/lwauth.yaml`, served at
    `GET /openapi.json` behind the same admin gate as
    `/metrics`. Publish the existing `.proto` files as a
    `buf.build` module so consumers can codegen clients without
    vendoring.

    *Status: shipped (v1.1).* Spec checked in at
    [api/openapi/lwauth.yaml](https://github.com/mikeappsec/lightweightauth/blob/main/api/openapi/lwauth.yaml) and
    embedded into the lwauthd binary by the
    [api/openapi](https://github.com/mikeappsec/lightweightauth/blob/main/api/openapi/openapi.go) package. Two
    endpoints share one source: `GET /openapi.yaml` returns the
    bytes verbatim (preserving comments + ordering); `GET
    /openapi.json` returns a lazily-converted, cached JSON form.
    Both sit on the same listener as `/metrics`; operators
    shrink the surface with the new `--disable-http-openapi`
    flag (mirrors `--disable-http-metrics`). Module-mounted
    prefixes (`/oauth2/*`, etc.) intentionally live in their
    own per-module docs rather than in this transport-layer
    spec — the lwauthd binary doesn't know which mounters a
    given config will compose. Buf module name set in
    [buf.yaml](https://github.com/mikeappsec/lightweightauth/blob/main/buf.yaml) (`buf.build/mikeappsec/lightweightauth`)
    so `buf push` publishes the api/proto tree to the BSR.
    Fenced by `TestHTTPHandler_OpenAPI_JSON`,
    `TestHTTPHandler_OpenAPI_YAML`, and
    `TestHTTPHandler_DisableOpenAPI` in
    [internal/server/openapi_test.go](https://github.com/mikeappsec/lightweightauth/blob/main/internal/server/openapi_test.go).

#### Tier C — operator adoption (v1.1)

These do not change auth semantics; they make the shipped v1.x surface
easier to adopt, operate, and support. They should land before the
enterprise runtime work so users can validate and migrate safely.

C1. **DOC-COOKBOOK-1 (was C2 / 27) — Cookbook recipes + hosted docs.**
  ✅ shipped on `v1.1-tier-c`. `docs/cookbook/` now contains nine
  end-to-end recipes: five core workflows (gate-upstream-service,
  oauth2-pkce, openfga-on-envoy, istio-grpc-rbac, rotate-hmac) plus
  four enterprise runbooks (rotate-jwks, policy-shadow-mode,
  cache-invalidation, valkey-outage-drill). Static-site build
  (`mkdocs-material`) configured in `mkdocs.yml` with full nav.

C2. **OPS-GITOPS-1 — Config promotion, rollback, and drift detection.**
  ✅ shipped on `v1.1-tier-c`. `lwauthctl` gains three subcommands:
  `promote` (validate, stamp `spec.version`, compute SHA-256 digest,
  emit canonical JSON), `rollback` (rewrite version, re-validate),
  and `drift` (compare local version+digest against live
  `status.appliedVersion` / `status.appliedDigest` via kubectl; exit
  1 on mismatch for CI gating). `config.AuthConfig` gains
  `spec.version`; `AuthConfigStatus` gains `appliedVersion` and
  `appliedDigest` (set by the controller on every successful
  compile+swap). Operator docs:
  [operations/gitops.md](operations/gitops.md).

C3. **OPS-ADMIN-1 — Admin-plane authentication and authorization.**
  ✅ shipped on `v1.1-tier-c`. New `internal/admin` package
  implements admin-plane auth middleware with two mechanisms (admin
  JWT via dedicated JWKS + mTLS subject mapping), role-based verb
  authorization (`read_status`, `push_config`, `invalidate_cache`,
  `revoke_token`, `read_audit`), and four admin endpoint stubs
  (`/v1/admin/status`, `/v1/admin/cache/invalidate`,
  `/v1/admin/revoke`, `/v1/admin/audit`). Wired into `lwauthd.Run`
  via `Options.Admin`; disabled by default. Operator docs:
  [operations/admin-auth.md](operations/admin-auth.md). Tests:
  7 unit tests covering disabled mode, no-credential rejection,
  mTLS success/forbidden/unmapped, and wildcard/specific verb checks.

#### Tier D — enterprise runtime control (v1.2)

These are the first enterprise features to pull from §11 into the
official roadmap. They are ordered so observability and rollback land
before enforcement changes.

D1. **ENT-KEYROT-1 — Seamless verifier-side key rotation.**
  Implement the §11.1 overlap model for JWKS force-refresh metrics,
  HMAC `secrets: [{kid, secret, notBefore, notAfter}]`, `jwt-issue`
  `signingKeys`, OAuth2 client-secret fallback, API-key retirement
  metrics, and mTLS CA-bundle hot reload. Acceptance bar: no Pod
  restart, old/new key overlap is observable through
  `IdentityProvider.status.conditions`, and `lwauth_key_verify_total`
  proves the old key has drained before retirement.

D2. **ENT-POLICY-1 — Policy versioning, shadow mode, and replay diff.**
  Implement `AuthConfig.spec.version`, `status.appliedVersion`, audit
  and metric tagging by `policy_version`, and `spec.mode: shadow` so a
  new policy can run without affecting the production verdict. Add the
  replay diff workflow sketched in §11.2 so operators can compare two
  compiled engines against captured audit JSONL before promotion.

D3. **ENT-POLICY-2 — Canary policy enforcement.**
  Build on D2 by adding weighted/sticky canary evaluation with
  `agreement` metrics. The default remains observe-only; setting
  `canary.enforce: true` is the explicit cutover. This must compose
  with `composite` authorizers and decision caching without caching a
  canary verdict as the production verdict.

D4. **ENT-AUDIT-1 — Pluggable audit sinks and retention controls.**
  Extend M9's audit `Sink` beyond stdout JSONL with pluggable backends:

  - **Loki** — log aggregation (already planned).
  - **Kafka** — streaming to downstream consumers.
  - **PostgreSQL** — queryable relational store for compliance teams.
    Enables `SELECT * FROM audit_events WHERE tenant = 'acme' AND
    action = 'revoke' ORDER BY ts DESC LIMIT 100`.
  - **S3 / GCS** — cold-archive for long-term retention and forensics.
    Batches events into Parquet or JSONL objects with hourly partitioning.

  Add sampling rules (`always: [deny, shadow_disagreement, revoke]`),
  back-pressure behaviour that never blocks the auth hot path, and a
  sink registry so third-party sinks can be registered at import time.
  This is the compliance counterpart to D2/D3: every shadow or canary
  disagreement must be retained somewhere durable. Revocation events
  (E2) are emitted as audit entries so revocation history is queryable
  independently of the hot-path Valkey store (which TTL-expires entries).

D5. **ENT-DR-1 — Backup, restore, and disaster-recovery runbooks.**
  Recommended new feature. Define export/import for CRDs, policy
  bundles, key metadata, Valkey-backed revocation/cache state where
  appropriate, and audit-sink offsets. Ship a `make dr-test` or
  `lwauthctl dr verify` workflow that restores a fixture cluster and
  proves identical decisions for a golden request set. This turns HA
  from "replicas are running" into "the service can recover".

#### Tier E — enterprise cache, revocation, and HA (v1.2+)

These features change cross-replica behaviour. They should follow tiers
C/D because they rely on admin auth, policy versioning, audit retention,
and operator runbooks.

E1. **ENT-CACHE-1 — Two-tier read-through cache.**
  Implement §11.3's L1 in-process LRU + L2 Valkey read-through/write-
  through model for decision, introspection, and DPoP replay caches.
  New replicas should warm from L2 rather than forcing p99 misses on
  every pod start. Expose `lwauth_cache_layer_hits_total` by cache,
  layer, and tenant.

E2. **M14-REVOCATION (was C3 / 16) — Token, session, and decision revoke.**
  Promote the old Tier X revocation item into the enterprise HA line.
  Add a shared revocation store keyed by JWT `jti` or `sha256(token)`,
  a stable authenticated `POST /v1/admin/revoke` endpoint, `lwauthctl
  revoke`, decision-cache deletion by `(tenant, sub)` or key prefix,
  and a shared Valkey session store so OAuth2 logout on one replica is
  honored by all replicas. The default remains short-TTL; revocation
  is opt-in for operators with kill-switch or long-lived-key needs.

E3. **ENT-CACHE-2 — Tag-based invalidation and stale-while-revalidate.**
  Cache writes carry tags for tenant, subject, policy version, and
  AuthConfig. Admin invalidation publishes Valkey events so every
  replica drops matching L1 entries. Add opt-in
  `serveStaleOnUpstreamError` with `maxStaleness` so IdP/OpenFGA
  outages degrade predictably instead of turning every TTL expiry into
  a hard 503.

E4. **ENT-CACHE-3 — Cross-replica singleflight + peer broadcast.**
  Add Valkey `SETNX`-style short locks around hot cache misses so N
  replicas do not stampede the IdP, OpenFGA, or OPA sidecar on the
  same key. Fallback to in-process singleflight when Valkey is down;
  never block longer than the caller's request context.

  Additionally, harden revocation and invalidation propagation via
  direct HTTP peer broadcast so that safety-critical events reach all
  replicas even when Valkey Pub/Sub is partitioned.

  **Implementation:**

  1. *Distributed singleflight* — `internal/cache/distsf.go` provides a
     `DistSF` coordinator backed by `DistSFLocker` (Valkey `SET NX PX`).
     On cache miss: try distributed lock → winner evaluates, stores to L2,
     releases lock. Losers poll L2 every 5ms for the winner's result
     (bounded by holdDuration, default 200ms). On Valkey error or context
     cancellation, each replica falls back to per-pod singleflight (zero
     correctness impact, only N× authorizer load).

  2. *Shared HMAC key* — When `distributedSingleflight` is enabled,
     operators provide a `sharedHmacKey` (base64, ≥16 bytes). All replicas
     sign L2 entries with this shared secret so winners' results are
     verifiable by losers. The per-instance ephemeral key remains as
     fallback for L1 entries.

  3. *Peer broadcast* (`internal/admin/peerbroadcast.go`) — On revocation
     or cache invalidation, the admin handler fans out the request body to
     all discovered peers via HTTP POST. Peers are discovered via a
     `PeerResolver` interface (DNS headless Service by default, static list
     for non-Kubernetes). A sentinel header `X-Peer-Broadcast: true`
     prevents infinite re-fan-out. Fire-and-forget: failures are logged but
     never block the admin caller. Pub/Sub remains the primary propagation
     channel; peer broadcast is belt-and-suspenders.

  **Revocation safety during Valkey outage:**

  The pipeline already checks the revocation store *before* the decision
  cache (E2: `checkRevocation` → `runAuthorize`), so a cached "allow"
  can never bypass a known revocation. The remaining gap was *propagation*:
  if replica A issues a revocation but Pub/Sub is down, replicas B–N don't
  learn about it until Pub/Sub recovers.

  Peer broadcast closes this gap: the revoking replica sends the
  revocation directly to all peers. Each peer writes to its local store
  and the next request for that credential hits the revocation gate.
  Worst-case latency: one HTTP round-trip per peer (typically <2ms
  in-cluster).

  **Trade-off analysis (why #2 + #4 over alternatives):**

  | Approach | Per-request cost | Complexity | Failure coverage |
  |----------|-----------------|------------|------------------|
  | 1. Disable stale on CB open | 0 | Config-only | Loses E3 value during combined failures |
  | 2. Revocation before cache | ~30ns (map lookup) | Already done (E2) | Enforces known revocations regardless of cache |
  | 3. Peer gossip (CRDT mesh) | Background O(n²) | High (protocol, convergence) | Strongest, but operational burden |
  | **4. Admin peer broadcast** | **0 per request; O(n) per revocation** | **~50 lines** | **Covers Pub/Sub outage; only gap is full network partition** |

  We chose **#2 + #4** because:
  - #2 is already free (pipeline ordering from E2 ensures revocation
    gate runs unconditionally before cache lookup — zero new cost).
  - #4 adds negligible complexity (one file, DNS resolution + HTTP POST)
    and covers 99% of real-world Valkey outage scenarios.
  - #3 (gossip) would add operational burden disproportionate to the
    marginal coverage gain (only helps if replicas can't reach each other
    *at all*, which implies broader service degradation).

  **Config:**
  ```yaml
  cache:
    backend: tiered
    distributedSingleflight: true
    sfHoldDuration: "200ms"
    sharedHmacKey: "<base64-32-bytes>"
  admin:
    peerBroadcast:
      enabled: true
      headlessService: "lwauth-headless.ns.svc.cluster.local"
      port: "8080"
  ```

E5. **ENT-HA-1 — Controller leader election and active/active safety.**
  Enable `controller-runtime` leader election by default when
  `replicas > 1`, document lease tuning, and prove that non-leader
  pods continue serving traffic from the latest configstream snapshot.
  This is small, but it makes the controller story match the hot-path
  stateless HA story.

E6. **ENT-SLO-1 — Per-AuthConfig quotas and SLO templates.**
  Build on the v1.1 distributed rate limiter with per-AuthConfig quota
  defaults, tenant overrides, and example Sloth/Grafana recording
  rules for p99 latency and deny/error rates. Core exports metrics and
  enforces quotas; it does not become an SLO engine.

##### Tier E Cross-Item Dependency Analysis

The items in Tier E share infrastructure and must be implemented in a
way that avoids redundancy and conflict. The following matrix documents
the interactions identified during E2 planning:

| Pair   | Interaction | Resolution |
|--------|-------------|------------|
| E2↔E3  | Both use Valkey Pub/Sub for cross-replica fan-out. E3 invalidates cache entries by tag; E2 invalidates the revocation negative cache. | **Single unified event bus** (`pkg/revocation/eventbus`) with typed messages (`{"type":"revoke",...}` / `{"type":"invalidate",...}`). One subscriber goroutine per replica dispatches to the appropriate handler. E3 extends the existing bus rather than adding a second channel. |
| E2↔E3  | Both need to purge decision-cache entries by pattern — E2 by `(tenant, sub)` on subject revocation, E3 by tag on policy update. | **Tag-aware cache eviction** is built generically in E2. E3 adds more tag types (policy_version, AuthConfig digest) to the same mechanism. |
| E2↔E4  | After a subject is revoked and cache entries purged, many replicas may concurrently discover "cache miss" and hit the authorizer (thundering herd). | E4's distributed singleflight prevents post-revocation stampedes. E4's peer broadcast also ensures the revocation itself propagates without Pub/Sub dependency. |
| E2↔E5  | The Pub/Sub subscriber and negative cache run on **all** replicas, not just the leader. | **No conflict.** E5 leader election applies only to the config reconciler, not to the hot-path or revocation infra. |
| E2↔E6  | Revocation metrics must follow the same labeling scheme so SLO templates can reference them. | Revocation counters use `{tenant, result}` labels consistent with `lwauth_decisions_total`. |
| E3↔E4  | E3 invalidation may trigger a burst of cache misses; E4 dampens that burst. E3 invalidation also needs to reach peers when Pub/Sub is down. | E4's distributed singleflight dampens the burst. Peer broadcast propagates invalidation requests directly. |
| E3↔E5  | Cache invalidation Pub/Sub messages must reach non-leader pods. | Same resolution as E2↔E5 — all pods subscribe. |

**Implementation order constraint:** E2 → E3 → E4 → (E5, E6 are independent
of each other but both follow E4).

#### Tier F — ecosystem and experimental (customer-benefit ordered)

These items sit outside the core enterprise runtime path, but they have
real customer value when the surrounding ecosystem is ready. The order is
now based on operator benefit: first reduce adoption friction, then meet
procurement and release requirements, then add ecosystem integrations,
and only then graduate experimental data planes.

F1. **RELEASE-1 — Automated build, package, and release pipeline.** ✅
  shipped on `v1.2-tier-f`. GitHub Actions release workflow
  (`.github/workflows/release.yaml`) triggers on tag push: GoReleaser
  cross-compiles lwauth + lwauthctl for linux/{amd64,arm64} and
  darwin/arm64, produces archives with SHA-256 checksums, generates
  per-release SBOMs (syft/SPDX), signs checksums with Cosign (keyless
  Sigstore OIDC), publishes the Helm chart to
  `oci://ghcr.io/mikeappsec/charts/lightweightauth`, and creates a
  GitHub Release. Version injected via `-ldflags` into
  `pkg/buildinfo.{Version,Commit,Date}`. `.goreleaser.yaml` drives the
  reproducible build matrix. `make release-snapshot` allows local
  dry-run verification.

F2. **HELM-OCI-1 — Publish Helm chart to GitHub OCI registry.** ✅
  shipped on `v1.2-tier-f`. The `helm` job in `release.yaml` packages
  `deploy/helm/lightweightauth`, stamps `Chart.yaml` version from the
  git tag, pushes to `oci://ghcr.io/mikeappsec/charts/lightweightauth`,
  and Cosign-signs the OCI artifact. Operators install directly:
  `helm install lwauth oci://ghcr.io/mikeappsec/charts/lightweightauth
  --version <ver>`.

F3. **M13-SUPPLY-CHAIN (was 15) — Supply-chain hardening.** ✅
  shipped on `v1.2-tier-f`. Release workflow now produces SLSA level-3
  provenance for Go binaries via `slsa-github-generator`, Cosign-signed
  checksums (keyless Sigstore OIDC), per-release SPDX SBOMs, and Docker
  images with embedded provenance + SBOM (already in `build.yaml`).
  New [docs/operations/supply-chain.md](operations/supply-chain.md)
  covers: artifact verification (checksums, Cosign, SLSA), air-gap
  mirror workflow (crane pull/push for images, helm pull/push for
  charts), and admission-policy integration (Kyverno,
  sigstore/policy-controller). Hardened-image bases (dhi.io) remain
  deferred until an operator sponsors image entitlements.

F4. **LICENSE-HEADERS-1 — Apache 2.0 license headers on all Go source.** ✅
  shipped on `v1.2-tier-f`. Every non-generated `.go` file now carries
  `// Copyright 2026 LightweightAuth Contributors` +
  `// SPDX-License-Identifier: Apache-2.0`. CI enforcement via
  `license-check` job in `build.yaml` (runs
  `scripts/check-license-headers.sh`). Generated `.pb.go` files
  excluded. `scripts/add-license-headers.sh` available for future use.

F5. **INSTALL-TF-1 — Terraform and GitOps deployment modules.**
  New recommended feature. Many platform teams standardize on Terraform,
  OpenTofu, Argo CD, or Flux rather than hand-running Helm. Ship a small
  Terraform/OpenTofu module that installs the Helm chart, wires common
  ServiceMonitor / NetworkPolicy / values defaults, and emits a matching
  Argo CD Application example. Promotion trigger: Helm OCI publishing
  (F2) is stable and at least one reference cloud deployment is tested.

F6. **M7-SPICEDB (was C1 / 26) — SpiceDB authorizer adapter.**
  Customer benefit is strongest for teams already invested in Authzed or
  Zanzibar-style permissions. Land `pkg/authz/spicedb` registered as
  `spicedb`, composing under `composite` exactly like `openfga` does.
  Decision-cache and `pkg/upstream` Guard wiring is reused verbatim.
  Promotion trigger: at least one operator needs SpiceDB specifically
  rather than the already-shipped OpenFGA adapter.

F7. **POL-MARKET-1 — Policy bundle registry.**
  Moved up from the enterprise request list because its strongest value
  is ecosystem acceleration: reusable, signed policy bundles reduce
  time-to-first-policy for every customer. Publish reusable `AuthConfig`
  snippets and authorizer bundles ("PCI-DSS baseline", "OWASP Top 10
  rate-limit bundle", "GDPR audit profile") as OCI artifacts pulled by
  `lwauthctl`. Promotion trigger: F1 + F2 shipped, plus at least three
  reference policies authored and maintained by the project.

F8. **ENT-FEDERATION-1 — Multi-cluster config and decision federation.**
  High value for global edge deployments, but gated by the correctness
  and audit work in tiers C/D/E. Define how multiple clusters share
  signed config snapshots, tenant policy versions, and revocation events
  without trusting a single Kubernetes API server. Promotion trigger:
  admin-plane auth (C3), policy versioning (D2), audit retention (D4),
  and cache invalidation (E3) are shipped.

F9. **eBPF data plane (was 16) — experimental Mode C.**
  Customer benefit is meaningful for high-density or non-HTTP east-west
  enforcement, but the operational risk is high. Continue in the
  separate `lightweightauth-ebpf` repo. Linux-only, privileged,
  kernel-sensitive, and not a v1.x stability promise. Promotion
  trigger: at least three production reference deployments report stable
  operation and a maintainer signs up for kernel-version support.

F10. **WASM plugins (was 17) — sandboxed in-process extension runtime.**
  Useful for policy snippets and lightweight custom logic, but lower
  near-term customer value than out-of-process plugins because auth
  libraries in WASM remain immature. Evaluate `wazero` for untrusted
  policy/credential snippets with CPU, memory, and wall-clock budgets.
  Promotion trigger: auth-library support in WASM is mature enough that
  users can implement real identifiers/authorizers without
  reimplementing crypto badly.

#### Tier G — enterprise customer requests (v1.3+, customer-benefit ordered)

These items are features enterprise customers would specifically evaluate
during procurement or platform rollout. The order now prioritizes buyer
benefit: removing blockers for regulated adoption first, then reducing
policy-change risk, then improving supportability, and finally adding
advanced or narrower integrations.

G1. **SEC-EXTREF-1 — External secret-backend resolvers.**
  Highest enterprise benefit because many regulated customers cannot
  accept plaintext secrets in Kubernetes manifests. Add a pluggable
  `SecretResolver` interface in `pkg/secrets`. Reference format:
  `secretRef: "vault://kv/lwauth/jwt-key#current"` resolved at compile
  time, with TTL-bounded caching. Adapters: HashiCorp Vault, AWS
  Secrets Manager, GCP Secret Manager, Azure Key Vault, Kubernetes CSI
  Secrets Store driver. Promotion trigger: D1 (key rotation) shipped —
  secret refs feed rotatable identifiers.

G2. **ADMIN-RBAC-1 — RBAC for the admin plane itself.**
  Required by separation-of-duties programs and most enterprise change
  management. Per-tenant policy authors: who can edit which
  `AuthConfig` CRD? Today anyone with K8s edit on the namespace can
  change auth. Implement Kubernetes RBAC + admission webhook validation
  so one team cannot edit another team's policy. Promotion trigger: C3
  (admin-plane auth) shipped — that gates *who* can call the API; G2
  gates *which* policies they can edit.

G3. **DATA-RES-1 — PII redaction and data residency.**
  Non-negotiable for EU and multi-region customers. Audit events gain
  configurable PII fields that are auto-hashed or dropped per region
  (GDPR Art. 17 right-to-erasure). Audit sink routing by tenant region
  (EU events -> EU Loki only; US events -> US Kafka). Per-tenant
  data-residency policy attaches to `AuthConfig`. Promotion trigger:
  D4 (audit sinks) shipped.

G4. **COMP-REPORT-1 — Compliance report generator.**
  Converts technical controls into procurement evidence. `lwauthctl
  compliance --framework {soc2|iso27001|pci-dss|hipaa|fedramp}` emits
  PDF and JSON evidence: who can access what, who changed policy when
  (immutable audit trail), key-rotation history, audit retention proof,
  MFA enforcement coverage, break-glass history, and unresolved drift.
  Scheduled generation via CronJob; exportable to GRC tools. Promotion
  trigger: D2 + D4 (versioned policy + durable audit).

G5. **ID-MFA-1 — Step-up MFA and assurance-level policies.**
  New recommended feature. Enterprise buyers often need policies like
  "allow read with normal SSO, require phishing-resistant MFA for admin
  writes". Add identity assurance claims (`acr`, `amr`, device posture,
  IdP risk level) as first-class policy inputs and a response path that
  can return a step-up challenge hint to the upstream or IdP. Promotion
  trigger: D2 (policy versioning) and OAuth2/OIDC flow docs are stable.

G6. **EXPLAIN-API-1 — Decision explainability API.**
  High day-two value: support teams need to answer "why was this denied?"
  without reproducing a live request. `POST /v1/explain` (admin-gated)
  returns a full trace for a request: which identifier matched, which
  authorizer ran, which rule fired, which mutators executed, with
  per-stage timing and the policy version evaluated. Outputs are
  structured JSON suitable for support tooling and incident response.
  Promotion trigger: D2 (policy versioning) for trace stamping.

G7. **POL-SIM-1 — Policy simulation and impact analysis.**
  Reduces production-change risk. Replay last N hours of production
  audit events against a candidate policy; report percentage of
  decisions changed, top affected subjects/paths, deny reasons, and
  per-tenant breakdown. Goes beyond shadow mode by answering "if I
  merge this, who breaks?" before committing the change. Promotion
  trigger: D2 + D4 (audit sinks for replay source).

G8. **POL-TEST-1 — Policy-as-Code testing framework.**
  Gives application teams a CI contract for policy changes. Add
  `lwauthctl test` that runs YAML test fixtures (`request -> expected
  decision`) like Rego unit tests. Generate test scaffolds from
  `lwauthctl explain` outputs. Provide a Go testing harness for CI
  integration. Allow fixtures to be checked into Git alongside
  `AuthConfig` CRDs so PRs require passing tests. Promotion trigger:
  D2 (policy versioning) shipped.

G9. **ID-SAML-1 — SAML 2.0 + SCIM 2.0 identifiers.**
  Common procurement blocker in FSI, healthcare, education, and
  government. Add `pkg/identity/saml` (SP-initiated and IdP-initiated
  flows, signature validation, NotBefore/NotOnOrAfter) and
  `pkg/identity/scim` (provisioning callbacks). Required for customers
  whose IdPs (PingFederate, ADFS, older Okta) emit SAML, not OIDC.
  Promotion trigger: at least one customer commitment — adds
  significant XML / xmldsig dependency surface.

G10. **BREAKGLASS-1 — Time-bounded / break-glass access.**
  Operationally important for on-call and incident response. Built-in
  support for: "grant `user X` role `admin` until `T+1h`, audited as
  break-glass". Auto-revokes; emits a distinct compliance event tagged
  `break_glass=true`; requires ticket / incident ID metadata. Promotion
  trigger: E2 (revocation) shipped — uses the same store.

G11. **QUOTA-TIER-1 — Per-tenant SLA & quota enforcement.**
  Buyer value is strongest for SaaS platforms that map commercial tiers
  to technical limits. Beyond rate limiting: burst credits, monthly
  quotas, "tier=enterprise gets 10K rps, tier=free gets 100 rps" with
  billing-grade accounting. Quota state durable in Valkey; overage
  events publishable to billing pipelines. Compatible with the existing
  rate limiter API. Promotion trigger: E1 (two-tier cache) for quota
  state.

G12. **DEC-SIGN-1 — Bring-your-own KMS for decision signing.**
  Valuable for zero-trust mesh and high-assurance integrations. Sign
  decision responses (Door A/B/C) with a tenant-scoped key from external
  KMS (AWS KMS, GCP KMS, Azure Key Vault, Vault Transit) so downstream
  services can verify the decision came from a trusted policy engine.
  Promotion trigger: G1 (external secrets) shipped — same resolver and
  key-management surface.

G13. **CHANGE-APPROVAL-1 — Policy change approval workflow.**
  New recommended feature. Many enterprises require two-person review
  for production authorization changes. Add optional approval metadata
  (`approvedBy`, `changeTicket`, `expiresAt`) validated by an admission
  webhook or `lwauthctl promote`; block production promotion when the
  approval is missing, stale, or self-approved. Promotion trigger: G2
  (admin RBAC) + C2 (GitOps promotion) shipped.

G14. **PORTAL-RO-1 — Self-service policy portal (read-only first).**
  Reduces platform-team ticket volume once the admin model is safe. Web
  UI gated by SSO that lets app teams search "why was my request
  denied?" by trace ID, view their tenant's effective policy, view
  recent decisions, and request changes via a generated PR. Read-only
  first; write access (G2 RBAC + G13 approvals required) is a follow-up.
  Promotion trigger: G2 (admin RBAC) for write mode.

G15. **POL-LINT-1 — Policy linting and best-practice rules.**
  Good ROI and useful early, but less of a blocker than secrets,
  residency, or compliance evidence. `lwauthctl lint` warns on overly
  permissive rules (`defaultAllow: true`), missing rate limits,
  identifiers without `requireMfa`, unbounded session TTLs, deprecated
  module types, config-shape antipatterns, and missing owner metadata.
  Configurable rule severity. Hooks into `lwauthctl validate` and CI.
  Promotion trigger: immediate — pure additive tooling.

G16. **SIEM-DETECT-1 — SIEM mappings and detection content.**
  New recommended feature. Ship Splunk, Elastic, Microsoft Sentinel,
  and Chronicle parsers/dashboards for audit events plus detection
  rules for unusual deny spikes, break-glass use, admin-policy edits,
  key-rotation failures, and cross-tenant access attempts. Promotion
  trigger: D4 (audit sinks) shipped and audit event schemas are stable.

G17. **CDC-INVAL-1 — Cross-cluster cache invalidation via CDC.**
  Important for multi-region customers, but behind the core revocation
  and invalidation work. Stream cache-invalidation events through Kafka
  or NATS instead of point-to-point Valkey Pub/Sub. Bounded-staleness
  guarantees per tenant; survives regional Valkey outages because
  invalidation events buffer at the broker. Promotion trigger: E3
  (cache invalidation) plus at least one multi-region customer.

G18. **FED-CRDT-1 — Multi-region active/active policy sync.**
  Advanced global-control-plane feature. Extends F8 (federation):
  CRDT-style policy version vectors so two regions can edit
  independently and merge cleanly without a global lock or single write
  region. Conflict resolution rules per policy-section type (lattice for
  rate limits, last-writer-wins for rule lists, etc.). Promotion
  trigger: F8 prototype + at least one customer with a global
  active/active deployment commitment.

### Prioritization rationale

The reorder follows a single rule: **never ship a new feature on top of
a known security or correctness gap.** Concretely:

- **Tier S items are non-negotiable.** S1 is an active mode-B bypass
  (query / body never reach the engine), S2 re-enables a previously
  fixed XFCC class with one config typo, and S3 is masking real
  concurrency regressions. They block the v1.1 branch from opening.
- **Tier A items are hardening, not features.** Each one closes a
  category of attack we already know about (plugin payload trust,
  introspection-driven DoS, rate-limit-N-replica DoS, plugin process
  supervision, FIPS compliance). They land before any new module.
- **Tier B is the test / contract investment** that pays for tier C
  going faster. The conformance matrix in particular will catch a
  whole class of "we added a new identifier and Door B does
  something subtly different" regressions before they ship.
- **Tier C is adoption and control-plane safety.** Docs, GitOps
  promotion, rollback, drift detection, and admin-plane auth land before
  new enterprise endpoints so every later feature has a safe operating
  model.
- **Tier D is runtime enterprise control.** Key rotation, policy
  versioning, shadow/canary, audit sinks, and disaster-recovery runbooks
  are the first §11 features to graduate because they reduce operational
  risk without requiring global cache semantics.
- **Tier E is cross-replica state.** Revocation, tag invalidation,
  two-tier caches, cross-replica singleflight, leader election, and SLO
  templates are grouped together because they all affect HA behaviour
  across replicas.
- **Tier F is demand-driven ecosystem work.** Its order is customer-
  benefit weighted: release automation, Helm OCI, supply-chain trust,
  and deployment modules come before optional adapters or experimental
  runtimes because they shorten the path from evaluation to production.
  SpiceDB, federation, eBPF, and WASM still require an operator or
  maintainer to own the external ecosystem before they graduate.
- **Tier G is enterprise-customer requests.** Its order is buyer-
  benefit weighted: external secrets, admin RBAC, data residency,
  compliance evidence, and MFA step-up remove procurement blockers;
  explainability, simulation, and policy tests reduce day-two support
  and change risk; quota, signing, portal, SIEM, CDC, and global sync
  follow once their prerequisite runtime surfaces are stable.

The sibling repos (`lightweightauth-idp`, `lightweightauth-plugins`,
`lightweightauth-ebpf`) inherit this ordering: plugin work follows the
same S/A/B hardening gates, enterprise operator features land only after
the core control plane is safe, and experimental data-plane work stays
demand-driven.

### Explicit non-goals

- **OAuth2 implicit flow** — dropped by OAuth 2.1; we will not ship it.
  Users with a legacy IdP that only emits implicit can wrap it as an
  out-of-process plugin.
- **Reimplementing Zanzibar** — we adapt OpenFGA / SpiceDB; we will
  not build our own ReBAC engine (§5).
- **Becoming a service mesh** — we integrate with one (Envoy) instead.

---

## 8. Resolved decisions

These were open questions; answers below are accepted.

- **Multi-tenancy: YES, day one.** One `lwauth` instance can front many
  APIs / tenants with isolated config. Implications:
  - `AuthConfig` CRDs are namespaced; the controller indexes them by
    `(host, path-pattern)` so a single Pod serves many tenants.
  - The pipeline carries a `tenantID` in `module.Request.Context`; cache
    keys, metrics labels, and audit logs are all tenant-scoped.
  - Per-tenant rate limits and per-tenant key material (HMAC secrets,
    OAuth client secrets) are loaded from the tenant's namespace only.
  - Cluster-scoped `IdentityProvider` resources can be shared across
    tenants; tenant-scoped overrides are allowed.

- **License: Apache-2.0.** Matches Envoy/OPA/K8s and the modules we depend
  on. The `LICENSE` file will be replaced with the full Apache-2.0 text
  before the first tagged release.

- **Request body access: opt-in per route.** Default = off. An
  `AuthConfig` can declare `withBody: true` (and a `maxBodyBytes` cap) for
  routes that genuinely need it (e.g. signature verification over the body,
  fine-grained ABAC on payload fields). Envoy is configured with
  `with_request_body` only when at least one matching route requests it.

- **Repository split (built-in IdP, proxy, eBPF agent move out).**
  See §9 below for the full topology. Short version: the main repo keeps
  the name **`lightweightauth`** (no `-core` suffix); IdP, proxy, and eBPF
  agent each live in their own sibling repo and consume `lightweightauth`
  as a library or via its plugin contract.

---

## 9. Repository topology

We deliberately split the project across several repositories instead of
shipping a monorepo. The goal is to keep the **core small, stable, and
dependency-light** so that operators who only need ext_authz never pull in
proxy/IdP/eBPF code paths.

```
  ┌──────────────────────────────────────────────────────────────────┐
  │                       lightweightauth (this repo)                  │
  │                                                                    │
  │  • pipeline (Identify / Authorize / Mutate)                        │
  │  • built-in modules: JWT, mTLS, HMAC, API key, RBAC, OPA, OpenFGA  │
  │  • servers: HTTP, native gRPC, Envoy ext_authz                     │
  │  • CRDs (AuthConfig / AuthPolicy / IdentityProvider) + controller  │
  │  • Helm chart                                                      │
  │  • plugin contract (pkg/module + plugin proto)                     │
  └─────────┬──────────┬────────────┬──────────────────┐
            │ imported  │ imported │ imported   │ imported by
            │ by        │ by       │ by         │
            ▼           ▼          ▼            ▼
  ┌──────────────┐ ┌──────────────┐ ┌──────────────────┐
  │ -idp (M3+) │ │ -ebpf      │ │ -plugins         │
  │ issuer +   │ │ Mode C     │ │ SDK + reference  │
  │ token ep + │ │ sockops    │ │ plugins (Python, │
  │ admin UI   │ │ redirector │ │ Rust, Go)        │
  └──────────────┘ └──────────────┘ └──────────────────┘
     Tier 1         Tier 3         Tier 2
```

### `lightweightauth` (this repo) — the core

- **What's in it:** pipeline, all in-process built-in modules, the HTTP +
  native gRPC + Envoy ext_authz servers, the CRDs and controller, the Helm
  chart, and the public plugin contract.
- **Dep weight:** intentionally small. `grpc-go`, `controller-runtime`,
  `opa/rego`, `lestrrat-go/jwx`, `golang-lru/v2`. **No HTTP/2/3 proxy**
  libraries, no UI deps, no eBPF toolchain.
- **What it does NOT contain:** reverse-proxy code, an IdP UI, eBPF
  programs, sample non-Go plugins.
- **Module path:** `github.com/mikeappsec/lightweightauth`.
- **Image:** `ghcr.io/mikeappsec/lightweightauth`.
- **Helm chart:** `lightweightauth`.

### `lightweightauth-idp` — built-in IdP (separate repo, Tier 2)

- **What's in it:** OIDC issuer, token endpoint, optional admin UI, user
  store adapters. Implements `lightweightauth`'s `Identifier` interface so
  the core consumes it like any third-party IdP.
- **Why split:** an IdP needs a UI, a user store, and migration tooling —
  none of which belong in a sidecar auth proxy. Lets the IdP evolve
  independently.
- **Module path:** `github.com/mikeappsec/lightweightauth-idp`.

### `lightweightauth-ebpf` — Mode C (separate repo, Tier 3, post-v1)

- **What's in it:** eBPF programs (CO-RE), the privileged DaemonSet that
  loads them, and the bridge that turns redirected connections into
  `module.Request`s for `lightweightauth`.
- **Why split:** Linux-only, `CAP_BPF`, kernel-version-sensitive. Keeping
  it separate means the core stays portable (Windows/macOS dev, ARM).

### `lightweightauth-plugins` — plugin SDK + reference impls (Tier 2)

- **What's in it:** the language SDKs (Go, Python, Rust) for writing
  out-of-process plugins, plus reference plugins (e.g. a SAML bridge, a
  Vault-backed API-key store, a custom HMAC validator).
- **Why split:** non-Go users shouldn't have to clone the Go core repo.
  Reference plugins want a permissive contribution policy and a fast review
  loop; security-critical core wants the opposite.
- **Module paths:** `github.com/mikeappsec/lightweightauth-plugins/{go,python,rust}/...`

### Default vs custom plugins (the rule of thumb)

Three tiers, increasingly external:

| Tier | Where | Examples | Maintainer policy |
|---|---|---|---|
| **1. Default** (in core) | `pkg/identity/*`, `pkg/authz/*` of the core repo, blank-imported by `pkg/builtins` | `jwt`, `apikey`, `rbac` | Strict review. Broadly useful. Dependency-light. Released on core's cadence. |
| **2. Sibling Go plugins** (in-process) | `lightweightauth-plugins/go/...`, blank-imported by the user's own binary (see `cmd/lwauth-extra`) | `hs-jwt`, future `vault-apikeys`, custom HMAC | Permissive review. Niche credentials/policies. May pull heavier deps. |
| **3. Out-of-process plugins** (any language) | gRPC, behind the `plugin/v1` contract in `api/proto/.../plugin.proto` | written in Python / Rust / etc. by users | Versioned by the proto, not by core. |

**The mechanism that holds the line:** `module.RegisterIdentifier` (and
its sibling `RegisterAuthorizer` / `RegisterMutator`) plus blank-import.
Core's `pkg/builtins` only blank-imports defaults. Anyone wanting more
builds their own binary that blank-imports the extras alongside, e.g.:

```go
import (
    _ "github.com/mikeappsec/lightweightauth/pkg/builtins"            // tier 1
    _ "github.com/mikeappsec/lightweightauth-plugins/go/identity/hsjwt" // tier 2
    "github.com/mikeappsec/lightweightauth/pkg/lwauthd"               // public façade
)

func main() { lwauthd.Main() }
```

The `pkg/lwauthd` package exposes `Run(opts) / Main()` so external
binaries don't have to reach into core's `internal/`. This is what the
[lwauth-extra example](https://github.com/mikeappsec/lightweightauth-plugins/tree/main/go/cmd/lwauth-extra)
demonstrates end-to-end.

**Promotion criteria from tier 2 → tier 1:** broad demand, dep-light,
willingness to track core's release cadence, sign-off from a core
maintainer. We expect this to be rare; staying at tier 2 is fine forever.

### What we deliberately did NOT split out

- **CRDs and controller** — they are the K8s expression of the same
  config the core consumes. Splitting would force users to track two
  release cadences for one feature.
- **OPA / OpenFGA adapters** — small Go shims over external libs/services.
  Keeping them as built-in modules preserves "batteries included" without
  meaningful dep weight.
- **The plugin contract proto** — lives in core (`api/proto/...`) so
  there is exactly one source of truth that every plugin SDK regenerates
  from.

### Versioning across repos

- `lightweightauth` is the version anchor. Sibling repos declare a
  *minimum compatible core version* in their README and CI matrix.
- The plugin contract uses its own SemVer (`plugin/v1`, `plugin/v2`),
  decoupled from core's version, so a plugin built against `plugin/v1`
  keeps working across multiple core releases.

---

## 10. Still-open questions

_(none today; add new ones here as they come up during review.)_

---

## 11. Enterprise features (key & policy rotation, advanced caching, HA)

This section is **forward-looking design detail** for the unified
post-v1 roadmap above. The implementation order now lives in tiers C/D/E
instead of being repeated here: this section explains the architecture
behind those roadmap items so they slot into the existing pipeline /
cache / controller surfaces instead of reshaping them.

The themes are: **(a)** never make an operator restart a Pod to roll a
key or a policy; **(b)** make the cache a tunable knob, not a
correctness foot-gun; **(c)** make a multi-replica deployment behave
like one logical service. Everything below assumes the existing
primitives — `EngineHolder` atomic swap (§6), `cache.Backend` registry
(M7), `AuthConfig` / `IdentityProvider` CRDs (§3), and the `Recorder`
metrics surface (M9) — and adds *only* the missing edges.

### 11.1 Seamless key rotation (runtime)

Six key materials need rotation. None of them should require a Pod
restart, an `AuthConfig` re-apply, or a window of broken auth.

| Key material | Where it lives today | Verifier behaviour during rotation | Proposed rotation knob |
|---|---|---|---|
| **JWKS / IdP signing keys** | `pkg/identity/jwt`, refreshed every 10 min or on `Cache-Control: max-age` (§5) | Already multi-key by `kid`; verifier picks the JWK whose `kid` matches the token header | Background refresh stays as designed; expose `forceRefresh()` on the JWKS cache + a `lwauth_jwks_refresh_total{issuer,outcome}` counter so SREs can prove the new `kid` is loaded *before* the IdP starts signing with it |
| **HMAC shared secrets** (`pkg/identity/hmac`) | Single `secret` per identifier | Single key — flips the moment the secret changes, breaks any in-flight request signed under the old one | Add `secrets: [{kid, secret, notBefore?, notAfter?}]`; verifier tries `kid` first, falls back to enabled secrets in declaration order; signers (e.g. `jwt-issue`) always pick the newest non-expired |
| **`jwt-issue` mutator signing keys** | `pkg/mutator/jwtissue`, single `signingKey` | Same: a single-key flip drops in-flight tokens at the moment of swap | Same overlap-window shape: `signingKeys: [{kid, key, alg, active: true}]`; new tokens pick the newest `active:true`, verifiers downstream read `kid` from the JWS header |
| **OAuth2 client secrets** (`pkg/clientauth`, M8) | `IdentityProvider.spec.clientSecret` | Single secret | Promote to `clientSecrets: [{secret, retiredAt?}]`; outbound caller tries newest first, falls back to retired ones until `retiredAt + grace` (default 24 h) so a botched IdP rotation self-heals on revert |
| **API keys** (`pkg/identity/apikey`) | argon2id store; per-`keyId` records | Already multi-key (per-`keyId` lookup); rotation = add new + retire old | No design change. Document the “issue, distribute, retire” pattern in the cookbook; add `lwauth_apikey_lookup_total{outcome}` so retirement can be verified by absence of hits |
| **mTLS trust bundle** (`pkg/identity/mtls`) | `trustedIssuers` Subject-DN list, leaf trust via process root pool | Process-level: changing it required restart | `caBundle: { configMap: …, intervalSec: 60 }`; reloader re-parses on change and atomically swaps the `*x509.CertPool` via `atomic.Pointer`. Same fsnotify path used by the file watcher; mirrors the engine swap idiom |

#### Rotation choreography

The general shape is **dual-publish → drain → retire**, with the
controller surfacing each phase on `IdentityProvider.status.conditions`
(same `metav1.Condition` mechanism the AuthConfig fix landed in this
branch):

```yaml
# IdentityProvider.status.conditions
- type: KeysRotating
  status: "True"
  reason: OverlapWindow
  message: "kid=2026-05 published; kid=2026-04 still accepted until 2026-05-01T00:00:00Z"
- type: Ready
  status: "True"
```

Two new Prometheus metrics make rotations observable:

| Metric | Type | Labels |
|---|---|---|
| `lwauth_key_active{material,kid}` | gauge (0/1) | `material` ∈ {jwks, hmac, jwtissue, mtls_ca}, `kid` |
| `lwauth_key_verify_total` | counter | `material`, `kid`, `outcome` ∈ {ok, expired, unknown_kid} |

A rotation is "done" when `lwauth_key_verify_total{kid="<old>"}` flatlines
across all replicas — a property that can be alerted on without any
human-in-the-loop verification.

#### Lock-in versus optionality

We deliberately do **not** plan to bake a rotation *scheduler* into
core. KMS / Vault / cert-manager / SPIFFE Workload API users all have
opinions. Core ships the verifier-side overlap window and the status
surface; rotation cadence stays in whatever already drives secrets in
the operator's cluster.

### 11.2 Seamless policy rotation (runtime)

Policy rotation is mechanically simpler than key rotation — the engine
swap is already atomic via `EngineHolder` — but operators need three
things on top of "the swap works":

1. **Versioning** — know what policy answered which decision.
2. **Canary / shadow** — try a new policy on a slice of traffic before
   committing.
3. **Diffing** — see which decisions would change between v_n and
   v_{n+1} *without* changing them.

#### Versioning

Add `spec.version: <opaque-string>` to `AuthConfig`; the controller
echoes it on `status.appliedVersion` once compile + atomic swap succeed.
The Prometheus `lwauth_decisions_total` counter gains a `policy_version`
label (low cardinality — bounded by the number of versions live across
the rolling window). The audit pipeline (M9) tags every decision line
with the same value, so a postmortem can reliably correlate "this allow
came from policy v=2026-05-02".

#### Canary mode

```yaml
spec:
  authorizers:
    - name: prod
      type: rbac
      # ...existing prod policy
  canary:
    weight: 10                  # % of traffic
    sample: header:x-canary     # OR: sticky by hash(sub)
    authorizer:
      type: opa
      policy: file:///etc/lwauth/abac-next.rego
```

Engine evaluates **both** authorizers concurrently. The canary's verdict
is **logged** (audit + metrics) but the request gets the prod verdict
unless `canary.enforce: true` is set. Two new metric labels
(`policy_track ∈ {prod, canary}`, `agreement ∈ {match, prod_allow_canary_deny, prod_deny_canary_allow}`)
let an SRE confirm "canary diverges on 0.02% of requests, all of which
are X" before promoting it.

The composite authorizer (M5) provides the underlying machinery: canary
is mechanically `composite{anyOf:[…], observe:<canary>}` with a
side-channel for the observed verdict. We document it as a top-level
field because that's how operators think about it.

#### Shadow / dry-run AuthConfig

A standalone `AuthConfig` with `spec.mode: shadow` performs the full
identify → authorize → mutate pipeline but **never** affects the verdict
returned to Envoy / Door B. It exists purely to feed the audit + metrics
streams. Composes naturally with canary: ship a new policy as `shadow`
for a week, promote to `canary: { weight: 10 }` once the audit log
shows no surprises, promote to default once `agreement=match` saturates.

#### Decision diffing CLI

`lwauth diff --left v=2026-05-01 --right v=2026-05-02 --replay <audit.jsonl>`
re-evaluates a captured audit log against two compiled engines and
prints the divergence (what would have changed, grouped by `(method,
path-template, deny_reason)`). This is a debugging tool, not a hot path;
it lives in `cmd/lwauth-diff` and shells out to the same compile
machinery the controller uses.

### 11.3 Caching improvements (multi-tier, tag-based, prewarmed)

Current cache design (§5, M5+M7): single-tier per layer (in-process LRU
*or* Valkey), TTL invalidation, `singleflight` coalescing, negative
caching. That gets us a long way — and it is what the cookbook recipes
exercise today — but four enterprise-scale failure modes show up beyond
that:

| Failure mode | Today's behaviour | Proposed mitigation |
|---|---|---|
| **Cold pod starts cold** — replica added by HPA serves p99 misses for the first ~minute | Each pod's LRU fills independently | Two-tier read-through: L1 = in-process LRU (already in `internal/cache/lru.go`), L2 = Valkey (already in `internal/cache/valkey`). On L1 miss, read L2 before evaluating; on evaluate, write through both. New replicas warm L1 from L2 in O(p99 latency). |
| **Stampede on hot key after revoke** | TTL expiry → all replicas evaluate at once → singleflight is per-pod, so N replicas = N concurrent evaluations | Promote `singleflight` to a *cross-replica* primitive via Valkey `SETNX` lock with a short hold (200 ms default); whichever replica wins writes the answer and the rest read it from L2. Falls back gracefully to per-pod singleflight if Valkey is unreachable. Additionally, peer broadcast ensures revocations propagate without Valkey Pub/Sub dependency. |
| **Manual revocation can't beat TTL** | Operators wait for TTL to elapse, or restart pods | Tag-based invalidation. Cache writes carry tags `{tenant=…, sub=…, policy_version=…}`; revocation publishes a `cache.invalidate` event over Valkey pub/sub, every replica drops L1 entries matching the tags. New `lwauth_cache_invalidations_total{scope}` counter. |
| **Stale-while-revalidate** for upstream lookups (introspection / OpenFGA `Check`) goes silent on upstream outage | TTL hits → entry evicted → next request hits ErrUpstream | Add `staleTtl` per layer: on `ErrUpstream` and `now > expiresAt && now < expiresAt + staleTtl`, serve the stale value and fire a background refresh. Behaviour is opt-in per `AuthConfig.cache.serveStaleOnUpstreamError: true`. |

#### Freshness budget

`AuthConfig.cache.maxStaleness: 30s` becomes the *user-facing* knob —
"my decisions may be at most 30s out of date". The implementation
chooses TTL + staleTtl + tag-invalidation parameters under the hood to
honour it. This is the same idiom HTTP `Cache-Control: max-age` /
`stale-while-revalidate` uses; operators already have intuition for it.

#### Per-tenant prefix isolation

Today `cache.backend.keyPrefix` isolates AuthConfigs sharing one Valkey.
Add automatic per-tenant prefixing — `keyPrefix: "{authconfig}/{tenant}/"`
— so a tenant invalidation can `SCAN` + `DEL` an entire tenant's slice
without touching others. Tenant ID flows in via the existing
`module.Request.Context.TenantID` (resolved decisions, multi-tenancy day
one).

#### Prewarming via `AuthorizeStream`

Door B's `AuthorizeStream` (M8) already supports long-lived sessions.
Document — and ship a Go SDK helper for — the pattern of issuing a
"prewarm" Authorize for high-value subjects (e.g. on session
establishment) so the first real request hits L1. This is operator
opt-in and policy-shape-dependent; we don't enable it by default.

#### Cache observability additions

| Metric | Type | Labels |
|---|---|---|
| `lwauth_cache_layer_hits_total` | counter | `cache`, `layer` ∈ {l1, l2}, `tenant` |
| `lwauth_cache_stale_served_total` | counter | `cache`, `tenant` |
| `lwauth_cache_invalidations_total` | counter | `scope` ∈ {tag_subject, tag_policy_version, tag_tenant, full} |
| `lwauth_cache_lock_wait_seconds` | histogram | `cache` |

### 11.4 HA, leader election, and decision audit

Three smaller enterprise concerns that share a section because they
each need ~one design paragraph:

**HA / leader election.** lwauth pods are stateless on the hot path —
`AuthConfig` is the only durable state and it lives in the K8s API. The
*controller* loop, however, currently runs in every replica
(`controller-runtime` default), which is fine but wasteful. Adopt
`controller-runtime`'s built-in `LeaderElection: true` so only one
replica reconciles; the rest still serve traffic. ConfigMap-based
election in the lwauth namespace, 30 s lease, no new dependency. Helm
exposes `controller.leaderElection.enabled` (default `true` when
`replicas > 1`).

**Per-AuthConfig SLOs / quotas.** Operators want both "my tenant gets at
most 1000 RPS" (quota) and "my tenant's p99 stays under 5 ms" (SLO).
- *Quota* lands as a token-bucket on the request-path keyed by
  `tenantID`, backed by Valkey for cross-replica sharing. New
  `AuthConfig.spec.rateLimit: { rps, burst }`. Over-quota = 429
  (HTTP) / `RESOURCE_EXHAUSTED` (gRPC), audit-tagged.
- *SLO* is reporting only — the existing latency histogram, sliced by
  `tenant`, fed to whatever SLO platform (Sloth, Grafana SLO) the
  operator already runs. Core ships an example recording rule, not its
  own SLO engine.

**Audit pipeline.** Today decisions emit Prometheus + OTel spans (M9).
Add a structured audit *sink* with three implementations:
| Sink | Use case |
|---|---|
| `stdout-jsonl` | default; 12-factor; piped into whatever log system is already running |
| `loki` | direct push, for clusters that want decision logs separate from app logs |
| `kafka` | high-volume / long-retention compliance use case |

`audit.sample: { rate: 0.01, always: ["deny", "shadow_disagreement"] }`
keeps cost bounded without dropping the records that matter
(denies + canary disagreements are always logged). Audit lines carry
the W3C `traceparent` already exposed by `tracing.TraceIDFromContext`,
so an audit entry deep-links to a trace in one click.

### 11.5 Why this lives in core (and what doesn't)

These features fit core because they extend primitives that *already
exist* there (engine swap, cache backend registry, controller status,
metrics recorder). Three explicit non-goals to keep the surface honest:

- **A built-in rotation scheduler.** cert-manager / Vault / KMS already
  do this. We expose the verifier overlap window and the status surface;
  the *when* stays out of core.
- **A managed canary controller.** Argo Rollouts / Flagger already do
  traffic shaping. We expose canary at the policy layer; integration
  with traffic-shaping is documentation, not code.
- **An SLO engine.** Sloth / Grafana SLO / Pyrra exist. We export the
  histograms and ship example recording rules.

These features land incrementally — none of them requires a single big
release. The canonical ordering is the unified roadmap in §7: Tier C
establishes operator safety, Tier D adds runtime key/policy control and
durable audit, and Tier E adds cross-replica cache, revocation, and HA
semantics. Keep this section as design rationale; update §7 when the
implementation order changes.
