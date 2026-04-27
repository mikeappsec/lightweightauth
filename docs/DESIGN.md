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
[pkg/module/module.go](../pkg/module/module.go)). That's what makes adding a
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
  the `Request` abstraction (see [pkg/module/module.go](../pkg/module/module.go))
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
[pkg/module/module.go](../pkg/module/module.go)):

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
[pkg/module/module.go](../pkg/module/module.go) but forwards each call
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
| **B. `lightweightauth-proxy`** | ✅ **Tier 1 (GA)** | A sibling repo: a Go reverse proxy that imports `lightweightauth` as a library | Standalone edge gateways, local dev, air-gapped, "I just want one container" |
| **C. eBPF redirection** | 🔬 **Tier 3 (experimental, post-v1)** | A separate `lwauth-ebpf` agent (own repo) that uses sockops/sk_msg to redirect connections to lwauth | High-density east-west enforcement, ambient-mesh-style deployments |

"Tier 1" = full docs, Helm support, CI matrix, security review.
"Tier 3" = published, but operators are expected to engage actively.

The key architectural point: **all three modes drive the same pipeline.**
Mode A and C produce a `module.Request` via the ext_authz adapter; Mode B
produces it directly from the proxy handler. Adding or replacing a data
plane never touches policy/identifier code.

```
  ┌─────────── Mode A ──────────┐    ┌── Mode B ──┐    ┌── Mode C (future) ──┐
  │  Envoy ── ext_authz gRPC ── │    │  lwauth    │    │  eBPF agent ──────  │
  │                             │    │  proxy     │    │  (sockops redirect) │
  └─────────────┬───────────────┘    └─────┬──────┘    └─────────┬───────────┘
                │                          │                     │
                └──────────► same module.Request ◄───────────────┘
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

### Mode B — `lightweightauth-proxy` (Tier 1, separate repo)

**Where it lives.** Mode B is delivered as a sibling repository
**`lightweightauth-proxy`** that imports `lightweightauth` as a library
and wraps `pipeline.Evaluate` with a Go reverse proxy. See the repository
topology in §9.

**How it works.** `lwauth-proxy --upstream=…` boots a Go reverse proxy
(`httputil.ReverseProxy` + `http2` + optional `quic-go`) that calls the
pipeline in-process and then forwards to the upstream. One binary, one
config, no Envoy.

**Implementation cost for us:** moderate. Core proxy is ~500 LOC, but
production hardening (TLS hot-reload, HTTP/2 limits, connection draining,
request-smuggling defenses, header normalization) is real engineering.
Isolating it in its own repo keeps that hardening surface — and its
dependency tree (`x/net/http2`, optionally `quic-go`) — out of the core.

**Benefits**
- One container, one config file, one log stream for users who want it.
- ~15 MB image, ~10 MB RSS — fits a Raspberry Pi, a lambda-style sidecar,
  or an air-gapped appliance.
- Direct access to the request: features that ext_authz makes painful
  (e.g. mutating the request body, chunked re-signing) are trivial.
- Library mode for embedders is just "import `lightweightauth` directly";
  they don't need the proxy at all.
- Core stays dependency-light. Users running Mode A never pull HTTP/2/3
  proxy code into their image.

**Costs / honest limits**
- We are not going to outperform Envoy at p99 throughput. We won't try.
- HTTP/3 support will lag Envoy. Protocol corner cases (large trailers,
  HTTP/1.1 upgrade dances) will be discovered the hard way.
- Security: every CVE Envoy has had for HTTP parsing is a CVE we could
  also have. We mitigate by leaning on stdlib `net/http` (well-audited)
  and by *not* writing our own parser.

**Scope guardrails for Mode B**
  - Supports HTTP/1.1 + HTTP/2 at v1.0; HTTP/3 best-effort.
  - No load balancing across upstreams beyond simple round-robin.
  - No retries / outlier detection on day one.
  - We document explicitly: "if you need full L7 features, use Mode A."

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
   - Optional sub-chart dependency on `lightweightauth-proxy` or an Envoy
     Deployment, depending on the chosen data-plane mode.
2. **Helm chart** at `deploy/helm/lightweightauth-proxy/` (in the proxy
   repo) for users who want Mode B without the core CRDs/controller — e.g.
   a single-binary edge gateway.
3. **CRDs** under [api/crd](../api/crd/):
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
- **Mode B (own proxy)** is a fully supported, first-class alternative —
  not a toy mode — for everyone who values one-binary simplicity.
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

Recommended built-ins, all under [pkg/identity](../pkg/identity/):

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
   [pkg/module/module.go](../pkg/module/module.go)) plus the out-of-process
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
     declare `cache: { key: ["sub", "method", "pathTemplate"], ttl: 30s }`
     in `AuthConfig` to opt into (a).

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

### Next

10. **M8 – Native gRPC (Door B) + SDKs.**
   - Implement `lightweightauth.v1.Auth` (`Authorize` unary +
     `AuthorizeStream` for per-message stream re-checks) on the same
     `:9001` listener as Door A.
   - Tiny **Go interceptor SDK** in core (`pkg/client/go`) for callers
     that want native gRPC instead of ext_authz.
   - Conformance tests proving Door A and Door B reach identical
     `Decision`s for the same input.

11. **M9 – Observability + audit.**
    - Prometheus metrics surface: `lwauth_cache_*`, `lwauth_decision_*`
      (latency histogram split by allow/deny + authorizer), per-tenant
      labels.
    - OpenTelemetry tracing with `traceparent` propagation from Envoy /
      callers; spans on each pipeline stage.
    - Structured audit log (one JSON line per decision, including
      `Identity.Source`, tenant, decision, latency, deny reason).
    - `lwauthctl audit` to tail a running instance.

12. **M10 – Sibling repos + plugin runtime.**
    - Bootstrap `lightweightauth-proxy` (Mode B reverse proxy importing
      the core as a library) with its own Dockerfile + Helm chart.
    - Bootstrap `lightweightauth-idp` (OIDC issuer, token endpoint,
      minimal admin UI).
    - Bootstrap `lightweightauth-plugins` (SDKs in Go / Python / Rust +
      reference plugins: SAML bridge, Vault-backed API keys, custom
      HMAC).
    - **Out-of-process plugin host runtime** in core: lifecycle
      (spawn / health-check / restart), `grpc-plugin` adapter under the
      `plugin/v1` proto.

13. **M11 – Multi-tenancy hardening + xDS push.**
    - Replace ConfigMap+SIGHUP with a controller-pushed gRPC stream
      (xDS-style) for clusters with many `AuthConfig`s.
    - Per-tenant rate limits (token-bucket).
    - Per-tenant key-material isolation; cluster-scoped
      `IdentityProvider` with tenant overrides.

14. **M12 – Supply-chain hardening.**
    - Docker Hardened Image bases (`dhi.io/golang`, `dhi.io/alpine`,
      `dhi.io/envoy`).
    - Cosign-signed releases verified by Kyverno / Sigstore policy.
    - SBOM publication (`syft`) on every release.
    - Mirrored images for air-gapped deployments.
    - Deferred from M2 to keep the early build pipeline accessible to
      contributors without dhi.io entitlement.

15. **M13 – v1.0.**
    - `pkg/module` API frozen under SemVer; CRDs promoted from
      `v1alpha1` to `v1`.
    - Plugin contract `plugin/v1` declared stable; future evolution
      through `plugin/v2`.
    - Documented promotion criteria for tier 2 → tier 1 plugins.
    - Published Go SDK + Python/Rust plugin SDKs.

### Experimental / post-v1

16. **eBPF data plane** in the separate `lightweightauth-ebpf` repo
    (Mode C, §3). Linux-only, `CAP_BPF`, kernel ≥ 5.10. Stays
    experimental until at least three production users report stable
    operation.
17. **WASM plugins** via `wazero`. Defer until the auth-library
    ecosystem in WASM matures (§2).

### Explicit non-goals

- **OAuth2 implicit flow** — dropped by OAuth 2.1; we will not ship it.
  Users with a legacy IdP that only emits implicit can wrap it as an
  out-of-process plugin.
- **Reimplementing Zanzibar** — we adapt OpenFGA / SpiceDB; we will
  not build our own ReBAC engine (§5).
- **Becoming a service mesh** — we integrate with one (Envoy) instead.
- **Outperforming Envoy at p99 throughput in Mode B** — Mode B exists
  for one-binary simplicity, not for throughput records (§3).

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
  ┌──────────────┐ ┌────────────┐ ┌──────────────┐ ┌──────────────────┐
  │ -idp (M3+) │ │  -proxy  │ │ -ebpf      │ │ -plugins         │
  │ issuer +   │ │ Mode B   │ │ Mode C     │ │ SDK + reference  │
  │ token ep + │ │ reverse  │ │ sockops    │ │ plugins (Python, │
  │ admin UI   │ │ proxy    │ │ redirector │ │ Rust, Go)        │
  └──────────────┘ └────────────┘ └──────────────┘ └──────────────────┘
     Tier 1         Tier 1       Tier 3         Tier 2
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

### `lightweightauth-proxy` — Mode B (separate repo, Tier 1)

- **What's in it:** the reverse-proxy binary that imports
  `lightweightauth` as a library, plus its own Helm chart and Dockerfile.
  Owns TLS hot-reload, HTTP/2 limits, optional HTTP/3 (`quic-go`),
  connection draining, header normalization.
- **Why split:** keeps proxy hardening / dep tree out of every core user.
  Releases on its own cadence; HTTP/3 churn doesn't force a core release.
- **Module path:** `github.com/mikeappsec/lightweightauth-proxy`.
- **Image:** `ghcr.io/mikeappsec/lightweightauth-proxy`.
- **Helm chart:** `lightweightauth-proxy` (can be a sub-chart of
  `lightweightauth`).

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
