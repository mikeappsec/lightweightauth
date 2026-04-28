# `grpc-plugin` — out-of-process plugin host

Lets a config entry pull in an identifier, authorizer, or response
mutator that lives in a **separate process** and speaks the
[`lightweightauth.plugin.v1`](../../api/proto/lightweightauth/plugin/v1/plugin.proto)
gRPC contract. The pipeline cannot tell built-ins from plugins apart —
same caching, same observability, same audit emission.

**Source:** [pkg/plugin/grpc](../../pkg/plugin/grpc/) — registered as
`grpc-plugin` under all three module kinds.

## When to use

- The credential format is **proprietary** (corporate SAML bridge,
  legacy mainframe ticket, vendor-specific HMAC variant) and you don't
  want to fork the core to add it.
- You want to write the policy in **a language other than Go** (Python,
  Rust, Java) — the SDK in `lightweightauth-plugins/` covers Go,
  Python, and Rust.
- The credential check needs **state lwauth doesn't carry** (a Vault
  read, a custom database lookup, an HSM call) and you'd rather isolate
  that I/O in its own process.

**Don't use** for things a built-in already handles (JWT / OAuth2 /
OPA / CEL / RBAC / HMAC / mTLS / DPoP / API key) — the in-process path
is faster and one fewer thing to operate.

## How it works

Each plugin process implements one or more of three gRPC services:

| Service              | RPC          | Maps to                  |
|----------------------|--------------|--------------------------|
| `IdentifierPlugin`   | `Identify`   | `module.Identifier`      |
| `AuthorizerPlugin`   | `Authorize`  | `module.Authorizer`      |
| `MutatorPlugin`      | `Mutate`     | `module.ResponseMutator` |

The lwauth core dials the address once per `(address)` (a process-wide
connection pool de-dups multiple modules pointed at the same socket),
wraps each remote call in a per-call timeout, and translates between
the in-process `module.Request/Identity/Decision` types and the
`authv1.AuthorizeRequest/Identity/AuthorizeResponse` messages the
plugin sees over the wire.

### Result handling — identifier

| Plugin reply                          | Pipeline behaviour                            |
|---------------------------------------|-----------------------------------------------|
| `identity` populated                  | Use it; pass to authorizers                   |
| `no_match=true`                       | `module.ErrNoMatch` — try the next identifier |
| `error != ""`                         | `module.ErrUpstream` — fail closed            |
| RPC failure (timeout / Unavailable)   | `module.ErrUpstream` — fail closed            |
| Empty identity, no `no_match`         | `module.ErrInvalidCredential`                 |

### Result handling — authorizer / mutator

`AuthorizePluginResponse` is mapped verbatim onto `*module.Decision`
(allow / status / deny_reason / both header maps). `MutateResponse`
headers are **merged** into the existing decision headers, so chained
mutators compose cleanly.

## Configuration

```yaml
identifiers:
  - name: corp-saml
    type: grpc-plugin
    config:
      address: unix:///var/run/lwauth/saml.sock   # or "host:port"
      timeout: 200ms                              # per-call deadline (default 1s)

authorizers:
  - name: vendor-policy
    type: grpc-plugin
    config:
      address: lwauth-policy-plugin:9000
      timeout: 50ms

mutators:
  - name: enrich-headers
    type: grpc-plugin
    config:
      address: unix:///var/run/lwauth/enrich.sock
```

The same `grpc-plugin` type name resolves to a different factory
depending on the section it's listed under (identifiers / authorizers /
mutators) — the registry maps are kind-separated, so callers never need
to disambiguate.

### Address forms

- `unix:///path/to/socket.sock` — recommended for sidecar-style
  co-located plugins. Zero TCP overhead, kernel-enforced ACLs via
  filesystem permissions.
- `host:port` — for plugins running as their own Service in the same
  cluster (e.g. a dedicated `corp-saml-bridge` Deployment).
- `dns:///service.namespace:port` — gRPC's standard resolver; useful
  when targeting a headless Service for client-side load-balancing.

### TLS

The host **fails closed** when a non-loopback TCP address is configured
without transport security. Plaintext is permitted only for loopback
(`localhost` / `127.0.0.1` / `[::1]`) and Unix-socket addresses, where
the plugin process is co-located and the connection never traverses a
network an attacker can reach.

For any other address, configure server-cert verification (and
optionally client mTLS) via the `tls` block:

```yaml
authorizers:
  - name: vendor-policy
    type: grpc-plugin
    config:
      address: corp-policy.svc.cluster.local:9000
      timeout: 50ms
      tls:
        caFile: /etc/lwauth/plugin-ca.pem      # verify the plugin's server cert
        certFile: /etc/lwauth/plugin-client.pem # optional: present a client cert
        keyFile: /etc/lwauth/plugin-client.key  # optional: paired with certFile
        serverName: corp-policy.internal       # optional: SNI / hostname override
```

Operators who really do want plaintext for a non-loopback address (e.g.
a hardened L4 mesh that already wraps the connection) must opt in
explicitly with `insecure: true`. This is a deliberate ceremony — the
plugin's responses directly drive auth outcomes, so a forged reply is
an authorization bypass.

```yaml
authorizers:
  - name: vendor-policy
    type: grpc-plugin
    config:
      address: corp-policy:9000
      insecure: true   # documented opt-in; only safe inside an mTLS mesh
```

`insecure: true` cannot be combined with any `tls.*` setting, and
`tls.certFile` / `tls.keyFile` must be configured together.

### Application-layer signing (F-PLUGIN-2, v1.1+)

TLS protects the **transport**: it stops a network attacker from
forging plugin replies in flight. It does **not** stop a same-host
attacker who can win a Unix-socket path race, replace the plugin
binary on disk between health-check and exec, or otherwise
impersonate the plugin process. For deployments that want
defense-in-depth against those scenarios — or that simply want to
refuse to honour anything the operator hasn't explicitly minted — the
`signing` block enables an HMAC-SHA256 application-layer signature
over a deterministic canonical encoding of the plugin's response.

```yaml
authorizers:
  - name: vendor-policy
    type: grpc-plugin
    config:
      address: corp-policy.svc.cluster.local:9000
      timeout: 50ms
      tls:
        caFile: /etc/lwauth/plugin-ca.pem
      signing:
        mode: require                # disabled (default) | verify | require
        keys:
          - id: ops-2026-04          # arbitrary stable label
            hmacSecret: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
          - id: ops-2026-05          # rolling rotation: list both during overlap
            hmacSecret: fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210
```

| Mode       | When the plugin sends a valid signature | When the plugin sends no signature | When the plugin sends a bad signature |
|------------|-----------------------------------------|------------------------------------|----------------------------------------|
| `disabled` | trailer ignored                          | accepted                            | trailer ignored                        |
| `verify`   | accepted                                 | accepted                            | **rejected** (`ErrUpstream`)           |
| `require`  | accepted                                 | **rejected** (`ErrUpstream`)        | **rejected** (`ErrUpstream`)           |

`disabled` is the v1.0 default — existing configs are unaffected by
the v1.1 upgrade. Use `verify` while rolling signed plugins out across
a fleet, then flip to `require` once every plugin has the SDK update.

The signature, key id, and algorithm travel as gRPC trailing metadata
(`lwauth-sig`, `lwauth-kid`, `lwauth-alg`). The signed payload is a
length-prefixed canonical encoding that includes a version tag, the
type of the response message, the alg/kid, and every field of the
response with map keys sorted lexicographically — see
[pkg/plugin/sign/sign.go](../../pkg/plugin/sign/sign.go) for the
exact byte layout. Plugins in any language can implement it; v1.1
ships a Go helper in `pkg/plugin/sign`.

**Key sizing.** Secrets must be at least 16 bytes (32 hex chars).
v1.1 only understands `hmac-sha256`; X.509 / asymmetric signatures
are tracked as a follow-up and the trailer scheme is
forward-compatible (the alg name is part of the signed payload, so a
future host can refuse a downgrade attempt without ambiguity).

**Threat model.** Application-layer signing closes:

- A path-race attacker on a shared host who replaces a Unix socket
  between dial and call.
- A same-host process that wins an IP-stack race to bind the
  plaintext loopback port.
- A compromised TLS terminator (sidecar mesh) that can rewrite the
  plugin response without rotating keys.

It does **not** replace TLS — a network attacker still gets to see
unencrypted credentials and policy decisions if you turn TLS off. Use
both.

## Helm wiring

The simplest deployment is a sidecar container in the same Pod sharing
an `emptyDir` for the Unix socket:

```yaml
# values.yaml — lightweightauth chart
extraContainers:
  - name: corp-saml-plugin
    image: ghcr.io/acme/corp-saml-plugin:1.4.2
    args: ["--listen", "/run/lwauth/saml.sock"]
    volumeMounts:
      - name: lwauth-plugins
        mountPath: /run/lwauth
extraVolumes:
  - name: lwauth-plugins
    emptyDir: {}
extraVolumeMounts:
  - name: lwauth-plugins
    mountPath: /run/lwauth

config:
  inline: |
    identifiers:
      - name: corp-saml
        type: grpc-plugin
        config:
          address: unix:///run/lwauth/saml.sock
          timeout: 200ms
```

For a separately-scaled plugin, deploy it as its own Deployment +
Service and point `address: my-plugin-service:9000`.

## Lifecycle

By default the host assumes the plugin process is supervised
**externally** (systemd, the sidecar's own restart policy, the kubelet
for a dedicated Pod). The Helm topology above gives Kubernetes-native
restart for free, and that remains the recommended deployment.

For operators who want lwauth itself to own the plugin process — most
commonly when running outside an orchestrator, or when the plugin is
private to a single replica and a sidecar would be overkill — v1.1
ships an opt-in supervisor under
[pkg/plugin/supervisor](../../pkg/plugin/supervisor/). Add a
`lifecycle` block:

```yaml
identifiers:
  - name: corp-saml
    type: grpc-plugin
    config:
      address: unix:///run/lwauth/saml.sock
      timeout: 200ms
      lifecycle:
        command: /usr/local/bin/corp-saml-plugin
        args: ["--listen", "/run/lwauth/saml.sock"]
        env: ["VAULT_ADDR=https://vault.internal:8200"]   # optional; nil = inherit
        workDir: /run/lwauth                              # optional
        gracefulTimeout: 5s     # SIGTERM grace before SIGKILL (Unix); Kill on Windows
        startTimeout: 30s       # max wait for first successful health probe
        healthCheck:
          service: ""           # grpc.health.v1 service name; "" = overall
          interval: 5s
          timeout: 1s
          failureThreshold: 3
        restart:
          initialBackoff: 200ms
          maxBackoff: 30s
          jitter: 0.2           # ±20% on each backoff
          maxRestarts: 0        # 0 = unlimited (recommended)
```

The supervisor:

- Spawns the child via `os/exec` with the configured command, args,
  env, and working directory.
- Probes `grpc.health.v1.Health.Check` over the same connection the
  data plane uses (so a probe failure means exactly what an Authorize
  failure would: TLS, mTLS, signing — all the same).
- After `failureThreshold` consecutive failed probes, sends SIGTERM
  (Windows: `Process.Kill`), waits up to `gracefulTimeout`, then
  forcibly kills.
- Restarts the child with **exponential backoff** (`initialBackoff *
  2^n`, capped at `maxBackoff`) plus uniform `±jitter`. `maxRestarts:
  0` is unlimited; a positive value moves the supervisor to a terminal
  *gave up* state once exhausted, surfaced via
  `Supervisor.State()` for an operator's readiness probe.
- Captures the child's stdout/stderr line-by-line into the host's
  `slog` logger under `plugin stdout` / `plugin stderr` keys.

When more than one module (e.g. an identifier *and* a mutator) points
at the same plugin, the supervisor — like the gRPC connection — is
de-duplicated process-wide. One child, one supervisor, one connection
pool, regardless of how many config entries reference it.

`startTimeout` bounds engine startup: if the plugin does not produce
its first successful health probe within that window, engine
construction fails with `ErrConfig` so the operator finds out at boot,
not at the first request. `failureThreshold * interval` is therefore a
useful sanity check during rollout — it caps how long a transient
plugin hiccup can hold the engine ready-gate open.

This is opt-in on purpose: most users running on Kubernetes / systemd
will leave it unset and let the platform restart the sidecar, which is
both simpler to reason about and integrates with the platform's own
observability (Pod restart counts, `kubectl describe`, etc.). The
in-host supervisor exists for the topologies where there is no such
platform.

## Authoring a plugin

The reference SDK + sample plugins live in the sibling repo
[`mikeappsec/lightweightauth-plugins`](https://github.com/mikeappsec/lightweightauth-plugins)
(SAML bridge in Go, Vault-backed API keys in Python, custom HMAC in
Rust). The minimum viable plugin in Go is:

```go
package main

import (
    "context"
    "log"
    "net"

    "google.golang.org/grpc"
    pluginv1 "github.com/mikeappsec/lightweightauth/api/proto/lightweightauth/plugin/v1"
    authv1   "github.com/mikeappsec/lightweightauth/api/proto/lightweightauth/v1"
)

type identifier struct{ pluginv1.UnimplementedIdentifierPluginServer }

func (identifier) Identify(_ context.Context, in *pluginv1.IdentifyRequest) (*pluginv1.IdentifyResponse, error) {
    tok := in.GetRequest().GetHeaders()["X-Corp-Ticket"]
    if tok == "" {
        return &pluginv1.IdentifyResponse{NoMatch: true}, nil
    }
    sub, ok := verifyCorpTicket(tok) // your code
    if !ok {
        return &pluginv1.IdentifyResponse{Error: "invalid ticket"}, nil
    }
    return &pluginv1.IdentifyResponse{
        Identity: &authv1.Identity{Subject: sub, Source: "corp-saml"},
    }, nil
}

func main() {
    lis, err := net.Listen("unix", "/run/lwauth/saml.sock")
    if err != nil {
        log.Fatal(err)
    }
    s := grpc.NewServer()
    pluginv1.RegisterIdentifierPluginServer(s, identifier{})
    log.Fatal(s.Serve(lis))
}
```

The wire types are the same `authv1` messages used by Door B (the
native gRPC service), so any Door B client library doubles as a
test harness for plugin authors.
