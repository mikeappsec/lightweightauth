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

The host today assumes the plugin process is supervised **externally**
(systemd, the sidecar's own restart policy, or the kubelet for a
dedicated Pod). This is a deliberate scope cut: the topologies above
already give Kubernetes-native restart behaviour for free.

In-host spawn / health-check / restart with exponential backoff lands
in **M11** alongside circuit-breaking, for operators who want lwauth to
own the plugin process directly (e.g. running outside Kubernetes).

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
