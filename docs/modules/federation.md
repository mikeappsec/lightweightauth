# Federation — multi-cluster config and revocation sync

> **Status: implemented but not wired in.** `pkg/federation` is a
> real, tested package (HMAC-signed snapshot/revocation replication),
> but there is no `federation:` key on `AuthConfig`
> (`internal/config/config.go` has no such field) and nothing in
> `cmd/lwauth` or `cmd/lwauth-controlplane` ever constructs a
> `federation.Server`/`Peer`/`PeerSet` — `grep -rn
> "federation.NewServer\|federation.NewPeer\|federation.NewPeerSet"`
> outside `pkg/federation` itself returns nothing.
> `internal/controller/clusterpeer.go` defines a
> `ClusterPeerReconciler` that references the federation types, but it
> is never instantiated or registered anywhere either. No Helm chart
> references "federation" at all. Everything below describes the
> package's design/intended shape, not something you can turn on today
> via `AuthConfig` or Helm values.

Replicates AuthConfig snapshots and revocation entries across clusters
via HMAC-signed gRPC streams. Each cluster independently evaluates
requests using its local engine, but receives config updates and
revocation broadcasts from its configured peers.

**Source:** [pkg/federation](https://github.com/mikeappsec/lightweightauth/blob/main/pkg/federation/) — a standalone library today, not reachable from `AuthConfig`.

## When to use

- You run lwauth in **multiple clusters** (regions, availability zones)
  and need consistent policy across all of them.
- Token revocations in one cluster must **propagate** to other clusters
  within seconds — not minutes.
- You want a central control plane cluster to **push config** to edge
  clusters without each edge cluster needing registry access.

**Don't use** for single-cluster deployments — it adds operational
complexity (pre-shared keys, peer TLS, network connectivity) for no
benefit.

## Configuration (Go API shape — see status note above)

This is `federation.Config`'s field shape as used from Go, not a YAML
schema anything in this repo actually loads. Note also that
`federation.Config.FederationKey` is tagged `json:"-" yaml:"-"`
(`pkg/federation/federation.go`) — even if `federation:` were wired
into `AuthConfig` tomorrow, that field is architecturally excluded
from (de)serialization, so a plain YAML `federationKey: "..."` could
never populate it as shown below without further code changes.
`PeerConfig.ClusterID` is also required (`Config.Validate()` rejects a
peer with an empty `ClusterID`) but easy to omit by accident since
it's easy to conflate with the top-level `clusterID`.

```yaml
federation:
  enabled: true
  clusterID: "us-east-1"
  federationKey: "${FEDERATION_PSK}"   # 32–256 byte pre-shared key
  syncInterval: "30s"                   # heartbeat re-push interval
  revocationTTL: "24h"                  # federated revocation lifetime
  peers:
    - clusterId: "eu-west-1"            # required — the peer's own cluster identity
      endpoint: "eu-west-1.lwauth.internal:9443"
      tlsCertFile: /etc/lwauth/federation-client.pem
      tlsKeyFile: /etc/lwauth/federation-client-key.pem
      tlsCAFile: /etc/lwauth/federation-ca.pem
      namespaces: ["production"]
    - clusterId: "ap-south-1"
      endpoint: "ap-south-1.lwauth.internal:9443"
      tlsCertFile: /etc/lwauth/federation-client.pem
      tlsKeyFile: /etc/lwauth/federation-client-key.pem
      tlsCAFile: /etc/lwauth/federation-ca.pem
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `false` | Enable federation |
| `clusterID` | string | *required* | This cluster's identity (max 253 chars, DNS-safe) |
| `federationKey` | string | *required* | HMAC-SHA256 pre-shared key (32–256 bytes) — `yaml:"-"`, see note above |
| `syncInterval` | duration | `30s` | How often to re-push current snapshot |
| `revocationTTL` | duration | `24h` | How long federated revocations live |
| `peers[].clusterId` | string | *required* | The peer's cluster identity |
| `peers[].endpoint` | string | *required* | Remote cluster gRPC address |
| `peers[].tlsCertFile` | string | — | mTLS client certificate |
| `peers[].tlsKeyFile` | string | — | mTLS client key |
| `peers[].tlsCAFile` | string | — | CA for server verification |
| `peers[].namespaces` | []string | all | Filter: only sync these namespaces |

## Security model

| Control | Description |
|---------|-------------|
| **HMAC-SHA256 signing** | Every snapshot and revocation payload is signed; receiver verifies before processing |
| **Constant-time compare** | Signature verification uses `crypto/subtle` to prevent timing attacks |
| **Known-peer auth** | Only pre-configured endpoints can subscribe; unknown callers are rejected |
| **mTLS transport** | All peer-to-peer traffic requires mutual TLS |
| **Version monotonicity** | Stale snapshots (lower version or older timestamp) are rejected |
| **Key never serialized** | `federationKey` is tagged `json:"-" yaml:"-"` — never appears in logs or API responses |

## Topology

```text
┌─────────────────┐        HMAC-signed snapshot         ┌─────────────────┐
│   us-east-1     │ ──────────────────────────────────→ │   eu-west-1     │
│   (control)     │ ←────────────────────────────────── │   (edge)        │
│                 │        revocation broadcast          │                 │
└─────────────────┘                                     └─────────────────┘
        │                                                        ▲
        │           HMAC-signed snapshot                          │
        └──────────────────────────────────────→ ┌───────────────┘
                                                 │  ap-south-1
                                                 │  (edge)
                                                 └───────────────┘
```

Any cluster can push to any other (mesh topology), or you can designate
one cluster as the control plane that pushes to all edges (hub-spoke).

## Revocation broadcast (design intent)

The admin revoke body shape shown here is also wrong independent of
the wiring gap — `POST /v1/admin/revoke` has no generic `key` field;
it accepts `jti`/`token_hash`/`subject`/`tenant`/`reason`/`ttl` (see
[revocation-immediate-logout.md](../cookbook/revocation-immediate-logout.md#3-revoking-credentials-via-the-admin-api)).
If federation were wired in, the intent would be that a revocation in
one cluster is automatically broadcast to all configured peers, each
inserting it into its local revocation store with the configured
`revocationTTL` — but this doesn't happen today regardless of body
shape, since nothing calls the federation broadcast path.

## Helm wiring — not currently supported

No chart references `federation:`/`FEDERATION_PSK` today; the
snippet below is aspirational, matching the config shape above.

## Failure modes

| Scenario | Behaviour |
|----------|-----------|
| Peer unreachable | Local engine continues with last-known config; reconnects on next sync interval |
| HMAC mismatch | Payload rejected; metric incremented; no config change |
| Version regression | Stale snapshot rejected (monotonicity check) |
| Key rotation | Deploy new key to all clusters simultaneously (rolling update) |

## References

- Source: [pkg/federation/](https://github.com/mikeappsec/lightweightauth/blob/main/pkg/federation/).
