# Federation — multi-cluster config and revocation sync

Replicates AuthConfig snapshots and revocation entries across clusters
via HMAC-signed gRPC streams. Each cluster independently evaluates
requests using its local engine, but receives config updates and
revocation broadcasts from its configured peers.

**Source:** [pkg/federation](https://github.com/mikeappsec/lightweightauth/blob/main/pkg/federation/) — wired via the `federation:` top-level config block.

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

## Configuration

```yaml
federation:
  enabled: true
  clusterID: "us-east-1"
  federationKey: "${FEDERATION_PSK}"   # 32–256 byte pre-shared key
  syncInterval: "30s"                   # heartbeat re-push interval
  revocationTTL: "24h"                  # federated revocation lifetime
  peers:
    - endpoint: "eu-west-1.lwauth.internal:9443"
      tlsCertFile: /etc/lwauth/federation-client.pem
      tlsKeyFile: /etc/lwauth/federation-client-key.pem
      tlsCAFile: /etc/lwauth/federation-ca.pem
      namespaces: ["production"]
    - endpoint: "ap-south-1.lwauth.internal:9443"
      tlsCertFile: /etc/lwauth/federation-client.pem
      tlsKeyFile: /etc/lwauth/federation-client-key.pem
      tlsCAFile: /etc/lwauth/federation-ca.pem
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `false` | Enable federation |
| `clusterID` | string | *required* | This cluster's identity (max 253 chars, DNS-safe) |
| `federationKey` | string | *required* | HMAC-SHA256 pre-shared key (32–256 bytes) |
| `syncInterval` | duration | `30s` | How often to re-push current snapshot |
| `revocationTTL` | duration | `24h` | How long federated revocations live |
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

## Revocation broadcast

When a token is revoked in one cluster:

```yaml
# POST /v1/admin/revoke in us-east-1
{
  "key": "jti:compromised-token-abc",
  "reason": "credential-leak",
  "ttl": "1h"
}
```

The revocation is automatically broadcast to all configured peers.
Each peer inserts it into its local revocation store with the
configured `revocationTTL`.

## Helm wiring

```yaml
# values.yaml
config:
  inline: |
    federation:
      enabled: true
      clusterID: "us-east-1"
      federationKey: "${FEDERATION_PSK}"
      syncInterval: 30s
      revocationTTL: 24h
      peers:
        - endpoint: "eu-west-1.lwauth.internal:9443"
          namespaces: ["production"]
env:
  - name: FEDERATION_PSK
    valueFrom:
      secretKeyRef:
        name: lwauth-federation
        key: psk
```

## Failure modes

| Scenario | Behaviour |
|----------|-----------|
| Peer unreachable | Local engine continues with last-known config; reconnects on next sync interval |
| HMAC mismatch | Payload rejected; metric incremented; no config change |
| Version regression | Stale snapshot rejected (monotonicity check) |
| Key rotation | Deploy new key to all clusters simultaneously (rolling update) |

## References

- Source: [pkg/federation/](https://github.com/mikeappsec/lightweightauth/blob/main/pkg/federation/).
