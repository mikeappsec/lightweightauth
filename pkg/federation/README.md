# pkg/federation

Multi-cluster config replication and revocation sync with HMAC-signed payloads.

## Usage

```go
import (
    "context"
    "github.com/mikeappsec/lightweightauth/pkg/federation"
)

cfg := &federation.Config{
    Enabled:       true,
    ClusterID:     "us-east-1",
    FederationKey: []byte("32-byte-pre-shared-key-material!"),
    Peers: []federation.PeerConfig{
        {Endpoint: "eu-west-1.lwauth:9443", TLSCertFile: "..."},
    },
    SyncInterval:  30 * time.Second,
    RevocationTTL: 24 * time.Hour,
}

// Server side (publish snapshots to peers)
server, err := federation.NewServer(cfg)
server.Publish(&federation.Snapshot{
    SpecJSON:        specJSON,
    SourceClusterID: cfg.ClusterID,
})

// Peer side (accept snapshots)
peer := federation.NewPeer(cfg, peerCfg)
err := peer.AcceptSnapshot(snap, signature)

// Broadcast a revocation to all peers
peerSet := federation.NewPeerSet(cfg)
peerSet.BroadcastRevocation(&federation.RevocationEntry{
    Key:             "jti:compromised-token",
    Reason:          "credential-leak",
    SourceClusterID: cfg.ClusterID,
})
```

## Configuration

```yaml
federation:
  enabled: true
  clusterID: "us-east-1"
  federationKey: "${secretRef:vault://kv/lwauth/federation-key}"
  syncInterval: "30s"
  revocationTTL: "24h"
  peers:
    - endpoint: "eu-west-1.lwauth:9443"
      tlsCertFile: "/etc/lwauth/federation-client.pem"
      tlsKeyFile: "/etc/lwauth/federation-client-key.pem"
      tlsCAFile: "/etc/lwauth/federation-ca.pem"
      namespaces: ["production"]
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `false` | Enable federation |
| `clusterID` | string | *required* | This cluster's identity (max 253 chars) |
| `federationKey` | []byte | *required* | HMAC pre-shared key (32–256 bytes) |
| `peers` | []PeerConfig | — | Remote cluster connections |
| `syncInterval` | duration | `30s` | Heartbeat re-push interval |
| `revocationTTL` | duration | `24h` | Federated revocation entry lifetime |

## Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `MaxSnapshotSize` | 16 MiB | Maximum snapshot payload |
| `MaxRevocationKeyLen` | 512 | Maximum revocation key length |
| `MaxClusterIDLen` | 253 | DNS-compatible cluster ID limit |
| `MaxFederationKeyLen` | 256 | Maximum HMAC key length |

## Features

- HMAC-SHA256 payload signing with constant-time verification
- Known-peer authentication (only configured peers can subscribe)
- Stale snapshot rejection via version monotonicity + timestamp fallback
- Non-blocking fan-out to subscribers (drops on slow consumer with warning)
- Namespace filtering per peer for partial replication
- Federation key never serialized (`json:"-" yaml:"-"`)
- mTLS transport between clusters via PeerConfig TLS fields

## How It Works

1. **Server.Publish()**: Validates JSON, increments version, signs with HMAC-SHA256, fans out to subscribed peers.
2. **Peer.AcceptSnapshot()**: Verifies HMAC signature, checks version/timestamp freshness, rejects stale snapshots, applies new config.
3. **PeerSet.BroadcastRevocation()**: Signs revocation entry with HMAC, sends to all configured peers (fire-and-forget).
4. **Server.HandleRevocation()**: Verifies HMAC, validates key length, passes to the revocation handler callback.
