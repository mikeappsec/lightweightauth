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

// Server side (publish snapshots to peers) — NewServer takes a
// revocation handler as a second arg; Publish takes raw bytes and
// builds the Snapshot internally, it doesn't accept a *Snapshot literal
server, err := federation.NewServer(cfg, myRevocationHandler)
err = server.Publish(ctx, specJSON)

// Peer side (accept snapshots) — PeerConfig comes first, *Config second
peer := federation.NewPeer(peerCfg, cfg)
err := peer.AcceptSnapshot(snap, signature)

// Broadcast a revocation to all peers — BroadcastRevocation takes a
// context and a push function, not just the entry
peerSet := federation.NewPeerSet(cfg)
err = peerSet.BroadcastRevocation(ctx, &federation.RevocationEntry{
    Key:             "jti:compromised-token",
    Reason:          "credential-leak",
    SourceClusterID: cfg.ClusterID,
}, myPushFunc)
```

## Configuration

Field casing below matches the actual struct tags — `clusterId`
(lowercase `d`), `revocationTtl`, `tlsCaFile` — not
`clusterID`/`revocationTTL`/`tlsCAFile`. `federationKey` is tagged
`json:"-" yaml:"-"` — it can **never** be populated from this YAML at
all; set `Config.FederationKey` directly in Go. This package is also
not currently reachable from `AuthConfig` — see
[docs/modules/federation.md](../../../docs/modules/federation.md) for
the full "not wired in" picture:

```yaml
federation:
  enabled: true
  clusterId: "us-east-1"
  # federationKey: cannot be set via YAML — see above
  syncInterval: "30s"
  revocationTtl: "24h"
  peers:
    - clusterId: "eu-west-1"
      endpoint: "eu-west-1.lwauth:9443"
      tlsCertFile: "/etc/lwauth/federation-client.pem"
      tlsKeyFile: "/etc/lwauth/federation-client-key.pem"
      tlsCaFile: "/etc/lwauth/federation-ca.pem"
      namespaces: ["production"]
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `false` | Enable federation |
| `clusterId` | string | *required* | This cluster's identity (max 253 chars) |
| `federationKey` | []byte | *required* | HMAC pre-shared key (32–256 bytes) — `yaml:"-"`, must be set in Go |
| `peers` | []PeerConfig | — | Remote cluster connections, each requiring its own `clusterId` |
| `syncInterval` | duration | `30s` | Heartbeat re-push interval |
| `revocationTtl` | duration | `24h` | Federated revocation entry lifetime |

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
