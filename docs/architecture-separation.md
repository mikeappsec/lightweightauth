# Architecture: Control Plane Design

## Principle

The control plane is a **stateless management service**. It does NOT participate in cluster coordination, consensus, or leader election. The lwauth nodes handle their own internal coordination.

```
               ┌───────────────────────┐
               │  K8s API (etcd)       │
               │  Source of truth      │
               └───────────┬───────────┘
                           │
           ┌───────────────┼───────────────┐
           │                               │
┌──────────▼──────────┐       ┌────────────▼────────────┐
│  lwauth-controlplane │       │   lwauth nodes          │
│  (stateless)         │       │   (self-coordinating)   │
│                      │       │                         │
│  • REST API          │       │  • Own leader election  │
│  • WebSocket streams │       │  • Own consensus        │
│  • Embedded UI       │       │  • Own health mgmt     │
│  • Creates Deploys   │       │  • Data-plane traffic   │
│  • Reads state       │       │                         │
│  • No leader election│       │  • Independent of CP    │
└──────────────────────┘       └─────────────────────────┘
```

## What the control plane IS

| Role | Description |
|------|-------------|
| Dashboard | Serves the SolidJS UI at `/` |
| API gateway | REST endpoints under `/v1/controlplane/` |
| Deployment creator | Directly creates k8s Deployments + Services |
| Metadata reader | Lists instances, configs, routes from k8s |
| Stream aggregator | WebSocket hub for real-time decisions/metrics |

## What the control plane is NOT

| Anti-pattern | Why it's bad |
|---|---|
| Consensus authority | Creates dual control systems |
| Scheduler | Conflicts with k8s scheduler |
| Cluster leader | Splits authority with node-level leader |
| Distributed lock owner | Makes UI part of cluster availability |
| Operator/reconciler | Adds unnecessary indirection |

## Failure tolerance

| Failure | Result |
|---------|--------|
| lwauth node dies | Other nodes continue; k8s reschedules |
| Node leader dies | Nodes elect new leader internally |
| One control plane dies | Other replicas serve UI/API via LB |
| Entire control plane down | Cluster continues operating normally |

The last property is critical: **the cluster never depends on the control plane**.

## Data flow: creating an instance

1. User clicks "Create Instance" in UI
2. Control plane directly creates Deployment + Service via k8s API
3. Kubernetes schedules pods
4. lwauth nodes start, elect leader, begin serving traffic
5. Control plane's discovery watcher sees the new pods
6. UI updates via WebSocket stream

No CRDs. No operator. No reconciliation loop. The control plane expresses desired state directly as native Kubernetes resources. The lwauth nodes self-coordinate from there.

## HA deployment

```yaml
# Control plane: multiple stateless replicas, no leader election
apiVersion: apps/v1
kind: Deployment
metadata:
  name: lwauth-controlplane
spec:
  replicas: 3  # All active, load-balanced
  ...
```

## Binaries

| Binary | Path | Purpose | Leader election |
|--------|------|---------|-----------------|
| `lwauth-controlplane` | `cmd/lwauth-controlplane/` | Stateless UI/API | **No** |
| `lwauth` | `cmd/lwauth/` | Data-plane node | **Yes** (self-coordinated) |
| `lwauthctl` | `cmd/lwauthctl/` | CLI tool | N/A |

---

## Trust Model: Discovery vs Authority

### Core Principle

The control plane is a **discovery layer**, NOT an authoritative consensus owner.

```
Control Plane
    │
    │ publishes candidate peers
    ▼
Node receives peer list
    │
    ├── verify cert (mTLS)
    ├── verify cluster identity (SPIFFE ID)
    ├── perform handshake (protocol negotiation)
    ├── validate protocol version
    └── join consensus (if trusted)
```

The **node decides** "Do I trust this peer?" — not the control plane alone.

### What this means in practice

| The CP may... | The CP must NOT... |
|---|---|
| Publish candidate peer lists | Dictate which peers a node trusts |
| Suggest cluster topology | Force membership changes |
| Aggregate health/metrics | Be required for node-to-node auth |
| Create Deployments | Own distributed locks |

### Node-Side Peer Verification

When a node receives a peer candidate from the control plane, it MUST independently:

1. **Verify the peer's certificate** against the cluster CA
2. **Validate the SPIFFE/X.509 identity** matches the expected cluster
3. **Perform a mutual handshake** (protocol version, capabilities)
4. **Check revocation status** (CRL/OCSP or local revocation cache)
5. **Rate-limit join attempts** to prevent flood-based attacks

Only after all checks pass does the node add the peer to its local peer table.

---

## PKI & Node Identity

### Required Components

| Component | Purpose |
|-----------|---------|
| Internal CA | Sign node certificates (per-cluster or per-tenant) |
| mTLS | Secure all node-to-node and node-to-CP communication |
| Node identity | SPIFFE IDs prevent impersonation (`spiffe://cluster/ns/name`) |
| Certificate rotation | Reduce long-term compromise window |
| Revocation | Remove compromised nodes immediately |

### Trust Bootstrapping

```
1. Node starts → loads signed cert from Secret/volume
2. Node contacts CP for peer discovery (mTLS)
3. CP returns candidate peer list (signed response)
4. Node verifies each peer independently (mTLS handshake)
5. Node joins consensus with verified peers only
```

The federation package (`pkg/federation`) already supports:
- Per-peer TLS certs (`TLSCertFile`, `TLSKeyFile`, `TLSCAFile`)
- HMAC-SHA256 signed snapshots (`FederationKey`)
- The identity/mtls package supports SPIFFE, CA hot-reload, cert rotation

---

## Topology & Scale

### Avoid at scale

Full mesh (all-to-all) creates O(N²) connections, connection explosion, and harder security management.

### Recommended patterns by scale

| Scale | Topology | Rationale |
|-------|----------|-----------|
| < 10 nodes | Full mesh | Simple, low overhead |
| 10–100 nodes | Leader/follower | Elected leader fans out |
| 100–1000 nodes | Partial mesh + gossip | Logarithmic propagation |
| 1000+ nodes | Hierarchical routing | Zone-based, bounded connections |

The current design (nodes elect their own leader, leader coordinates) naturally supports the leader/follower model. At larger scale, the federation layer can shard by namespace/tenant.

---

## Security Invariants

### Required (non-negotiable)

- [x] mTLS everywhere (node↔node, node↔CP, federation)
- [x] Signed node identities (X.509/SPIFFE)
- [x] Authenticated node bootstrap (cert from Secret, not IP-based)
- [x] RBAC on control plane API
- [x] Audit logs for all mutations
- [x] Peer verification handshake before consensus join
- [x] Rate limiting on discovery/registration endpoints

### Avoid (anti-patterns)

- [ ] ~~Blindly trusting CP-published membership~~
- [ ] ~~Unauthenticated peer connections~~
- [ ] ~~IP-based trust (IPs change in k8s)~~
- [ ] ~~Static/hardcoded secrets~~
- [ ] ~~Hardcoded leaders (use election)~~
- [ ] ~~Full mesh at scale~~
