# Node Cluster Authentication Design

## Problem Statement

There are two ways a node enters a cluster:

| Path | How | Who provisions identity? |
|------|-----|--------------------------|
| **Bootstrap node** | Helm / `kubectl apply` at cluster init time | Helm chart (cert-manager Certificate or pre-baked Secret) |
| **UI-created node** | Operator clicks "Add Node" in the control-plane UI | Control plane (creates Deployment + Certificate + Secret via k8s API) |

Both paths must produce a node that:

1. Can authenticate to every other node **without talking to the control plane at runtime**.
2. Survives a full control-plane outage — nodes must still accept/reject peers using state that was persisted before the outage.
3. Can be isolated from nodes serving a different application (application-level segmentation).

---

## Core Principle

> **The control plane is the provisioner, not the runtime authority.**

Once a node has been issued an identity (cert + cluster membership entry), that
identity is stored in Kubernetes Secrets / CRDs and retrieved from etcd directly —
not from the control-plane API. The control plane is only involved at creation time.

```
                     ┌───────────────────────────────────┐
                     │         etcd (k8s state)          │
                     │                                   │
                     │  • Node cert Secrets              │
                     │  • ClusterMembership CRDs         │
                     │  • AppCluster CRDs                │
                     │  • cluster CA Secrets             │
                     └────────────────┬──────────────────┘
                                      │  (shared source of truth)
               ┌──────────────────────┼──────────────────────┐
               │                      │                       │
  ┌────────────▼──────────┐  ┌────────▼───────┐  ┌──────────▼────────┐
  │  Control Plane (UI)   │  │  lwauth node A │  │  lwauth node B    │
  │  (stateless, optional)│  │  (data-plane)  │  │  (data-plane)     │
  │                       │  │                │  │                   │
  │  Provisions identity  │  │  Reads cert    │  │  Reads cert       │
  │  Creates k8s objects  │  │  from Secret   │  │  from Secret      │
  │  Can be down          │  │  Watches CRD   │  │  Watches CRD      │
  └───────────────────────┘  └───────┬────────┘  └──────────┬────────┘
                                     │  mTLS (SPIFFE)        │
                                     └───────────────────────┘
                                       direct node↔node trust
```

---

## Persistence Layer

All auth-relevant state lives in Kubernetes (etcd). Nothing depends on an
external database. The control plane loses state across restarts but that
state is always reconstructible from the k8s objects it created.

| Object | Kind | Content | Survives CP outage? |
|--------|------|---------|---------------------|
| `lwauth-cluster-ca` | Secret (`kubernetes.io/tls`) | Cluster CA cert + key | ✅ Yes |
| `lwauth-node-<name>` | Secret (`kubernetes.io/tls`) | Node TLS cert + key, signed by cluster CA | ✅ Yes |
| `ClusterMembership` | CRD | Peer list (name, SPIFFE ID, endpoint, labels) | ✅ Yes |
| `AppCluster` | CRD | Application-level node group, own CA ref, namespace scope | ✅ Yes |
| `LwauthInstance` | CRD | Desired node deployment spec | ✅ Yes |

No application-level database (Postgres, SQLite, etc.) is needed. etcd is the
persistence layer. This is intentional: it shares the same HA, backup, and
encryption-at-rest guarantees as the rest of the cluster.

---

## Two Bootstrap Paths

### Path 1 — Bootstrap node (Helm / kubectl)

Executed once per cluster before the control plane is running.

```
1. Helm chart renders:
     - Secret: lwauth-cluster-ca          (cluster CA cert+key)
     - Certificate: lwauth-node-bootstrap  (cert-manager, signed by CA)
     - ServiceAccount + RBAC              (read Secrets, watch CRDs)
     - ClusterMembership CR               (initial membership entry)
     - AppCluster CR                      (defines the app group)

2. Pod starts → mounts Secret volume (cert + key from cert-manager)

3. Node reads ClusterMembership CR → builds initial peer table

4. Node starts mTLS listener; ready to accept peers
```

The Helm chart is the only actor that touches the CA Secret. The CA key
**never leaves the cluster** — cert-manager signs on-cluster.

### Path 2 — UI-created node

Executed when an operator creates a node via the management UI.

Two actors are involved: the **API handler** (handles the HTTP request) and the
**reconciler** (runs in a background controller loop). They are separate goroutines
— the API handler returns immediately after writing the `LwauthInstance` CR; the
reconciler does all the real work asynchronously.

```
API handler (serves the POST):

  1. Operator fills in "Add Node" form in UI
       └─► POST /v1/controlplane/instances (LwauthInstance spec)
  2. Handler writes LwauthInstance CR to etcd → returns 202 Accepted
       (This is the only thing the handler does. It does not create certs
        or Deployments directly.)

Reconciler (background controller loop, triggered by the CR write):

  3. Sees the new LwauthInstance CR via informer
  4. Creates k8s objects in sequence (each step is individually atomic;
     the sequence as a whole is NOT — there is no cross-resource transaction):
       a. Certificate CR  → cert-manager signs it → Secret created with cert+key
       b. ServiceAccount + RBAC
       c. Deployment      (mounts the cert Secret as a volume)
       d. Service         (labelled app.kubernetes.io/name=lwauth,
                           lwauth.io/app-cluster=<app-cluster-id>)
       e. Upsert into ClusterMembership spec.members  ← broadcast trigger
  5. Updates LwauthInstance status

cert-manager (independent controller):

  6. Issues signed cert after step 4a → Secret becomes available → Pod can start

Node startup (independent of the reconciler):

  7. Deployment Pod starts → reads cert from mounted Secret → starts mTLS listener

Existing nodes (watching ClusterMembership):

  8. Informer fires on step 4e
       └─► each node diffs spec.members against its local peer table
       └─► initiates mTLS handshake to new node's endpoint
       └─► SPIFFE ID verified against cluster CA
       └─► new peer added to peer table on success

UI update:

  9. Control plane WebSocket broadcasts "node joined" event to UI subscribers
```

**If the control plane crashes mid-reconcile (e.g. after step 4c but before 4e):**
the `LwauthInstance` CR is still in etcd. When the control plane restarts,
`controller-runtime` re-syncs all existing CRs and re-queues the `LwauthInstance`
for reconciliation. Each step uses `CreateOrUpdate` — objects already created are
no-ops. The reconciler picks up exactly where it left off and completes step 4e.
No manual intervention is needed and no duplicate resources are created.

---

## UI Failure Resilience

```
Scenario: Control plane is completely down for 2 hours.

During the outage:
  ✅ Existing nodes continue serving auth decisions
  ✅ Node-to-node mTLS uses certs from mounted Secrets (no CP call needed)
  ✅ Peer discovery uses the ClusterMembership CRD (read from etcd directly)
  ✅ Leader election runs independently within the lwauth node cluster
  ✅ New node created by Helm still starts (reads its cert from its Secret)

Not possible during outage:
  ❌ Creating new nodes via UI (CP is the creator)
  ❌ Config changes via UI
  ❌ Viewing the dashboard

Recovery after CP restart:
  - CP reconciler re-reads all LwauthInstance CRDs
  - Any partially created instance gets completed (idempotent reconcile)
  - No manual intervention needed
```

### Key design constraint

Nodes must **never call the control-plane API** at runtime for peer trust
decisions. If a node has to phone home to the CP to decide whether to accept
a peer connection, the cluster inherits the CP's availability SLO. The CP
must be treated as a provisioning tool, not a runtime authority.

---

## Node-to-Node Authentication Protocol

All intra-cluster node communication uses **mutual TLS with SPIFFE X.509
identities**. There are no passwords, no symmetric tokens, and no IP-based trust.

### SPIFFE ID scheme

```
spiffe://<app-cluster-id>.lwauth/<namespace>/<node-name>

Examples:
  spiffe://payments.lwauth/payments/node-a
  spiffe://payments.lwauth/payments/node-b
  spiffe://analytics.lwauth/analytics/node-c   ← different app cluster
```

The `<app-cluster-id>` in the trust domain ensures a node from the `analytics`
app cluster cannot impersonate a node in `payments`, even if both run in the
same Kubernetes cluster.

### Handshake flow

```
Node A (initiator)              Node B (acceptor)
        │                               │
        │──── mTLS ClientHello ────────►│
        │◄─── mTLS ServerHello + cert ──│
        │──── mTLS client cert ────────►│
        │                               │
        │  B verifies A's cert:         │
        │    1. Chain to cluster CA     │
        │    2. SPIFFE ID trust domain  │
        │       matches expected        │
        │    3. Not in revocation list  │
        │    4. NotBefore / NotAfter    │
        │                               │
        │  A verifies B's cert:         │
        │    (same checks)              │
        │                               │
        │──── ClusterHandshakeReq ─────►│
        │     {nodeID, appClusterID,    │
        │      protocolVersion}         │
        │                               │
        │◄─── ClusterHandshakeResp ─────│
        │     {nodeID, appClusterID,    │
        │      capabilities}            │
        │                               │
        │  A checks appClusterID        │
        │    matches its own AppCluster │
        │    (cross-app-cluster peer    │
        │     rejected at this layer)   │
        │                               │
        │──── [established] ───────────►│
```

The `ClusterHandshakeReq/Resp` messages are a thin gRPC call on the
established mTLS channel. They serve as an application-level identity
check on top of the TLS layer.

### Peer verification failure handling

| Failure | Action |
|---------|--------|
| Invalid cert chain | Reject, log with peer address + partial SPIFFE ID |
| Wrong trust domain (wrong app cluster) | Reject, structured audit event |
| Revoked cert | Reject, increment `peer_auth_revoked_total` metric |
| Protocol version mismatch | Reject, log negotiation failure |
| Rate limit exceeded (> N join attempts/s) | Reject with backoff, alert |

---

## ClusterMembership CRD

This is the durable peer registry. Nodes watch it via `controller-runtime`
informers — no polling, instant delivery.

```go
// api/crd/v1alpha1/clustermembership_types.go

type ClusterMembership struct {
    metav1.TypeMeta   `json:",inline"`
    metav1.ObjectMeta `json:"metadata,omitempty"`
    Spec   ClusterMembershipSpec   `json:"spec"`
    Status ClusterMembershipStatus `json:"status,omitempty"`
}

type ClusterMembershipSpec struct {
    // AppClusterID scopes this membership list to one application cluster.
    AppClusterID string `json:"appClusterID"`

    // Members is the authoritative list of nodes in this app cluster.
    Members []ClusterMember `json:"members"`
}

type ClusterMember struct {
    // Name is the node's k8s object name.
    Name string `json:"name"`

    // Namespace is the k8s namespace the node's pod runs in.
    Namespace string `json:"namespace"`

    // Endpoint is the gRPC address (host:port) for peer connections.
    Endpoint string `json:"endpoint"`

    // SPIFFEID is the expected SPIFFE X.509 SAN for this node.
    // Must match the cert issued at provisioning time.
    SPIFFEID string `json:"spiffeID"`

    // JoinedAt is the time this member was admitted.
    JoinedAt metav1.Time `json:"joinedAt"`

    // Labels can carry application-specific metadata (e.g. zone, tier).
    Labels map[string]string `json:"labels,omitempty"`
}
```

### Who writes ClusterMembership?

| Actor | Operation | When |
|-------|-----------|------|
| Helm chart | Creates initial CR with bootstrap nodes | Cluster init |
| `instance_reconciler.go` | Patches `spec.members` on LwauthInstance create/delete | UI creates/deletes node |
| Node itself | Updates `status` only (health, last-seen) | Runtime |
| Human / `lwauthctl` | Manual add/remove for VM or external nodes | Edge cases |

Nodes are **readers**, not writers of `spec.members`. This prevents a
compromised node from injecting fake peers into the membership list.

---

## Application-Level Isolation (AppCluster)

Different services (payments, analytics, internal tooling) should have
completely separate auth planes: different CA, different node identities,
different SPIFFE trust domain, no cross-talk by default.

```
Kubernetes cluster "production"
│
├── Namespace: payments
│   ├── AppCluster: payments          (SPIFFE domain: payments.lwauth)
│   ├── ClusterMembership: payments-membership
│   ├── Secret: lwauth-cluster-ca     (payments CA)
│   ├── LwauthInstance: payments-node-a
│   └── LwauthInstance: payments-node-b
│
├── Namespace: analytics
│   ├── AppCluster: analytics         (SPIFFE domain: analytics.lwauth)
│   ├── ClusterMembership: analytics-membership
│   ├── Secret: lwauth-cluster-ca     (separate analytics CA)
│   ├── LwauthInstance: analytics-node-a
│   └── LwauthInstance: analytics-node-b
│
└── Namespace: lwauth-control-plane
    └── lwauth-controlplane           (manages all app clusters above)
```

### AppCluster CRD

```go
type AppCluster struct {
    metav1.TypeMeta   `json:",inline"`
    metav1.ObjectMeta `json:"metadata,omitempty"`
    Spec   AppClusterSpec   `json:"spec"`
    Status AppClusterStatus `json:"status,omitempty"`
}

type AppClusterSpec struct {
    // ID is the globally unique identifier for this app cluster.
    // Used as the SPIFFE trust domain component.
    // Must be DNS-label safe (lowercase, hyphens, max 63 chars).
    ID string `json:"id"`

    // Description is a human-readable label shown in the UI.
    Description string `json:"description,omitempty"`

    // CASecretRef references the cluster CA Secret in this namespace.
    // The Secret must have type kubernetes.io/tls.
    CASecretRef corev1.LocalObjectReference `json:"caSecretRef"`

    // AllowedNamespaces controls which namespaces can host nodes for
    // this app cluster. Empty = only the AppCluster's own namespace.
    AllowedNamespaces []string `json:"allowedNamespaces,omitempty"`

    // CrossClusterRoutes lists AppCluster IDs that nodes in this cluster
    // may proxy auth decisions to (via ProxyRoute). Explicit allowlist.
    CrossClusterRoutes []string `json:"crossClusterRoutes,omitempty"`
}
```

### Isolation enforcement

| Layer | Mechanism |
|-------|-----------|
| Network | NetworkPolicy: pods in `payments` namespace cannot initiate TCP to `analytics` namespace |
| TLS | Each AppCluster has its own CA; certs from different CAs will not chain-verify |
| SPIFFE | Trust domain mismatch rejected in `ClusterHandshakeReq` application layer |
| RBAC | `ClusterMembership` CRDs are namespace-scoped; RBAC limits which SAs can read them |
| ProxyRoute | Cross-AppCluster calls only permitted through explicit `ProxyRoute` + allowlist |

A node from `analytics` attempting to join the `payments` AppCluster fails at
**all four layers independently** — no single misconfiguration compromises isolation.

---

## Broadcast: "New Node Joined"

When the control plane creates a new node (Path 2), existing nodes must learn
about it quickly. The mechanism is a CRD watch, not a push notification through
the control plane.

```
Control plane patches ClusterMembership spec.members
          │
          ▼  (etcd update)
controller-runtime informer on each existing node fires
          │
          ▼
Node reads updated spec.members
          │
          ├─► For each new member not in local peer table:
          │     Initiate mTLS handshake (with rate-limit + backoff)
          │     Verify SPIFFE ID
          │     Add to peer table on success
          │
          └─► For each member removed from spec.members:
                Remove from peer table
                Close existing connection (graceful shutdown)
```

This works **without** the control plane being involved in the actual handshake.
The CRD is the broadcast channel; etcd delivers it to all watchers within
milliseconds.

### Consistency: what if a node starts before the ClusterMembership patch?

```
Timeline:
  t=0   CP creates Deployment (spec.members not yet patched)
  t=5s  Pod starts, tries to read ClusterMembership
  t=8s  CP patches ClusterMembership (after cert-manager issues cert)

  Result: node starts with empty peer list, then informer fires at t=8s
          and it discovers existing peers and initiates handshakes.
          This is fine — node is already serving auth traffic from t=5s,
          it just hasn't joined the peer mesh yet.
```

The node should tolerate starting with zero peers and building its peer table
incrementally. It must not require a full peer table to serve auth decisions
(its local config is sufficient; the mesh is for replication/revocation sync).

---

## Revised `instance_reconciler.go` Responsibilities

The reconciler must be updated to handle ClusterMembership patching:

```
Reconcile(LwauthInstance) {
  1. Resolve AppCluster (from spec.appClusterID label or namespace default)
  2. Ensure Certificate CR exists (cert-manager)
  3. Ensure ServiceAccount + RBAC exist
  4. Ensure Deployment exists (mounts cert Secret)
  5. Ensure Service exists (labelled with app-cluster-id)
  6. Patch ClusterMembership spec.members (upsert this instance's entry)
     - SPIFFE ID = spiffe://<appClusterID>.lwauth/<namespace>/<name>
     - Endpoint  = <service-dns>:<port>
  7. Update LwauthInstance status
}

Reconcile(LwauthInstance — deleted) {
  1. Remove entry from ClusterMembership spec.members
  2. Delete Deployment, Service, Certificate, ServiceAccount
  (do NOT delete the CA Secret — shared by all nodes in the AppCluster)
}
```

---

## Security Considerations

### What the control plane is NOT trusted to do at runtime

- The control plane **cannot force a node to trust a peer**. The node verifies
  the cert independently.
- The control plane **cannot revoke a cert directly**. Revocation goes through
  cert-manager / CRL / OCSP — the node checks this independently.
- The control plane **cannot read node-to-node traffic**. It has no position in
  the mTLS data path.

### CA key protection

The cluster CA Secret (`lwauth-cluster-ca`) holds the CA private key. This must be:
- Stored with `type: kubernetes.io/tls` in a dedicated namespace
- Protected by a restrictive `Role` — only the `instance_reconciler` ServiceAccount
  can read it, and only for the purpose of passing it to cert-manager
- Rotated on a schedule (cert-manager supports CA rotation natively)
- **Never mounted into node pods** — nodes only receive their leaf cert/key, not the CA key

### Admission of external / VM nodes

For nodes not running in Kubernetes (e.g. bare-metal or VMs), use `lwauthctl`:

```bash
# Generate a CSR on the external node
lwauthctl node csr --cluster payments --name external-node-1 > external.csr

# Sign on the cluster (requires admin RBAC)
lwauthctl node sign --csr external.csr --cluster payments > external.crt

# Register in ClusterMembership
lwauthctl node register \
  --cluster payments \
  --name external-node-1 \
  --endpoint 10.0.1.50:9001 \
  --spiffe-id spiffe://payments.lwauth/external/external-node-1

# Copy cert to external node — out-of-band (scp, secrets manager, etc.)
```

The external node then uses the same mTLS + SPIFFE handshake as in-cluster nodes.

---

## Summary: Answers to the Original Questions

| Question | Answer |
|----------|--------|
| How do nodes connect securely? | mTLS with SPIFFE X.509 certs, signed by the AppCluster's CA. No passwords. |
| What if the UI fails? | Nothing breaks. Certs are in Secrets; peer list is in ClusterMembership CRD — both in etcd, independent of the control plane. |
| Where is auth state persisted? | Kubernetes Secrets (certs) + ClusterMembership CRD (peer registry). etcd is the database. |
| How does a new UI-created node broadcast to others? | Control plane patches ClusterMembership; controller-runtime informer on each node fires within seconds; nodes initiate mTLS handshakes independently. |
| How do we isolate different services? | AppCluster CRD — separate namespace, separate CA, separate SPIFFE trust domain, NetworkPolicy enforcement. Four independent isolation layers. |
