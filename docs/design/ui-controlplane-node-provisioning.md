# UI Control Plane — Node Provisioning, Access Endpoints & OCI Free-Tier Production

> Status: **Draft** · Extends [UIDESIGN.md](./UIDESIGN.md) and
> [node-cluster-auth.md](./node-cluster-auth.md)
>
> **Scope:** Redesign the "Create Instance" workflow into a module-aware
> provisioning form, expose queryable endpoint URLs per node, and deploy
> the full stack on Oracle Cloud Infrastructure (OCI) Always Free tier.

---

## Table of Contents

1. [Problem Statement](#1-problem-statement)
2. [Goals & Non-Goals](#2-goals-non-goals)
3. [High-Level Architecture](#3-high-level-architecture)
4. [UI: Create Node — Module-Aware Form](#4-ui-create-node-module-aware-form)
5. [Helm Values Generation](#5-helm-values-generation)
6. [Node Provisioning Flow](#6-node-provisioning-flow)
7. [UI: Node Endpoint Display](#7-ui-node-endpoint-display)
8. [API Additions](#8-api-additions)
9. [OCI Free-Tier Production Architecture](#9-oci-free-tier-production-architecture)
10. [Terraform Module for OCI](#10-terraform-module-for-oci)
11. [Production Readiness Checklist](#11-production-readiness-checklist)
12. [Delivery Phases](#12-delivery-phases)
13. [Security Considerations](#13-security-considerations)
14. [Lessons Learned: Local kind Deployment](#14-lessons-learned-local-kind-deployment)
15. [Console Login & Node Lifecycle](#15-console-login-node-lifecycle)

---

## 1. Problem Statement

The current "Create Instance" dialog (Phase 1.10 of UIDESIGN.md) accepts raw
inline YAML for auth config. This has three problems:

1. **Operators must know the config schema by heart** — there is no
   guided form for selecting identity modules, authorizers, or mutators.
2. **No endpoint visibility** — after a node is created, the operator must
   manually construct the gRPC, HTTP, and Envoy ext_authz URLs.
3. **No production deployment path** — no Terraform/Helm automation for
   running the control plane + data plane on a cloud provider.

---

## 2. Goals & Non-Goals

### Goals

- Replace raw YAML input with a **step-by-step form** that maps to lwauth
  modules (identifiers, authorizers, mutators, cache, rate limiting).
- Auto-generate valid Helm `values.yaml` from form inputs.
- Display **ready-to-use endpoint URLs** (gRPC, HTTP, Envoy ext_authz) on
  the instance detail page once the node is healthy.
- Provide a **Terraform module** for deploying the full stack on OCI
  Always Free tier (ARM Ampere A1, 4 OCPU / 24 GB RAM).
- Load-balanced access via a single ingress URL that fans out to all
  replicas of the same `LwauthInstance`.

### Non-Goals

- Visual pipeline builder / drag-and-drop (future work).
- Multi-cloud abstraction (this design targets OCI only; the Helm chart is
  cloud-agnostic, so AWS/GCP/Azure users just swap the Terraform module).
- WASM module upload from the UI.
- Paid OCI resources (everything fits within Always Free).

---

## 3. High-Level Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                    OCI Always Free Cluster                       │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │               OKE (Kubernetes) — ARM A1                   │  │
│  │                                                            │  │
│  │  ┌──────────────────┐    ┌──────────────────────────────┐  │  │
│  │  │  Control Plane   │    │  Data Plane (lwauth nodes)   │  │  │
│  │  │  Pod (1 replica) │    │  Pod (1-2 replicas per inst) │  │  │
│  │  │  ┌────────────┐  │    │  ┌────────────┐              │  │  │
│  │  │  │ CP API     │  │    │  │ lwauth     │ :8080 HTTP   │  │  │
│  │  │  │ :8443      │──┼────┼─►│            │ :9001 gRPC   │  │  │
│  │  │  ├────────────┤  │    │  └────────────┘              │  │  │
│  │  │  │ SolidJS UI │  │    │  ┌────────────┐              │  │  │
│  │  │  │ (embedded) │  │    │  │ Envoy      │ :10000       │  │  │
│  │  │  └────────────┘  │    │  │ (optional) │              │  │  │
│  │  └──────────────────┘    │  └────────────┘              │  │  │
│  │                          └──────────────────────────────────┘ │
│  │  ┌──────────────────┐    ┌──────────────────────────────┐  │  │
│  │  │  Ingress Nginx   │    │  cert-manager (Let's Encrypt)│  │  │
│  │  │  (NodePort+LB)   │    │  ClusterIssuer               │  │  │
│  │  └──────────────────┘    └──────────────────────────────┘  │  │
│  └────────────────────────────────────────────────────────────┘  │
│                                                                  │
│  ┌────────────────┐  ┌──────────────┐  ┌──────────────────────┐  │
│  │ OCI LB (10Mbps)│  │ OCI DNS Zone │  │ OCI Object Storage   │  │
│  │ (Always Free)  │  │ (Free)       │  │ (Terraform state)    │  │
│  └────────────────┘  └──────────────┘  └──────────────────────┘  │
└──────────────────────────────────────────────────────────────────┘
```

---

## 4. UI: Create Node — Module-Aware Form

### 4.1 Form Structure

The "Create Node" dialog becomes a **multi-step wizard** with five tabs.
Each tab maps to a section of the lwauth config and the Helm values.

```
┌─────────────────────────────────────────────────────────────┐
│  Create LwAuth Node                                    [X]  │
│                                                             │
│  ① Basics  ② Identity  ③ Authorization  ④ Response  ⑤ Infra│
│  ─────────────────────────────────────────────────────────── │
│                                                             │
│  Step 1: Basics                                             │
│  ┌───────────────────────────────────────────────────────┐  │
│  │ Node Name:      [payments-auth_____________]         │  │
│  │ Namespace:      [payments___________________]         │  │
│  │ Cluster:        [▾ local                    ]         │  │
│  │ Replicas:       [▾ 1 ]                                │  │
│  │ Image Version:  [▾ latest (v1.2.0)          ]         │  │
│  └───────────────────────────────────────────────────────┘  │
│                                                             │
│  Step 2: Identity Modules                                   │
│  Select one or more identity verification methods:          │
│  ┌───────────────────────────────────────────────────────┐  │
│  │ [+] Add Identifier                                    │  │
│  │                                                       │  │
│  │ ┌─ JWT ──────────────────────────────────────────┐    │  │
│  │ │  Name:       [jwt-verifier__________]          │    │  │
│  │ │  JWKS URL:   [https://auth.example/.well-known]│    │  │
│  │ │  Issuer:     [https://auth.example.com_______] │    │  │
│  │ │  Audiences:  [api.example.com________________] │    │  │
│  │ │  Clock Skew: [30s____]                         │    │  │
│  │ └────────────────────────────────────────────────┘    │  │
│  │                                                       │  │
│  │ ┌─ API Key ──────────────────────────────────────┐    │  │
│  │ │  Name:       [apikey-svc___________]           │    │  │
│  │ │  Backend:    [▾ kubernetes-secret   ]           │    │  │
│  │ │  Secret:     [lwauth-api-keys______]           │    │  │
│  │ │  Header:     [X-API-Key___________]            │    │  │
│  │ └────────────────────────────────────────────────┘    │  │
│  └───────────────────────────────────────────────────────┘  │
│                                                             │
│  Step 3: Authorization                                      │
│  Select an authorization engine:                            │
│  ┌───────────────────────────────────────────────────────┐  │
│  │ (•) RBAC    ( ) OPA/Rego    ( ) CEL    ( ) OpenFGA   │  │
│  │ ( ) Composite    ( ) SpiceDB                          │  │
│  │                                                       │  │
│  │ ┌─ RBAC Config ──────────────────────────────────┐    │  │
│  │ │  Roles:                                        │    │  │
│  │ │  ┌──────────────────────────────────────────┐  │    │  │
│  │ │  │ admin:                                   │  │    │  │
│  │ │  │   permissions: [read, write, delete]     │  │    │  │
│  │ │  │ viewer:                                  │  │    │  │
│  │ │  │   permissions: [read]                    │  │    │  │
│  │ │  └──────────────────────────────────────────┘  │    │  │
│  │ └────────────────────────────────────────────────┘    │  │
│  └───────────────────────────────────────────────────────┘  │
│                                                             │
│  Step 4: Response Mutators                                  │
│  ┌───────────────────────────────────────────────────────┐  │
│  │ [+] Add Mutator                                       │  │
│  │                                                       │  │
│  │ ┌─ Header Add ───────────────────────────────────┐    │  │
│  │ │  Name:           [forward-identity_____]       │    │  │
│  │ │  Subject Header: [X-Auth-Subject_______]       │    │  │
│  │ │  Roles Header:   [X-Auth-Roles_________]       │    │  │
│  │ └────────────────────────────────────────────────┘    │  │
│  └───────────────────────────────────────────────────────┘  │
│                                                             │
│  Step 5: Infrastructure                                     │
│  ┌───────────────────────────────────────────────────────┐  │
│  │ Cache Backend:  [▾ memory    ]  │ valkey, tiered      │  │
│  │ Rate Limiting:  [ ] Enable       RPS: [100] Burst:[200]│ │
│  │ Revocation:     [ ] Enable       Backend: [▾ memory  ]│  │
│  │ Gateway/Envoy:  [ ] Enable sidecar                    │  │
│  │   Upstream:     [app-svc.default.svc:8000__]          │  │
│  │ Network Policy: [✓] Enable                            │  │
│  └───────────────────────────────────────────────────────┘  │
│                                                             │
│  ┌───────────────────────────────────────────────────────┐  │
│  │  [Preview YAML]  [Preview Helm Values]    [Create ▸]  │  │
│  └───────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

### 4.2 Module Registry Integration

The form dynamically populates available modules from the lwauth module
registry. The control plane exposes a read-only catalogue:

```
GET /v1/controlplane/modules
```

Response:

```json
{
  "identifiers": [
    {
      "type": "jwt",
      "displayName": "JWT (OIDC / JWKS)",
      "description": "Verify JWTs against a JWKS endpoint",
      "schema": { /* JSON Schema for config fields */ },
      "builtIn": true
    },
    {
      "type": "apikey",
      "displayName": "API Key",
      "schema": { ... },
      "builtIn": true
    },
    { "type": "mtls", ... },
    { "type": "hmac", ... },
    { "type": "oauth2", ... },
    { "type": "oauth2-introspection", ... },
    { "type": "dpop", ... }
  ],
  "authorizers": [
    { "type": "rbac", ... },
    { "type": "opa", ... },
    { "type": "cel", ... },
    { "type": "openfga", ... },
    { "type": "spicedb", ... },
    { "type": "composite", ... }
  ],
  "mutators": [
    { "type": "header-add", ... },
    { "type": "header-remove", ... },
    { "type": "header-passthrough", ... },
    { "type": "jwt-issue", ... }
  ],
  "cacheBackends": ["memory", "valkey", "tiered"],
  "revocationBackends": ["memory", "valkey"]
}
```

Each module type includes a **JSON Schema** for its config fields. The UI
renders form fields dynamically from the schema. This means:

- Core modules have pre-built, polished form layouts.
- Custom/plugin modules get auto-generated forms from their schema.
- The form always stays in sync with the binary's capabilities.

### 4.3 Module Presets (Templates)

Common configurations are offered as one-click presets:

| Preset | Identity | Authorizer | Mutator | Use Case |
|--------|----------|------------|---------|----------|
| **API Gateway** | JWT | RBAC | header-add | Protect REST APIs behind Envoy |
| **Service Mesh** | mTLS | CEL | header-passthrough | Zero-trust service-to-service |
| **Internal Tools** | API Key | RBAC | header-add | Internal dashboards, CLI tools |
| **OAuth2 App** | OAuth2 auth-code | OPA | jwt-issue | Browser-based SPA with sessions |
| **Machine-to-Machine** | HMAC | CEL | header-add | Webhooks, cron jobs, IoT |
| **Custom** | (empty) | (empty) | (empty) | Build from scratch |

Selecting a preset pre-fills the form. The operator can then customize.

---

## 5. Helm Values Generation

### 5.1 Form → Values Mapping

The control plane backend converts the form submission into a valid Helm
`values.yaml`. The mapping is deterministic:

```
Form Field                    → Helm Value Path
─────────────────────────────────────────────────────
basics.name                   → (LwauthInstance CR metadata.name)
basics.namespace              → (LwauthInstance CR metadata.namespace)
basics.cluster                → (target cluster selection)
basics.replicas               → replicaCount
basics.imageVersion           → image.tag

identity[*]                   → config.inline.identifiers[*]
authorizer                    → config.inline.authorizers[0]
mutators[*]                   → config.inline.response[*]

infra.cacheBackend            → cache.backend
infra.cacheAddr               → cache.addr
infra.rateLimitEnabled        → rateLimit.perTenant.rps / burst
infra.revocationEnabled       → revocation.backend
infra.gatewayEnabled          → gateway.enabled
infra.gatewayUpstream         → gateway.upstream.service / port
infra.networkPolicy           → networkPolicy.enabled
```

### 5.2 Generated Config Example

For a form submission with JWT + RBAC + header-add:

```yaml
# Auto-generated by lwauth control plane
# Instance: payments-auth | Cluster: local | Namespace: payments
replicaCount: 2

image:
  tag: "v1.2.0"

config:
  inline: |
    identifiers:
      - name: jwt-verifier
        type: jwt
        config:
          jwksUrl: "https://auth.example.com/.well-known/jwks.json"
          issuer: "https://auth.example.com"
          audiences: ["api.example.com"]
          clockSkew: "30s"

    authorizers:
      - name: rbac-main
        type: rbac
        config:
          # rolesFrom reads the subject's roles from a JWT claim or identity
          # field. Default: "claim:roles". The allow list names the roles that
          # are permitted; any subject whose roles intersect this list passes.
          rolesFrom: "claim:roles"
          allow:
            - admin
            - viewer

    response:
      - name: forward-identity
        type: header-add
        config:
          subjectHeader: "X-Auth-Subject"
          rolesHeader: "X-Auth-Roles"

cache:
  backend: memory

networkPolicy:
  enabled: true
```

> **Schema note:** The `rbac` authorizer does **not** use a
> `roles: { name: { permissions: [...] } }` structure. It uses a flat
> `allow: [role_names]` list — any subject whose identity carries at least
> one of the listed roles is allowed. Permission-level rules (read/write)
> are enforced by the upstream application, not by lwauth's built-in RBAC.
> The form UI may display a richer permissions model for ergonomics; the
> provisioner must collapse it to the `allow` list when generating config.

### 5.3 Preview & Validation

Before submission, the UI offers two preview modes:

- **Preview YAML** — shows the `config.inline` auth pipeline config.
- **Preview Helm Values** — shows the full `values.yaml` that will be
  applied to the Helm chart.

The backend validates the generated config by calling
`internal/config.Compile()` before creating the `LwauthInstance` CR.
Validation errors are returned as structured JSON with field-level
pointers so the UI can highlight the problematic form field.

---

## 6. Node Provisioning Flow

```
  Operator                      UI                   CP API               K8s (etcd)
     │                          │                       │                      │
     │  Fill form + click       │                       │                      │
     │  "Create"                │                       │                      │
     │ ─────────────────────────►                       │                      │
     │                          │  POST /instances/create                      │
     │                          │  { form fields }      │                      │
     │                          │ ──────────────────────►│                      │
     │                          │                       │  1. Validate config  │
     │                          │                       │     (config.Compile) │
     │                          │                       │  2. Generate values  │
     │                          │                       │  3. Create LwauthInstance CR
     │                          │                       │ ─────────────────────►│
     │                          │  202 Accepted         │                      │
     │                          │  { name, status:      │                      │
     │                          │    "provisioning" }   │                      │
     │                          │ ◄──────────────────── │                      │
     │                          │                       │                      │
     │  UI shows spinner        │                       │  Reconciler watches  │
     │  + WebSocket updates     │                       │  LwauthInstance CR   │
     │                          │                       │ ◄─────────────────── │
     │                          │                       │                      │
     │                          │                       │  4. Create Certificate CR
     │                          │                       │  5. Create SA + RBAC │
     │                          │                       │  6. Create Deployment│
     │                          │                       │     (helm template)  │
     │                          │                       │  7. Create Service   │
     │                          │                       │  8. Patch ClusterMembership
     │                          │                       │  9. Create Ingress rule
     │                          │                       │ ─────────────────────►│
     │                          │                       │                      │
     │                          │  WS: status=ready     │  10. Pod healthy     │
     │                          │  + endpoints          │  11. Update CR status│
     │                          │ ◄──────────────────── │ ◄─────────────────── │
     │                          │                       │                      │
     │  Node card shows         │                       │                      │
     │  green + endpoint URLs   │                       │                      │
```

### 6.1 Reconciler Steps (Detail)

The `LwauthInstance` reconciler (from node-cluster-auth.md §UI-Created
Node Path) is extended with:

| Step | Resource | Purpose |
|------|----------|---------|
| 1 | ConfigMap `lwauth-config-<name>` | Stores generated `config.yaml` from form |
| 2 | Certificate CR | cert-manager signs node TLS cert |
| 3 | Secret `lwauth-node-<name>` | Stores signed cert + key |
| 4 | ServiceAccount + RBAC | Namespace-scoped permissions |
| 5 | Deployment | lwauth binary + config volume + cert volume |
| 6 | Service (ClusterIP) | `<name>.<namespace>.svc.cluster.local` |
| 7 | Ingress rule | `<name>.lwauth.<domain>` (or path-based) |
| 8 | ClusterMembership patch | Add peer entry for mTLS mesh |
| 9 | Status update | Write endpoints + health to CR status |

### 6.2 Status Tracking

The `LwauthInstance` CR status subresource is extended:

```go
type LwauthInstanceStatus struct {
    Phase           string            `json:"phase"`           // Provisioning, Running, Degraded, Failed
    Conditions      []metav1.Condition `json:"conditions"`
    Replicas        int32             `json:"replicas"`
    ReadyReplicas   int32             `json:"readyReplicas"`
    ConfigVersion   string            `json:"configVersion"`
    Endpoints       NodeEndpoints     `json:"endpoints"`       // NEW
    ProvisionedAt   *metav1.Time      `json:"provisionedAt"`
    LastHealthCheck *metav1.Time      `json:"lastHealthCheck"`
}

type NodeEndpoints struct {
    HTTP       string `json:"http"`       // http://<svc>:8080
    GRPC       string `json:"grpc"`       // <svc>:9001
    ExtAuthz   string `json:"extAuthz"`   // grpc://<svc>:9001 (envoy ext_authz)
    IngressURL string `json:"ingressUrl"` // https://<name>.lwauth.<domain>
    AdminURL   string `json:"adminUrl"`   // http://<svc>:8080/v1/admin
}
```

---

## 7. UI: Node Endpoint Display

### 7.1 Instance Detail — Endpoints Panel

Once a node reaches `Phase: Running`, the instance detail page shows a
new **Endpoints** card:

```
┌─────────────────────────────────────────────────────────────┐
│  Endpoints                                    [Copy All]    │
│                                                             │
│  ┌─ HTTP ─────────────────────────────────────────────────┐ │
│  │  Internal: http://payments-auth.payments.svc:8080      │ │
│  │  External: https://payments-auth.lwauth.example.com    │ │
│  │                                                        │ │
│  │  Sample:                                               │ │
│  │  curl -H "Authorization: Bearer <token>" \             │ │
│  │    https://payments-auth.lwauth.example.com/v1/authorize│ │
│  └────────────────────────────────────────────────────────┘ │
│                                                             │
│  ┌─ gRPC (Native) ───────────────────────────────────────┐  │
│  │  Internal: payments-auth.payments.svc:9001             │  │
│  │  External: payments-auth.lwauth.example.com:443        │  │
│  │                                                        │  │
│  │  Sample (grpcurl):                                     │  │
│  │  grpcurl -d '{"method":"GET","resource":"/api/v1/...}' │  │
│  │    payments-auth.lwauth.example.com:443                │  │
│  │    lightweightauth.v1.Auth/Authorize                   │  │
│  └────────────────────────────────────────────────────────┘ │
│                                                             │
│  ┌─ Envoy ext_authz ─────────────────────────────────────┐  │
│  │  Cluster config for envoy.yaml:                        │  │
│  │  ┌──────────────────────────────────────────────────┐  │  │
│  │  │ http_filters:                                    │  │  │
│  │  │ - name: envoy.filters.http.ext_authz             │  │  │
│  │  │   typed_config:                                  │  │  │
│  │  │     grpc_service:                                │  │  │
│  │  │       envoy_grpc:                                │  │  │
│  │  │         cluster_name: lwauth                     │  │  │
│  │  │     transport_api_version: V3                    │  │  │
│  │  │                                                  │  │  │
│  │  │ clusters:                                        │  │  │
│  │  │ - name: lwauth                                   │  │  │
│  │  │   type: STRICT_DNS                               │  │  │
│  │  │   lb_policy: ROUND_ROBIN                         │  │  │
│  │  │   typed_extension_protocol_options: ...           │  │  │
│  │  │   load_assignment:                               │  │  │
│  │  │     endpoints:                                   │  │  │
│  │  │     - lb_endpoints:                              │  │  │
│  │  │       - endpoint:                                │  │  │
│  │  │           address:                               │  │  │
│  │  │             socket_address:                      │  │  │
│  │  │               address: payments-auth.payments.svc│  │  │
│  │  │               port_value: 9001                   │  │  │
│  │  └──────────────────────────────────────────────────┘  │  │
│  │  [Copy Envoy Config]                                   │  │
│  └────────────────────────────────────────────────────────┘  │
│                                                             │
│  ┌─ Load Balancing ──────────────────────────────────────┐  │
│  │  All replicas share the same Service (ClusterIP).     │  │
│  │  Kubernetes kube-proxy distributes traffic via        │  │
│  │  round-robin across 2 ready pods.                     │  │
│  │                                                       │  │
│  │  Replicas: 2/2 ready                                  │  │
│  │  Pod IPs: 10.244.0.15, 10.244.0.16                   │  │
│  └───────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

### 7.2 Quick-Test Widget

A built-in "Try It" panel lets operators send a test authorization
request directly from the UI:

```
┌─────────────────────────────────────────────────────────────┐
│  Quick Test                                                  │
│                                                             │
│  Protocol:  (•) HTTP   ( ) gRPC   ( ) ext_authz             │
│  Method:    [▾ GET ]   Path: [/api/v1/payments____]         │
│  Headers:                                                    │
│    Authorization: [Bearer eyJhbGci...____________]          │
│    X-API-Key:     [____________________________]            │
│                                                             │
│  [Send Request]                                              │
│                                                             │
│  Response:                                                   │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ Status: 200 OK (Allow)                    12ms       │   │
│  │ Headers:                                              │   │
│  │   X-Auth-Subject: user:alice                          │   │
│  │   X-Auth-Roles: admin                                 │   │
│  │ Identity: { sub: "alice", iss: "https://auth.ex..." } │   │
│  └──────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

The Quick Test sends the request to the node's admin `/v1/admin/explain`
endpoint, which returns the full pipeline trace.

---

## 8. API Additions

### 8.1 Module Catalogue

```
GET /v1/controlplane/modules
```

Returns the module registry with JSON Schema per module type. Populated
from `pkg/module.Registry` at startup. Read-only, no auth required beyond
the existing admin JWT / mTLS gate.

### 8.2 Extended Create Instance

```
POST /v1/controlplane/instances/create
Content-Type: application/json

{
  "name": "payments-auth",
  "namespace": "payments",
  "cluster": "local",
  "replicas": 2,
  "imageTag": "v1.2.0",
  "preset": "api-gateway",          // optional, overridden by explicit fields
  "identifiers": [
    {
      "name": "jwt-verifier",
      "type": "jwt",
      "config": {
        "jwksUrl": "https://auth.example.com/.well-known/jwks.json",
        "issuer": "https://auth.example.com",
        "audiences": ["api.example.com"],
        "clockSkew": "30s"
      }
    }
  ],
  "authorizers": [
    {
      "name": "rbac-main",
      "type": "rbac",
      "config": {
        "roles": {
          "admin": { "permissions": ["read", "write", "delete"] },
          "viewer": { "permissions": ["read"] }
        }
      }
    }
  ],
  "mutators": [
    {
      "name": "forward-identity",
      "type": "header-add",
      "config": {
        "subjectHeader": "X-Auth-Subject"
      }
    }
  ],
  "infrastructure": {
    "cacheBackend": "memory",
    "rateLimiting": { "enabled": false },
    "revocation": { "enabled": false },
    "gateway": { "enabled": false },
    "networkPolicy": true
  }
}
```

Response (202):

```json
{
  "name": "payments-auth",
  "namespace": "payments",
  "cluster": "local",
  "status": "Provisioning",
  "generatedConfig": "identifiers:\n  - name: jwt-verifier\n    ...",
  "generatedHelmValues": "replicaCount: 2\nimage:\n  tag: v1.2.0\n..."
}
```

### 8.3 Get Instance Endpoints

```
GET /v1/controlplane/instances/{cluster}/{name}/endpoints
```

Response:

```json
{
  "http": {
    "internal": "http://payments-auth.payments.svc.cluster.local:8080",
    "external": "https://payments-auth.lwauth.example.com"
  },
  "grpc": {
    "internal": "payments-auth.payments.svc.cluster.local:9001",
    "external": "payments-auth.lwauth.example.com:443"
  },
  "extAuthz": {
    "envoyClusterConfig": "...",
    "address": "payments-auth.payments.svc.cluster.local",
    "port": 9001
  },
  "loadBalancing": {
    "strategy": "round-robin",
    "readyReplicas": 2,
    "totalReplicas": 2,
    "podIPs": ["10.244.0.15", "10.244.0.16"]
  }
}
```

### 8.4 Quick Test

```
POST /v1/controlplane/instances/{cluster}/{name}/test
Content-Type: application/json

{
  "protocol": "http",
  "method": "GET",
  "path": "/api/v1/payments",
  "headers": {
    "Authorization": "Bearer eyJhbGci..."
  }
}
```

Proxied to the target node's `/v1/admin/explain`. Response includes the
full pipeline trace (identity resolved, authorizer decision, mutated
headers, latency breakdown).

---

## 9. OCI Free-Tier Production Architecture

### 9.1 OCI Always Free Resources Used

| Resource | Free Tier Limit | Our Usage |
|----------|-----------------|-----------|
| **ARM Ampere A1** | 4 OCPU, 24 GB RAM (shared across all A1 VMs) | 1 VM: 4 OCPU, 24 GB → K3s single-node |
| **Boot Volume** | 200 GB total (2 × 50 GB default + 100 GB free) | 1 × 100 GB boot volume |
| **Block Volume** | 200 GB total | 50 GB for persistent data |
| **Load Balancer** | 1 × flexible (10 Mbps) | 1 LB for ingress |
| **Object Storage** | 20 GB | Terraform state + backups |
| **Outbound Data** | 10 TB/month | More than sufficient |
| **DNS** | Free hosted zone | `lwauth.yourdomain.com` |
| **VCN** | 2 VCNs, 5 subnets | 1 VCN, 2 subnets (public/private) |

### 9.2 Cluster Topology

Single ARM A1 VM running **K3s** (lightweight Kubernetes):

```
┌─────────────────────────────────────────────────────────┐
│  ARM Ampere A1  (4 OCPU / 24 GB RAM / Oracle Linux 9)   │
│                                                          │
│  ┌─ K3s (single-node cluster) ───────────────────────┐  │
│  │                                                    │  │
│  │  System pods (~400 MB):                            │  │
│  │    - k3s-server (API + scheduler + etcd)           │  │
│  │    - traefik (built-in ingress, or swap for nginx) │  │
│  │    - coredns                                       │  │
│  │    - metrics-server                                │  │
│  │                                                    │  │
│  │  LwAuth pods (~600 MB):                            │  │
│  │    - lwauth-controlplane (1 replica)    ~64 MB     │  │
│  │    - lwauth-node-a (2 replicas)         ~32 MB ea  │  │
│  │    - lwauth-node-b (1 replica)          ~32 MB     │  │
│  │    - cert-manager (3 pods)              ~128 MB    │  │
│  │                                                    │  │
│  │  Optional (~300 MB):                               │  │
│  │    - valkey (1 replica)                 ~64 MB     │  │
│  │    - prometheus + grafana               ~256 MB    │  │
│  │                                                    │  │
│  │  Available: ~22 GB RAM headroom for more nodes     │  │
│  └────────────────────────────────────────────────────┘  │
│                                                          │
│  OCI LB (10 Mbps) ─► NodePort 80/443 ─► Ingress ─► Svc │
└─────────────────────────────────────────────────────────┘
```

**Why K3s over OKE?**
- OKE (managed Kubernetes) requires at least one worker node pool, which
  is **not** in the Always Free tier (worker nodes are billed).
- K3s on a single A1 VM is fully free and provides a real Kubernetes API.
- For production beyond free tier, swap to OKE with the same Helm charts.

### 9.3 Networking

```
Internet ─► OCI LB (10 Mbps, free)
             │
             ├─► :443 → NodePort 30443 → Ingress Controller
             │    ├─► lwauth.example.com/          → CP UI (port 8443)
             │    ├─► lwauth.example.com/v1/       → CP API (port 8443)
             │    ├─► *.lwauth.example.com          → Data plane nodes
             │    └─► grpc.lwauth.example.com       → gRPC (TLS passthrough)
             │
             └─► :80  → NodePort 30080 → Redirect to HTTPS

  VCN: 10.0.0.0/16
  ├─ Public subnet:  10.0.0.0/24  (LB, VM public IP)
  └─ Private subnet: 10.0.1.0/24  (pod CIDR, internal only)
```

### 9.4 TLS Strategy

- **cert-manager** with Let's Encrypt ClusterIssuer (free certificates).
- Wildcard cert `*.lwauth.example.com` via DNS-01 challenge using OCI DNS.
- Each lwauth node gets its own subdomain:
  `<node-name>.lwauth.example.com`.
- gRPC: TLS termination at ingress (nginx `grpc_pass`) or TLS passthrough
  for end-to-end encryption.

### 9.5 DNS Setup

```
lwauth.example.com       → OCI LB public IP (A record)
*.lwauth.example.com     → OCI LB public IP (wildcard A record)
```

Alternatively, use a free subdomain via services like `nip.io` or
`sslip.io` for testing (`lwauth.<LB-IP>.nip.io`).

---

## 10. Terraform Module for OCI

> **Repository:** The IaC module lives in a **separate repository**
> [`lightweightauth-infra`](https://github.com/mikeappsec/lightweightauth-infra).
> Keeping infrastructure code separate from the application repo:
> - Prevents accidental deploys when only app code changes.
> - Allows different access controls (fewer people can `terraform apply`).
> - Lets the app repo's CI/CD stay fast — no Terraform plan/apply in every PR.

### 10.1 `lightweightauth-infra` Repository Structure

```
lightweightauth-infra/
  terraform/
    oci/
      main.tf            # OCI compute, VCN, LB, DNS
      k3s.tf             # K3s installation via cloud-init
      helm.tf            # Helm releases (ArgoCD, cert-manager, ingress)
      variables.tf       # Inputs
      outputs.tf         # Endpoints, kubeconfig path
      versions.tf        # Provider constraints
      cloud-init.yaml    # K3s + ArgoCD bootstrap script
      README.md
  argocd/
    apps/
      app-of-apps.yaml          # Root Application — manages everything below
      lwauth-controlplane.yaml  # Application for the CP Helm release
    values/
      oci-free/
        lwauth-controlplane.yaml  # OCI-specific values overlay (defaultImage, etc.)
  README.md
```

**Separation of concerns:**
- `lightweightauth` (app repo) — Helm charts (`deploy/helm/`), Go source, UI.
  ArgoCD watches this repo for chart changes and auto-deploys.
- `lightweightauth-infra` (IaC repo) — Terraform, ArgoCD Application manifests,
  environment-specific values overrides.
  Operators push here to change infrastructure or promote a new image tag.

### 10.2 Key Resources

```hcl
# Compute (Always Free ARM)
resource "oci_core_instance" "k3s" {
  shape = "VM.Standard.A1.Flex"
  shape_config {
    ocpus         = 4
    memory_in_gbs = 24
  }
  source_details {
    source_type = "image"
    source_id   = data.oci_core_images.oracle_linux_9_arm.images[0].id
  }
  metadata = {
    user_data = base64encode(templatefile("cloud-init.yaml", {
      k3s_token  = random_password.k3s_token.result
      domain     = var.domain
    }))
  }
}

# Load Balancer (Always Free)
resource "oci_network_load_balancer_network_load_balancer" "ingress" {
  display_name                 = "lwauth-ingress"
  is_preserve_source_destination = false
  subnet_id                    = oci_core_subnet.public.id
  is_private                   = false
  # Free tier: 1 flexible LB
}

# DNS Zone (Free)
resource "oci_dns_zone" "lwauth" {
  compartment_id = var.compartment_id
  name           = var.domain
  zone_type      = "PRIMARY"
}

# Wildcard DNS record
resource "oci_dns_rrset" "wildcard" {
  zone_name_or_id = oci_dns_zone.lwauth.id
  domain          = "*.${var.domain}"
  rtype           = "A"
  items {
    domain = "*.${var.domain}"
    rdata  = oci_core_instance.k3s.public_ip
    rtype  = "A"
    ttl    = 300
  }
}
```

### 10.3 Cloud-Init (K3s Bootstrap)

The cloud-init script only bootstraps the minimum to get ArgoCD running.
All further installs (cert-manager, ingress, lwauth-CP) are then driven
by ArgoCD from `lightweightauth-infra` — so the VM never needs re-imaging
to change what's deployed.

```yaml
#cloud-config
package_update: true
packages:
  - curl
  - jq

runcmd:
  # Install K3s (ARM64) — disable built-in traefik, we use ingress-nginx
  - curl -sfL https://get.k3s.io | INSTALL_K3S_EXEC="server
      --tls-san ${public_ip}
      --tls-san ${domain}
      --disable traefik
      --write-kubeconfig-mode 644" sh -

  # Wait for K3s to be ready
  - until kubectl get nodes; do sleep 5; done

  # Install Helm
  - curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash

  # Install ArgoCD — everything else is deployed by ArgoCD from the infra repo
  - kubectl create namespace argocd
  - kubectl apply -n argocd -f
      https://raw.githubusercontent.com/argoproj/argo-cd/stable/manifests/install.yaml
  - until kubectl -n argocd get deployment argocd-server -o jsonpath='{.status.readyReplicas}'
      | grep -q '^1$'; do sleep 5; done

  # Register the lightweightauth-infra repo (SSH or HTTPS)
  - kubectl -n argocd create secret generic infra-repo
      --from-literal=type=git
      --from-literal=url=https://github.com/mikeappsec/lightweightauth-infra
      --from-literal=password=${github_token}
      --from-literal=username=x-token-auth
  - kubectl -n argocd label secret infra-repo argocd.argoproj.io/secret-type=repository

  # Bootstrap: apply the App-of-Apps — ArgoCD takes it from here
  - kubectl apply -f https://raw.githubusercontent.com/mikeappsec/lightweightauth-infra/main/argocd/apps/app-of-apps.yaml
```

### 10.4 Deployment Commands (unchanged)

```bash
# One-time setup
cd lightweightauth-infra/terraform/oci
terraform init

# Deploy everything (provisions VM, runs cloud-init, ArgoCD bootstraps the rest)
terraform apply \
  -var="compartment_id=ocid1.compartment.oc1..xxx" \
  -var="domain=lwauth.example.com" \
  -var="admin_email=admin@example.com" \
  -var="ssh_public_key=$(cat ~/.ssh/id_rsa.pub)" \
  -var="github_token=$GITHUB_TOKEN"

# Outputs
# control_plane_url = "https://lwauth.example.com"
# argocd_url        = "https://argocd.lwauth.example.com"
# kubeconfig_cmd    = "ssh opc@<ip> 'cat /etc/rancher/k3s/k3s.yaml'"
```

### 10.5 ArgoCD Integration

**GitOps flow:** After `terraform apply`, every subsequent change is
driven by a git push — no `kubectl apply` or `helm upgrade` by hand.

```
 Developer pushes new image tag to app repo
     │
     ▼
 lightweightauth (app repo)
   deploy/helm/lightweightauth-controlplane/Chart.yaml ← bumped appVersion
     │
     ▼  ArgoCD watches this repo (auto-sync, 3 min poll or webhook)
 ArgoCD detects drift → runs helm upgrade in cluster
     │
     ▼
 lwauth-controlplane pod rolling-restarted with new image
```

**App-of-Apps pattern** (`argocd/apps/app-of-apps.yaml`):

```yaml
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: lwauth-infra
  namespace: argocd
spec:
  project: default
  source:
    repoURL: https://github.com/mikeappsec/lightweightauth-infra
    targetRevision: HEAD
    path: argocd/apps          # directory of Application manifests
  destination:
    server: https://kubernetes.default.svc
    namespace: argocd
  syncPolicy:
    automated:
      prune: true
      selfHeal: true
```

**Control-plane Application** (`argocd/apps/lwauth-controlplane.yaml`):

```yaml
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: lwauth-controlplane
  namespace: argocd
spec:
  project: default
  sources:
    # Helm chart from the app repo
    - repoURL: https://github.com/mikeappsec/lightweightauth
      targetRevision: HEAD
      path: deploy/helm/lightweightauth-controlplane
    # Environment-specific values from the infra repo
    - repoURL: https://github.com/mikeappsec/lightweightauth-infra
      targetRevision: HEAD
      ref: values
  destination:
    server: https://kubernetes.default.svc
    namespace: lwauth-system
  syncPolicy:
    automated:
      prune: true
      selfHeal: true
    syncOptions:
      - CreateNamespace=true
```

**OCI-specific values override** (`argocd/values/oci-free/lwauth-controlplane.yaml`):

```yaml
# Pinned image — never use latest in production (see §14.3 I-1)
defaultImage: "ghcr.io/mikeappsec/lightweightauth:v1.2.0"
image:
  tag: "v1.2.0"
  pullPolicy: IfNotPresent

clusterName: oci-free
leaderElection:
  enabled: false   # single-replica on free tier

service:
  type: ClusterIP  # exposed via ingress-nginx, not NodePort
```

**Promoting a new release:**
1. Tag and push image `v1.3.0` to GHCR (done by CI).
2. Edit `argocd/values/oci-free/lwauth-controlplane.yaml` — bump `defaultImage` and `image.tag`.
3. `git commit && git push` to `lightweightauth-infra`.
4. ArgoCD detects the change within 3 minutes (or immediately via webhook) and
   rolls out the new pod. Zero `kubectl` commands required.

**Data-plane nodes (dynamic provisioning):**

Nodes created via the UI wizard are still provisioned imperatively by the CP
(Deployment + Service + ConfigMap via the Kubernetes API). They are excluded
from ArgoCD management via the annotation `argocd.argoproj.io/managed-by-cluster-argocd: false`
added by the provisioner so ArgoCD doesn't try to reconcile or prune them.
A future GitOps mode (Phase D) would have the CP commit an ArgoCD `Application`
manifest to `lightweightauth-infra` per node, making wizard-created nodes
full GitOps citizens.



---

## 11. Production Readiness Checklist

### 11.1 Security

- [ ] TLS everywhere (Let's Encrypt wildcard via cert-manager)
- [ ] Control plane API gated by admin JWT (existing C3 auth)
- [ ] Node-to-node mTLS (SPIFFE, per node-cluster-auth.md)
- [ ] OCI Security List: only 80, 443, 6443 (K8s API, optional) inbound
- [ ] OCI NSG: restrict K8s API to operator IPs only
- [ ] K3s secrets encryption at rest (`--secrets-encryption`)
- [ ] Non-root containers, read-only rootfs (existing Dockerfile)
- [ ] NetworkPolicy between namespaces
- [ ] GHCR image signing (cosign, existing CI)
- [ ] Rate limiting on control plane API

### 11.2 Reliability

- [ ] K3s auto-restart via systemd
- [ ] Control plane PDB (when replicas > 1)
- [ ] Data plane PDB per instance
- [ ] Liveness/readiness probes (existing)
- [ ] Automated etcd snapshots (K3s built-in, daily)
- [ ] OCI boot volume backup (weekly, free tier allows 5 backups)

### 11.3 Observability

- [ ] Prometheus + Grafana (optional, ~256 MB overhead)
- [ ] lwauth metrics scraped (`lwauth_decisions_total`, etc.)
- [ ] Control plane metrics (instance count, reconcile latency)
- [ ] Alert rules: unhealthy instance, high deny rate, cert expiry
- [ ] Structured audit logs to stdout (existing slog)

### 11.4 Operations

- [ ] `lwauthctl` CLI for emergency operations without UI
- [ ] Terraform state in OCI Object Storage (remote backend)
- [ ] Runbook: VM recovery (re-apply Terraform, K3s auto-restores from etcd)
- [ ] Runbook: certificate rotation (cert-manager auto-renews)
- [ ] Runbook: lwauth upgrade (Helm upgrade with rolling strategy)

---

## 12. Delivery Phases

### Phase A: Module-Aware Create Form (UI + API)

| # | Task | Deliverable |
|---|------|-------------|
| A.1 | Module catalogue API (`GET /modules`) | `internal/controlplane/api/modules.go` |
| A.2 | Form → Helm values generator | `internal/controlplane/provisioner/values.go` |
| A.3 | Config validation endpoint | Extend `POST /instances/create` with structured validation |
| A.4 | UI: Multi-step create wizard | `ui/console/src/pages/CreateInstance.tsx` (5-tab form) |
| A.5 | UI: Module presets | Preset definitions + one-click apply |
| A.6 | UI: YAML/Helm preview panel | Preview modal with syntax highlighting |
| A.7 | E2E test | Create instance via form → verify generated config is valid |

### Phase B: Endpoint Display + Quick Test

| # | Task | Deliverable |
|---|------|-------------|
| B.1 | Extend `LwauthInstanceStatus` with `NodeEndpoints` | CRD schema update |
| B.2 | Reconciler: compute + write endpoints on status | Controller update |
| B.3 | Endpoints API (`GET /instances/{c}/{n}/endpoints`) | API handler |
| B.4 | UI: Endpoints card on instance detail | `InstanceDetail.tsx` update |
| B.5 | UI: Envoy config snippet generator | Template-based, copy-to-clipboard |
| B.6 | Quick Test API (`POST /instances/{c}/{n}/test`) | Proxy to admin/explain |
| B.7 | UI: Quick Test panel | `InstanceDetail.tsx` — inline test form |

### Phase C: OCI Free-Tier Terraform Module

**C.0 — Provisioner prerequisites** (complete and merge before starting C.1; these
bugs were identified during local kind deployment — see §14 for detail):

| # | Task | Deliverable | Issue |
|---|------|-------------|-------|
| C.0.1 | Fix `rbac` config generation: emit `allow: [roles]` not `permissions: {...}` | `internal/controlplane/provisioner/values.go` | §14.1 P-1 |
| C.0.2 | Fix `apikey` config generation: emit `static:` block for inline keys | `internal/controlplane/provisioner/values.go` | §14.1 P-2 |
| C.0.3 | Provisioner: set `scheme: HTTPS` on liveness/readiness probes when TLS is configured | `internal/controlplane/api/server.go` | §14.1 P-4 |
| C.0.4 | CP watcher: use `https://` admin URL when node Service has a TLS annotation | `internal/controlplane/discovery/kubernetes.go` | §14.4 T-1 |
| C.0.5 | UI: validate JWKS URL reachability (HTTP HEAD check) before submitting create form | `ui/console/src/pages/CreateInstance.tsx` | §14.4 T-3 |
| C.0.6 | Console login: single preconfigured admin (bcrypt hash), HttpOnly cookie session, UI gate | `internal/controlplane/auth/session.go`, `ui/console/src/auth/*`, `pages/Login.tsx` | §15 |
| C.0.7 | Node delete: full teardown of CP-owned Deployment/Service/ConfigMap/Secret (was registry-only) | `internal/controlplane/api/server.go` (`handleDeleteInstance`) | §15 |

**C.1–C.8 — IaC repo + OCI infrastructure + ArgoCD:**

| # | Task | Deliverable |
|---|------|-------------|
| C.1 | Create `lightweightauth-infra` repo; move Terraform module from `deploy/terraform/oci/` | `lightweightauth-infra/terraform/oci/` |
| C.2 | Cloud-init: K3s + ArgoCD bootstrap only (no direct Helm installs) | `lightweightauth-infra/terraform/oci/cloud-init.yaml` |
| C.3 | Terraform: provision OCI compute, VCN, LB, DNS; install ArgoCD via cloud-init | `main.tf`, `k3s.tf`, `helm.tf` |
| C.4 | ArgoCD App-of-Apps manifest + CP Application manifest | `lightweightauth-infra/argocd/apps/` |
| C.5 | OCI-specific Helm values overlay (pinned image, clusterName, etc.) | `lightweightauth-infra/argocd/values/oci-free/` |
| C.6 | DNS + TLS automation (cert-manager ClusterIssuer, wildcard cert via OCI DNS-01) | `main.tf` |
| C.7 | Annotate provisioner-created Deployments/Services with `argocd.argoproj.io/managed-by-cluster-argocd: false` so ArgoCD ignores dynamic nodes | `internal/controlplane/api/server.go` |
| C.8 | Documentation + validation — test matrix must cover all items in §14.5; verify ArgoCD auto-syncs after a CP image bump | `lightweightauth-infra/README.md` |

**C.9–C.11 — CI/CD + login secret + verification (see [oci-phase-c-deploy.md](../operations/oci-phase-c-deploy.md)):**

| # | Task | Deliverable |
|---|------|-------------|
| C.9 | GitHub Actions Terraform pipeline in the private IaC repo: OCI creds from repo secrets, `plan` on PR, `apply` behind a **manual-approval GitHub Environment** (cost-safe gate) | `lightweightauth-infra/.github/workflows/terraform.yml` |
| C.10 | Console admin login Secret: generate bcrypt hash, store as GitHub secret → k8s Secret `lwauth-console-auth`, mount into CP (`CP_AUTH_ENABLED`, `CP_AUTH_USERNAME`, `CP_AUTH_PASSWORD_HASH_FILE`) | `lightweightauth-infra/argocd/values/oci-free/values.yaml` |
| C.11 | Whole-stack verification script/checklist run after `apply` completes (cluster + CP + ArgoCD + TLS + login + node create/delete) | `scripts/verify-phase-c.sh` |

### Phase D: Polish + Production Hardening

| # | Task | Deliverable |
|---|------|-------------|
| D.1 | Security hardening (NSG, secrets encryption) | Terraform + K3s config |
| D.2 | Automated backups (etcd + boot volume) | Cron + Terraform |
| D.3 | Monitoring stack (Prometheus + Grafana) | Optional Helm values |
| D.4 | Operational runbooks | `docs/operations/oci-*.md` |
| D.5 | Load testing | Verify capacity on free tier (target: 500 RPS) |

---

## 13. Security Considerations

### 13.1 Form Input Validation

All form inputs pass through `internal/config.Compile()` before being
written to a `LwauthInstance` CR. This ensures:

- No arbitrary code execution via OPA/CEL fields (sandboxed evaluators).
- JWKS URLs validated (HTTPS required in production mode).
- Secret references validated (must point to existing K8s Secrets or Vault
  paths, never inline plaintext in production).

### 13.2 Control Plane API Security

- **Console login (implemented — see §15):** a single preconfigured admin
  credential gates the UI. The password is verified against a **bcrypt hash**
  (never stored in plaintext) supplied via a Kubernetes Secret. Successful
  login mints an opaque server-side session referenced by an **HttpOnly,
  Secure, SameSite=Strict cookie**. All `/v1/controlplane/*` data endpoints
  (except `/auth/*`) return `401` without a valid session.
- The existing bearer-token / service-account RBAC middleware
  (`CP_RBAC_ENABLED`) remains available for machine-to-machine callers and
  composes with the cookie session layer.
- Rate limiting on `POST /instances/create` (prevent resource exhaustion).
- Audit log entry for every instance create/delete/config-push.

### 13.3 OCI-Specific

- Terraform state contains sensitive values → encrypted OCI Object Storage
  with customer-managed key (or Terraform Cloud).
- SSH key rotation: recommend ed25519 keys, rotate quarterly.
- OCI IAM: least-privilege policy for the Terraform service principal.
- K3s token: generated randomly, stored as Terraform sensitive output.

### 13.4 Ingress Security

- HSTS enabled on all responses.
- gRPC endpoints: TLS passthrough mode (no decryption at ingress) for
  nodes that require end-to-end encryption.
- Control plane UI: Content-Security-Policy header (already in embed.go).
- Public gRPC endpoints require client authentication (mTLS or bearer
  token) — the lwauth pipeline itself enforces this.

---

## 14. Lessons Learned: Local kind Deployment

The following issues were found running the full stack on a local kind cluster
(`kind-lwauth`, K8s v1.35.0, Cilium CNI, no kube-proxy). They are recorded
here so Phase C does not repeat them. Each item has a status and the specific
Phase C action required.

### 14.1 Provisioner Bugs

These are bugs in `GenerateAuthConfig()` / `handleCreateInstance` that cause
silently-wrong deployments — the pod starts, but auth doesn't work as
configured. All must be fixed before Phase C validation (§12 C.0).

| ID | Issue | Root Cause | Status |
|----|-------|------------|--------|
| P-1 | **`rbac` config schema** — all requests denied after wizard create | Provisioner rendered `roles: { admin: { permissions: [...] } }` but the `rbac` module reads a flat `allow: [role_names]` list. The `permissions` key is silently ignored. | ⚠️ Fix in C.0.1 |
| P-2 | **`apikey` inline config schema** — keys not loaded | Wizard sends `entries`/`backend` fields in generic map passthrough, but the `apikey` module expects `static:` for plaintext inline keys. Pod starts with 0 keys; every request returns 401. | ⚠️ Fix in C.0.2 |
| P-3 | **Generated config discarded** — pod uses embedded example config | `handleCreateInstance` called `GenerateAuthConfig()` then never wrote it anywhere. The pod started with the binary's embedded stub (`corp-jwt`, `idp.example.com`). | ✅ Fixed — ConfigMap created, volume-mounted, `--config` arg added |
| P-4 | **HTTP probes with TLS** — CrashLoopBackOff on TLS-enabled nodes | Provisioner always creates `scheme: HTTP` probes. When `--tls-cert`/`--tls-key` are set, Kubernetes kubelet sends a plain HTTP request to an HTTPS listener; the binary logs "client sent an HTTP request to an HTTPS server" and the probe fails. | ⚠️ Fix in C.0.3 |

**P-1 fix detail:** Replace the form's `roles: { name: { permissions } }` UI
concept with `allow: [role_names]` in `GenerateAuthConfig()`. The
provisioner should extract the role names from the form's role map and emit:

```yaml
config:
  rolesFrom: "claim:roles"
  allow:
    - admin
    - viewer
```

**P-2 fix detail:** When `apikey` identifier config contains an inline keys
object (from the wizard's "Static Keys" input), emit:

```yaml
config:
  headerName: X-API-Key
  static:
    <key-value>:
      subject: <subject>
      roles: [<role>]
```

Not `entries:` or `backend: inline`.

### 14.2 RBAC / Kubernetes Permissions

| ID | Issue | Root Cause | Status |
|----|-------|------------|--------|
| R-1 | **CP cannot create ConfigMaps → 500 on every node create** | The CP ClusterRole listed `services`, `serviceaccounts`, `endpoints` but not `configmaps`. Every `POST /instances/create` with a generated config returned HTTP 500 from the Kubernetes API. | ✅ Fixed — `configmaps` added to ClusterRole |
| R-2 | **Watcher reports wrong `adminUrl` port** | K8s watcher iterated Service ports and preferred the `admin` named port (8081). The binary only listens on `http` (8080) and `grpc` (9001). All CP health checks to auto-discovered instances timed out. | ✅ Fixed — watcher preference order: `http` > `admin` > default 8080 |

**Phase C action for R-1:** Ensure the Terraform `helm.tf` deploys the CP chart
version that includes `configmaps` in the ClusterRole. Verify with:
```sh
kubectl get clusterrole lwauth-controlplane-... -o yaml | grep configmaps
```

### 14.3 Image Resolution

| ID | Issue | Root Cause | Status |
|----|-------|------------|--------|
| I-1 | **Provisioned pods use wrong image → ImagePullBackOff** | Helm chart set `CP_DEFAULT_IMAGE` env var; `main.go` never read it. `resolveImage()` fell through to the hardcoded `ghcr.io/mikeappsec/lightweightauth:latest` default regardless of the Helm value. | ✅ Fixed — `DefaultImage` wired through `config` → `NewServer` → `resolveImage` |

**Phase C action for I-1:** In `helm.tf`, always set `defaultImage` explicitly
to a pinned, published, signed tag. Never rely on the `latest` tag in
production — an image that doesn't exist in the registry surfaces as
`ImagePullBackOff`, which is hard to distinguish from a registry outage.

```hcl
set {
  name  = "defaultImage"
  value = "ghcr.io/mikeappsec/lightweightauth:v1.2.0"
}
```

### 14.4 TLS

| ID | Issue | Root Cause | Status |
|----|-------|------------|--------|
| T-1 | **CP watcher sends plain HTTP to HTTPS nodes** | The watcher always constructs `http://` admin URLs. Nodes serving HTTPS respond with a TLS handshake error, so the CP marks them unhealthy indefinitely. | ⚠️ Fix in C.0.4 |
| T-2 | **Self-signed cert: probe scheme must be HTTPS** | When `--tls-cert`/`--tls-key` are set, Kubernetes kubelet's HTTP probe hits an HTTPS port → handshake error → pod is killed. Must set `scheme: HTTPS` on both liveness and readiness probes. | ⚠️ Partially fixed (manual patch); provisioner not yet updated — fix in C.0.3 |
| T-3 | **JWT node crashes on example JWKS URL** | The wizard pre-fills `https://auth.example.com/.well-known/jwks.json`. On startup the binary does a blocking JWKS fetch; DNS fails → process exits. The operator doesn't realise the URL placeholder is live-fetched. | ⚠️ Fix in C.0.5 |

**T-1 fix detail:** The watcher should inspect the node's Service or Deployment
annotations for a TLS indicator (e.g., `lwauth.io/tls: "true"` set by the
provisioner) and build `https://` admin URLs accordingly. Alternatively, the
provisioner can annotate the Service when `--tls-cert` is set.

**T-3 fix detail:** Two changes required:
1. UI: before submitting the create form, send an HTTP HEAD to the JWKS URL
   from the browser (or via a CP proxy endpoint) and surface an error if it
   times out or returns non-2xx.
2. Binary (longer term): fetch JWKS lazily on first request rather than at
   startup, so a temporarily unreachable IdP doesn't crash the pod.

### 14.5 Phase C Pre-Deployment Checklist

Run through this list before `terraform apply`. These are the items that
caused silent failures in local deployment.

**Provisioner (code must be merged):**
- [ ] `rbac` authorizer: provisioner emits `allow: [role_names]`, not `permissions`
- [ ] `apikey` identifier: provisioner emits `static:` block for inline keys, not `entries:`
- [ ] Provisioner sets `scheme: HTTPS` on probes for TLS-enabled nodes
- [ ] CP watcher uses `https://` admin URL when node is TLS-enabled

**Helm / Terraform values:**
- [ ] `defaultImage` in `helm.tf` is a pinned, published image tag (not `""` or `latest`)
- [ ] CP chart version includes `configmaps` in the ClusterRole; verified post-deploy
- [ ] cert-manager installed and `letsencrypt-prod` ClusterIssuer is `Ready` before first node create
- [ ] Wildcard DNS (`*.lwauth.example.com`) resolves to the OCI LB IP before cert issuance

**Validation test matrix for C.6:**

| Test | Expected outcome |
|------|-----------------|
| Create JWT node with real JWKS URL | Pod Running, CP shows Healthy, `/healthz` returns 200 |
| Create API Key node with inline static keys | Pod Running, `POST /v1/authorize` with valid key returns 200 with correct subject |
| Create API Key node with TLS enabled | Pod Running (HTTPS probes pass), `curl -k https://<node>/v1/authorize` returns 200 |
| Submit create form with example.com JWKS URL | UI shows validation error before submit |
| CP health check on TLS node | CP UI shows node as Healthy (watcher uses https://) |
| RBAC: alice (admin) sends request | `allow: true`, `subject: alice` |
| RBAC: invalid key | 401 unauthenticated |
| CP service account creates ConfigMap | No 500 errors in CP logs during node create |

---

## 15. Console Login & Node Lifecycle

These capabilities were added before Phase C so the production console is gated
and provisioned nodes can be cleanly removed.

### 15.1 Console Login (single preconfigured admin)

**Model.** One administrator account gates the entire console. There is no
self-service registration and no in-app password change — rotation is done by
updating the secret and redeploying. The control plane runs as a single replica,
so sessions are stored in memory.

**Backend** — `internal/controlplane/auth/session.go` (`auth.Manager`):

- `POST /v1/controlplane/auth/login` — validates `{username,password}`. The
  password is checked with `bcrypt.CompareHashAndPassword`; the username with a
  constant-time compare. bcrypt runs even on username mismatch to avoid timing
  based user enumeration. On success a 32-byte random token is stored server-side
  and returned as an **HttpOnly, Secure, SameSite=Strict** cookie
  (`lwauth_session`).
- `POST /v1/controlplane/auth/logout` — deletes the session and clears the cookie.
- `GET  /v1/controlplane/auth/session` — reports `{authenticated,user,authEnabled}`;
  never returns 401 so the SPA can probe login state on load.
- `Manager.Middleware` — enforces a valid session on every `/v1/controlplane/*`
  path except `/auth/*`; returns `401` otherwise. Static console assets and
  `/healthz` are always served (the SPA renders its own login screen).

**Configuration (env on the CP):**

| Variable | Default | Purpose |
|----------|---------|---------|
| `CP_AUTH_ENABLED` | `false` | Turn login enforcement on. Leave `false` for local dev. |
| `CP_AUTH_USERNAME` | `admin` | Administrator account name. |
| `CP_AUTH_PASSWORD_HASH` | — | bcrypt hash of the password (inline). |
| `CP_AUTH_PASSWORD_HASH_FILE` | — | Path to a file with the bcrypt hash (preferred; mount from Secret). |
| `CP_AUTH_COOKIE_SECURE` | `true` | Set `false` only for plain-HTTP local testing. |
| `CP_AUTH_SESSION_TTL` | `12h` | Session lifetime (Go duration). |

The bcrypt hash originates as a **GitHub secret** in the private IaC repo, is
materialised into a Kubernetes Secret (`lwauth-console-auth`) by the deploy
pipeline, and mounted into the CP via `CP_AUTH_PASSWORD_HASH_FILE`. Generate it
with any bcrypt tool, e.g. `htpasswd -bnBC 12 "" '<password>' | tr -d ':\n'`.

**Frontend** — `ui/console/src/auth/`:

- `AuthGate.tsx` wraps the whole app; on load it calls `getSession()`. While the
  probe is in flight it shows a loader; if `authEnabled && !authenticated` it
  renders `pages/Login.tsx`; otherwise it renders the console.
- `pages/Login.tsx` posts credentials and, on success, updates the shared
  `auth/store.ts` session signal.
- The API client (`api/client.ts`) sends `credentials: "include"` and, on any
  `401`, dispatches a `lwauth:unauthenticated` event that returns the user to the
  login screen. The sidebar footer shows the current user and a **Sign out** button.

When `CP_AUTH_ENABLED=false`, `/auth/session` reports `authenticated=true`, so
the developer console renders directly with no login screen.

### 15.2 Node Deletion — full teardown

`DELETE /v1/controlplane/instances/{cluster}/{name}` previously only removed the
in-memory registry entry, leaving the Deployment/Service/ConfigMap running in the
cluster. It now performs a full teardown (`handleDeleteInstance`):

1. Look up the instance to resolve its namespace (defaults to `lwauth-system`).
2. For **CP-provisioned** (auto-discovered) nodes, `DeleteAllOf` each of
   Deployment, Service, ConfigMap, and Secret filtered by the labels the CP
   stamps at create time:
   `app.kubernetes.io/instance=<name>, app.kubernetes.io/managed-by=lwauth-controlplane`.
   Not-found errors are ignored (idempotent).
3. Deregister from the in-memory registry and return `204 No Content`.

**Safety design.** Deletion is scoped by CP-owned labels, so **externally
provided TLS secrets** (shared or cert-manager-managed wildcard certs, which do
not carry these labels) are intentionally preserved — deleting one node never
breaks another node or cert-manager. **Manually registered** external instances
own no cluster resources, so their delete only drops the registry entry.

The UI already calls `deleteInstance` from the Instances page; no UI change was
required beyond the backend behavior.

### 15.3 Whole-stack verification (Phase C)

After `terraform apply` and ArgoCD sync complete, run
[`scripts/verify-phase-c.sh`](https://github.com/mikeappsec/lightweightauth/blob/main/scripts/verify-phase-c.sh) (documented in
[oci-phase-c-deploy.md](../operations/oci-phase-c-deploy.md) step 14). It checks,
in order: node readiness, ArgoCD app health, cert-manager certificate readiness,
CP `/healthz` and login enforcement, and a create→verify→delete round-trip for a
throwaway node. It is read-only except for the throwaway node it creates and then
deletes, and it exits non-zero on the first failure.
