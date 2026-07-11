# UI Interaction — User Stories & Workflows

This document lists every user story and workflow currently available in the LightweightAuth Console UI.

---

## Navigation

The sidebar provides access to all top-level views:

| Nav Item   | Route                          | Purpose                                    |
|------------|--------------------------------|--------------------------------------------|
| Dashboard  | `/`                            | Global overview, KPIs, instance summary    |
| Instances  | `/instances`                   | Manage & view all data-plane instances     |
| Clusters   | `/clusters`                    | Register and manage remote clusters        |
| Routes     | `/routes`                      | Define proxy routes between instances      |
| Mesh       | `/mesh`                        | D3-force graph of service mesh topology    |
| Decisions  | `/decisions`                   | Live tail of authorization decisions       |
| Health     | `/health`                      | Overall system health                      |

---

## 1. Dashboard (`/`)

### User Stories

| # | As a…       | I want to…                                  | So that…                                  |
|---|-------------|---------------------------------------------|-------------------------------------------|
| 1 | Operator    | See total/healthy/unhealthy instance counts | I know the fleet state at a glance        |
| 2 | Operator    | See live decision rate, deny rate, error rate | I can detect anomalies immediately     |
| 3 | Operator    | See cache-hit ratio                         | I know if caching is effective            |
| 4 | Operator    | See a quick table of instances w/ status    | I don't need to leave the dashboard       |

### Workflow

1. Open `/` → Dashboard loads.
2. **KPI cards** (row 1): Total Instances · Healthy · Unhealthy · Decision Rate.
3. **KPI cards** (row 2): Deny Rate · Cache Hit Ratio · Error Rate.
4. **Instances table**: Name | Cluster | Status badge | Source.
5. All data auto-refreshes:
   - Instance/health counters: REST poll every 15 s.
   - Metrics KPIs: WebSocket push every 2 s (`/stream/metrics`).

---

## 2. Instances (`/instances`)

### User Stories

| # | As a…       | I want to…                                      | So that…                                       |
|---|-------------|--------------------------------------------------|------------------------------------------------|
| 1 | Operator    | See all instances across clusters in one table   | I have a unified view of my fleet              |
| 2 | Operator    | **Create a new instance** from scratch in the cluster | A new lwauth pod is deployed and managed by the CP |
| 3 | Operator    | **Link an external instance** by admin URL       | I can federate pre-existing deployments        |
| 4 | Operator    | Click an instance to see its details             | I can drill into health, metrics, config       |
| 5 | Operator    | Remove an instance                               | I can decommission instances I no longer need  |

### Workflow — View Instances

1. Navigate to `/instances`.
2. Table loads with columns: Name | Cluster | Namespace | Status | Config | Replicas | Source | Actions.
3. Each name is a link to `/instances/:cluster/:name`.
4. Data auto-refreshes every 10 s.

### Workflow — Create New Instance (deploys a new pod)

> This creates a `LwauthInstance` CRD which the control-plane reconciler turns into a Deployment + Service + PDB.

1. Click **"Create Instance"** button.
2. Dialog opens with fields:
   - **Name** (required) — becomes the pod/service name.
   - **Namespace** (optional, defaults to `lwauth-system`).
   - **Cluster** — which cluster to deploy into (defaults to `local`).
   - **Replicas** (default 2).
   - **Version / Image** — which container image tag to deploy.
   - **Config** (optional) — inline auth config YAML or reference to an AuthConfig CR.
3. Click **"Create"** → `POST /v1/controlplane/instances/create`
4. Control-plane creates a `LwauthInstance` CR → reconciler deploys the pod.
5. Instance appears in the table with Source = `crd`, Status = Progressing → Ready.

### Workflow — Link External Instance (legacy / federation)

> Useful when you have a pre-existing lwauth deployment not managed by this control plane.

1. Click **"Link External"** button.
2. Dialog opens with fields:
   - **Name** (required).
   - **Cluster** (required).
   - **Admin URL** (required) — the HTTP endpoint the CP will health-check.
3. Click **"Register"** → `POST /v1/controlplane/instances/register`
4. CP adds it to the registry, starts health-checking.
5. Instance appears with Source = `manual`.

### Workflow — Remove Instance

1. Click **"Remove"** button on a row.
2. Confirmation prompt.
3. `DELETE /v1/controlplane/instances/:cluster/:name`
4. If Source = `crd`, the CR is deleted → reconciler removes pod/service.
5. If Source = `manual`, it's just removed from the in-memory registry.

---

## 3. Instance Detail (`/instances/:cluster/:name`)

### User Stories

| # | As a…       | I want to…                                  | So that…                                  |
|---|-------------|---------------------------------------------|-------------------------------------------|
| 1 | Operator    | See full instance metadata                  | I know its URLs, cluster, namespace       |
| 2 | Operator    | See live health status                      | I know if it's serving                    |
| 3 | Operator    | See per-instance sparklines (rate, latency) | I can spot per-instance problems          |
| 4 | Operator    | Navigate to the config editor               | I can push config changes                 |

### Workflow

1. Click instance name in the table (or navigate to `/instances/:cluster/:name`).
2. **Instance Info** panel: Name, Cluster, Namespace, Admin URL, Source, Last Seen.
3. **Health Status** panel: Healthy/Ready badges, Config Version, Replicas, Last Check.
4. **Sparklines** (WebSocket): Decision rate, Latency p50, Latency p99, Cache hit.
5. **"Edit Config"** link → navigates to `/instances/:cluster/:name/config`.

---

## 4. Config Editor (`/instances/:cluster/:name/config`)

### User Stories

| # | As a…       | I want to…                                  | So that…                                  |
|---|-------------|---------------------------------------------|-------------------------------------------|
| 1 | Operator    | View the current live config                | I know what's deployed                    |
| 2 | Operator    | Edit and push a new config version          | I can change auth rules                   |
| 3 | Operator    | See validation errors before pushing        | I don't deploy broken config              |
| 4 | Operator    | View config history                         | I can see who changed what and when       |
| 5 | Operator    | Rollback to a previous version              | I can recover from bad pushes             |

### Workflow — Push Config

1. Navigate to `/instances/:cluster/:name/config`.
2. Textarea loads with current config content (YAML/JSON).
3. Edit the config → live JSON validation runs on change.
4. Add an optional commit comment.
5. Click **"Push"** → `POST /instances/:cluster/:name/config`
6. New version stored; config pushed to the instance.

### Workflow — View History & Rollback

1. Click **"History"** toggle.
2. Version list appears: version number, timestamp, author, comment.
3. Click a version → diff view showing changes.
4. Click **"Rollback to this version"** → `POST /instances/:cluster/:name/config/rollback`
5. Creates a new version with the old content (non-destructive).

---

## 5. Clusters (`/clusters`)

### User Stories

| # | As a…       | I want to…                                  | So that…                                  |
|---|-------------|---------------------------------------------|-------------------------------------------|
| 1 | Operator    | See all registered clusters                 | I know the multi-cluster topology         |
| 2 | Operator    | Add a remote cluster (API server + token)   | I can manage instances across clusters    |
| 3 | Operator    | Remove a cluster                            | I can clean up decommissioned clusters    |

### Workflow — Add Cluster

1. Navigate to `/clusters`.
2. Click **"Add Cluster"**.
3. Dialog with fields: Name, API Server URL, Bearer Token, CA Bundle, Kubeconfig Path/Context.
4. Click **"Add"** → `POST /v1/controlplane/clusters`
5. CP connects to the remote cluster; starts discovering lwauth instances there.
6. Cluster appears in the table with instance count.

### Workflow — Remove Cluster

1. Click **"Remove"** on a cluster row.
2. `DELETE /v1/controlplane/clusters/:name`
3. All instances from that cluster are removed from the registry.

---

## 6. Routes (`/routes`)

### User Stories

| # | As a…       | I want to…                                  | So that…                                  |
|---|-------------|---------------------------------------------|-------------------------------------------|
| 1 | Operator    | View all proxy routes between instances     | I understand the mesh topology            |
| 2 | Operator    | Create a new route (src → target)           | Instances can proxy auth decisions        |
| 3 | Operator    | See route health and latency                | I know if cross-instance links are ok     |
| 4 | Operator    | Delete a route                              | I can remove unwanted proxy paths         |

### Workflow — Create Route

1. Navigate to `/routes`.
2. Click **"Create Route"**.
3. Form expands with fields:
   - Route name.
   - Source: instance + cluster.
   - Target: instance + cluster + optional path prefix.
4. Click **"Create"** → `POST /v1/controlplane/routes`
5. Route appears in the table. CP creates a `ProxyRoute` CRD; reconciler configures the instances.

### Workflow — Delete Route

1. Click **"Delete"** on a route row.
2. `DELETE /v1/controlplane/routes/:name`
3. ProxyRoute CRD deleted; proxy configuration removed from instances.

---

## 7. Service Mesh (`/mesh`)

### User Stories

| # | As a…       | I want to…                                   | So that…                                  |
|---|-------------|----------------------------------------------|-------------------------------------------|
| 1 | Operator    | See a visual graph of instance connectivity  | I understand the mesh at a glance         |
| 2 | Operator    | See which links are healthy vs broken        | I can identify routing failures           |

### Workflow

1. Navigate to `/mesh`.
2. D3-force graph renders:
   - **Nodes** = instances (labelled by name).
   - **Edges** = proxy routes.
   - **Green** edges = healthy; **Red** edges = unhealthy.
3. Graph auto-updates every 5 s as routes change.
4. Legend shows healthy/unhealthy color coding.

---

## 8. Decisions (`/decisions`)

### User Stories

| # | As a…        | I want to…                                   | So that…                                  |
|---|--------------|----------------------------------------------|-------------------------------------------|
| 1 | Operator     | See a live tail of all auth decisions        | I can debug access issues in real-time    |
| 2 | Operator     | Filter by cluster, tenant, or verdict        | I can focus on specific traffic           |
| 3 | Operator     | Pause/resume the stream                      | I can inspect a specific decision         |
| 4 | Security Eng | See denied requests with reasons             | I can investigate policy violations       |

### Workflow

1. Navigate to `/decisions`.
2. **Live** indicator shows green dot; stream connects via WebSocket (`/stream/decisions`).
3. **Filter bar**: Cluster input, Tenant input, Verdict dropdown (All / Allow / Deny).
4. Table shows: Time | Verdict | Method | Path | Subject | Instance | Latency | Reason.
5. Click **"Pause"** → stream disconnects; button changes to **"Resume"**.
6. Counter shows "N shown" of decisions currently buffered (max 500).

---

## Summary of API Endpoints Used by UI

| Method | Endpoint                                          | UI Page           |
|--------|---------------------------------------------------|-------------------|
| GET    | `/v1/controlplane/health`                         | Dashboard         |
| GET    | `/v1/controlplane/instances`                      | Dashboard, Instances |
| GET    | `/v1/controlplane/instances/:cluster/:name`       | InstanceDetail    |
| POST   | `/v1/controlplane/instances/create`               | Instances (Create)|
| POST   | `/v1/controlplane/instances/register`             | Instances (Link)  |
| DELETE | `/v1/controlplane/instances/:cluster/:name`       | Instances         |
| GET    | `/v1/controlplane/clusters`                       | Clusters          |
| POST   | `/v1/controlplane/clusters`                       | Clusters          |
| DELETE | `/v1/controlplane/clusters/:name`                 | Clusters          |
| GET    | `/v1/controlplane/instances/:c/:n/config`         | ConfigEditor      |
| POST   | `/v1/controlplane/instances/:c/:n/config`         | ConfigEditor      |
| GET    | `/v1/controlplane/instances/:c/:n/config/history` | ConfigEditor      |
| POST   | `/v1/controlplane/instances/:c/:n/config/rollback`| ConfigEditor      |
| GET    | `/v1/controlplane/routes`                         | Routes, Mesh      |
| POST   | `/v1/controlplane/routes`                         | Routes            |
| DELETE | `/v1/controlplane/routes/:name`                   | Routes            |
| GET    | `/v1/controlplane/metrics`                        | Dashboard         |
| GET    | `/v1/controlplane/metrics/:cluster/:name`         | InstanceDetail    |
| WS     | `/v1/controlplane/stream/decisions`               | Decisions         |
| WS     | `/v1/controlplane/stream/metrics`                 | Dashboard, InstanceDetail |

---

## Design Decision: "Create Instance" vs "Register Instance"

### Problem

The current "Register Instance" dialog only **links** to an already-running instance by admin URL.  
This is useful for federation but confusing as a primary workflow because:
- The user needs to manually deploy the pod first (Helm, kubectl, etc.)
- Providing an "admin URL" makes no sense if the goal is to spin up a new instance.

### Solution

The control plane already has a `LwauthInstance` CRD + reconciler that:
1. Creates a Deployment (with the lwauth container, probes, resources).
2. Creates a Service (ports 8080, 9001, 8081).
3. Creates a PodDisruptionBudget.
4. Watches for readiness and updates status conditions.

The UI should expose **"Create Instance"** as the primary action, which creates a `LwauthInstance` CR via a new API endpoint. The reconciler handles the actual deployment.

**"Register/Link External"** remains as a secondary option for federating pre-existing instances.

### CRD Spec Fields (exposed in Create dialog)

| Field             | Type     | Default              | Description                         |
|-------------------|----------|----------------------|-------------------------------------|
| `name`            | string   | required             | Instance and deployment name        |
| `namespace`       | string   | `lwauth-system`      | Target namespace for the deployment |
| `cluster`         | string   | `local`              | Which cluster to deploy into        |
| `replicas`        | int      | 2                    | Pod replica count                   |
| `version`         | string   | latest               | Image tag (e.g., `v1.2.0`)         |
| `image`           | string   | —                    | Full image override                 |
| `config.inline`   | YAML     | —                    | Inline auth config spec             |
| `config.ref`      | string   | —                    | Reference to AuthConfig CR name     |
| `networkPolicy`   | bool     | true                 | Create restrictive NetworkPolicy    |
| `tls.enabled`     | bool     | false                | Enable TLS on serving endpoints     |
