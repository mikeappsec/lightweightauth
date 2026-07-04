# MCP Server Design

## Overview

The LightweightAuth MCP (Model Context Protocol) server exposes deployment
platform resources to AI agents in a secure, auditable, and role-bounded way.

AI agents use it to inspect running instances, read logs and metrics, and
(when authorised) create or mutate resources. The MCP server is a thin
adapter over the existing control-plane REST API — it adds no new business
logic, only tooling definitions, server-side authorization enforcement, and
structured audit trails specific to AI-driven access.

### Why a separate MCP server?

The control-plane API is consumed by humans (via the UI) and automation
(CI/CD, lwauthctl). AI agents have different access patterns:

- They issue many fine-grained reads before acting
- They may hallucinate roles or permissions supplied in system prompts
- Their actions must be individually auditable ("which tool call caused this?")
- Blast radius from a compromised or misconfigured agent must be bounded

A dedicated MCP layer enforces these properties without changing the core API.

---

## Architecture

```
AI Agent (Claude, GPT, etc.)
        │
        │  MCP protocol (JSON-RPC over stdio / SSE / HTTP)
        ▼
┌───────────────────────────────────┐
│          MCP Server               │
│                                   │
│  ┌────────────┐  ┌─────────────┐  │
│  │ Tool Layer │  │ Auth Layer  │  │
│  │            │  │             │  │
│  │ • list     │  │ • authn     │  │
│  │ • get      │  │ • authz     │  │
│  │ • create   │  │ • audit     │  │
│  │ • logs     │  │             │  │
│  │ • metrics  │  └──────┬──────┘  │
│  └─────┬──────┘         │         │
│        │                │         │
└────────┼────────────────┼─────────┘
         │                │
         ▼                ▼
  Control Plane API    Audit Sink
  /v1/controlplane/    (structured JSON log / SIEM)
```

### Key invariant

**The MCP server NEVER trusts role or permission information supplied by
the AI client.** All authorization decisions are made server-side based on
the caller's verified token, not on any claim made in a tool call or prompt.

---

## Authentication

Every request to the MCP server must include a credential. Supported methods:

| Method | Header / field | Use case |
|--------|---------------|----------|
| Bearer token | `Authorization: Bearer <token>` | Human-delegated sessions, CI tokens |
| Service account | k8s ServiceAccount token | In-cluster agents |
| mTLS | TLS client certificate | Agent-to-server pod identity (SPIFFE) |

On startup the server validates the credential and resolves it to an
internal identity:

```
Identity {
    Subject:  "ci-agent@example.com"
    Groups:   ["operator"]
    Source:   "bearer"
}
```

The identity is pinned for the lifetime of the session. Roles cannot be
escalated mid-session.

---

## Roles and Permissions

Roles are assigned to identities by the platform administrator (not the
AI agent). Three roles are defined:

### `user`

Least-privilege read access scoped to the caller's own resources.

| Capability | Allowed |
|-----------|---------|
| List own deployments | ✅ |
| Get deployment status | ✅ |
| View non-sensitive logs | ✅ |
| View non-sensitive metrics | ✅ |
| Create resources | ❌ |
| Delete resources | ❌ |
| Access secrets | ❌ |
| Access infrastructure config | ❌ |
| Access other tenants' data | ❌ |

### `operator`

Elevated read access across all deployments, plus safe operational actions.

| Capability | Allowed |
|-----------|---------|
| List all deployments | ✅ |
| Get deployment status | ✅ |
| View logs (all deployments) | ✅ |
| View metrics (all deployments) | ✅ |
| Restart a deployment | ✅ |
| Create resources | ❌ |
| Access secrets | ❌ |
| Modify infrastructure config | ❌ |
| Access administrative reports | ❌ |

### `admin`

Full access including sensitive and destructive operations.

| Capability | Allowed |
|-----------|---------|
| All operator capabilities | ✅ |
| Create resources | ✅ |
| Update resources | ✅ |
| Delete resources | ✅ |
| Access sensitive deployment data | ✅ |
| Access infrastructure config | ✅ |
| Access audit logs | ✅ |
| Manage users | ✅ |

---

## Tool Definitions

Each MCP tool maps to one or more control-plane API calls. Every tool
specifies its minimum required role. The server rejects calls from
under-privileged identities before any downstream call is made.

### Instance / Deployment Tools

#### `list_instances`

List registered lwauth instances, optionally filtered by cluster.

```json
{
  "name": "list_instances",
  "description": "List all registered lwauth instances. Operators and admins see all instances; users see only their own.",
  "inputSchema": {
    "type": "object",
    "properties": {
      "cluster": {
        "type": "string",
        "description": "Filter by cluster name (optional)."
      },
      "namespace": {
        "type": "string",
        "description": "Filter by Kubernetes namespace (optional)."
      }
    }
  },
  "requiredRole": "user"
}
```

#### `get_instance`

Get detailed status for a single instance.

```json
{
  "name": "get_instance",
  "description": "Get the status, health, and metadata of a single lwauth instance.",
  "inputSchema": {
    "type": "object",
    "required": ["cluster", "name"],
    "properties": {
      "cluster": { "type": "string" },
      "name":    { "type": "string" }
    }
  },
  "requiredRole": "user"
}
```

#### `create_instance`

Deploy a new lwauth instance into the cluster.

```json
{
  "name": "create_instance",
  "description": "Create and deploy a new lwauth instance. Requires admin role.",
  "inputSchema": {
    "type": "object",
    "required": ["name", "namespace"],
    "properties": {
      "name":      { "type": "string", "description": "Instance name (DNS label)." },
      "namespace": { "type": "string", "description": "Target Kubernetes namespace." },
      "cluster":   { "type": "string", "description": "Target cluster (default: local)." },
      "replicas":  { "type": "integer", "minimum": 1, "maximum": 10 },
      "version":   { "type": "string", "description": "Image tag / version." },
      "image":     { "type": "string", "description": "Override default container image." }
    }
  },
  "requiredRole": "admin"
}
```

#### `delete_instance`

Remove an instance and its associated Kubernetes resources.

```json
{
  "name": "delete_instance",
  "description": "Delete a deployed lwauth instance. Requires admin role. DESTRUCTIVE.",
  "inputSchema": {
    "type": "object",
    "required": ["cluster", "name"],
    "properties": {
      "cluster": { "type": "string" },
      "name":    { "type": "string" },
      "confirm": {
        "type": "boolean",
        "description": "Must be true to confirm the deletion. Prevents accidental deletes."
      }
    }
  },
  "requiredRole": "admin"
}
```

#### `restart_instance`

Trigger a rolling restart of an instance's pods.

```json
{
  "name": "restart_instance",
  "description": "Trigger a rolling restart of an lwauth instance deployment.",
  "inputSchema": {
    "type": "object",
    "required": ["cluster", "name"],
    "properties": {
      "cluster": { "type": "string" },
      "name":    { "type": "string" }
    }
  },
  "requiredRole": "operator"
}
```

### Observability Tools

#### `get_logs`

Fetch recent log lines from an instance.

```json
{
  "name": "get_logs",
  "description": "Fetch recent log lines from an lwauth instance. Sensitive log fields (tokens, credentials) are redacted for non-admin callers.",
  "inputSchema": {
    "type": "object",
    "required": ["cluster", "name"],
    "properties": {
      "cluster":    { "type": "string" },
      "name":       { "type": "string" },
      "lines":      { "type": "integer", "default": 100, "maximum": 1000 },
      "since":      { "type": "string", "description": "ISO 8601 timestamp or Go duration (e.g. 15m, 1h)." },
      "filter":     { "type": "string", "description": "Optional log level filter: debug|info|warn|error." }
    }
  },
  "requiredRole": "user"
}
```

Sensitive field redaction:

| Field | `user` / `operator` | `admin` |
|-------|---------------------|---------|
| Log messages | Full | Full |
| `token=`, `secret=` values | `[REDACTED]` | Full value |
| IP addresses | Masked (`10.x.x.x`) | Full |
| Subject/identity | Masked | Full |

#### `get_metrics`

Fetch operational metrics for an instance.

```json
{
  "name": "get_metrics",
  "description": "Fetch operational metrics (request rate, latency, error rate) for an instance.",
  "inputSchema": {
    "type": "object",
    "required": ["cluster", "name"],
    "properties": {
      "cluster":  { "type": "string" },
      "name":     { "type": "string" },
      "window":   { "type": "string", "description": "Time window: 5m, 15m, 1h, 24h (default: 15m)." }
    }
  },
  "requiredRole": "user"
}
```

### Administrative Tools

#### `list_audit_logs`

Retrieve audit log entries for AI-driven and human-driven API actions.

```json
{
  "name": "list_audit_logs",
  "description": "Retrieve audit log entries. Admin only.",
  "inputSchema": {
    "type": "object",
    "properties": {
      "subject":    { "type": "string", "description": "Filter by identity subject." },
      "action":     { "type": "string", "description": "Filter by action (e.g. create_instance)." },
      "since":      { "type": "string" },
      "limit":      { "type": "integer", "default": 50, "maximum": 500 }
    }
  },
  "requiredRole": "admin"
}
```

#### `get_infrastructure_config`

Retrieve the current cluster-level infrastructure configuration.

```json
{
  "name": "get_infrastructure_config",
  "description": "Get infrastructure-level cluster configuration. Admin only. Contains sensitive operational data.",
  "inputSchema": {
    "type": "object",
    "required": ["cluster"],
    "properties": {
      "cluster": { "type": "string" }
    }
  },
  "requiredRole": "admin"
}
```

#### `manage_user`

Create, update, or deactivate a platform user.

```json
{
  "name": "manage_user",
  "description": "Create, update role, or deactivate a platform user. Admin only.",
  "inputSchema": {
    "type": "object",
    "required": ["action", "subject"],
    "properties": {
      "action":  { "type": "string", "enum": ["create", "update_role", "deactivate"] },
      "subject": { "type": "string", "description": "User identifier (email or service account)." },
      "role":    { "type": "string", "enum": ["user", "operator", "admin"] }
    }
  },
  "requiredRole": "admin"
}
```

---

## Authorization Enforcement

Authorization is checked in this order for every tool call:

```
1. Authenticate caller (token → Identity)
        │ fail → 401
2. Validate tool name (is it a known tool?)
        │ fail → 404
3. Check role: caller.role >= tool.requiredRole
        │ fail → 403
4. Check resource scope: user can only access own resources
        │ fail → 403
5. Validate input schema
        │ fail → 400
6. Execute tool
7. Post-execution: redact fields based on role
8. Emit audit record
```

### Scope enforcement for `user` role

A caller with `user` role is further restricted by resource ownership.
Ownership is resolved by matching the caller's `Subject` against:

- `Deployment.metadata.labels["lwauth.io/owner"]`
- The namespace the caller's ServiceAccount belongs to

This prevents users from enumerating or reading other tenants' resources
even when they know the resource names.

---

## Audit Log Format

Every tool execution emits a structured JSON audit record — regardless of
success or failure.

```json
{
  "ts":          "2026-06-01T12:34:56.789Z",
  "event":       "mcp.tool_call",
  "tool":        "create_instance",
  "subject":     "ci-agent@example.com",
  "role":        "admin",
  "source":      "bearer",
  "input":       { "name": "tenant-b", "namespace": "prod" },
  "outcome":     "success",
  "status_code": 200,
  "duration_ms": 142,
  "remote_addr": "10.0.1.5",
  "session_id":  "sess_abc123"
}
```

Sensitive input fields (`image`, user-supplied values) are included in
the audit record at full fidelity for admin accountability. The audit
sink is append-only and separate from the application log.

### Denied access record

```json
{
  "ts":       "2026-06-01T12:35:00.001Z",
  "event":    "mcp.authz_denied",
  "tool":     "create_instance",
  "subject":  "read-only-agent@example.com",
  "role":     "user",
  "reason":   "insufficient_role: requires admin, caller is user",
  "outcome":  "denied"
}
```

---

## Security Properties

### Prompt injection resistance

The MCP server never passes raw AI-supplied strings to shell commands,
template engines, or eval paths. All inputs are:

1. Schema-validated (type, format, length, enum)
2. Passed as structured parameters to the control-plane API
3. Never interpolated into log messages without sanitization

Name and namespace fields are validated against `^[a-z0-9][a-z0-9\-]{0,61}[a-z0-9]$`
before use.

### Destructive operation safeguards

`delete_instance` and `manage_user` (deactivate) require an explicit
`"confirm": true` field. Without it the server returns:

```json
{
  "error": "confirmation_required",
  "message": "Set confirm=true to proceed with deletion of instance 'tenant-b'."
}
```

This prevents an AI agent from accidentally deleting resources after
misunderstanding a user instruction.

### Rate limiting

All MCP sessions are subject to the same rate limiter as the control-plane
API: 100 requests/second per identity, with a burst of 200. AI agents that
generate excessive tool calls are throttled before they can cause disruption.

### No role escalation via tool call

The `manage_user` tool cannot be used to escalate the calling identity's
own role. A check is performed server-side:

```
if input.subject == caller.subject && input.role > caller.role {
    return 403 "cannot escalate own role"
}
```

---

## Implementation Plan

### Phase 1 — Read-only tools (user + operator)

- `list_instances`
- `get_instance`
- `get_logs`
- `get_metrics`

Wire directly to existing control-plane endpoints. Add MCP JSON-RPC
transport (stdio for local development, SSE/HTTP for Kubernetes).

### Phase 2 — Operational tools (operator)

- `restart_instance`
- Scope-enforcement middleware for `user` role

### Phase 3 — Admin tools

- `create_instance`
- `delete_instance`
- `list_audit_logs`
- `get_infrastructure_config`
- `manage_user`
- Dedicated audit sink (separate from application log)

### Phase 4 — SPIRE integration

- Replace bearer tokens with SPIFFE SVIDs for agent identity
- Short-lived tokens (≤1h) issued per session
- Trust domain per cluster; cross-cluster agent access denied by default

---

## File Layout

```
cmd/
  lwauth-mcp/
    main.go               # MCP server entrypoint
internal/
  mcp/
    server.go             # MCP JSON-RPC transport
    tools/
      instances.go        # list_instances, get_instance, create_instance, delete_instance, restart_instance
      observability.go    # get_logs, get_metrics
      admin.go            # list_audit_logs, get_infrastructure_config, manage_user
    auth/
      auth.go             # authn + authz middleware
      scope.go            # resource-scope enforcement for user role
    audit/
      sink.go             # structured audit log emitter
    schema/
      validate.go         # input schema validation + sanitization
```

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `MCP_ADDR` | `:8080` | HTTP listen address |
| `MCP_TRANSPORT` | `http` | `stdio` / `sse` / `http` |
| `MCP_RBAC_ENABLED` | `true` | Disable only for local dev |
| `MCP_AUDIT_PATH` | stdout | Path to write audit NDJSON |
| `MCP_CP_ADDR` | `http://lwauth-cp:8443` | Control plane base URL |
| `MCP_CP_TOKEN` | — | Service token for CP API (admin-scoped) |
| `LWAUTH_SPIRE_ENABLED` | `false` | Use SPIRE for agent identity |
| `LWAUTH_SPIRE_SOCKET_PATH` | — | SPIRE agent socket |
