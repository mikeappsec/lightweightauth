# MCP Enterprise-Managed Authorization Design

## Overview

This document specifies how LightweightAuth acts as the **Resource Authorization
Server** for any deployed MCP server, implementing the
[MCP Enterprise-Managed Authorization](https://github.com/modelcontextprotocol/ext-auth/blob/main/specification/stable/enterprise-managed-authorization.mdx)
specification (an application of
[Identity Assertion JWT Authorization Grant](https://datatracker.ietf.org/doc/draft-ietf-oauth-identity-assertion-authz-grant/),
draft-ietf-oauth-identity-assertion-authz-grant).

**LightweightAuth is not the MCP server.** LightweightAuth is the auth layer
that any MCP server registers with. An operator registers their MCP server
(GitHub MCP, internal tooling server, filesystem server, or the lwauth
control-plane MCP server) via a `MCPServer` CRD, and LightweightAuth provides
the complete enterprise auth infrastructure for it — token issuance, discovery
endpoints, and token validation via the existing ext_authz pipeline.

---

## The Problem LightweightAuth Solves Here

Any MCP server deployed in an enterprise faces the same problem:

> How does an AI agent (Claude, Cursor, Copilot) prove it is acting on behalf of
> a specific employee, under that employee's IdP policies (MFA, conditional
> access, group membership), without an operator manually provisioning a token?

Without this, every agent gets a long-lived static token. Tokens accumulate,
are never rotated, bypass MFA, and cannot be tied to an individual user session.

With this design, the enterprise IdP becomes the choke point. LightweightAuth
handles the protocol complexity; MCP server authors need only:

1. Deploy their MCP server normally.
2. Create a `MCPServer` CR pointing to it.
3. Protect their server's endpoints with lwauth's ext_authz (or validate tokens
   against lwauth's JWKS endpoint directly).

---

## Roles in This Spec

| Spec role | What it is in practice |
|-----------|------------------------|
| **MCP Client** | Any AI agent — Claude, Cursor, Copilot, custom agent |
| **MCP Server** | Any deployed MCP server — could be GitHub MCP, internal tooling, filesystem server, the lwauth control-plane MCP server, or anything else |
| **Resource Authorization Server** | LightweightAuth (`lwauth`) — validates ID-JAG tokens, issues access tokens, serves discovery endpoints |
| **IdP Authorization Server** | Enterprise IdP (Okta, Entra ID, Google Workspace) — referenced via existing `IdentityProvider` CRD |

One lwauth deployment can serve as the Resource Authorization Server for
**multiple** MCP servers simultaneously, each registered as its own `MCPServer` CR.

---

## End-to-End Flow

```
 Enterprise IdP          AI Agent (MCP Client)         LightweightAuth (lwauth)    MCP Server
 (Okta / Entra)                                        Resource Auth Server        (any server)
       │                        │                              │                       │
       │◄─ 1. OIDC login ───────┤                              │                       │
       │── ID Token ───────────►│                              │                       │
       │                        │                              │                       │
       │◄─ 2. Token Exchange ───┤                              │                       │
       │   (ID Token → ID-JAG,  │                              │                       │
       │    aud=lwauth,         │                              │                       │
       │    resource=mcp-server)│                              │                       │
       │── ID-JAG ─────────────►│                              │                       │
       │                        │                              │                       │
       │                        │──── 3. GET /.well-known/ ───►│                       │
       │                        │     oauth-protected-resource  │                       │
       │                        │◄─── {auth_server, scopes} ───│                       │
       │                        │                              │                       │
       │                        │──── 4. POST /oauth2/token ──►│                       │
       │                        │     grant_type=jwt-bearer    │                       │
       │                        │     assertion=<ID-JAG>       │                       │
       │                        │◄─── Access Token ────────────│                       │
       │                        │     (aud=mcp-server,         │                       │
       │                        │      role=operator)          │                       │
       │                        │                              │                       │
       │                        │──── 5. MCP tool calls ──────────────────────────────►│
       │                        │     Authorization: Bearer <token>                    │
       │                        │                              │                       │
       │                        │                   MCP Server validates token via:    │
       │                        │                   Option A: lwauth ext_authz ───────►│
       │                        │                   Option B: lwauth JWKS endpoint     │
       │                        │◄─── tool results ───────────────────────────────────-│
```

Steps 3–4 happen once per token lifetime (cached by the agent). Steps 1–2
re-run when the user's IdP session expires.

---

## New CRD: `MCPServer`

An operator registers any MCP server with LightweightAuth by creating a
`MCPServer` CR. This is the only configuration step required. LightweightAuth
uses it to:

- Populate the RFC 9728 Protected Resource Metadata endpoint for that server
- Validate the `resource` and `aud` claims in incoming ID-JAG tokens
- Map granted OAuth scopes to roles in the issued access token
- Enforce the client allowlist

```go
// api/crd/v1alpha1/mcpserver_types.go

type MCPServer struct {
    metav1.TypeMeta   `json:",inline"`
    metav1.ObjectMeta `json:"metadata,omitempty"`
    Spec              MCPServerSpec   `json:"spec"`
    Status            MCPServerStatus `json:"status,omitempty"`
}

type MCPServerSpec struct {
    // ResourceIdentifier is the canonical URL of the MCP server being
    // registered. Must match the `resource` claim the IdP puts in ID-JAG
    // tokens. Typically the base URL of the MCP server.
    // Example: "https://github-mcp.internal.example.com/"
    // +kubebuilder:validation:Required
    // +kubebuilder:validation:Pattern=`^https://`
    ResourceIdentifier string `json:"resourceIdentifier"`

    // IdentityProviderRef names the IdentityProvider CR whose JWKS is used
    // to verify incoming ID-JAG token signatures.
    // +kubebuilder:validation:Required
    IdentityProviderRef string `json:"identityProviderRef"`

    // ScopeBindings maps OAuth scopes (granted by the IdP) to roles that
    // LightweightAuth embeds in the issued access token.
    // Scopes present in the ID-JAG but absent here are silently dropped.
    // At least one binding must be present.
    // +kubebuilder:validation:MinItems=1
    ScopeBindings []MCPScopeBinding `json:"scopeBindings"`

    // TokenTTL controls how long LightweightAuth's issued access tokens are
    // valid. Should be short — agents refresh automatically.
    // +kubebuilder:default="1h"
    TokenTTL string `json:"tokenTTL,omitempty"`

    // AllowedClients optionally restricts which client_id values are
    // accepted. If empty, any client_id in a valid ID-JAG is accepted
    // (rely on IdP registration instead).
    // +optional
    AllowedClients []string `json:"allowedClients,omitempty"`

    // TokenValidation configures how the registered MCP server validates
    // tokens issued by LightweightAuth.
    TokenValidation MCPTokenValidation `json:"tokenValidation"`
}

type MCPScopeBinding struct {
    // Scope is the OAuth scope string (e.g. "mcp:read").
    // +kubebuilder:validation:Required
    Scope string `json:"scope"`

    // Role is embedded as a claim in the issued access token.
    // The MCP server reads this to enforce its own authorization.
    // +kubebuilder:validation:Required
    Role string `json:"role"`
}

type MCPTokenValidation struct {
    // Mode controls how the MCP server validates tokens.
    // "extauthz" — MCP server uses lwauth as an Envoy ext_authz filter.
    //              LightweightAuth intercepts every request; the MCP server
    //              needs no token validation code at all.
    // "jwks"     — MCP server fetches lwauth's JWKS endpoint and validates
    //              tokens itself. Suitable for servers not behind Envoy.
    // +kubebuilder:validation:Enum=extauthz;jwks
    // +kubebuilder:default="extauthz"
    Mode string `json:"mode"`

    // AuthConfigRef names the AuthConfig to use when validating MCP
    // requests in extauthz mode. If empty, a default AuthConfig is
    // auto-generated from the MCPServer spec by the reconciler.
    // +optional
    AuthConfigRef string `json:"authConfigRef,omitempty"`
}

type MCPServerStatus struct {
    // DiscoveryURL is the RFC 9728 Protected Resource Metadata URL for
    // this MCPServer. Tell AI agents to start here.
    DiscoveryURL string `json:"discoveryURL,omitempty"`

    // TokenEndpointURL is the OAuth 2.0 token endpoint for this MCPServer.
    TokenEndpointURL string `json:"tokenEndpointURL,omitempty"`

    // JWKSEndpointURL is the JWKS endpoint for token validation (jwks mode).
    JWKSEndpointURL string `json:"jwksEndpointURL,omitempty"`

    // SigningKeyExpiry is the expiry of the current RS256 signing key.
    SigningKeyExpiry *metav1.Time `json:"signingKeyExpiry,omitempty"`

    // Conditions follow the standard k8s condition pattern.
    Conditions []metav1.Condition `json:"conditions,omitempty"`
}
```

### Example: registering a generic MCP server

```yaml
apiVersion: lightweightauth.io/v1alpha1
kind: MCPServer
metadata:
  name: github-mcp
  namespace: platform
spec:
  resourceIdentifier: https://github-mcp.internal.example.com/
  identityProviderRef: corp-idp
  tokenTTL: 1h
  allowedClients:
    - cursor-enterprise
    - claude-enterprise
  scopeBindings:
    - { scope: mcp:read,  role: reader }
    - { scope: mcp:write, role: writer }
    - { scope: mcp:admin, role: admin  }
  tokenValidation:
    mode: extauthz
```

### Example: the lwauth control-plane MCP server

The lwauth control-plane's own MCP server is just another `MCPServer` CR.
LightweightAuth treats it identically to any other registration:

```yaml
apiVersion: lightweightauth.io/v1alpha1
kind: MCPServer
metadata:
  name: lwauth-cp-mcp
  namespace: lwauth-control-plane
spec:
  resourceIdentifier: https://mcp.lwauth.internal.example.com/
  identityProviderRef: corp-idp
  tokenTTL: 1h
  scopeBindings:
    - { scope: mcp:read,    role: user     }
    - { scope: mcp:operate, role: operator }
    - { scope: mcp:admin,   role: admin    }
  tokenValidation:
    mode: extauthz
```

---

## LightweightAuth as Resource Authorization Server

### New endpoints on `lwauth`

Added to the existing lwauth HTTP server. Each `MCPServer` registration gets
its own path prefix so multiple MCP servers share one lwauth deployment without
conflict.

| Endpoint | RFC | Description |
|----------|-----|-------------|
| `GET /mcp/{name}/.well-known/oauth-protected-resource` | RFC 9728 | Protected Resource Metadata |
| `GET /mcp/{name}/.well-known/oauth-authorization-server` | RFC 8414 | Auth Server Metadata |
| `POST /mcp/{name}/oauth2/token` | RFC 7523 | Exchange ID-JAG → access token |
| `GET /mcp/{name}/.well-known/jwks.json` | RFC 7517 | JWKS for self-validation (jwks mode) |

The AI agent discovers everything from a single URL an operator publishes:

```
https://lwauth.internal.example.com/mcp/github-mcp/.well-known/oauth-protected-resource
```

#### Protected Resource Metadata (RFC 9728)

```json
{
  "resource": "https://github-mcp.internal.example.com/",
  "authorization_servers": [
    "https://lwauth.internal.example.com/mcp/github-mcp/"
  ],
  "scopes_supported": ["mcp:read", "mcp:write", "mcp:admin"],
  "bearer_methods_supported": ["header"]
}
```

#### Authorization Server Metadata (RFC 8414)

```json
{
  "issuer": "https://lwauth.internal.example.com/mcp/github-mcp/",
  "token_endpoint": "https://lwauth.internal.example.com/mcp/github-mcp/oauth2/token",
  "jwks_uri": "https://lwauth.internal.example.com/mcp/github-mcp/.well-known/jwks.json",
  "grant_types_supported": [
    "urn:ietf:params:oauth:grant-type:jwt-bearer"
  ],
  "authorization_grant_profiles_supported": [
    "urn:ietf:params:oauth:grant-profile:id-jag"
  ],
  "scopes_supported": ["mcp:read", "mcp:write", "mcp:admin"]
}
```

---

## ID-JAG Validation Pipeline

`POST /mcp/{name}/oauth2/token` routes the request through the existing
`pipeline.Evaluate` using a per-MCPServer `AuthConfig` auto-generated by the
reconciler. This reuses the existing JWKS cache, revocation store, and audit
sink — no new infrastructure.

```
POST /mcp/github-mcp/oauth2/token
  assertion=<ID-JAG>
  grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer
        │
        ▼
  pipeline.Evaluate (AuthConfig: _mcpserver-github-mcp-tokenendpoint)
        │
        ├── idjag identifier  (new — pkg/identity/idjag)
        │     1. Parse JWT, check typ = "oauth-id-jag+jwt"
        │     2. Fetch IdP JWKS (cached — same infrastructure as jwt identifier)
        │     3. Verify signature
        │     4. Validate exp / nbf / iat (±5 min clock skew)
        │     5. Validate iss = IdentityProvider.spec.issuerUrl
        │     6. Validate aud = lwauth's issuer URL for this MCPServer name
        │     7. Validate resource claim = MCPServer.spec.resourceIdentifier
        │     8. Validate client_id ∈ allowedClients (if set)
        │     9. Check jti not in revocation.Store; store jti with TTL=exp−now
        │    10. Extract sub, email, client_id, scope → Identity
        │
        ├── cel authorizer
        │     Verify at least one scope maps to a ScopeBinding
        │
        └── jwtissue mutator  (existing — pkg/mutator/jwtissue)
              Issue access token:
                aud  = MCPServer.spec.resourceIdentifier
                iss  = lwauth issuer URL for this MCPServer
                sub  = ID-JAG sub
                role = highest-ranked ScopeBinding matched
                jti  = new UUID
                exp  = now + MCPServer.spec.tokenTTL
              Sign with per-MCPServer RS256 key
```

The `jwtissue` mutator is **already implemented** in
`pkg/mutator/jwtissue/jwtissue.go`. The only new module is `idjag`.

The reconciler auto-generates the `AuthConfig` — operators never write it:

```yaml
# auto-generated — do not edit manually
apiVersion: lightweightauth.io/v1alpha1
kind: AuthConfig
metadata:
  name: _mcpserver-github-mcp-tokenendpoint
  namespace: platform
spec:
  identifiers:
    - name: id-jag
      type: idjag
      config:
        jwksUrl:             https://corp.idp.example/.well-known/jwks.json
        issuer:              https://corp.idp.example
        authServerIssuer:    https://lwauth.internal.example.com/mcp/github-mcp/
        mcpServerResourceId: https://github-mcp.internal.example.com/
        allowedClients:      [cursor-enterprise, claude-enterprise]
  authorizers:
    - name: has-valid-scope
      type: cel
      config:
        expression: >
          identity.claims.scope.split(" ").exists(s,
            s in ["mcp:read", "mcp:write", "mcp:admin"])
  response:
    - name: issue-token
      type: jwt-issue
      config:
        issuer:          https://lwauth.internal.example.com/mcp/github-mcp/
        audience:        https://github-mcp.internal.example.com/
        ttl:             1h
        algorithm:       RS256
        privateKeyFile:  /etc/lwauth/mcp/github-mcp/signing.key
        copyClaims:      [sub, email, client_id]
        extraClaims:
          role: "${scopeToRole(identity.claims.scope)}"
```

---

## Token Validation by the MCP Server

### Option A — `extauthz` mode (recommended)

The MCP server sits behind Envoy. lwauth acts as the ext_authz filter exactly
as it does for any other upstream. The MCP server binary has no token
validation code.

```
AI Agent
  │  Authorization: Bearer <access-token>
  ▼
Envoy (or compatible proxy)
  │  CheckRequest → lwauth ext_authz
  │
  lwauth validates token (jwt identifier):
    - Signature against per-MCPServer JWKS
    - aud = MCPServer.spec.resourceIdentifier
    - exp > now
    - role claim present
  │
  ├─ allow → inject headers, forward to MCP server
  │          X-MCP-Role:    reader
  │          X-MCP-Subject: alice@example.com
  │          X-MCP-Client:  cursor-enterprise
  └─ deny  → 401/403 returned to AI agent
                    │
                    ▼
              MCP server reads X-MCP-Role to enforce tool-level authorization
              (no JWT library needed in the MCP server)
```

Auto-generated `AuthConfig` for ext_authz validation:

```yaml
# auto-generated — do not edit
apiVersion: lightweightauth.io/v1alpha1
kind: AuthConfig
metadata:
  name: _mcpserver-github-mcp-extauthz
  namespace: platform
spec:
  identifiers:
    - name: bearer
      type: jwt
      config:
        jwksUrl:   https://lwauth.internal.example.com/mcp/github-mcp/.well-known/jwks.json
        audiences: [https://github-mcp.internal.example.com/]
  authorizers:
    - name: has-role
      type: rbac
      config:
        rolesFrom: "claim:role"
        allow: ["*"]
  response:
    - name: inject
      type: header-add
      config:
        headers:
          X-MCP-Role:    "${identity.claims.role}"
          X-MCP-Subject: "${identity.subject}"
          X-MCP-Client:  "${identity.claims.client_id}"
```

### Option B — `jwks` mode

For MCP servers that validate tokens natively (Python, Node.js, etc.):

```
GET /mcp/github-mcp/.well-known/jwks.json
→ Returns RS256 public key for this MCPServer

MCP server validates access token:
  - Signature against JWKS
  - aud == its own resource identifier
  - exp > now
  - reads role claim for authorization
```

---

## New Identifier Module: `pkg/identity/idjag`

```go
// Config is the yaml config block for type: idjag
type Config struct {
    // JWKSURL is the IdP's JWKS endpoint for ID-JAG signature verification.
    JWKSURL string `yaml:"jwksUrl"`

    // Issuer is the expected iss claim (enterprise IdP issuer URL).
    Issuer string `yaml:"issuer"`

    // AuthServerIssuer is the expected aud claim — the lwauth issuer URL
    // for this specific MCPServer registration.
    AuthServerIssuer string `yaml:"authServerIssuer"`

    // MCPServerResourceID is the expected resource claim in the ID-JAG.
    MCPServerResourceID string `yaml:"mcpServerResourceId"`

    // AllowedClients, if non-empty, restricts accepted client_id values.
    AllowedClients []string `yaml:"allowedClients,omitempty"`
}

// On success, the returned Identity carries:
//   Subject                  = ID-JAG sub
//   Claims["email"]          = email (if present)
//   Claims["client_id"]      = client_id
//   Claims["scope"]          = granted scopes (space-separated)
//
// Replay prevention uses the existing revocation.Store (Valkey):
//   key: "jti:<jti-value>", TTL: ID-JAG exp − now
```

---

## MCPServer Reconciler

`internal/controlplane/mcpserver_reconciler.go` watches `MCPServer` CRDs and
manages the two auto-generated `AuthConfig` objects and the signing key:

```
Reconcile(MCPServer) {
  1. Ensure per-MCPServer signing key Secret exists
     (cert-manager Certificate, RS256 2048-bit, auto-rotated)

  2. CreateOrUpdate AuthConfig "_mcpserver-<name>-tokenendpoint"
     (idjag identifier + cel authorizer + jwtissue mutator)
     Sync from: MCPServer.spec (identityProviderRef, resourceIdentifier,
                                allowedClients, scopeBindings, tokenTTL)

  3. If tokenValidation.mode == "extauthz" && authConfigRef == "":
       CreateOrUpdate AuthConfig "_mcpserver-<name>-extauthz"
       (jwt identifier + rbac authorizer + header-add mutator)

  4. Update MCPServer.status:
       discoveryURL     = https://<lwauth-host>/mcp/<name>/.well-known/oauth-protected-resource
       tokenEndpointURL = https://<lwauth-host>/mcp/<name>/oauth2/token
       jwksEndpointURL  = https://<lwauth-host>/mcp/<name>/.well-known/jwks.json
       signingKeyExpiry = from cert-manager Certificate status
}

Reconcile(MCPServer — deleted) {
  1. Delete "_mcpserver-<name>-tokenendpoint" AuthConfig
  2. Delete "_mcpserver-<name>-extauthz" AuthConfig (if present)
  3. Delete signing key Certificate CR
}
```

---

## Deployment Topology

```
Kubernetes cluster
│
├── Namespace: platform
│   ├── MCPServer: github-mcp            ← operator registers GitHub MCP
│   ├── MCPServer: internal-docs-mcp     ← operator registers internal tooling
│   │
│   └── lwauth pod
│         Serves:
│           /mcp/github-mcp/...
│           /mcp/internal-docs-mcp/...
│
├── Namespace: github-mcp-ns
│   └── github-mcp Pod (any MCP server implementation)
│         ← protected by Envoy + lwauth ext_authz
│         ← reads X-MCP-Role header, no JWT code needed
│
├── Namespace: docs-ns
│   └── internal-docs-mcp Pod
│         ← uses jwks mode, validates tokens directly
│
└── Namespace: lwauth-control-plane
    ├── MCPServer: lwauth-cp-mcp          ← lwauth's own MCP server, same pattern
    └── lwauth-controlplane Pod
          MCP server endpoint also protected by ext_authz, same as any other
```

---

## Implementation Plan

### Phase 1 — CRD + discovery

| Task | File |
|------|------|
| `MCPServer` CRD type + DeepCopy | `api/crd/v1alpha1/mcpserver_types.go` |
| Register in scheme | `api/crd/v1alpha1/types.go` |
| Discovery handlers (RFC 9728, RFC 8414, JWKS) | `internal/server/mcp_discovery.go` |
| `MCPServer` reconciler (signing key + AuthConfig sync) | `internal/controlplane/mcpserver_reconciler.go` |

### Phase 2 — `idjag` identifier

| Task | File |
|------|------|
| `idjag` identifier + replay prevention via `revocation.Store` | `pkg/identity/idjag/idjag.go` |
| Unit tests (valid, expired, wrong aud, wrong resource, replayed jti, blocked client) | `pkg/identity/idjag/idjag_test.go` |
| Register in identifier factory | `pkg/builtins/identifiers.go` |

### Phase 3 — Token endpoint

| Task | File |
|------|------|
| Token endpoint handler | `internal/server/mcp_token.go` |
| Scope-to-role resolution helper | `internal/server/mcp_scoperole.go` |

### Phase 4 — Integration + tooling

| Task | File |
|------|------|
| E2E test: ID-JAG flow, two MCPServer CRs, both validation modes | `tests/e2e/mcp_enterprise_auth_test.go` |
| `lwauthctl mcp register` (creates MCPServer CR interactively) | `cmd/lwauthctl/mcp.go` |
| `lwauthctl mcp add-client` (appends to allowedClients) | `cmd/lwauthctl/mcp.go` |

---

## Security Considerations

### One signing key per MCPServer

Each registration gets its own RS256 key pair. A compromised key for one MCP
server does not affect any other. Rotation is automatic via cert-manager.

### JTI replay prevention

ID-JAG tokens are single-use. After validation the `jti` is stored in the
existing `revocation.Store` (Valkey) with `TTL = exp − now`. Replays return
`401 invalid_grant`.

### Audience-restricted access tokens

Issued access tokens carry `aud = MCPServer.spec.resourceIdentifier`. A token
issued for `github-mcp` is rejected by `internal-docs-mcp`'s ext_authz check
because the audience does not match — even if both use the same lwauth.

### Scope downgrade is IdP-controlled

The IdP decides at token exchange which scopes to include in the ID-JAG.
LightweightAuth cannot escalate scopes beyond what the IdP granted.

### No IdP visibility into MCP traffic

The IdP participates only in token issuance (steps 1–4). Tool call content,
parameters, and responses never reach the IdP.
