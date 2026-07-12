# Install the LightweightAuth MCP Server with Enterprise MCP Auth

This guide walks through installing the **lwauth control-plane MCP server**
and wiring up **enterprise-managed MCP authorization** so AI agents
(Claude, Cursor, Copilot) authenticate through your IdP instead of using
static tokens.

LightweightAuth plays two roles here:

1. It **is** an MCP server — the control-plane MCP server exposes platform
   tools (`list_instances`, `get_logs`, `restart_instance`, ...).
2. It is the **Resource Authorization Server** for that MCP server — it
   verifies IdP-issued ID-JAG assertions and mints the short-lived access
   tokens the MCP server accepts.

The same steps apply to *any* MCP server; the lwauth control-plane MCP
server is just the example used throughout.

> Background reading:
> [docs/design/mcp-enterprise-auth.md](../design/mcp-enterprise-auth.md) and
> [docs/design/mcp-server.md](../design/mcp-server.md).

---

## What you'll build

```
Okta/Entra  ──ID-JAG──►  AI Agent  ──token exchange──►  lwauth (RAS)
                              │                              │
                              │  Bearer <access token>       │ mints access token
                              ▼                              ▼
                       lwauth MCP server ◄── ext_authz validation ── lwauth
```

---

## Prerequisites

- A Kubernetes cluster with LightweightAuth installed (CRDs + controller).
- An enterprise IdP (Okta, Entra ID, Google Workspace) that can issue
  **ID-JAG** assertions via token exchange
  (`urn:ietf:params:oauth:grant-type:token-exchange`).
- `kubectl` access and the `lwauthctl` CLI.
- cert-manager (used to mint the RS256 signing key for issued tokens).

---

## Step 1 — Register your IdP

LightweightAuth verifies ID-JAG signatures against your IdP's JWKS. Register
the IdP once:

```yaml
apiVersion: lightweightauth.io/v1alpha1
kind: IdentityProvider
metadata:
  name: corp-okta
  namespace: lwauth-system
spec:
  issuer: https://corp.okta.com/
  jwksUrl: https://corp.okta.com/oauth2/v1/keys
```

```bash
kubectl apply -f idp.yaml
```

---

## Step 2 — Deploy the lwauth MCP server

The control-plane MCP server runs as an `LwauthInstance` that fronts the
control-plane API. Give it the canonical resource URL your agents will use.

```yaml
apiVersion: lightweightauth.io/v1alpha1
kind: LwauthInstance
metadata:
  name: mcp-server
  namespace: lwauth-system
spec:
  appClusterID: lwauth-system
  # Exposes the MCP tool surface at this resource identifier.
  # Must match the resourceIdentifier in the MCPServer CR below.
```

```bash
kubectl apply -f mcp-instance.yaml
```

Confirm it is serving:

```bash
kubectl -n lwauth-system get lwauthinstance mcp-server
```

---

## Step 3 — Register the MCP server with lwauth (`MCPServer` CR)

This is the single configuration object that turns lwauth into the Resource
Authorization Server for your MCP server. It maps IdP scopes to roles and
pins the IdP and token validation mode.

```yaml
apiVersion: lightweightauth.io/v1alpha1
kind: MCPServer
metadata:
  name: lwauth-mcp
  namespace: lwauth-system
spec:
  # Canonical URL of the MCP server. Must equal the `resource` claim the
  # IdP places in ID-JAG tokens AND the `aud` of issued access tokens.
  resourceIdentifier: https://lwauth-mcp.internal.example.com/

  # IdP whose JWKS verifies incoming ID-JAG signatures.
  identityProviderRef: corp-okta

  # Map IdP-granted OAuth scopes to roles the MCP server enforces.
  scopeBindings:
    - scope: mcp:read
      role: user
    - scope: mcp:operate
      role: operator
    - scope: mcp:admin
      role: admin

  # Short-lived access tokens; agents refresh automatically.
  tokenTTL: 1h

  # Optionally restrict which OAuth clients may exchange tokens.
  allowedClients:
    - claude-desktop
    - cursor-agent

  tokenValidation:
    # extauthz (recommended): the MCP server sits behind lwauth ext_authz.
    # jwks: the MCP server validates tokens itself against lwauth's JWKS.
    mode: extauthz
```

```bash
kubectl apply -f mcpserver.yaml
kubectl -n lwauth-system get mcpserver lwauth-mcp -o yaml | grep -A8 status:
```

The status block surfaces the generated endpoints:

```yaml
status:
  discoveryURL:     https://lwauth-mcp.internal.example.com/.well-known/oauth-protected-resource
  tokenEndpointURL: https://lwauth.example.com/mcp/lwauth-mcp/oauth2/token
  jwksEndpointURL:  https://lwauth.example.com/mcp/lwauth-mcp/.well-known/jwks.json
```

---

## Step 4 — Configure the token-exchange endpoint (`idjag` + `jwt-issue`)

LightweightAuth's token endpoint accepts the IdP's ID-JAG assertion,
verifies it with the **`idjag`** identifier, and mints the MCP access token
with the **`jwt-issue`** mutator. Wire them with an `AuthConfig`:

```yaml
apiVersion: lightweightauth.io/v1alpha1
kind: AuthConfig
metadata:
  name: mcp-token-endpoint
  namespace: lwauth-system
spec:
  identifiers:
    - name: verify-idjag
      type: idjag
      config:
        # IdP JWKS — same as the IdentityProvider above.
        jwksUrl: https://corp.okta.com/oauth2/v1/keys
        issuer:  https://corp.okta.com/
        # This lwauth authorization server (the ID-JAG `aud`).
        audience: https://lwauth.example.com/
        # The MCP server this token is scoped to (the ID-JAG `resource`).
        resourceIdentifier: https://lwauth-mcp.internal.example.com/
        allowedClients:
          - claude-desktop
          - cursor-agent
        # Remember consumed jti values to block replay.
        replayWindow: 10m

  response:
    - name: issue-mcp-token
      type: jwt-issue
      config:
        issuer:   https://lwauth.example.com/
        # aud of the minted token = the MCP server resource id.
        audience: https://lwauth-mcp.internal.example.com/
        ttl:      1h
        algorithm: RS256
        privateKeyFile: /etc/lwauth/mcp-signing/tls.key
        # Carry the user identity + granted scope into the access token.
        copyClaims:
          - email
          - client_id
          - scope
```

```bash
kubectl apply -f mcp-token-endpoint.yaml
```

The `idjag` identifier enforces, in order:

| Check | Rejects |
|-------|---------|
| `typ` header == `oauth-id-jag+jwt` | A normal ID/access token replayed as an ID-JAG |
| JWS signature against IdP JWKS | Forged assertions |
| `exp` present + not expired, `nbf`/`iat` | Stale assertions |
| `iss` == IdP issuer | Wrong-issuer tokens |
| `aud` == this lwauth server | Tokens minted for a different audience |
| `resource` == MCP server id | Tokens scoped to a different MCP server |
| `client_id` in `allowedClients` | Unregistered agents |
| `jti` unseen within `replayWindow` | Replayed assertions |

---

## Step 5 — Protect the MCP server endpoints (ext_authz)

In `extauthz` mode the MCP server sits behind Envoy with lwauth as the
ext_authz service. Validate the issued access token:

```yaml
apiVersion: lightweightauth.io/v1alpha1
kind: AuthConfig
metadata:
  name: mcp-server-extauthz
  namespace: lwauth-system
spec:
  identifiers:
    - name: verify-access-token
      type: jwt
      config:
        # lwauth's own JWKS for the issued access tokens.
        jwksUrl:   https://lwauth.example.com/mcp/lwauth-mcp/.well-known/jwks.json
        issuerUrl: https://lwauth.example.com/
        audiences:
          - https://lwauth-mcp.internal.example.com/
  authorizers:
    - name: require-role
      type: cel
      config:
        # Enforce that a role claim is present; per-tool checks happen
        # inside the MCP server using the same claim.
        expression: 'has(identity.claims.role)'
```

```bash
kubectl apply -f mcp-server-extauthz.yaml
```

> If you set `tokenValidation.mode: jwks` instead, skip the ext_authz
> AuthConfig and have the MCP server validate tokens directly against the
> `jwksEndpointURL` from the `MCPServer` status.

---

## Step 6 — Configure the AI agent

Point the agent at the MCP server's discovery URL. Compliant MCP clients
(Claude Desktop, Cursor) follow RFC 9728 automatically: they fetch the
protected-resource metadata, exchange the IdP ID token for an ID-JAG, call
the token endpoint, and attach the resulting access token.

Example Claude Desktop config:

```json
{
  "mcpServers": {
    "lwauth": {
      "url": "https://lwauth-mcp.internal.example.com/",
      "auth": {
        "type": "oauth",
        "discovery": "https://lwauth-mcp.internal.example.com/.well-known/oauth-protected-resource"
      }
    }
  }
}
```

The agent never holds a long-lived secret — every session is tied to the
employee's live IdP session (MFA, conditional access, group membership all
apply).

---

## Step 7 — Verify the flow

Simulate the agent's token exchange with `curl`. First obtain an ID-JAG from
your IdP (token-exchange call), then:

```bash
# Exchange the ID-JAG for an MCP access token.
ACCESS_TOKEN=$(curl -s \
  -X POST https://lwauth.example.com/mcp/lwauth-mcp/oauth2/token \
  -d grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer \
  -d "assertion=$ID_JAG" | jq -r .access_token)

# Call an MCP tool with the issued token.
curl -s https://lwauth-mcp.internal.example.com/ \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call",
       "params":{"name":"list_instances","arguments":{}}}'
```

Expected failures (each returns 401/403, audit-logged):

```bash
# Replay the same ID-JAG twice → second call rejected (jti replay).
# Wrong resource in the ID-JAG → rejected (resource mismatch).
# Tampered signature → rejected (signature failure).
```

---

## Troubleshooting

| Symptom | Likely cause |
|---------|--------------|
| `401 invalid credential: idjag: unexpected typ` | IdP isn't setting `typ=oauth-id-jag+jwt`; configure the token-exchange profile |
| `401 idjag: resource claim does not match` | IdP `resource` ≠ `resourceIdentifier` in the MCPServer CR |
| `401 idjag: assertion replay detected` | Agent reused a one-time assertion; it must exchange once and cache the access token |
| `401 idjag: client_id not allowed` | Add the agent's `client_id` to `allowedClients` |
| MCP tool call returns `403` | Access token lacks a `role`; check the `scopeBindings` mapping |

---

## Summary

1. `IdentityProvider` — registers the IdP JWKS.
2. `LwauthInstance` — runs the MCP server.
3. `MCPServer` — registers the server as a protected resource.
4. `AuthConfig` (idjag + jwt-issue) — the token-exchange endpoint.
5. `AuthConfig` (jwt + cel) — validates issued tokens at the MCP server.
6. Agent config — points at the discovery URL.

The only secret in the system is the RS256 signing key, managed by
cert-manager and rotated automatically. Agents authenticate per-session
through your IdP — no static MCP tokens.
