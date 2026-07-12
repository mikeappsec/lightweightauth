# `idjag` — Identity Assertion JWT Authorization Grant

Verifies an ID-JAG (Identity Assertion JWT Authorization Grant) assertion
— the token-exchange leg of the [MCP Enterprise-Managed
Authorization](https://github.com/modelcontextprotocol/ext-auth/blob/main/specification/stable/enterprise-managed-authorization.mdx)
spec (`draft-ietf-oauth-identity-assertion-authz-grant`). An enterprise
IdP issues a short-lived ID-JAG assertion naming a specific MCP server as
the target resource; LightweightAuth, acting as the Resource
Authorization Server for that MCP server, verifies the assertion here.
A downstream [`jwt-issue`](jwt-issue.md) mutator typically mints the
actual MCP access token afterward.

**Source:** [pkg/identity/idjag](https://github.com/mikeappsec/lightweightauth/blob/main/pkg/identity/idjag/idjag.go) — registered as `idjag`.

## When to use

- LightweightAuth is deployed as the Resource Authorization Server in
  front of an MCP server, per the MCP enterprise-managed authorization
  flow — see [MCP Enterprise-Managed Authorization](../design/mcp-enterprise-auth.md)
  and [MCP Server Design](../design/mcp-server.md) for the full flow this
  identifier is one leg of.
- An AI agent (Claude, Cursor, Copilot) presents an ID-JAG assertion
  obtained from the enterprise IdP on the user's behalf, rather than a
  static long-lived token.

**Don't use** for general bearer-token verification — reach for
[`jwt`](jwt.md) instead; `idjag` specifically pins the `typ` header,
`resource` claim, and single-use replay semantics the ID-JAG spec
requires, which a general JWT verifier does not enforce.

## Configuration

```yaml
identifiers:
  - name: mcp-gateway
    type: idjag
    config:
      jwksUrl:             https://idp.example.com/.well-known/jwks.json
      issuer:              https://idp.example.com/
      audience:            https://lwauth.example.com/         # this AS
      resourceIdentifier:  https://github-mcp.example.com/     # target MCP server
      allowedClients:      [my-agent-client]                   # optional
      header:              Authorization                       # default
      scheme:              Bearer                               # default
      expectedTyp:         oauth-id-jag+jwt                     # default
      minRefreshInterval:  15m                                  # default
      replayWindow:        10m                                  # default; should be >= max ID-JAG lifetime
```

| Field | Type | Default | Description |
|---|---|---|---|
| `jwksUrl` | string | *required* | IdP JWKS endpoint used to verify the assertion's signature. |
| `issuer` | string | *required* | Expected `iss` — pinned to the IdP. |
| `audience` | string | *required* | Expected `aud` — pinned to this authorization server. |
| `resourceIdentifier` | string | *required* | Expected `resource` claim — pinned to the specific MCP server this identifier fronts. |
| `allowedClients` | list of string | — | Optional `client_id` allow-list; unset accepts any client the IdP vouches for. |
| `header` | string | `Authorization` | Header the assertion is read from. |
| `scheme` | string | `Bearer` | Scheme prefix stripped from the header value. |
| `expectedTyp` | string | `oauth-id-jag+jwt` | Required JWS `typ` header — pins the token type per RFC 7519 §5.1. |
| `minRefreshInterval` | duration | `15m` | Minimum interval between JWKS re-fetches on a `kid` miss. |
| `replayWindow` | duration | `10m` | How long a consumed `jti` is remembered to block replay; must cover the maximum ID-JAG lifetime. |

## Validation performed

1. JWS signature against the IdP's JWKS.
2. `typ` header equals `expectedTyp` (RFC 7519 §5.1 token-type pinning) —
   rejects a same-IdP token minted for a different purpose.
3. `exp` / `nbf` / `iat` enforcement (`exp` is required).
4. `iss` pinned to `issuer`.
5. `aud` pinned to `audience` (this authorization server).
6. `resource` claim pinned to `resourceIdentifier` (the target MCP server)
   — a valid assertion minted for a *different* MCP server is rejected.
7. Optional `client_id` allow-list check.
8. `jti` single-use replay prevention within `replayWindow`.

## Composition

- Pair with [`jwt-issue`](jwt-issue.md) on the response side to mint the
  short-lived MCP access token after a successful ID-JAG exchange — keeps
  the enterprise assertion off the wire to the actual MCP server.
- See the [Install the LightweightAuth MCP server](../cookbook/install-lwauth-mcp-server.md)
  cookbook recipe for a full worked setup.

## References

- [MCP Enterprise-Managed Authorization specification](https://github.com/modelcontextprotocol/ext-auth/blob/main/specification/stable/enterprise-managed-authorization.mdx).
- Identity Assertion JWT Authorization Grant,
  `draft-ietf-oauth-identity-assertion-authz-grant`.
- [docs/design/mcp-enterprise-auth.md](../design/mcp-enterprise-auth.md).
- Source: [pkg/identity/idjag/idjag.go](https://github.com/mikeappsec/lightweightauth/blob/main/pkg/identity/idjag/idjag.go).
