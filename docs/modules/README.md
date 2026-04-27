# Module Reference

Every module in lightweightauth's pipeline is selected by a `type` string in
the `AuthConfig` YAML (or CRD `spec`). This directory documents each
registered module on `main` — what it does, the full `config:` shape it
accepts, the Helm chart wiring required to ship it, and a worked example.

If you are integrating lightweightauth for the first time, read these in
order:

1. [Identifiers](#identifiers) — produce an `Identity` from the request.
2. [Authorizers](#authorizers) — turn an `Identity` + `Request` into an
   allow/deny decision.
3. [Response mutators](#response-mutators) — stamp headers / mint internal
   JWTs after the decision.
4. [Cache backends](#cache-backends) — selected via the `cache.backend`
   field on each `AuthConfig`.

The pipeline runs them in that order: Identify → Authorize → Mutate. See
[../DESIGN.md](../DESIGN.md) §0 for the architectural diagram and §2 for
the `pkg/module` interfaces these implement.

## Identifiers

| Type | Module | When to reach for it |
|---|---|---|
| `jwt` | [jwt.md](jwt.md) | Self-contained signed bearer tokens (OIDC, OAuth2 access tokens). |
| `oauth2-introspection` | [oauth2-introspection.md](oauth2-introspection.md) | Opaque bearers that need RFC 7662 introspection. |
| `oauth2` | [oauth2.md](oauth2.md) | Browser-facing OAuth 2.0 Authorization Code + PKCE + sessions. |
| `apikey` | [apikey.md](apikey.md) | Long-lived API keys (with argon2id hashing for production). |
| `mtls` | [mtls.md](mtls.md) | Service-to-service identity via client certificates / SPIFFE. |
| `hmac` | [hmac.md](hmac.md) | AWS-SigV4-style request signatures (CLI tools, webhooks). |
| `dpop` | [dpop.md](dpop.md) | RFC 9449 sender-constrained bearers (wraps another identifier). |

## Authorizers

| Type | Module | When to reach for it |
|---|---|---|
| `rbac` | [rbac.md](rbac.md) | Roles → routes. The cheap default. |
| `cel` | [cel.md](cel.md) | Single-line bool expressions over identity / request. |
| `opa` | [opa.md](opa.md) | Full OPA / Rego policies. |
| `openfga` | [openfga.md](openfga.md) | Zanzibar-style ReBAC against an external OpenFGA Pod. |
| `composite` | [composite.md](composite.md) | Combine the above with `allOf` / `anyOf`. |

## Response mutators

| Type | Module | When to reach for it |
|---|---|---|
| `header-add` | [header-add.md](header-add.md) | Stamp `X-User: ${sub}` etc. for the upstream. |
| `header-remove` | [header-remove.md](header-remove.md) | Strip sensitive headers before they reach upstream. |
| `header-passthrough` | [header-passthrough.md](header-passthrough.md) | Allow-list specific incoming headers. |
| `jwt-issue` | [jwt-issue.md](jwt-issue.md) | Mint a fresh internal JWT for the upstream. |

## Cache backends

| Type | Module | When to reach for it |
|---|---|---|
| `memory` | [cache-memory.md](cache-memory.md) | Default. In-process LRU. Single replica or per-replica state. |
| `valkey` | [cache-valkey.md](cache-valkey.md) | Shared decision/introspection/DPoP-replay cache across replicas. |

## How `type` is registered

Every module file ends with a one-liner like:

```go
func init() { module.RegisterIdentifier("jwt", factory) }
```

The `pkg/builtins` package blank-imports each one, so a binary that imports
`pkg/builtins` ships every default module out of the box. Plugin authors
register their own type names the same way; see
[../DESIGN.md](../DESIGN.md) §9 (tier 2 plugins).

## How these get into a Helm release

The chart at [deploy/helm/lightweightauth](../../deploy/helm/lightweightauth)
exposes one inline `AuthConfig` via `config.inline` (file mode) and
optionally a CRD-watching controller via `controller.enabled` (CRD mode).
Each module's `config:` block from this directory drops directly into one
of those two surfaces — every example below shows both.
