# `cel` — CEL expression authorizer

Evaluates a Common Expression Language program against `(identity,
request)`. Compiled once at config load; per-request evaluation is
allocation-light.

**Source:** [pkg/authz/cel](https://github.com/mikeappsec/lightweightauth/blob/main/pkg/authz/cel/cel.go) — registered as `cel`.

## When to use

- Rules that depend on the *request* (path, method, headers, query).
- Policies expressible as a single boolean ("admin OR owns-the-tenant").
- You want production-grade safety: CEL is non-Turing-complete.

**Don't use** for ReBAC (use [`openfga`](openfga.md)) or rules that
require hundreds of LOC (use [`opa`](opa.md)).

## Configuration

`expression` is the only config field (`CelConfig` in `cel.go` has
exactly one field). There's no `variables:` block — config is decoded
via `module.DecodeConfig`, which derives known keys from the struct
tags and rejects anything else, so `variables:` fails with
`unknown config key(s): variables`.

```yaml
authorizers:
  - name: scoped
    type: cel
    config:
      expression: |
        identity.claims.roles.exists(r, r == "admin") ||
        (request.method == "GET" &&
         request.path.startsWith("/tenants/" + identity.tenantId))
```

Available bindings (`identityVars`/`requestVars`/`contextVars` in `cel.go`):

| Binding | Type |
|---|---|
| `identity.subject` | `string` |
| `identity.source` | `string` |
| `identity.claims` | `map<string, dyn>` |
| `request.method` | `string` |
| `request.path` | `string` |
| `request.host` | `string` |
| `request.tenantId` | `string` |
| `request.headers` | `map<string, string>` — flattened to first-value-only, **not** `list<string>`; a repeated header loses everything past the first value |
| `context` | `map<string, dyn>` — pipeline scratch (`Request.Context`) |

There is no `request.query` binding — `module.Request` has no
query-string field anywhere in this codebase.

Compile errors fail-fast at config load (a syntax error in
`expression` fails config compilation, not a request). At runtime, an
evaluation error (not a `false` result — an actual CEL error, or the
expression not yielding a bool) returns `module.ErrUpstream`, which
maps to a 503 and is never cached — it does **not** deny. Only an
expression that successfully evaluates to `false` produces an actual
`Deny{Status: 403, Reason: "cel: denied"}`.

## Helm wiring

```yaml
# values.yaml
config:
  inline: |
    authorizers:
      - name: scoped
        type: cel
        config:
          expression: |
            identity.claims.roles.exists(r, r == "admin") ||
            request.path.startsWith("/tenants/" + identity.claims.tenant)
```

## Worked example

Identity: `{subject: alice, claims: {roles: [viewer], tenant: acme}}`
Request: `GET /tenants/acme/things` → expression evaluates `true` → permit.

Same identity, request `GET /tenants/globex/things` → `false` → deny.

## Composition

- `composite` `allOf: [rbac, cel]` — role gate then expression refinement.
- Use the [`header-add`](header-add.md) mutator with a CEL-derived value to
  stamp tenant context into upstream requests after authorization.

## References

- CEL language spec: <https://github.com/google/cel-spec>.
- Source: [pkg/authz/cel/cel.go](https://github.com/mikeappsec/lightweightauth/blob/main/pkg/authz/cel/cel.go).
