# `cel` — CEL expression authorizer

Evaluates a Common Expression Language program against `(identity,
request)`. Compiled once at config load; per-request evaluation is
allocation-light.

**Source:** [pkg/authz/cel](../../pkg/authz/cel/cel.go) — registered as `cel`.

## When to use

- Rules that depend on the *request* (path, method, headers, query).
- Policies expressible as a single boolean ("admin OR owns-the-tenant").
- You want production-grade safety: CEL is non-Turing-complete.

**Don't use** for ReBAC (use [`openfga`](openfga.md)) or rules that
require hundreds of LOC (use [`opa`](opa.md)).

## Configuration

```yaml
authorizers:
  - name: scoped
    type: cel
    config:
      expression: |
        identity.claims.roles.exists(r, r == "admin") ||
        (request.method == "GET" &&
         request.path.startsWith("/tenants/" + identity.claims.tenant))

      # Optional declared variables (allowed types: string,int,bool,list,map).
      variables:
        env: prod
```

Available bindings:

| Binding | Type |
|---|---|
| `identity.subject` | `string` |
| `identity.source` | `string` |
| `identity.claims` | `map<string, dyn>` |
| `request.method` | `string` |
| `request.path` | `string` |
| `request.host` | `string` |
| `request.headers` | `map<string, list<string>>` |
| `request.query` | `map<string, list<string>>` |

Compile errors fail-fast at config load. Runtime errors deny.

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
- Source: [pkg/authz/cel/cel.go](../../pkg/authz/cel/cel.go).
