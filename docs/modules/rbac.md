# `rbac` — Role-based access control

Static, declarative role gate. Pulls the role list out of an `Identity`
field (claim, source, or subject) and checks it against an allow-list.
The cheapest authorizer in the kit.

**Source:** [pkg/authz/rbac](../../pkg/authz/rbac/rbac.go) — registered as `rbac`.

## When to use

- Role list lives directly on the identity (JWT `roles` claim, API-key store).
- Coarse "admin / editor / viewer" gating that doesn't need per-resource policy.
- Fast path before expensive authorizers under [`composite`](composite.md) `firstAllow`.

**Don't use** for relationship checks (use [`openfga`](openfga.md)) or
expression logic (use [`cel`](cel.md)).

## Configuration

```yaml
authorizers:
  - name: gate
    type: rbac
    config:
      # Where to read the role list from. Supported prefixes:
      #   claim:<key>   – Identity.Claims[key] (string or []string)
      #   source        – Identity.Source (the identifier name)
      #   subject       – Identity.Subject
      rolesFrom: "claim:roles"

      allow:
        - admin
        - editor
        # "*" matches any non-empty role
```

Decision logic: extract the role set → intersect with `allow` →
`Permit{}` on hit, `Deny{Reason: "rbac: role not allowed"}` on miss.
Empty role list against a non-`["*"]` allow-list → deny.

## Helm wiring

```yaml
# values.yaml
config:
  inline: |
    identifiers:
      - { name: bearer, type: jwt, config: { jwksUrl: https://idp/jwks } }
    authorizers:
      - name: gate
        type: rbac
        config:
          rolesFrom: claim:roles
          allow: [admin, editor]
```

## Worked example

JWT carries `"roles": ["editor", "viewer"]`. Config has
`allow: [admin, editor]` → intersection `{editor}` → `Permit{}`.

## Composition

- `composite` `firstAllow: [rbac, openfga]` — coarse role gate first;
  fall back to relationship check only when needed.
- Stack with [`cel`](cel.md) for "admin OR (editor AND owns the resource)"
  patterns — `cel` reads `identity.claims.roles` directly.

## References

- Source: [pkg/authz/rbac/rbac.go](../../pkg/authz/rbac/rbac.go).
- DESIGN.md §5 — authorization layer.
