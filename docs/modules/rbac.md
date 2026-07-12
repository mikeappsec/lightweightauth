# `rbac` — Role-based access control

Static, declarative role gate. Pulls the role list out of an
`Identity` claim and checks it against an allow-list. The cheapest
authorizer in the kit.

**Source:** [pkg/authz/rbac](https://github.com/mikeappsec/lightweightauth/blob/main/pkg/authz/rbac/rbac.go) — registered as `rbac`.

## When to use

- Role list lives directly on the identity (JWT `roles` claim, API-key store).
- Coarse "admin / editor / viewer" gating that doesn't need per-resource policy.
- Fast path before expensive authorizers under [`composite`](composite.md) `anyOf`.

**Don't use** for relationship checks (use [`openfga`](openfga.md)) or
expression logic (use [`cel`](cel.md)).

## Configuration

```yaml
authorizers:
  - name: gate
    type: rbac
    config:
      # Only "claim:<key>" is supported — Identity.Claims[key], which
      # may be a string, []string, or []any of strings. There is no
      # "source" or "subject" prefix; any other value silently yields
      # zero roles (extractRoles returns nil), which denies everything.
      rolesFrom: "claim:roles"

      allow:
        - admin
        - editor
        # No wildcard support — "*" only matches a role literally
        # named "*", it doesn't match "any non-empty role".
```

Decision logic: extract the role set → intersect with `allow` →
`Permit{}` on hit. On miss:
`Deny{Status: 403, Reason: fmt.Sprintf("rbac: subject %q has no allowed role", id.Subject)}`
— e.g. `rbac: subject "alice" has no allowed role`. Empty role list
always denies.

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

- `composite` `anyOf: [rbac, openfga]` — coarse role gate first;
  fall back to relationship check only when needed.
- Stack with [`cel`](cel.md) for "admin OR (editor AND owns the resource)"
  patterns — `cel` reads `identity.claims.roles` directly.

## References

- Source: [pkg/authz/rbac/rbac.go](https://github.com/mikeappsec/lightweightauth/blob/main/pkg/authz/rbac/rbac.go).
- DESIGN.md §5 — authorization layer.
