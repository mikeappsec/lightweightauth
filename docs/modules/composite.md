# `composite` — Combine authorizers

Runs a list of child authorizers under a combinator. The only authorizer
that takes other authorizers; lets you express "fast path then slow
path", "must pass all", or "any one is enough" without code.

**Source:** [pkg/authz/composite](https://github.com/mikeappsec/lightweightauth/blob/main/pkg/authz/composite/composite.go) — registered as `composite`.

## When to use

- Mixing role gates with policy / ReBAC checks.
- Short-circuiting on cheap authorizers before expensive ones.
- Implementing "deny overrides" or "permit overrides" patterns.

## Configuration

```yaml
authorizers:
  - name: gate
    type: composite
    config:
      mode: firstAllow      # firstAllow | allOf | anyOf | firstDeny
      children:
        - { name: admins, type: rbac, config: { rolesFrom: claim:roles, allow: [admin] } }
        - { name: rebac,  type: openfga, config: { ... } }
```

Modes:

| `mode` | Semantics |
|---|---|
| `firstAllow` | Stop at the first child that returns `Permit`. Default for fast-path-first stacks. |
| `allOf` | Every child must permit. First deny short-circuits. |
| `anyOf` | At least one child permits. All deny → deny. |
| `firstDeny` | Stop at the first child that returns `Deny`. Useful for "veto chains". |

Children can themselves be `composite`, so arbitrary trees compose.

## Helm wiring

```yaml
# values.yaml
config:
  inline: |
    authorizers:
      - name: gate
        type: composite
        config:
          mode: firstAllow
          children:
            - name: admins
              type: rbac
              config: { rolesFrom: claim:roles, allow: [admin] }
            - name: scoped
              type: cel
              config:
                expression: |
                  request.method == "GET" &&
                  request.path.startsWith("/tenants/" + identity.claims.tenant)
            - name: rebac
              type: openfga
              config: { apiUrl: ..., storeId: ..., check: { ... } }
```

## Worked example

`firstAllow` chain `[rbac(admins), cel(tenant-scoped), openfga(rebac)]`:

- Request from an admin → `rbac` permits → done. No CEL eval, no FGA call.
- Request from a viewer to their own tenant → `rbac` denies → `cel`
  permits → done. No FGA call.
- Cross-tenant viewer → `rbac` and `cel` deny → `openfga.Check` runs.

## Composition

- Always order children cheap → expensive in `firstAllow` to maximize cache hits.
- For "veto" patterns (revocation, deny lists) put a [`cel`](cel.md) deny check first under `firstDeny`, then your normal `firstAllow` tree as the fallback.

## References

- Source: [pkg/authz/composite/composite.go](https://github.com/mikeappsec/lightweightauth/blob/main/pkg/authz/composite/composite.go).
- DESIGN.md §5 — composing authorizers.
