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

There is no `mode:`/`children:` shape — the config has exactly two
possible top-level keys, `anyOf` and `allOf`, each holding the child
list directly (`pkg/authz/composite/composite.go`'s `knownKeys`).
Using both, or any other key, fails with `unknown config key(s)`.

```yaml
authorizers:
  - name: gate
    type: composite
    config:
      anyOf:                # or allOf — pick exactly one
        - { name: admins, type: rbac, config: { rolesFrom: claim:roles, allow: [admin] } }
        - { name: rebac,  type: openfga, config: { apiUrl: ..., storeId: ..., check: { ... } } }
```

Modes:

| Key | Semantics |
|---|---|
| `anyOf` | At least one child permits wins. All deny → deny. |
| `allOf` | Every child must permit. First deny short-circuits (no further children evaluated). |

There is no third "firstDeny"/veto mode — only these two.

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
          anyOf:
            - name: admins
              type: rbac
              config: { rolesFrom: claim:roles, allow: [admin] }
            - name: scoped
              type: cel
              config:
                expression: |
                  request.method == "GET" &&
                  request.path.startsWith("/tenants/" + identity.claims.tenant)
```

## Worked example

`anyOf` chain `[rbac(admins), cel(tenant-scoped)]`:

- Request from an admin → `rbac` permits → done. No CEL eval.
- Request from a viewer to their own tenant → `rbac` denies → `cel`
  permits → done.
- Cross-tenant viewer → both deny → overall deny.

## Composition

- Order children cheap → expensive under `anyOf` so a fast permit
  short-circuits the rest.
- Under `allOf`, put the child most likely to deny first so an
  expensive downstream check (e.g. [`openfga`](openfga.md),
  [`spicedb`](spicedb.md)) is skipped on the common deny path.

## References

- Source: [pkg/authz/composite/composite.go](https://github.com/mikeappsec/lightweightauth/blob/main/pkg/authz/composite/composite.go).
- DESIGN.md §5 — composing authorizers.
