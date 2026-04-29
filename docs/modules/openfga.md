# `openfga` — ReBAC via OpenFGA

Asks an OpenFGA / Auth0 FGA store whether `(user, relation, object)`
holds. Decisions are cached per `(authorizationModelId, user, relation,
object)` against the shared `cache.Backend`.

**Source:** [pkg/authz/openfga](https://github.com/mikeappsec/lightweightauth/blob/main/pkg/authz/openfga/openfga.go) — registered as `openfga`.

## When to use

- Resource ownership / sharing graphs (`document:42#viewer@user:alice`).
- "Member of any team that owns this folder" — transitive reach.
- You already run OpenFGA and want lwauth to talk to it.

**Don't use** for role-only ("is this an admin?") — [`rbac`](rbac.md) is
two orders of magnitude faster.

## Configuration

```yaml
authorizers:
  - name: rebac
    type: openfga
    config:
      apiUrl:                https://openfga.svc.cluster.local:8080
      storeId:               01HQ...
      authorizationModelId:  01HQ...   # pin the model for stable decisions
      apiToken:              ${FGA_TOKEN}
      timeout:               150ms     # per-call deadline; enforced via context

      # CEL-driven check inputs. Same bindings as the cel authorizer.
      check:
        user:     "user:" + identity.subject
        relation: "viewer"
        object: |
          "document:" + request.path.split("/")[2]
```

Per-request flow: evaluate the three CEL expressions → cache lookup → on
miss call FGA `/check` → `Permit{}` on `allowed=true`. Cache TTL is
governed by `AuthConfig.cache.decisionTtl` (default 30s).

## Helm wiring

```yaml
# values.yaml
config:
  inline: |
    authorizers:
      - name: rebac
        type: openfga
        config:
          apiUrl: https://openfga.openfga.svc:8080
          storeId: 01HQ...
          authorizationModelId: 01HQ...
          apiToken: ${FGA_TOKEN}
          check:
            user: "user:" + identity.subject
            relation: viewer
            object: "document:" + request.path.split("/")[2]
    cache:
      backend: valkey
      addr: valkey-master.cache.svc:6379
      decisionTtl: 30s
extraEnv:
  - name: FGA_TOKEN
    valueFrom: { secretKeyRef: { name: lwauth-secrets, key: fga } }
```

The shared `valkey` cache lets all replicas reuse one another's
positive/negative answers — drops FGA QPS dramatically under fan-out.

## Worked example

Request `GET /documents/42`, identity `subject=alice`:

```
user     = "user:alice"
relation = "viewer"
object   = "document:42"
```

cache MISS → `POST /stores/{id}/check` → `{"allowed": true}` → permit; cached for 30s.

## Composition

- `composite` `firstAllow: [rbac, openfga]` — admins bypass FGA entirely.
- Use [`opa`](opa.md) for the *macro* policy and `openfga` for the
  *per-resource* check; combine via `composite` `allOf`.

## References

- OpenFGA: <https://openfga.dev>.
- Source: [pkg/authz/openfga/openfga.go](https://github.com/mikeappsec/lightweightauth/blob/main/pkg/authz/openfga/openfga.go).
