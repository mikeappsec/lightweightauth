# `openfga` — ReBAC via OpenFGA

Asks an OpenFGA / Auth0 FGA store whether `(user, relation, object)`
holds. There is no decision caching in this authorizer today — every
request issues a fresh `POST /check` call (subject to the circuit
breaker below); this module doesn't read the shared decision cache at
all.

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
      authorizationModelId:  01HQ...   # optional, latest if empty
      apiToken:              ${FGA_TOKEN}   # see warning below
      timeout:               150ms     # per-call deadline; default 2s

      # user/relation/object are Go text/template strings, NOT CEL —
      # a different templating mechanism than the cel authorizer.
      # Available fields: .Identity.{Subject,Source,Claims} and
      # .Request.{Method,Host,Path,PathParts,TenantID,Headers}.
      # Only two helper functions: lower, upper.
      check:
        user:     "user:{{ .Identity.Subject }}"
        relation: "{{ .Request.Method | lower }}"
        object:   "document:{{ index .Request.PathParts 1 }}"

      # Optional upstream.Guard circuit-breaker config — see
      # pkg/upstream for the resilience: block's fields.
      # resilience: { ... }
```

Per-request flow: render the three templates → `POST /stores/{id}/check`
(through the `resilience:` circuit breaker if configured) → `Permit{}`
on `allowed=true`.

!!! warning "`apiToken` is read literally — no `${VAR}` substitution"
    lwauth does not expand `${FGA_TOKEN}`-style placeholders anywhere
    in `AuthConfig`. `apiToken:` is forwarded to OpenFGA verbatim as
    `Authorization: Bearer <value>` — pasting `"${FGA_TOKEN}"` into a
    real config sends FGA the literal six characters, which it
    rejects with 401. Two ways to actually inject a secret:
    `apiToken: "vault://kv/lwauth/openfga#token"` (resolved at compile
    time — any string field in a module's `config:` is checked
    recursively, `internal/config/loader.go`'s `resolveMapSecrets`),
    or template the `AuthConfig` YAML itself at the deployment-pipeline
    layer (Helm, Kustomize, CI) so the real token is already inlined
    before lwauth ever parses it.

## Helm wiring

A pod `env:` var (like `FGA_TOKEN` below) is **not** automatically
substituted into `apiToken:` — lwauth doesn't read process environment
variables to fill in config placeholders. Use `secretRef:` instead,
which lwauth resolves itself via a direct call to the secret backend
(Vault) at compile time:

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
          apiToken: "vault://kv/lwauth/openfga#token"
          check:
            user: "user:{{ .Identity.Subject }}"
            relation: viewer
            object: "document:{{ index .Request.PathParts 1 }}"
```

## Worked example

Request `GET /documents/42`, identity `subject=alice`, `PathParts=["documents","42"]`:

```
user     = "user:alice"
relation = "viewer"
object   = "document:42"
```

`POST /stores/{id}/check` → `{"allowed": true}` → permit.

## Composition

- `composite` `anyOf: [rbac, openfga]` — admins bypass FGA entirely.
- Use [`opa`](opa.md) for the *macro* policy and `openfga` for the
  *per-resource* check; combine via `composite` `allOf`.

## References

- OpenFGA: <https://openfga.dev>.
- Source: [pkg/authz/openfga/openfga.go](https://github.com/mikeappsec/lightweightauth/blob/main/pkg/authz/openfga/openfga.go).
