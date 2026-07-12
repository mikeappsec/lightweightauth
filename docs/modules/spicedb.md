# `spicedb` — Zanzibar-style ReBAC authorizer

Evaluates a permission check against a [SpiceDB](https://authzed.com/spicedb)
(or any Authzed-compatible) relationship graph. A single
`CheckPermission` RPC per request determines whether the authenticated
subject has the specified relationship on the target resource.

**Source:** [pkg/authz/spicedb](https://github.com/mikeappsec/lightweightauth/blob/main/pkg/authz/spicedb/spicedb.go) — registered as `spicedb`.

## When to use

- Your access model is **relationship-based** — "user X is a member of
  org Y, which owns document Z".
- You already have (or plan to deploy) SpiceDB / Authzed for
  fine-grained permissions.
- You need **consistent** permission checks across multiple services
  sharing a SpiceDB schema.

**Don't use** for simple role checks ([`rbac`](rbac.md)), expression-based
rules ([`cel`](cel.md)), or graph models hosted on OpenFGA
([`openfga`](openfga.md)).

## Configuration

All five `check.*` fields are Go `text/template` strings, not plain
values — `resourceType`/`permission`/`subjectType` included, not just
`resourceId`/`subjectId`. Field names use lowercase-`d` `Id`
(`resourceId`, `subjectId`), not `resourceID`/`subjectID`. There is
no `tls:` block — TLS uses the system CA pool unconditionally
(`grpcutil.WithSystemCerts`); there's no way to pin a custom CA file
today.

```yaml
authorizers:
  - name: spicedb-check
    type: spicedb
    config:
      endpoint: "spicedb.authz.svc:50051"
      token: "${SPICEDB_PRESHARED_KEY}"   # see warning below
      insecure: false              # set true only for local dev
      timeout: "200ms"
      consistency: "minimize_latency"   # or "fully_consistent" — no third option
      check:
        resourceType: "document"
        resourceId: "{{ index .Request.PathParts 1 }}"
        permission: "{{ .Request.Method | lower }}"
        subjectType: "user"
        subjectId: "{{ .Identity.Subject }}"
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `endpoint` | string | *required* | SpiceDB gRPC address (host:port) |
| `token` | string | *required* | Pre-shared key or bearer token |
| `insecure` | bool | `false` | Allow plaintext (non-TLS) connection |
| `timeout` | duration | `200ms` (default 2s if omitted) | Per-RPC deadline |
| `consistency` | string | `"minimize_latency"` | `minimize_latency` or `fully_consistent` — any other value fails config validation |
| `check.resourceType` | template | *required* | Object type in the schema |
| `check.resourceId` | template | *required* | Resolves to the resource's object ID |
| `check.permission` | template | *required* | Relation/permission to check |
| `check.subjectType` | template | *required* | Subject object type |
| `check.subjectId` | template | *required* | Resolves to the subject's object ID |

!!! warning "`token` is read literally — no `${VAR}` substitution"
    lwauth does not expand `${SPICEDB_PRESHARED_KEY}`-style
    placeholders anywhere in `AuthConfig`. Two ways to actually inject
    it: `token: "vault://kv/lwauth/spicedb#token"` (resolved at
    compile time — any string field in a module's `config:` is
    checked recursively, `internal/config/loader.go`'s
    `resolveMapSecrets`), or template the `AuthConfig` YAML itself at
    the deployment-pipeline layer (Helm, Kustomize, CI) so the real
    token is already inlined before lwauth ever parses it.

## Template functions

Templates in the `check` block receive `{Identity, Request}`
(`templateInput` in `spicedb.go`) — there is no `.Request.PathSegment
N`, `.Request.Header "..."`, or `.Request.Query "..."` method; use
indexing/field access instead:

| Field/function | Description |
|----------|-------------|
| `.Request.Method` | HTTP method |
| `.Request.Host` | Host header |
| `.Request.Path` | Full path |
| `.Request.PathParts` | `[]string`, path split on `/` with leading empty segment stripped — index into it, e.g. `index .Request.PathParts 1` |
| `.Request.TenantID` | Tenant ID |
| `.Request.Headers` | `map[string]string`, lowercased keys, first value only |
| `.Identity.Subject` | Authenticated subject |
| `.Identity.Claims` | Map of identity claims |
| `.Identity.Source` | Identifier that matched |
| `lower` / `upper` / `sanitize` | Only three helper functions available, e.g. `{{ .Request.Method \| lower }}` (`sanitize` restricts a string to SpiceDB-safe object-ID characters) |

## Helm wiring

```yaml
# values.yaml
config:
  inline: |
    authorizers:
      - name: spicedb-check
        type: spicedb
        config:
          endpoint: "spicedb.authz.svc:50051"
          token: "vault://kv/lwauth/spicedb#token"
          check:
            resourceType: document
            resourceId: "{{ index .Request.PathParts 1 }}"
            permission: view
            subjectType: user
            subjectId: "{{ .Identity.Subject }}"
```

## Operational notes

- **Latency.** The `CheckPermission` RPC typically returns in <5ms
  when SpiceDB has the relationship cached. Set `timeout` to at least
  2× your p99 to avoid false denies during GC pauses.
- **Consistency.** `minimize_latency` uses SpiceDB's cache (eventually
  consistent). Switch to `fully_consistent` for writes that must
  reflect immediately (at a latency cost).
- **Caching.** The pipeline's decision cache also caches SpiceDB allow
  results. Configure `cache.ttl` on the engine to control freshness.
- **Circuit breaker.** Uses the shared `upstream.Guard` so SpiceDB
  outages trigger the circuit breaker rather than queuing requests.

## References

- DESIGN: [DESIGN.md](../DESIGN.md).
- Source: [pkg/authz/spicedb/spicedb.go](https://github.com/mikeappsec/lightweightauth/blob/main/pkg/authz/spicedb/spicedb.go).
- Tests: [pkg/authz/spicedb/spicedb_test.go](https://github.com/mikeappsec/lightweightauth/blob/main/pkg/authz/spicedb/spicedb_test.go).
