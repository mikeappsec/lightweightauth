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

```yaml
authorizers:
  - name: spicedb-check
    type: spicedb
    config:
      endpoint: "spicedb.authz.svc:50051"
      token: "${SPICEDB_PRESHARED_KEY}"
      insecure: false              # set true only for local dev
      timeout: "200ms"
      consistency: "minimize_latency"   # or "fully_consistent"
      tls:
        caFile: /etc/lwauth/spicedb-ca.pem  # optional
      check:
        resourceType: "document"
        resourceID: "{{ .Request.PathSegment 2 }}"   # Go template
        permission: "view"
        subjectType: "user"
        subjectID: "{{ .Identity.Subject }}"
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `endpoint` | string | *required* | SpiceDB gRPC address (host:port) |
| `token` | string | *required* | Pre-shared key or bearer token |
| `insecure` | bool | `false` | Allow plaintext (non-TLS) connection |
| `timeout` | duration | `200ms` | Per-RPC deadline |
| `consistency` | string | `"minimize_latency"` | SpiceDB consistency level |
| `tls.caFile` | string | — | Custom CA for server verification |
| `check.resourceType` | string | *required* | Object type in the schema |
| `check.resourceID` | template | *required* | Go template resolving to resource ID |
| `check.permission` | string | *required* | Relation/permission to check |
| `check.subjectType` | string | *required* | Subject object type |
| `check.subjectID` | template | *required* | Go template resolving to subject ID |

## Template functions

Templates in the `check` block have access to:

| Variable | Description |
|----------|-------------|
| `.Request.Method` | HTTP method |
| `.Request.Host` | Host header |
| `.Request.Path` | Full path |
| `.Request.PathSegment N` | Nth path segment (0-indexed) |
| `.Request.Header "X-Foo"` | Request header value |
| `.Request.Query "key"` | Query parameter |
| `.Identity.Subject` | Authenticated subject |
| `.Identity.Claims` | Map of identity claims |
| `.Identity.Source` | Identifier that matched |

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
          token: "${SPICEDB_PRESHARED_KEY}"
          check:
            resourceType: document
            resourceID: "{{ .Request.PathSegment 2 }}"
            permission: view
            subjectType: user
            subjectID: "{{ .Identity.Subject }}"
env:
  - name: SPICEDB_PRESHARED_KEY
    valueFrom:
      secretKeyRef:
        name: lwauth-spicedb
        key: token
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
