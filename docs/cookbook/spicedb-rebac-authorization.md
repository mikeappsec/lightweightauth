# SpiceDB relationship-based access control

Implement Zanzibar-style fine-grained permissions using SpiceDB as
the authorization backend. lwauth issues a `CheckPermission` RPC per
request to determine whether the authenticated subject has the
required relationship on the target resource.

## What this recipe assumes

- SpiceDB (or Authzed) deployed and reachable from lwauth pods.
- A SpiceDB schema defining your object types, relations, and
  permissions.
- A pre-shared key or bearer token for the SpiceDB API.
- Resource IDs derivable from the request path or headers.

## 1. Deploy SpiceDB

Minimal SpiceDB deployment for this recipe:

```bash
# Install SpiceDB operator
kubectl apply --server-side -f \
  https://github.com/authzed/spicedb-operator/releases/latest/download/bundle.yaml

# Or Helm (simpler for development)
helm repo add authzed https://authzed.github.io/helm-charts
helm install spicedb authzed/spicedb \
  --namespace authz --create-namespace \
  --set spicedb.grpcPresharedKey=$(openssl rand -base64 32) \
  --set spicedb.datastoreEngine=postgres \
  --set spicedb.datastoreConnUri="postgresql://..."
```

Capture the pre-shared key into a Secret:

```bash
kubectl -n lwauth-system create secret generic spicedb-token \
  --from-literal=token=<preshared-key>
```

## 2. Define a schema

Example schema for a document management system:

```zed
definition user {}

definition organization {
    relation admin: user
    relation member: user

    permission delete = admin
    permission read = admin + member
}

definition document {
    relation org: organization
    relation owner: user
    relation editor: user
    relation viewer: user

    permission delete = owner + org->admin
    permission edit = owner + editor + org->admin
    permission view = owner + editor + viewer + org->member
}
```

Write it to SpiceDB:

```bash
zed schema write schema.zed --endpoint spicedb.authz.svc:50051 --token "${TOKEN}"
```

## 3. Write relationships

Bootstrap some test data:

```bash
# Alice owns doc1
zed relationship create document:doc1 owner user:alice

# Bob can view doc1
zed relationship create document:doc1 viewer user:bob

# Carol is an org admin
zed relationship create organization:acme admin user:carol
zed relationship create document:doc1 org organization:acme
```

## 4. Configure lwauth with SpiceDB

```yaml
apiVersion: lightweightauth.io/v1alpha1
kind: AuthConfig
metadata:
  name: documents-spicedb
  namespace: documents
spec:
  identifiers:
    - name: bearer
      type: jwt
      config:
        issuerUrl: https://idp.example.com
        audiences: [documents-api]

  authorizers:
    - name: spicedb-check
      type: spicedb
      config:
        endpoint: "spicedb.authz.svc:50051"
        token: "${SPICEDB_PRESHARED_KEY}"   # see warning below
        insecure: false
        timeout: "200ms"
        consistency: "minimize_latency"
        # There is no `tls:` block — TLS uses the system CA pool
        # unconditionally (grpcutil.WithSystemCerts); there's no way
        # to pin a custom CA file today.

        check:
          resourceType: "document"
          resourceId: "{{ index .Request.PathParts 2 }}"
          permission: |-
            {{- if eq .Request.Method "GET" -}}view
            {{- else if eq .Request.Method "PUT" -}}edit
            {{- else if eq .Request.Method "DELETE" -}}delete
            {{- else -}}view
            {{- end -}}
          subjectType: "user"
          subjectId: "{{ .Identity.Subject }}"
```

!!! warning "`token` is read literally — no `${VAR}` substitution"
    lwauth does not expand `${SPICEDB_PRESHARED_KEY}`-style
    placeholders anywhere in `AuthConfig`. Two ways to actually inject
    it: `token: "vault://kv/lwauth/spicedb#token"` (resolved at
    compile time — any string field in a module's `config:` is
    checked recursively, `internal/config/loader.go`'s
    `resolveMapSecrets`), or template the `AuthConfig` YAML itself at
    the deployment-pipeline layer (Helm, Kustomize, CI) so the real
    token is already inlined before lwauth ever parses it.

## 5. Template functions

The `check` block uses Go `text/template` with these variables. Field
names use lowercase-`d` `Id` (`resourceId`, `subjectId`), not
`resourceID`/`subjectID`, and there is no `.Request.PathSegment N`,
`.Request.Header "..."`, or `.Request.Query "..."` method — use
`index`/field access on `.Request.PathParts`/`.Request.Headers` instead:

| Variable | Example | Description |
|----------|---------|-------------|
| `.Request.Method` | `GET` | HTTP method |
| `.Request.Path` | `/api/documents/doc1` | Full path |
| `.Request.PathParts` | `["api","documents","doc1"]` | Path split on `/`, leading empty segment stripped — index into it, e.g. `index .Request.PathParts 2` |
| `.Request.Headers` | map | Lowercased keys, first value only |
| `.Identity.Subject` | `alice` | Authenticated subject |
| `.Identity.Claims` | map | All identity claims |
| `lower` / `upper` / `sanitize` | — | The only three template helper functions available |

## 6. Consistency levels

Only two consistency levels are actually accepted — config validation
rejects anything else with `consistency must be 'minimize_latency' or
'fully_consistent'` (`pkg/authz/spicedb/spicedb.go`). There is no
`at_least_as_fresh`/ZedToken support today, despite it appearing in
the field's Go doc comment as an aspirational third mode:

| Level | Behavior | Latency | Use when |
|-------|----------|---------|----------|
| `minimize_latency` | Use SpiceDB cache | Lowest (~1-5ms) | Reads that can tolerate eventual consistency |
| `fully_consistent` | Full consistency | Higher (~10-50ms) | After relationship writes (e.g. sharing a document) |

For most read traffic, `minimize_latency` is correct. Use
`fully_consistent` only for operations immediately after a permission
change (e.g. "share → then access").

## 7. Combine with RBAC fast path

Avoid SpiceDB calls for obvious cases:

```yaml
  authorizers:
    - name: gate
      type: composite
      config:
        anyOf:
          # Super-admins skip SpiceDB entirely
          - name: admin-bypass
            type: rbac
            config:
              rolesFrom: claim:roles
              allow: [platform-admin]

          # Everyone else hits SpiceDB
          - name: spicedb-check
            type: spicedb
            config:
              endpoint: "spicedb.authz.svc:50051"
              token: "${SPICEDB_PRESHARED_KEY}"   # see warning in step 4
              timeout: "200ms"
              consistency: "minimize_latency"
              check:
                resourceType: "document"
                resourceId: "{{ index .Request.PathParts 2 }}"
                permission: view
                subjectType: "user"
                subjectId: "{{ .Identity.Subject }}"
```

## 8. Decision caching

Cache SpiceDB results to reduce RPC load:

```yaml
  cache:
    backend: valkey
    addr: valkey-master.cache.svc:6379
    keyPrefix: lwauth/documents/
    key: [sub, method, path]
    ttl: 30s          # positive decision cache
    negativeTtl: 5s   # negative decision cache
```

A 30s TTL means relationship changes take up to 30s to reflect. For
tighter consistency, lower the TTL or use cache invalidation when
relationships change.

## 9. Helm wiring

```yaml
# values.yaml
config:
  inline: |
    identifiers:
      - name: bearer
        type: jwt
        config:
          issuerUrl: https://idp.example.com
          audiences: [documents-api]
    authorizers:
      - name: gate
        type: composite
        config:
          anyOf:
            - name: admin-bypass
              type: rbac
              config:
                rolesFrom: claim:roles
                allow: [platform-admin]
            - name: spicedb-check
              type: spicedb
              config:
                endpoint: "spicedb.authz.svc:50051"
                token: "${SPICEDB_PRESHARED_KEY}"   # see warning in step 4
                timeout: 200ms
                consistency: minimize_latency
                check:
                  resourceType: document
                  resourceId: "{{ index .Request.PathParts 2 }}"
                  permission: view
                  subjectType: user
                  subjectId: "{{ .Identity.Subject }}"
    cache:
      backend: valkey
      addr: valkey-master.cache.svc:6379
      keyPrefix: lwauth/documents/
      ttl: 30s
      negativeTtl: 5s
env:
  - name: SPICEDB_PRESHARED_KEY
    valueFrom:
      secretKeyRef:
        name: spicedb-token
        key: token
```

## 10. Validate

```bash
# Alice (owner) can view doc1
curl -H "Authorization: Bearer ${ALICE_TOKEN}" \
     https://gateway/api/documents/doc1
# expect: 200

# Alice can delete doc1 (owner has delete permission)
curl -X DELETE -H "Authorization: Bearer ${ALICE_TOKEN}" \
     https://gateway/api/documents/doc1
# expect: 200

# Bob (viewer) can view doc1
curl -H "Authorization: Bearer ${BOB_TOKEN}" \
     https://gateway/api/documents/doc1
# expect: 200

# Bob cannot delete doc1 (viewer lacks delete)
curl -X DELETE -H "Authorization: Bearer ${BOB_TOKEN}" \
     https://gateway/api/documents/doc1
# expect: 403

# Unknown user cannot access
curl -H "Authorization: Bearer ${UNKNOWN_TOKEN}" \
     https://gateway/api/documents/doc1
# expect: 403

# Dry-run
lwauthctl explain --config documents-spicedb.yaml \
    --request '{"method":"GET","path":"/api/documents/doc1","headers":{"authorization":"Bearer ..."}}'
# identify  ✓  jwt      subject=alice
# authorize ✓  spicedb  resource=document:doc1 permission=view subject=user:alice → PERMIT
```

## Operational notes

- **Latency.** SpiceDB `CheckPermission` typically returns in <5ms
  with cache. Set `timeout` to ≥2× your p99 to avoid false denies.
- **Circuit breaker.** Uses `upstream.Guard` — a SpiceDB outage
  trips the breaker and returns 503 rather than queuing requests.
- **Schema versioning.** Pin `authorizationModelId` in production to
  avoid breaking changes from schema updates.
- **Metrics.** Monitor `lwauth_authz_duration_seconds{authorizer="spicedb"}`
  and `lwauth_upstream_circuit_state{target="spicedb"}`.

## Teardown

```bash
kubectl delete authconfig documents-spicedb -n documents
kubectl delete secret spicedb-token -n lwauth-system
helm uninstall spicedb -n authz
```
