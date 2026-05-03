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
        token: "${SPICEDB_PRESHARED_KEY}"
        insecure: false
        timeout: "200ms"
        consistency: "minimize_latency"
        tls:
          caFile: /etc/lwauth/spicedb-ca.pem

        check:
          resourceType: "document"
          resourceID: "{{ .Request.PathSegment 2 }}"
          permission: |-
            {{- if eq .Request.Method "GET" -}}view
            {{- else if eq .Request.Method "PUT" -}}edit
            {{- else if eq .Request.Method "DELETE" -}}delete
            {{- else -}}view
            {{- end -}}
          subjectType: "user"
          subjectID: "{{ .Identity.Subject }}"
```

## 5. Template functions

The `check` block uses Go `text/template` with these variables:

| Variable | Example | Description |
|----------|---------|-------------|
| `.Request.Method` | `GET` | HTTP method |
| `.Request.Path` | `/api/documents/doc1` | Full path |
| `.Request.PathSegment N` | `doc1` (N=2) | Nth path segment (0-indexed) |
| `.Request.Header "X-Foo"` | `bar` | Request header |
| `.Request.Query "key"` | `value` | Query parameter |
| `.Identity.Subject` | `alice` | Authenticated subject |
| `.Identity.Claims` | map | All identity claims |

## 6. Consistency levels

| Level | Behavior | Latency | Use when |
|-------|----------|---------|----------|
| `minimize_latency` | Use SpiceDB cache | Lowest (~1-5ms) | Reads that can tolerate eventual consistency |
| `fully_consistent` | Full consistency | Higher (~10-50ms) | After relationship writes (e.g. sharing a document) |
| `at_least_as_fresh` | With ZedToken | Medium | When you have the write's ZedToken |

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
              token: "${SPICEDB_PRESHARED_KEY}"
              timeout: "200ms"
              consistency: "minimize_latency"
              check:
                resourceType: "document"
                resourceID: "{{ .Request.PathSegment 2 }}"
                permission: view
                subjectType: "user"
                subjectID: "{{ .Identity.Subject }}"
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
                token: "${SPICEDB_PRESHARED_KEY}"
                timeout: 200ms
                consistency: minimize_latency
                check:
                  resourceType: document
                  resourceID: "{{ .Request.PathSegment 2 }}"
                  permission: view
                  subjectType: user
                  subjectID: "{{ .Identity.Subject }}"
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
