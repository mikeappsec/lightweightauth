# Quickstart

Three ways to bring up LightweightAuth and verify it is serving
decisions:

1. **Local binary** — fastest path; one `go run` and a `curl`.
2. **Docker Compose** — Envoy + lwauth + echo upstream wired together.
3. **Kubernetes (Helm)** — chart-based install with an `AuthConfig` CR.

Each section ends with a copy-paste verification step. For deeper
operational detail see [DEPLOYMENT.md](DEPLOYMENT.md); for the v1.0
feature inventory see [MILESTONES.md](MILESTONES.md).

---

## Prerequisites

| For path | You need |
|---|---|
| Local | Go 1.26.2+ (`GOTOOLCHAIN=go1.26.2` is honored), `curl` |
| Docker | Docker 24+ with the Compose v2 plugin |
| Kubernetes | A cluster (kind / minikube / real), `kubectl`, Helm 3.14+ |

Clone the repo:

```sh
git clone https://github.com/mikeappsec/lightweightauth.git
cd lightweightauth
```

---

## Path A — Local binary

### Build

```sh
make build       # produces ./bin/lwauth and ./bin/lwauthctl
# or directly:
go build -o ./bin/lwauth     ./cmd/lwauth
go build -o ./bin/lwauthctl  ./cmd/lwauthctl
```

### Run with a minimal config

Create a file `quickstart.yaml` next to the binary — the smallest
config that exercises an identifier (`apikey`) and an authorizer
(`rbac`) end-to-end:

```yaml
# quickstart.yaml
identifierMode: firstMatch
identifiers:
  - name: key
    type: apikey
    config:
      headerName: X-Api-Key
      static:
        demo-key-alice: { subject: alice, roles: [admin] }
authorizers:
  - name: gate
    type: rbac
    config:
      rolesFrom: claim:roles
      allow: [admin]
```

Start lwauth pointed at it:

```sh
./bin/lwauth --config ./quickstart.yaml --http-addr :8080
```

### Verify

```sh
# Healthz: 200, empty body
curl -i http://localhost:8080/healthz
# → HTTP/1.1 200 OK

# Allow path: API key for "alice" role=admin
curl -isS -X POST http://localhost:8080/v1/authorize \
  -H 'Content-Type: application/json' \
  -d '{"method":"GET","path":"/things","headers":{"X-Api-Key":["demo-key-alice"]}}'
# → HTTP/1.1 200 OK
# → {"allow":true,"subject":"alice","identitySource":"key"}

# Deny path: missing credential → HTTP status carries the deny status (401)
curl -isS -X POST http://localhost:8080/v1/authorize \
  -H 'Content-Type: application/json' \
  -d '{"method":"GET","path":"/things","headers":{}}'
# → HTTP/1.1 401 Unauthorized
# → {"allow":false,"status":401,"reason":"module: invalid credential: no identifier matched"}

# Metrics
curl -fsS http://localhost:8080/metrics | grep lwauth_decisions_total
# → lwauth_decisions_total{authorizer="gate",outcome="allow",tenant=""} 1
# → lwauth_decisions_total{authorizer="gate",outcome="error",tenant=""} 1
```

> **HTTP shape note.** `headers` is `map<string, list<string>>` (Envoy
> ext_authz convention) — every value is a JSON array, even when there
> is one. The request keys are `method`, `host`, `path`, `headers`,
> `tenantId`. The response keys are `allow`, `status`, `reason`,
> `subject`, `identitySource`, `upstreamHeaders`, `responseHeaders`.

You're good if `/healthz` is `200`, the allow case returns
`"allow":true`, and the deny case returns HTTP 401 with `"allow":false`
and a populated `reason`.

### Optional: dry-run a config without starting the server

```sh
./bin/lwauthctl validate ./quickstart.yaml
# → config OK; identifiers=1 authorizers=1 mutators=0

./bin/lwauthctl explain --config ./quickstart.yaml \
  --request '{"method":"GET","path":"/things","headers":{"X-Api-Key":["demo-key-alice"]}}'
# → identify   ✓ key    subject=alice
# → authorize  ✓ gate
# → decision   ALLOW
```

---

## Path B — Docker Compose

The compose stack wires Envoy → lwauth → echo upstream end-to-end:

```text
  curl ─► envoy:8000 ─(ext_authz gRPC)─► lwauth:9001
              └─(if allowed)──────────► echo:80
```

### Bring it up

```sh
docker compose -f deploy/docker/compose.yaml up --build --wait
```

`--wait` blocks until each container's healthcheck passes (the same
gate the CI smoke job uses).

### Verify

```sh
# Allow: valid API key
curl -isS http://localhost:8000/anything \
  -H 'x-api-key: demo-key-alice'
# → HTTP/1.1 200 OK
# → echo response body with method, headers, and X-User: alice
#   stamped on by the header-add mutator.

# Deny: missing key → Envoy returns 401 from lwauth's deny_reason
curl -isS http://localhost:8000/anything
# → HTTP/1.1 401 Unauthorized

# Direct lwauth metrics (skips Envoy)
curl -fsS http://localhost:8080/metrics | grep -E 'lwauth_(decisions_total|identifier_total)'
```

### Tear down

```sh
docker compose -f deploy/docker/compose.yaml down -v
```

---

## Path C — Kubernetes (Helm)

The chart at [deploy/helm/lightweightauth](../deploy/helm/lightweightauth/)
runs lwauth in either **file mode** (default; ConfigMap + fsnotify
reload) or **CRD mode** (`controller.enabled=true`; watches an
`AuthConfig` CR).

### Install (file mode, the simplest path)

```sh
# kind cluster (skip if you already have one)
kind create cluster --name lwauth-quickstart

# Install with the bundled CRDs and the demo inline config
helm install lwauth ./deploy/helm/lightweightauth \
  --create-namespace --namespace lwauth \
  --set image.tag=v1.0.0 \
  --set crds.install=true \
  --set-file config.inline=./quickstart.yaml
```

What you should see:

```sh
kubectl -n lwauth get pods
# → lwauth-xxxxx-yyyy   1/1   Running   0   30s

kubectl -n lwauth get crds | grep lightweightauth
# → authconfigs.lightweightauth.io
# → identityproviders.lightweightauth.io
# → plugins.lightweightauth.io
```

### Verify

```sh
# Forward the HTTP listener
kubectl -n lwauth port-forward svc/lwauth 8080:8080 &

# Same allow / deny calls as the local path
curl -isS -X POST http://localhost:8080/v1/authorize \
  -H 'Content-Type: application/json' \
  -d '{"method":"GET","path":"/things","headers":{"X-Api-Key":["demo-key-alice"]}}'
# → {"allow":true,"subject":"alice","identitySource":"key"}

curl -fsS http://localhost:8080/metrics | grep lwauth_decisions_total
```

### Switch to CRD mode (optional)

```sh
helm upgrade lwauth ./deploy/helm/lightweightauth \
  --namespace lwauth \
  --set controller.enabled=true \
  --set controller.watchNamespace=lwauth \
  --set controller.authConfigName=demo

# Apply a real AuthConfig
kubectl -n lwauth apply -f - <<'YAML'
apiVersion: lightweightauth.io/v1alpha1
kind: AuthConfig
metadata: { name: demo }
spec:
  identifiers:
    - name: key
      type: apikey
      config:
        headerName: X-Api-Key
        static:
          demo-key-alice: { subject: alice, roles: [admin] }
  authorizers:
    - { name: gate, type: rbac, config: { rolesFrom: "claim:roles", allow: [admin] } }
YAML
```

Verify the controller picked it up:

```sh
kubectl -n lwauth logs deploy/lwauth | grep -i 'authconfig.*demo'
# → ... reconciled AuthConfig=demo, swap=ok

# The same /v1/authorize call still works
curl -isS -X POST http://localhost:8080/v1/authorize \
  -H 'Content-Type: application/json' \
  -d '{"method":"GET","path":"/things","headers":{"X-Api-Key":["demo-key-alice"]}}'
```

### Clean up

```sh
helm uninstall lwauth -n lwauth
kubectl delete ns lwauth
kind delete cluster --name lwauth-quickstart
```

---

## Universal verification checklist

Regardless of which path you took, these four signals confirm v1.0
is serving correctly:

| Signal | Expected |
|---|---|
| `GET /healthz` | `200`, empty body |
| `POST /v1/authorize` with valid creds | `200`, body `"allow":true` |
| `POST /v1/authorize` with missing creds | non-2xx (401/403), body `"allow":false` + `reason` populated |
| `GET /metrics` | `lwauth_decisions_total` counters increase across the two calls above; `lwauth_decision_latency_seconds_bucket` populated |

If any of those fail, check:

- **Identifier did not match.** `lwauth_identifier_total{outcome="no_match"}`
  increments — confirm the request includes the credential the
  configured identifier expects (`Authorization: Bearer …` for `jwt`,
  `x-api-key: …` for `apikey`, etc.).
- **Authorizer denied.** Look at the `reason` body field and
  the audit JSONL (`kubectl logs` or stdout) for the structured
  decision record.
- **Config rejected on load.** `lwauthctl validate <path>` will
  print the parse / compile error before you start the binary.

## Where to go next

- **API reference:** [API.md](API.md) — every HTTP path and gRPC
  service the daemon exposes, with wire shapes and verification
  one-liners (`curl` + `grpcurl`).
- **Module catalog:** [modules/README.md](modules/README.md) — every
  `type:` string and a YAML sample.
- **Operations:** [DEPLOYMENT.md](DEPLOYMENT.md) — Envoy / Istio
  topologies, Helm values reference, hot reload, multi-tenant wiring.
- **Architecture:** [DESIGN.md](DESIGN.md) — pipeline, trust
  boundaries, the M0–M12 milestone log, and the post-v1 roadmap.
- **Security posture:** [security/v1.0-review.md](security/v1.0-review.md)
  — the v1.0 self-review and the tracked post-v1 follow-ups.
