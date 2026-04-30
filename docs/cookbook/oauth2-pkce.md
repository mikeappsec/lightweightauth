# OAuth 2.0 Authorization Code + PKCE with lwauth-idp

End-to-end recipe: deploy the lwauth gateway, the lwauth-idp issuer,
and a protected backend on a local kind cluster, then drive the full
PKCE flow from a Python script. The gateway accepts only requests
carrying a JWT minted by the IdP; everything else gets a 401.

| Layer | Component | Image |
|---|---|---|
| IdP | `lwauth-idp` (this recipe ships v0.5 with PKCE) | `lwauth-idp:dev` |
| Gateway + ext_authz | Envoy + `lwauth` | `envoyproxy/envoy:v1.32-latest`, `lwauth:dev` |
| Backend | `go-httpbin` | `ghcr.io/mccutchen/go-httpbin:v2.15.0` |

What you get when this works:

```
-- PKCE: verifier=CiI5tQkUN_vM.. challenge=qlxzVwC4fTlq..
-- authorize: 302 -> code=lWFj4aPKyjkp.. state=xyz123
-- token:     200 access_token=eyJhbGciOiJFUzI1Ni.. expires_in=900s id_token=yes
-- gateway:   GET /get with bearer       -> 200
-- gateway:   GET /get without bearer    -> 401
-- gateway:   GET /get with tampered JWT -> 401

PASS
```

## Prerequisites

- Docker Desktop + `kind` ≥ 0.31
- `kubectl`, `helm`, `python3`
- Local clones of `lightweightauth` and `lightweightauth-idp` side by
  side (paths in this guide assume `D:\coding\` but adjust for your
  layout).

## 1. Build the two images

The IdP and the lwauth core both build to local images that we then
load into kind (`imagePullPolicy: IfNotPresent` everywhere).

```powershell
# core (already built if you ran another cookbook today)
cd D:\coding\LightWeightAuth
docker build -t lwauth:dev .

# IdP
cd D:\coding\lightweightauth-idp
docker build -t lwauth-idp:dev .
```

## 2. Bring up kind + Cilium

We reuse the kind+Cilium config from the `gate-upstream-service`
cookbook. Cilium is what lets NetworkPolicy actually deny — Docker
Desktop's stock kindnet silently no-ops it.

```powershell
kind create cluster --config D:\coding\LightWeightAuth\examples\cookbook\gate-upstream-service\kind-cilium.yaml
helm repo add cilium https://helm.cilium.io
helm install cilium cilium/cilium --version 1.19.3 -n kube-system `
  --set kubeProxyReplacement=true `
  --set k8sServiceHost=lwauth-control-plane --set k8sServicePort=6443 `
  --wait --timeout 5m

kind load docker-image lwauth:dev --name lwauth
kind load docker-image lwauth-idp:dev --name lwauth
docker pull ghcr.io/mccutchen/go-httpbin:v2.15.0
kind load docker-image ghcr.io/mccutchen/go-httpbin:v2.15.0 --name lwauth
```

## 3. Deploy the IdP and the backend

```powershell
cd D:\coding\LightWeightAuth
kubectl apply -f examples/cookbook/oauth2-pkce/idp.yaml
kubectl apply -f examples/cookbook/oauth2-pkce/backend.yaml
```

The IdP config is hardcoded for the dryrun:

| Field | Value |
|---|---|
| Issuer URL | `http://lwauth-idp.demo.svc.cluster.local:9090` |
| Client ID | `demo-client` |
| Allowed redirect URIs | `http://localhost:8765/callback`, `http://127.0.0.1:8765/callback` |
| Audience baked into JWTs | `lwauth-demo` |
| Demo users | `alice / wonderland`, `bob / builder` |
| Signing alg | `ES256` (single P-256 key generated at boot) |
| Code TTL | 60 s |
| Access-token TTL | 15 min |

> **Don't ship this to staging.** `lwauth-idp` v0.5 stores passwords in
> plaintext and regenerates the signing key on every boot. It's a
> teaching-and-testing IdP; replace with a real one for anything else.

## 4. Install lwauth + apply the AuthConfig

The chart's `gateway.*` block renders an Envoy Pod that delegates
authorization to lwauth. The values file in `examples/` enables it and
points at the `backend` service.

```powershell
helm install lwauth ./deploy/helm/lightweightauth -n demo `
  -f examples/cookbook/oauth2-pkce/values.yaml --wait --timeout 3m
kubectl apply -f examples/cookbook/oauth2-pkce/authconfig.yaml
kubectl wait -n demo authconfig/demo --for=condition=Ready --timeout=30s
```

The AuthConfig wires identity to lwauth-idp via JWT verification and
authorization to the `rbac` module on the `scopes` array claim:

```yaml
identifiers:
  - name: jwt
    type: jwt
    config:
      jwksUrl:   http://lwauth-idp.demo.svc.cluster.local:9090/.well-known/jwks.json
      issuerUrl: http://lwauth-idp.demo.svc.cluster.local:9090
      audiences: [lwauth-demo]
authorizers:
  - name: gate
    type: rbac
    config:
      rolesFrom: claim:scopes
      allow:     [openid]
```

> **Why `scopes` (array) instead of `scope` (space-string)?** The
> standard claim is `scope` per RFC 6749 §3.3 — a single
> space-separated string. The lwauth `rbac` module reads roles
> directly from the claims map without splitting strings, so we mirror
> the value as a `scopes: []string` array. The IdP emits both
> claims; downstream consumers that expect the canonical `scope`
> string are unaffected.

## 5. Drive the flow

```powershell
python examples\cookbook\oauth2-pkce\run_flow.py
```

What the script does — every step is plain stdlib (`urllib`,
`hashlib`, `secrets`, `subprocess`):

1. Starts two `kubectl port-forward` children (IdP → 9090, gateway →
   8080) and waits for each port to accept TCP.
2. Generates a 32-byte PKCE verifier, derives the S256 challenge.
3. Submits `username=alice`, `password=wonderland` plus all the OAuth
   params (`response_type=code`, `code_challenge_method=S256`, …) to
   `/oauth2/authorize`. Captures the `code` from the 302 `Location`
   header.
4. Exchanges the code at `/oauth2/token` with the original verifier.
   The IdP recomputes `b64url(sha256(verifier))` and compares with the
   stored challenge in constant time.
5. Calls the gateway with the access token (`Authorization: Bearer
   <jwt>`) — must return 200.
6. Calls the gateway with no bearer and with a tampered bearer — both
   must return 401.

The port-forwards are torn down in a `finally` block so a mid-flow
exception never leaks them.

## 6. Verify the audit trail

```powershell
kubectl logs -n demo deploy/lwauth | Select-String '"msg":"audit"' | Select-Object -Last 3
```

You should see one `decision=allow` record for alice and two
`decision=error` records (no creds + tampered JWT). Each line carries
the `subject`, `identity_source`, `authorizer`, and `latency_ms` —
this is the same surface §5 of `DESIGN.md` calls out for SLO/SOC
correlation.

## 7. Tear down

```powershell
helm uninstall lwauth -n demo
kubectl delete -f examples/cookbook/oauth2-pkce/authconfig.yaml
kubectl delete -f examples/cookbook/oauth2-pkce/backend.yaml
kubectl delete -f examples/cookbook/oauth2-pkce/idp.yaml
kind delete cluster --name lwauth   # if you're done with the cluster
```

## What this exercises

| Concern | How it's covered |
|---|---|
| **Authorization Code + PKCE** | `/oauth2/authorize` requires `code_challenge_method=S256`; `/oauth2/token` rejects missing/wrong verifier with `invalid_grant`. |
| **Issuer pinning** | `jwt.issuerUrl` in AuthConfig is checked exactly; tokens minted with any other `iss` (e.g. an attacker-run lookalike IdP) are rejected before policy. |
| **Audience pinning** | Tokens for any audience other than `lwauth-demo` are rejected. |
| **Single-use codes** | `/oauth2/token` deletes the code on exchange regardless of outcome; `TestTokenRejectsReusedCode` proves replays return 400. |
| **Signature verification** | Tampering the last 4 chars of the JWT fails `ecdsa.Verify` against the JWKS-published P-256 key. |
| **State / CSRF** | `state=xyz123` is echoed back on the redirect — the script asserts it. A real client would compare against its own session state. |
| **JWKS hot-load** | The gateway's lwauth process fetches the IdP's JWKS via the cluster-internal Service URL on first verify, caches it with a 10-min refresh. Restart the IdP and the new `kid` flows in within the refresh window. |

## Known limitations of v0.5

- Plaintext password store — dev only. The `pkg/userstore` interface
  for SQL/LDAP backends is the next IdP increment.
- No refresh tokens. The token endpoint mints a 15-minute access
  token; clients re-run the full flow to refresh.
- No client_secret — public clients with PKCE are the only kind. Add
  `client_secret_basic` / `client_secret_post` when you ship the
  confidential-client surface.
- Single-process state (codes live in a `map+sync.Mutex`). Multi-
  replica HA needs a backing store; tracked under §11.4 in
  `DESIGN.md`.

## Files in this recipe

| Path | Purpose |
|---|---|
| `idp.yaml` | Namespace + Deployment + Service for `lwauth-idp` |
| `backend.yaml` | go-httpbin Deployment + Service |
| `authconfig.yaml` | AuthConfig with `jwt` identifier + `rbac` authorizer |
| `values.yaml` | Helm overrides (gateway on, upstream=`backend`, NodePort) |
| `run_flow.py` | Python 3 stdlib driver — six probes, exit 1 on any failure |
