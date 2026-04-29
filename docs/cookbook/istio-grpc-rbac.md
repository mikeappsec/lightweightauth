# Istio + lwauth + RBAC for gRPC

You run gRPC services on Istio, your IdP issues signed JWTs, and you
want a coarse role gate at the mesh edge that the service code does
not have to know about. This recipe lands lwauth as an Istio
[`extensionProviders`] target, points one or more
[`AuthorizationPolicy`] resources at it, and drops a single
[`AuthConfig`] CR in front of the workload.

The result is a path you can prove on the wire with `grpcurl`:

- A request without a JWT → `Unauthenticated`, no daemon I/O on the workload.
- A JWT for a `viewer` calling a write method → `PermissionDenied`.
- A JWT for an `admin` → the call reaches the upstream.

[`extensionProviders`]: https://istio.io/latest/docs/tasks/security/authorization/authz-custom/
[`AuthorizationPolicy`]: https://istio.io/latest/docs/reference/config/security/authorization-policy/
[`AuthConfig`]: ../modules/README.md

## What this recipe assumes

- Istio **1.22+** in `default` profile (the
  `extensionProviders` API is stable from 1.16, the gRPC
  `CheckRequest` shape is stable from 1.18).
- A Keycloak / Auth0 / Okta-style IdP that publishes a JWKS endpoint
  and emits signed JWTs whose payload includes a `roles` array. If
  your IdP nests roles (e.g. Keycloak's `realm_access.roles`), the
  [`rbac`](../modules/rbac.md) `rolesFrom` selector handles dotted
  paths — see step 3.
- A gRPC workload `payments-api` in namespace `payments` that exposes
  the `payments.v1.PaymentService` service.
- `kubectl`, `helm` 3.12+, and [`grpcurl`] on your workstation for the
  verification step.

[`grpcurl`]: https://github.com/fullstorydev/grpcurl

This recipe does **not** cover terminating user mTLS at the gateway
(see [`mtls`](../modules/mtls.md) and the
[Envoy guide](../deployment/envoy.md) §3 instead) or end-to-end
service-to-service mTLS (Istio's default `STRICT` PeerAuthentication
already handles it; nothing in this recipe interferes with it).

## 1. Install lwauth in `lwauth-system`

A two-replica deployment with the controller enabled is the
production-shaped baseline. CRD mode is what makes the rest of this
recipe possible — file mode would force you to redeploy the daemon
every time the policy changed.

```bash
helm install lwauth oci://ghcr.io/mikeappsec/lightweightauth/charts/lightweightauth \
  --namespace lwauth-system --create-namespace \
  --set controller.enabled=true \
  --set controller.watchNamespace=payments \
  --set replicaCount=2 \
  --set crds.install=true
```

The chart defaults already match what Istio wants on the wire: HTTP
on `:8080`, gRPC `ext_authz` on `:9001`. See
[deploy/helm/lightweightauth/values.yaml](https://github.com/mikeappsec/lightweightauth/blob/main/deploy/helm/lightweightauth/values.yaml)
for the full surface. `failure_mode_allow` is decided on the **Istio**
side (step 2), not on the daemon.

!!! warning "Network policy first"
    Apply your `NetworkPolicy` before the workload starts trusting
    lwauth. Anyone who can reach `lwauth.lwauth-system.svc:9001` can
    issue `Check` calls; the controller-side snapshot stream is gated,
    but the data-plane port is intentionally not — Envoy is the trust
    boundary, and only Envoy / the mesh should reach `:9001`.

## 2. Wire lwauth into the mesh

Istio learns about lwauth through one block in `MeshConfig`. Edit the
existing `IstioOperator` (or the equivalent `istioctl install
--set`) to add:

```yaml
spec:
  meshConfig:
    extensionProviders:
      - name: lwauth-authz
        envoyExtAuthzGrpc:
          # Must match the lwauth gRPC Service.
          service: lwauth.lwauth-system.svc.cluster.local
          port: 9001
          # Cap how long the proxy waits before failing closed. Match
          # your p99 decision-latency SLO + a safety margin; 250 ms
          # is what the Envoy guide recommends as a sane default.
          timeout: 0.25s
          # SEC-PROXY-1 parity (see Envoy guide §3): lwauth's HMAC
          # identifier and any body-keyed CEL/OPA policy need the
          # body. If you only ever do JWT + RBAC, drop this block.
          includeRequestBodyInCheck:
            maxRequestBytes: 1048576
            allowPartialMessage: false
            packAsBytes: true
```

Apply, then confirm Istiod accepted the provider:

```bash
istioctl proxy-config bootstrap deploy/istio-ingressgateway -n istio-system | \
  grep -A2 lwauth-authz
```

If the provider is not listed, the rest of this recipe will silently
no-op — Istio renders `AuthorizationPolicy` resources that reference
an unknown provider as **allow-all**. Verify before you proceed.

## 3. Author the `AuthConfig`

Drop the CR into the `payments` namespace. The controller picks it
up, compiles the engine, and streams the snapshot to every replica
through the broker (see
[modules/configstream.md](../modules/configstream.md)).

```yaml
# payments-authconfig.yaml
apiVersion: lightweightauth.io/v1alpha1
kind: AuthConfig
metadata:
  name: payments
  namespace: payments
spec:
  # The pipeline runs in this exact order: identify, authorize.
  identifiers:
    - name: bearer
      type: jwt
      config:
        # OIDC discovery is fine; the daemon caches the JWKS in
        # process and refreshes lazily on kid miss (no more than
        # every 5 minutes by default).
        issuerUrl: https://idp.example.com/realms/internal
        audiences: [payments-api]

  authorizers:
    - name: gate
      type: rbac
      config:
        # Keycloak nests roles under realm_access.roles. If your IdP
        # puts them at the top level, this is just `claim:roles`.
        rolesFrom: claim:realm_access.roles
        # The role list is intentionally short. Per-resource policy
        # belongs in `openfga` or `cel`, not here.
        allow:
          - payments-admin
          - payments-writer

  # Per-tenant decision cache. 30 s positive TTL is fine for RBAC
  # because the role list does not change inside a token's lifetime;
  # if you wire `openfga` later you will want to re-tune.
  cache:
    key: [sub, method, path]
    ttl: 30s
    negativeTtl: 5s
```

```bash
kubectl apply -f payments-authconfig.yaml
```

Confirm the engine compiled:

```bash
kubectl -n lwauth-system logs deploy/lwauth -c lwauth | \
  grep -E 'config: compiled|engine: hot-swap'
```

A typo in `cache.key` does **not** silently degrade the cache key
(unknown fields are rejected at config-load time);
the controller surfaces the error on the CR's `status.conditions` and
keeps the previous good snapshot live until you fix it.

## 4. Bind it to the workload with `AuthorizationPolicy`

```yaml
# payments-authz.yaml
apiVersion: security.istio.io/v1
kind: AuthorizationPolicy
metadata:
  name: payments-delegate
  namespace: payments
spec:
  # CUSTOM action means: hand the request to `provider.name` and
  # honour its allow/deny. The selector matches the workload, not
  # the route.
  action: CUSTOM
  provider:
    name: lwauth-authz
  selector:
    matchLabels:
      app.kubernetes.io/name: payments-api
  rules:
    - to:
        - operation:
            # Restrict to the gRPC service prefix so health probes
            # and grpc.reflection.v1.ServerReflection do not fan out
            # to lwauth. Adjust to match your actual service.
            paths: ["/payments.v1.PaymentService/*"]
```

```bash
kubectl apply -f payments-authz.yaml
```

!!! danger "CUSTOM is allow-deny, not allow-only"
    A `CUSTOM` policy whose provider is unreachable resolves according
    to the `failOpen` setting on the provider config (default `false`),
    not the policy. Keep the timeout tight (step 2 sets 250 ms), keep
    the daemon at ≥ 2 replicas with a PDB, and do **not** flip
    `failOpen: true` to paper over flakiness.

## 5. Verify on the wire

```bash
# 1. No token at all → lwauth returns Unauthenticated; Istio surfaces
#    that as the gRPC status, the client sees code 16.
grpcurl -plaintext payments.example.com:443 \
  payments.v1.PaymentService/ListPayments
# expect: Code: Unauthenticated

# 2. A JWT minted for `payments-viewer` calling a write method →
#    lwauth returns PermissionDenied (code 7).
TOKEN=$(./mint-jwt.sh --role payments-viewer)
grpcurl -plaintext -H "authorization: Bearer $TOKEN" \
  payments.example.com:443 \
  payments.v1.PaymentService/CreatePayment
# expect: Code: PermissionDenied

# 3. A JWT minted for `payments-writer` → upstream sees the call.
TOKEN=$(./mint-jwt.sh --role payments-writer)
grpcurl -plaintext -H "authorization: Bearer $TOKEN" -d '{"amount":42}' \
  payments.example.com:443 \
  payments.v1.PaymentService/CreatePayment
# expect: a normal Payment response; lwauth audit log records
#         sub + method.
```

The same three calls are a good shape for a CI smoke test: each one
exits non-zero on the wrong outcome and surfaces the lwauth-side
verbose reason on the `x-lwauth-reason` response header (which the
gateway strips at the public edge if you followed the
[Envoy guide §4.4](../deployment/envoy.md#44-strip-internal-headers-at-the-edge)).

## 6. What to look at next

- **Per-method policy.** RBAC's allow-list applies to every path on
  the selector. If you need "viewers can `Get*` but not `Create*`",
  layer [`cel`](../modules/cel.md) under
  [`composite`](../modules/composite.md) `firstAllow` so the cheap
  RBAC check runs first.
- **Browser / refresh-token flows.** This recipe only handles the
  service-call path. Browser flows belong in
  [`oauth2`](../modules/oauth2.md), not here.
- **OpenFGA for resource-level checks.** When you outgrow role
  gates, the next recipe is
  [OpenFGA on existing Envoy](openfga-on-envoy.md), which composes
  cleanly under the same `composite` you used in the previous bullet.

## References

- [`jwt` identifier](../modules/jwt.md)
- [`rbac` authorizer](../modules/rbac.md)
- [Envoy + lwauth deployment guide](../deployment/envoy.md) — the
  Istio sidecar shares this configuration surface.
- [DESIGN.md §3](../DESIGN.md) — Mode A topology lwauth runs in here.
- Istio reference for [CUSTOM authorization providers](https://istio.io/latest/docs/tasks/security/authorization/authz-custom/).
