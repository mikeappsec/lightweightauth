# Issues found during the 2026-04-30 dry-run of `cookbook/gate-upstream-service.md`

Three bugs and two recipe paper-cuts surfaced while walking the cookbook
end-to-end on (a) Docker Desktop's bundled k8s and (b) a kind+Cilium
cluster. Filed here as draft upstream issues; copy each section into a
GitHub issue when ready.

---

## 1. Helm chart: namespace-scoped Role can't grant access to cluster-scoped `IdentityProvider` CRD

**Status:** ✅ fixed in this changeset — see
[deploy/helm/lightweightauth/templates/rbac.yaml](../../deploy/helm/lightweightauth/templates/rbac.yaml)
and the regression tests `TestRBAC_NamespaceScopeStillEmitsClusterRoleForIdentityProvider`
/ `TestRBAC_OptOutOfIdentityProviderClusterRole` in
[helm_render_test.go](../../deploy/helm/lightweightauth/helm_render_test.go).
The chart now always emits a small `ClusterRole`/`ClusterRoleBinding`
for `identityproviders` (gate-able with
`controllerRBAC.identityProviderClusterRole.enabled=false` for users
who bind that permission out-of-band). The namespace-scoped Role no
longer references `identityproviders`.

**Severity:** medium — every user who follows the cookbook with
`controller.enabled=true` and `controller.watchNamespace=<ns>` hits this
on first install. Pods sit `Running 0/1` with readiness 503 forever
until they read the controller log.

### Repro

Stock chart, default values, just enable the controller:

```bash
helm install lwauth ./deploy/helm/lightweightauth \
  --namespace lwauth-demo \
  --set controller.enabled=true \
  --set controller.watchNamespace=lwauth-demo \
  --set controller.authConfigName=demo
```

### Symptom

```
kubectl -n lwauth-demo logs deploy/lwauth
…
ERROR lwauthd err="manager: failed to wait for authconfig caches to sync
  kind source: *v1alpha1.IdentityProvider: timed out waiting for cache
  to be synced for Kind *v1alpha1.IdentityProvider"
```

### Root cause

[`deploy/helm/lightweightauth/templates/rbac.yaml`](../../deploy/helm/lightweightauth/templates/rbac.yaml)
emits a namespace-scoped `Role` when both `controllerRBAC.preferNamespaceScope=true`
(the default) and `controller.watchNamespace` is set. The Role grants:

```yaml
- apiGroups: ["lightweightauth.io"]
  resources: ["authconfigs", "authpolicies", "identityproviders"]
  verbs: ["get", "list", "watch"]
```

But `IdentityProvider` is **cluster-scoped** in
[`api/crd/identityprovider_types.go`](../../api/crd/identityprovider_types.go)
— a namespace-scoped Role cannot grant list/watch on a cluster-scoped
resource, so the informer cache sync fails and the manager never
becomes Ready.

### Suggested fix

Pick one:

1. **Always emit a `ClusterRole` for `identityproviders`** (split the
   rules so `authconfigs`/`authpolicies` stay namespace-scoped when
   requested, but `identityproviders` always gets cluster scope).
2. **Make `IdentityProvider` namespace-scoped** if there's no design
   reason for cluster scope.
3. **Validate the combination** in `_helpers.tpl` and fail the render
   with a clear message ("`controllerRBAC.preferNamespaceScope=true`
   is incompatible with the cluster-scoped IdentityProvider CRD").

(1) is the lowest-risk change. (2) is the cleanest if it's compatible
with how `IdentityProvider` is intended to be referenced.

### Workaround

Add `--set controllerRBAC.preferNamespaceScope=false` to the helm
install. The cookbook now documents this.

---

## 2. AuthConfig `status` writes a flat `ready` bool instead of `conditions[]`

**Status:** ✅ fixed in this changeset.
[`AuthConfigStatus`](../../api/crd/v1alpha1/types.go) now carries a
standard `Conditions []metav1.Condition` field; the reconciler in
[`internal/controller/authconfig.go`](../../internal/controller/authconfig.go)
sets the `Ready` condition (with reasons `Compiled`, `CompileError`,
`IdPRefError`) via `meta.SetStatusCondition` through a new `setReady`
helper. The flat `Ready` bool is preserved as a deprecated mirror for
one release. `kubectl wait --for=condition=Ready authconfig/demo`
works against the resulting CRs; the CRD schema in
[`crds.yaml`](../../deploy/helm/lightweightauth/templates/crds.yaml)
was updated to declare the `conditions` field and a printer column
that reads `.status.conditions[?(@.type=="Ready")].status`. New
assertions in [`authconfig_test.go`](../../internal/controller/authconfig_test.go)
pin the condition shape on both happy and compile-error paths.

**Severity:** low — cosmetic, but breaks every `kubectl wait
--for=condition=Ready authconfig/...` users will reflexively try, and
the cookbook itself recommends exactly that command.

### Repro

```bash
kubectl -n lwauth-demo apply -f authconfig.yaml
kubectl -n lwauth-demo wait authconfig/demo --for=condition=Ready --timeout=60s
# error: timed out waiting for the condition on authconfigs/demo

kubectl -n lwauth-demo get authconfig demo -o jsonpath='{.status}'
# {"message":"compiled and swapped","observedGeneration":1,"ready":true}
```

The engine compiled fine and the gateway works (probes 5.1/5.2 pass);
only `kubectl wait` is misled.

### Root cause

[`internal/controller/authconfig.go`](../../internal/controller/authconfig.go)
sets `Status.Ready: true` directly (lines 91, 105, 124) instead of
appending a `metav1.Condition{Type: "Ready", Status: "True", …}` to
`Status.Conditions`.

### Suggested fix

Add a `Conditions []metav1.Condition` field to the `AuthConfigStatus`
type and update via `meta.SetStatusCondition(...)`. Keep `Ready` as a
deprecated mirror for one release, then drop it. Same change applies
to `AuthPolicy` and `IdentityProvider` if they share the pattern.

This is also the idiomatic shape for any future GitOps tooling
(Argo/Flux health checks default to reading `conditions[]`).

---

## 3. Cookbook: `mccutchen/go-httpbin` Pod fails with `exec '-port': executable file not found`

**Severity:** low — first-step blocker, breaks the whole walkthrough
until the user reads container logs.

### Repro

The cookbook's step 1 deployment:

```yaml
containers:
  - name: httpbin
    image: mccutchen/go-httpbin:v2.15.0
    args: ["-port", "8000"]
```

### Symptom

```
Last State:  Terminated
  Reason:    ContainerCannotRun
  Exit Code: 127
  Message:   OCI runtime create failed: …
             exec: "-port": executable file not found in $PATH
```

The `mccutchen/go-httpbin` image declares no `ENTRYPOINT`, so Kubernetes
treats `args[0]` as the executable.

### Fix

Add `command: ["go-httpbin"]` to the container spec. Already applied
to [docs/cookbook/gate-upstream-service.md](../cookbook/gate-upstream-service.md).

---

## 4. Cookbook: `envoyproxy/envoy:v1.37.3` is not a published Docker Hub tag

**Severity:** low — second-step blocker.

```
Failed to pull image "envoyproxy/envoy:v1.37.3":
  manifest for envoyproxy/envoy:v1.37.3 not found: manifest unknown
```

The recipe was written speculatively. `v1.32-latest` exists and works.
Already swapped in the cookbook.

---

## 5. Cookbook prerequisites: Docker Desktop / stock kind silently no-ops NetworkPolicy

Already documented in the recipe, but worth re-emphasising for the
cookbook landing page: probes 5.3 and 5.4 are the **only** thing that
proves the gating is real, and both will return `200` instead of `000`
on a CNI that ignores NetworkPolicy. The recipe now ships an optional
"kind + Cilium" subsection that gives users a working local cluster in
~3 minutes; consider promoting that to a top-level `LOCAL_DEV.md`.

---

## Verification artifacts

Both clusters used during the dry-run have been torn down. The exact
manifests applied are reproduced verbatim in the recipe; the
non-obvious overrides were:

| Override | Why |
|---|---|
| `image.repository=lwauth, image.tag=dev` | Local image build, not yet published to GHCR |
| `controllerRBAC.preferNamespaceScope=false` | Issue #1 above |
| `replicaCount=1` | Single-node demo cluster |
| Envoy image `v1.32-latest` | Issue #4 above |
| httpbin `command: ["go-httpbin"]` | Issue #3 above |
