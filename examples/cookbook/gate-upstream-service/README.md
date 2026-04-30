# gate-upstream-service — recipe manifests

These manifests are the worked example referenced by
[docs/cookbook/gate-upstream-service.md](../../../docs/cookbook/gate-upstream-service.md).
They are copied verbatim from the cookbook so a CI smoke test (or a
hurried operator) can `kubectl apply -f` them without re-reading the
prose.

| File | What it is |
|------|-----------|
| [`kind-cilium.yaml`](kind-cilium.yaml) | Optional kind cluster config that disables kindnet + kube-proxy so Cilium can be the CNI and actually enforce NetworkPolicy. |
| [`backend.yaml`](backend.yaml) | The httpbin upstream + Service. |
| [`authconfig.yaml`](authconfig.yaml) | Demo `AuthConfig` (apikey identifier + rbac authorizer). |
| [`netpol-backend.yaml`](netpol-backend.yaml) | The NetworkPolicy that closes the bypass — only the gateway can dial `:8000`. |

The Envoy gateway YAML is **not shipped here** any more — set
`gateway.enabled=true` on the lightweightauth Helm chart instead and
it renders the ConfigMap, Deployment, Service, and a matching
NetworkPolicy peer for you. See the cookbook step 3 for the one-line
helm-upgrade incantation.
