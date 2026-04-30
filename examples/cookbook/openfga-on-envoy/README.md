# OpenFGA-on-Envoy recipe — example manifests

Companion artifacts to
[`docs/cookbook/openfga-on-envoy.md`](../../../docs/cookbook/openfga-on-envoy.md).
The recipe walks through each file; this README is just the index.

| File | Purpose |
|---|---|
| [openfga.yaml](openfga.yaml) | OpenFGA Deployment+Service. In-memory datastore, `OPENFGA_AUTHN_METHOD=none` — local-only. |
| [fga-bootstrap.sh](fga-bootstrap.sh) | One-shot script: creates a store, writes a tiny `documents` model, writes two tuples (`alice viewer doc:42`, `carol owner doc:42`), prints `RESULT_STORE` / `RESULT_MODEL` for capture. |
| [authconfig.yaml](authconfig.yaml) | `composite/anyOf` with an `rbac` admin fast-path and an `openfga` ReBAC child. `STORE_ID_PLACEHOLDER` / `MODEL_ID_PLACEHOLDER` are rewritten by the recipe before `kubectl apply`. |

The recipe reuses two manifests from the
[`gate-upstream-service`](../gate-upstream-service/) folder:

- `kind-cilium.yaml` for the local cluster shape.
- `backend.yaml` for the httpbin upstream the gateway forwards to.
