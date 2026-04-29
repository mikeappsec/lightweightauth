# LightweightAuth Cookbook

End-to-end recipes for landing lightweightauth in real deployments. Each
recipe walks the full path from an empty cluster to a verified request,
calls out the failure modes operators hit in practice, and links to the
matching per-module reference under [../modules/](../modules/README.md)
for the deeper "why" once a recipe sends you in the right direction.

Pick a recipe by **what you already have**, not by what you want to add:

| Starting point                                         | Recipe |
| ------------------------------------------------------ | ------ |
| You have a workload Pod and want every request to arrive only through lwauth, on Kubernetes. | [Gate an upstream service through lwauth](gate-upstream-service.md) |
| You run gRPC services behind Istio and need RBAC at the edge. | [Istio + lwauth + RBAC for gRPC](istio-grpc-rbac.md) |
| You already terminate HTTP at Envoy and want fine-grained ReBAC. | [OpenFGA on an existing Envoy deployment](openfga-on-envoy.md) |
| You ship long-lived HMAC keys to clients and need to rotate them. | [Rotate HMAC secrets without downtime](rotate-hmac.md) |

## Conventions used in every recipe

- **`AuthConfig`** snippets are presented as YAML you can drop into a
  `kubectl apply`; the equivalent embedded-library wiring is shown in a
  collapsed block below the YAML.
- **Paths** start at the repository root unless otherwise noted.
- **Failure modes** are flagged with `!!!` admonitions when a mistake
  produces a working-looking system that is silently insecure. Read those
  even if you skim the rest.
- **Verification** at the end of each recipe is a copy-pasteable
  `curl` / `grpcurl` / `lwauthctl` command that exits non-zero if the
  recipe is broken — suitable for wiring into CI smoke tests.

## What is *not* here

- A tutorial-style "your first AuthConfig". That is
  [QUICKSTART.md](../QUICKSTART.md); recipes here assume you have a
  daemon running and are integrating it with something specific.
- The full `config:` reference for any one module. Each recipe links the
  matching page under `docs/modules/` for that.
- Decisions about *which* identifier or authorizer to use. That tree
  lives at the top of [modules/README.md](../modules/README.md).
