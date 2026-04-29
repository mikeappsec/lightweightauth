# Cookbook recipes (placeholder)

This recipe is part of [DOC-COOKBOOK-1](../../docs/DESIGN.md) (Tier C, v1.1)
and lands in a follow-up commit. It will cover landing lightweightauth on
an Istio mesh that already terminates client mTLS at the gateway, and
attaching an `rbac` authorizer to a gRPC service whose roles arrive on a
JWT claim.

Until then, the per-module references that compose this recipe are
already documented:

- Identifier — [JWT](../modules/jwt.md)
- Authorizer — [RBAC](../modules/rbac.md)
- Envoy wiring — [Envoy integration](../deployment/envoy.md)
