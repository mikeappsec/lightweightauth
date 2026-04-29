# Cookbook recipes (placeholder)

This recipe is part of [DOC-COOKBOOK-1](../../docs/DESIGN.md) (Tier C, v1.1)
and lands in a follow-up commit. It will cover composing
[`openfga`](../modules/openfga.md) under
[`composite`](../modules/composite.md) on an existing Envoy deployment that
already runs `lwauth` as an `ext_authz` filter, including decision-cache
sizing, the `pkg/upstream` guard tuning, and the failure-mode matrix when
the OpenFGA Pod is unreachable.
