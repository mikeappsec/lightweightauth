# Cookbook recipes (placeholder)

This recipe is part of [DOC-COOKBOOK-1](../../docs/DESIGN.md) (Tier C, v1.1)
and lands in a follow-up commit. It will cover the overlapping-key window
that `pkg/identity/hmac` supports, the operator workflow for rolling a
fresh secret into the active set, lwauthctl invocations, and how the
audit trail proves the old secret was retired without an unsigned-window
gap.
