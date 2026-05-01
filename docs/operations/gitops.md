# GitOps workflow — promote, rollback, and drift detection

lwauth's CRD controller records `status.appliedVersion` and
`status.appliedDigest` on every successful compile+swap. The
`lwauthctl` CLI provides three commands that wrap the existing
`validate` / `diff` workflow into GitOps-friendly operations:

| Command | What it does |
|---------|-------------|
| `lwauthctl promote` | Validate, tag `spec.version`, compute digest, emit GitOps-ready YAML |
| `lwauthctl rollback` | Rewrite `spec.version` to a previous value, re-validate, emit YAML |
| `lwauthctl drift` | Compare local config against live `status.appliedVersion` / `appliedDigest` |

## Status fields

The controller sets these on `AuthConfig.status` after a successful
reconcile:

| Field | Value |
|-------|-------|
| `appliedVersion` | `spec.version` from the config that was compiled |
| `appliedDigest` | `sha256:<hex>` of the canonical JSON encoding of the spec |

```bash
kubectl -n payments get authconfig payments -o jsonpath='{.status}'
# {"appliedVersion":"2026-05-01","appliedDigest":"sha256:abc123...","ready":true,...}
```

## Promote

Validate the config, optionally stamp a version, and emit a
deployment-ready artifact:

```bash
# Explicit version:
lwauthctl promote --config authconfig.yaml --version "2026-05-01"

# Auto-generated timestamp version:
lwauthctl promote --config authconfig.yaml --auto-version

# Write to file instead of stdout:
lwauthctl promote --config authconfig.yaml --version "v42" --out promoted.json
```

Output is canonical JSON. Pipe through `yq -P` for YAML if your
GitOps repo prefers YAML:

```bash
lwauthctl promote --config authconfig.yaml --auto-version | yq -P > authconfig-promoted.yaml
git add authconfig-promoted.yaml && git commit -m "promote: $(date +%F)"
```

### CI integration

Add to your CI pipeline:

```yaml
# .github/workflows/promote.yaml
- name: Validate and promote
  run: |
    lwauthctl promote --config deploy/authconfig.yaml \
      --version "${{ github.sha }}" \
      --out deploy/authconfig-promoted.json
    git diff --exit-code deploy/ || (git add deploy/ && git commit -m "auto-promote ${{ github.sha }}")
```

## Rollback

Rewrite `spec.version` to a known-good value and re-validate:

```bash
lwauthctl rollback --config authconfig.yaml --to-version "2026-04-30" --out rolled-back.json
kubectl apply -f rolled-back.json
```

The controller will reconcile, compile the config (which hasn't
changed structurally — only `spec.version` is different), and update
`status.appliedVersion`.

!!! note
    Rollback does not restore a previous *config shape*. It tags the
    *current* config with an older version string. To restore a
    previous shape, check out the old file from Git and `kubectl apply`
    it directly.

## Drift detection

Compare local config against the live cluster:

```bash
lwauthctl drift --config authconfig.yaml --namespace payments --name payments
# OK     version: "2026-05-01"
# OK     digest:  sha256:abc123...
#
# ✓ no drift detected
```

If drift is detected, exit code is 1:

```bash
lwauthctl drift --config authconfig.yaml --namespace payments
# DRIFT  version: local="2026-05-02"  live="2026-05-01"
# DRIFT  digest:  local=sha256:def456...  live=sha256:abc123...
#
# ✗ drift detected — run `lwauthctl promote` + `kubectl apply` to reconcile
```

### CI drift check

```yaml
# .github/workflows/drift.yaml (scheduled, e.g. every 15 min)
- name: Check for config drift
  run: lwauthctl drift --config deploy/authconfig.yaml --namespace payments
```

A non-zero exit fails the workflow, alerting the team.

## How it fits together

```
  Git repo                      Kubernetes cluster
  ┌────────────┐               ┌──────────────────────┐
  │ authconfig │──promote──►   │ AuthConfig CR         │
  │   .yaml    │  (validate,   │   spec.version: v42   │
  │            │   tag, push)  │   status:             │
  │            │               │     appliedVersion: v42│
  │            │◄──drift───────│     appliedDigest: ... │
  └────────────┘               └──────────────────────┘
```

## References

- [DESIGN.md §7 Tier C](../DESIGN.md) — C2 (OPS-GITOPS-1) roadmap.
- [Admin-plane auth](admin-auth.md) — admin API for cache/revoke
  operations (C3).
- [`validate` / `diff` commands](../QUICKSTART.md) — existing CLI
  commands that `promote` wraps.
