# Bundle — OCI policy bundle registry

Pack, push, pull, and inspect policy bundles as OCI artifacts. Bundles
package one or more `AuthConfig` YAML files into a versioned, signed,
registry-hosted artifact that `lwauthctl` or the CRD controller can
pull at deploy time.

**Source:** [pkg/bundle](https://github.com/mikeappsec/lightweightauth/blob/main/pkg/bundle/) — used by `lwauthctl bundle` subcommands.

## When to use

- Your policy team **versions and publishes** AuthConfigs independently
  from application deployments.
- You run a GitOps workflow where policies are built in CI, pushed to a
  container registry, and pulled by lwauth at startup.
- You need **tamper detection** — the OCI manifest digest proves the
  bundle hasn't been modified.

**Don't use** for single-file configs that live alongside the Helm
chart — just inline them in `values.yaml` or mount a ConfigMap.

## Bundle directory layout

```
my-bundle/
├── bundle.yaml           # Required: metadata
└── policies/
    ├── auth-config.yaml  # One or more AuthConfig files
    └── rate-limit.yaml
```

### bundle.yaml schema

```yaml
name: my-org-policy
version: "1.2.0"
description: "Production auth policies for the payments service"
author: "platform-team@example.com"
license: "Apache-2.0"
keywords:
  - payments
  - rbac
  - jwt
policies:
  - policies/auth-config.yaml
  - policies/rate-limit.yaml
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | yes | Bundle name (DNS-safe) |
| `version` | string | yes | Semantic version |
| `description` | string | no | Human-readable purpose |
| `author` | string | no | Bundle author/team |
| `license` | string | no | SPDX license identifier |
| `keywords` | []string | no | Searchable tags |
| `policies` | []string | yes | Relative paths to policy files |

## CLI usage

```bash
# Pack a bundle directory into a .tar.gz
lwauthctl bundle pack ./my-bundle/

# Push to OCI registry
lwauthctl bundle push ./my-bundle/ \
  --registry ghcr.io/myorg/lwauth-bundles/payments:v1.2.0

# Pull from registry
lwauthctl bundle pull ghcr.io/myorg/lwauth-bundles/payments:v1.2.0 \
  --output /etc/lwauth/bundles/

# Inspect metadata without pulling
lwauthctl bundle inspect ghcr.io/myorg/lwauth-bundles/payments:v1.2.0
```

## Security constraints

| Check | Limit | Effect |
|-------|-------|--------|
| Max uncompressed size | 10 MiB | Reject on pack/pull |
| Max tar entries | 1000 | Reject on unpack |
| Symlinks / hardlinks | Rejected | Tar entries with link headers are skipped |
| Path traversal (`..`) | Rejected | Entries with `..` components are rejected |
| Absolute paths | Rejected | Entries must be relative |

## OCI artifact details

| Property | Value |
|----------|-------|
| Media type | `application/vnd.lwauth.bundle.v1.tar+gzip` |
| Artifact type | `application/vnd.lwauth.bundle.v1` |
| Layers | Single layer (gzipped tar) |
| Registry protocol | ORAS v2 / OCI Distribution Spec 1.1 |

## Helm wiring (pull at startup)

```yaml
# values.yaml
config:
  bundleRef: ghcr.io/myorg/lwauth-bundles/payments:v1.2.0
  bundlePullSecret: lwauth-registry-creds
```

The init container pulls the bundle and mounts it at `/etc/lwauth/bundles/`;
the main container loads policies from that directory.

## GitOps workflow example

```yaml
# .github/workflows/policy-release.yml
on:
  push:
    paths: ['policies/**']
    branches: [main]

jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: |
          lwauthctl bundle pack ./policies/
          lwauthctl bundle push ./policies/ \
            --registry ghcr.io/${{ github.repository }}/policy:${{ github.sha }}
```

## References

- Source: [pkg/bundle/](https://github.com/mikeappsec/lightweightauth/blob/main/pkg/bundle/).
- CLI: [cmd/lwauthctl](https://github.com/mikeappsec/lightweightauth/tree/main/cmd/lwauthctl/).
