# pkg/bundle

Policy bundle registry — pack, push, pull, and inspect OCI-based policy bundles.

## Usage

```go
import (
    "context"
    "github.com/mikeappsec/lightweightauth/pkg/bundle"
)

// Pack a bundle directory into a tar.gz archive
archive, err := bundle.Pack("/path/to/my-bundle/")

// Push to OCI registry
digest, err := bundle.Push(ctx, "/path/to/my-bundle/", bundle.PushOptions{
    Registry: "ghcr.io/myorg/lwauth-bundles/my-policy:v1.0",
    Username: "user",
    Password: "token",
})

// Pull from OCI registry
meta, err := bundle.Pull(ctx, "/tmp/output/", bundle.PullOptions{
    Registry: "ghcr.io/myorg/lwauth-bundles/my-policy",
    Tag:      "v1.0",
    Username: "user",
    Password: "token",
})

// Load and validate metadata
meta, err := bundle.LoadMetadata("/path/to/my-bundle/")
```

## Configuration

Bundle directory structure:
```
my-bundle/
├── bundle.yaml          # Metadata (name, version, description)
└── policies/
    ├── auth-config.yaml # AuthConfig YAML files
    └── rate-limit.yaml
```

### bundle.yaml

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | Bundle name (required) |
| `version` | string | Semantic version (required) |
| `description` | string | Human-readable description |
| `keywords` | []string | Searchable tags |
| `author` | string | Bundle author |
| `license` | string | SPDX license identifier |
| `policies` | []string | List of policy file paths |

## Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `MediaType` | `application/vnd.lwauth.bundle.v1.tar+gzip` | OCI media type |
| `ArtifactType` | `application/vnd.lwauth.bundle.v1` | OCI artifact type |
| `MaxBundleSize` | 10 MiB | Maximum uncompressed size |
| `maxEntries` | 1000 | Maximum tar entries |

## Features

- OCI artifact packaging via ORAS v2
- Security: rejects symlinks, hardlinks, absolute paths, `..` traversal
- Decompression bomb protection (LimitReader at MaxBundleSize + 1)
- Entry count limit (1000) prevents inode exhaustion
- Pre-checks total uncompressed size before packing
- Metadata validation with path safety checks
- Registry auth via username/password or environment variables

## How It Works

1. **Pack**: Reads `bundle.yaml`, validates metadata, creates a gzipped tar archive of the bundle directory (skipping symlinks, enforcing size limits).
2. **Push**: Packs the bundle, uploads as a single-layer OCI artifact with the lwauth media type.
3. **Pull**: Downloads the OCI artifact, unpacks into the destination directory with full path traversal protection.
4. **LoadMetadata**: Reads and validates `bundle.yaml` from a bundle directory.
