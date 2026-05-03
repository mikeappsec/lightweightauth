# pkg/buildinfo

Build metadata and FIPS compliance status for binary introspection.

## Usage

```go
import (
    "github.com/mikeappsec/lightweightauth/pkg/buildinfo"
)

info := buildinfo.Get()
fmt.Printf("Version: %s\n", info.Version)
fmt.Printf("Commit:  %s\n", info.Commit)
fmt.Printf("FIPS:    %v\n", info.FIPSEnabled)
fmt.Printf("Go:      %s\n", info.GoVersion)
fmt.Printf("Summary: %s\n", info.Summary())
```

## Fields

| Field | Type | Source | Description |
|-------|------|--------|-------------|
| `Version` | string | `-ldflags` | Semantic version (e.g. `v1.2.0`) |
| `Commit` | string | `-ldflags` | Git SHA at build time |
| `GoVersion` | string | `runtime.Version()` | Go toolchain version |
| `FIPSEnabled` | bool | build tag | `true` when built with FIPS tag |
| `BuildTime` | string | `-ldflags` | ISO 8601 build timestamp |

## Features

- Zero non-stdlib dependencies
- `Summary()` returns a one-line human-readable string (useful for startup logs)
- FIPS status derived at compile time via build tag (not runtime detection)
- All fields populated via linker flags (`-X`) at build time
- Safe defaults: empty strings when not injected

## How It Works

Package variables are set at compile time via `go build -ldflags`:

```bash
go build -ldflags "-X .../buildinfo.version=v1.2.0 -X .../buildinfo.commit=$(git rev-parse HEAD)"
```

`Get()` returns a snapshot struct. `FIPSEnabled` is a compile-time constant set by the `fips` build tag in `Dockerfile.fips`.
