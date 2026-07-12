# pkg/buildinfo

Build metadata and FIPS compliance status for binary introspection.

## Usage

```go
import (
    "fmt"

    "github.com/mikeappsec/lightweightauth/pkg/buildinfo"
)

fmt.Printf("Version: %s\n", buildinfo.Version)
fmt.Printf("Commit:  %s\n", buildinfo.Commit)
fmt.Printf("Date:    %s\n", buildinfo.Date)
fmt.Printf("FIPS:    %v\n", buildinfo.FIPSEnabled())
fmt.Printf("Go:      %s\n", buildinfo.GoVersion())
fmt.Printf("Summary: %s\n", buildinfo.Summary())
```

There is no `Get()` function and no `Info` struct — everything is a
package-level `var` or zero-argument func.

## Fields

| Name | Kind | Source | Description |
|------|------|--------|-------------|
| `Version` | `var` (string) | `-ldflags` | Semantic version; defaults to `"dev"` if not injected |
| `Commit` | `var` (string) | `-ldflags` | Git SHA at build time; defaults to `"unknown"` |
| `Date` | `var` (string) | `-ldflags` | RFC 3339 build timestamp; defaults to `"unknown"` (there is no `BuildTime` field) |
| `FIPSEnabled()` | func → bool | `crypto/fips140.Enabled()` | Runtime check, not a compile-time constant — honors both `GOFIPS140` and legacy `GOEXPERIMENT=boringcrypto` |
| `GoVersion()` | func → string | `runtime.Version()` | Go toolchain version |
| `Summary()` | func → string | — | One-line startup-log string, e.g. `lwauth dev (unknown) go1.26.2 fips=true` |

## Features

- Zero non-stdlib dependencies
- `Summary()` returns a one-line human-readable string (useful for startup logs)
- `FIPSEnabled()` is a **runtime** check via `crypto/fips140.Enabled()`, not a build-tag constant
- `Version`/`Commit`/`Date` populated via linker flags (`-X`) at build time
- Safe defaults: `"dev"`/`"unknown"` when not injected

## How It Works

Package variables are set at compile time via `go build -ldflags`:

```bash
go build -ldflags "-X .../buildinfo.Version=v1.2.0 -X .../buildinfo.Commit=$(git rev-parse HEAD)"
```

`FIPSEnabled()` reports what the Go toolchain actually produced —
there's no separate `fips` build tag in this package; the check reads
`crypto/fips140.Enabled()` directly.

## Thread Safety

All exported functions and variables are safe for concurrent use. Package-level variables (`Version`, `Commit`, `Date`) are written once at link time and never mutated at runtime.
