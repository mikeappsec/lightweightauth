// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

// Package buildinfo exposes compile-time and runtime build attributes
// the rest of lwauth needs for observability and operator-facing
// surfaces (startup log line, Prometheus gauge, /healthz banner).
//
// Concretely:
//
//   - Version / Commit are populated via -ldflags at link time by the
//     Makefile and Dockerfiles. When the binary is `go run`ed during
//     development they fall back to "dev"/"unknown".
//
//   - FIPSEnabled reports whether the running binary is using a
//     FIPS 140-3 validated cryptographic module. The check honours
//     both Go 1.24+'s in-tree FIPS module (selected by the
//     `GOFIPS140` environment variable at build time) and the older
//     `GOEXPERIMENT=boringcrypto` path. Operators flip the build
//     mode via `make fips`; the binary itself does no special
//     handling — this package just *reports* what the toolchain
//     produced so a deployment can fail closed if the wrong artifact
//     was promoted to a regulated cluster.
//
// The package has zero non-stdlib dependencies on purpose: it is
// imported from the very-low-level lwauthd startup path and from the
// metrics registry, which together are pulled into every flavour of
// the binary.
package buildinfo

import (
	"crypto/fips140"
	"runtime"
)

// Version is the semantic version stamped at link time. "dev" means
// the binary was built without -ldflags '-X .Version=...'.
var Version = "dev"

// Commit is the short git SHA stamped at link time.
var Commit = "unknown"

// Date is the build timestamp (RFC 3339) stamped at link time.
var Date = "unknown"

// FIPSEnabled reports whether the running binary is using a
// FIPS 140-3 validated cryptographic module.
//
// The Go toolchain populates [crypto/fips140.Enabled] from the
// `GOFIPS140` build-time selector (Go 1.24+); when unset it returns
// false. The legacy `GOEXPERIMENT=boringcrypto` build also reports
// true through this surface because Go's boringcrypto path is the
// previous-generation FIPS-validated module.
//
// Operators verify deployment correctness with the
// `lwauth_fips_enabled` Prometheus gauge or the startup log line —
// see docs/operations/fips.md.
func FIPSEnabled() bool { return fips140.Enabled() }

// GoVersion is the Go toolchain version baked into the binary.
// Useful for the startup log line so operators can tell at a glance
// whether the deployed image was built with the expected toolchain.
func GoVersion() string { return runtime.Version() }

// Summary returns a single-line description suitable for a startup
// log entry: `lwauth dev (unknown) go1.26.2 fips=true`.
func Summary() string {
	fips := "false"
	if FIPSEnabled() {
		fips = "true"
	}
	return "lwauth " + Version + " (" + Commit + ") " + GoVersion() + " fips=" + fips
}
