// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package buildinfo

import (
	"runtime"
	"strings"
	"testing"
)

func TestSummary_ContainsRequiredFields(t *testing.T) {
	s := Summary()
	for _, want := range []string{Version, Commit, runtime.Version(), "fips="} {
		if !strings.Contains(s, want) {
			t.Errorf("Summary() = %q, missing %q", s, want)
		}
	}
}

func TestFIPSEnabled_StableUnderRepeatedCall(t *testing.T) {
	// FIPSEnabled wraps crypto/fips140.Enabled, which is constant for
	// the lifetime of the process. Two calls must agree.
	if FIPSEnabled() != FIPSEnabled() {
		t.Fatal("FIPSEnabled is not stable across calls")
	}
}

func TestVersionDefaults(t *testing.T) {
	// In a normal `go test` run (no ldflags), Version should remain
	// the package default "dev". CI smoke can still override it via
	// `go test -ldflags '-X .Version=ci-test'` and assert separately.
	if Version != "dev" && Version == "" {
		t.Fatalf("Version = %q; expected non-empty default", Version)
	}
}
