// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package api

import "testing"

// TestValidateHost_FailsClosedOnResolutionFailure is a regression test for
// a bypass where a DNS resolution failure was treated as "allow": an
// attacker controlling the queried domain's DNS can make the
// validation-time lookup fail on demand (e.g. SERVFAIL) while a later
// lookup from the actual outbound client succeeds with an
// internal/metadata IP, skipping the IP-range checks entirely. A
// resolution failure must be rejected, not passed through.
//
// "this-host-does-not-exist.invalid" uses the RFC 2606-reserved .invalid
// TLD, which is guaranteed to never resolve — deterministic regardless of
// whether the test environment has live network access.
func TestValidateHost_FailsClosedOnResolutionFailure(t *testing.T) {
	t.Parallel()
	if err := validateHost("this-host-does-not-exist.invalid", true); err == nil {
		t.Fatal("expected validateHost to fail closed when DNS resolution fails, got nil (allowed)")
	}
}
