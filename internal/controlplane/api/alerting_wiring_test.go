// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package api_test

import "testing"

// TestWithAlertingAfterNewServer reproduces the exact wiring main.go uses:
// NewServer (which registers alert routes) followed by an unconditional
// WithAlerting call. registerRoutes already registers the alert routes, so
// WithAlerting must not register them again — http.ServeMux panics on a
// duplicate pattern registration, which crashed the control plane on boot.
func TestWithAlertingAfterNewServer(t *testing.T) {
	s := newTestServer(t)
	s.WithAlerting(nil, nil)
}
