// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

// Package conformance is a reusable test harness for authors of
// LightweightAuth plugins.
//
// Vendor this package into your plugin's test suite and call the relevant
// Contract function from a regular *testing.T test:
//
//	func TestMyIdentifier(t *testing.T) {
//	    conformance.IdentifierContract(t, newMyIdentifier(t), conformance.IdentifierOpts{
//	        ValidRequest:   reqWithGoodCreds(),
//	        NoMatchRequest: reqWithoutCreds(),
//	        InvalidRequest: reqWithBadSignature(),
//	    })
//	}
//
// The harness exercises the contract documented in pkg/module/module.go and
// pkg/module/errors.go:
//
//   - Name() is non-empty and stable across calls.
//   - Methods are nil-Request safe (no panic; error returned).
//   - Methods are concurrent-safe (no race on shared state under -race).
//   - Methods do not retain references to the *Request after returning
//     (mutating Request.Context post-call must not panic the module on a
//     subsequent call).
//   - Cancelled / deadline-exceeded contexts are honoured without panic.
//   - Sentinel errors (ErrNoMatch, ErrInvalidCredential, ErrForbidden) are
//     returned via fmt.Errorf("...: %w", ...) so errors.Is works.
//
// The harness uses only the public pkg/module API, so a third-party plugin
// repo can vendor it without depending on lwauth internals.
package conformance
