// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

// Package upstream provides shared resilience primitives for every
// network-touching built-in module: a Hystrix-style circuit breaker, a
// gRPC-LB-style retry budget, and a small Do() helper that combines
// them with bounded exponential backoff.
//
// Today each module (oauth2-introspection, jwt JWKS fetch, openfga
// Check, IdP token endpoint, valkey backend) wires its own timeout but
// has no shared breaker. Under load, a slow IdP can chew up worker
// goroutines until every request is blocked on the same dead upstream.
// `pkg/upstream` is the M11 fix: one breaker per (module, target),
// shared retry-budget accounting, and explicit "is this error
// retryable?" semantics.
//
// Usage sketch:
//
//	g := upstream.NewGuard(upstream.GuardConfig{
//	    Breaker: upstream.BreakerConfig{
//	        FailureThreshold:  5,
//	        CoolDown:          30 * time.Second,
//	        HalfOpenSuccesses: 1,
//	    },
//	    Budget: upstream.RetryBudgetConfig{
//	        Capacity:     10,
//	        RefillPerSec: 1,
//	    },
//	    MaxRetries:  2,
//	    BackoffBase: 50 * time.Millisecond,
//	    BackoffMax:  500 * time.Millisecond,
//	})
//
//	err := g.Do(ctx, func(ctx context.Context) error {
//	    return callRemote(ctx)
//	})
//
// Errors:
//   - ErrCircuitOpen — the breaker rejected the call without dialing.
//     Callers should map this to module.ErrUpstream so the M5 negative
//     cache does not memoize it.
//   - context.DeadlineExceeded / context.Canceled propagate verbatim.
//   - Anything else is whatever fn returned (last attempt).
//
// The breaker counts attempts that returned a non-nil error and that
// the supplied Retryable predicate (or the default, which excludes
// context errors) classified as a real upstream failure. Successful
// calls reset the failure counter; in half-open state, the configured
// number of successes are required to fully close.
package upstream
