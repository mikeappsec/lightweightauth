// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package ratelimit

import "github.com/mikeappsec/lightweightauth/pkg/httputil"

// compile-time interface check: *Limiter satisfies httputil.KeyedLimiter.
var _ httputil.KeyedLimiter = (*Limiter)(nil)

// AsKeyedLimiter returns an httputil.KeyedLimiter that delegates to l.
// If l is nil, it returns a no-op limiter that always allows. This is
// useful when wiring the pipeline rate limiter into HTTP middleware.
func AsKeyedLimiter(l *Limiter) httputil.KeyedLimiter {
	if l == nil {
		return allowAll{}
	}
	return l
}

type allowAll struct{}

func (allowAll) Allow(string) bool { return true }
