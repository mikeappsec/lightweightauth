// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package cache

import (
	"context"
	"time"
)

// NoOp is a [Cache] that stores nothing: every Get is a miss and every Set
// and Delete succeeds without effect. It is the safe default when caching is
// disabled for a module, so callers never need a nil check.
type NoOp struct{}

// Get always reports a clean miss.
func (NoOp) Get(context.Context, string) ([]byte, bool, error) { return nil, false, nil }

// Set discards the value.
func (NoOp) Set(context.Context, string, []byte, time.Duration) error { return nil }

// Delete is a no-op.
func (NoOp) Delete(context.Context, string) error { return nil }

// noop is the shared instance returned by [NoOpCache].
var noop Cache = NoOp{}

// NoOpCache returns a shared no-op [Cache].
func NoOpCache() Cache { return noop }
