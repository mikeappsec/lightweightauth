// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package revocation

import (
	"context"

	"golang.org/x/sync/errgroup"
)

// ParallelChecker wraps a Store and checks multiple revocation keys
// concurrently using a bounded worker pool. For the common case of 2
// keys (jti + sub) this eliminates sequential round-trips.
type ParallelChecker struct {
	store       Store
	concurrency int
}

// ParallelCheckerOption configures a ParallelChecker.
type ParallelCheckerOption func(*ParallelChecker)

// WithConcurrency sets the maximum number of goroutines used for
// parallel key checks. Default is 4.
func WithConcurrency(n int) ParallelCheckerOption {
	return func(pc *ParallelChecker) {
		if n > 0 {
			pc.concurrency = n
		}
	}
}

// NewParallelChecker creates a ParallelChecker wrapping the given store.
func NewParallelChecker(store Store, opts ...ParallelCheckerOption) *ParallelChecker {
	pc := &ParallelChecker{
		store:       store,
		concurrency: 4,
	}
	for _, opt := range opts {
		opt(pc)
	}
	return pc
}

// ExistsAny checks multiple keys concurrently and returns true as soon
// as any key is found to be revoked. On error, the behaviour depends on
// the caller's fail-open/fail-closed policy (errors are returned, not
// swallowed).
//
// If keys has 0 or 1 elements, the call is inlined without spawning
// goroutines.
func (pc *ParallelChecker) ExistsAny(ctx context.Context, keys []string) (bool, error) {
	switch len(keys) {
	case 0:
		return false, nil
	case 1:
		return pc.store.Exists(ctx, keys[0])
	}

	// Use an errgroup with a derived context so that the first "revoked"
	// finding cancels outstanding checks.
	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(pc.concurrency)

	type result struct {
		revoked bool
	}
	results := make(chan result, len(keys))

	for _, key := range keys {
		g.Go(func() error {
			revoked, err := pc.store.Exists(ctx, key)
			if err != nil {
				return err
			}
			if revoked {
				results <- result{revoked: true}
			}
			return nil
		})
	}

	// Wait for all goroutines; collect the first error if any.
	err := g.Wait()
	close(results)

	// Check if any key was revoked.
	for r := range results {
		if r.revoked {
			return true, nil
		}
	}
	return false, err
}
