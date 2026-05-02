// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package conformance

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/mikeappsec/lightweightauth/pkg/module"
)

// MutatorOpts configures MutatorContract.
type MutatorOpts struct {
	// Request + Identity + Decision are passed to Mutate. Decision will
	// be cloned per sub-test so the mutator's mutations don't leak
	// across sub-tests.
	Request  *module.Request
	Identity *module.Identity
	Decision *module.Decision

	Concurrency int
	MaxLatency  time.Duration
}

// MutatorContract asserts module.ResponseMutator semantics.
func MutatorContract(t *testing.T, m module.ResponseMutator, opts MutatorOpts) {
	t.Helper()
	if m == nil {
		t.Fatal("conformance: nil ResponseMutator")
	}
	if opts.Request == nil || opts.Decision == nil {
		t.Fatal("conformance: MutatorOpts.Request + Decision required")
	}
	if opts.Concurrency <= 0 {
		opts.Concurrency = 32
	}
	if opts.MaxLatency <= 0 {
		opts.MaxLatency = 2 * time.Second
	}

	t.Run("Name_NonEmpty_Stable", func(t *testing.T) {
		n1 := m.Name()
		if n1 == "" {
			t.Fatal("Name() returned empty string")
		}
		if n2 := m.Name(); n1 != n2 {
			t.Fatalf("Name() not stable: %q then %q", n1, n2)
		}
	})

	t.Run("NilRequest_NoPanic", func(t *testing.T) {
		// Pipeline guarantees non-nil Identity + Decision to Mutate, so
		// we only require nil-Request safety. Most mutators legitimately
		// no-op on a nil request; we just require no panic.
		defer mustNotPanic(t, "Mutate(nil request)")
		_ = m.Mutate(context.Background(), nil, cloneIdentity(opts.Identity), cloneDecision(opts.Decision))
	})

	t.Run("HappyPath", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), opts.MaxLatency)
		defer cancel()
		dec := cloneDecision(opts.Decision)
		start := time.Now()
		if err := m.Mutate(ctx, cloneRequest(opts.Request), cloneIdentity(opts.Identity), dec); err != nil {
			t.Fatalf("Mutate: %v", err)
		}
		if d := time.Since(start); d > opts.MaxLatency {
			t.Errorf("Mutate took %s, exceeds MaxLatency %s", d, opts.MaxLatency)
		}
	})

	t.Run("CancelledContext_NoPanic", func(t *testing.T) {
		defer mustNotPanic(t, "Mutate(cancelled ctx)")
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_ = m.Mutate(ctx, cloneRequest(opts.Request), cloneIdentity(opts.Identity), cloneDecision(opts.Decision))
	})

	t.Run("Concurrent_NoRace", func(t *testing.T) {
		var wg sync.WaitGroup
		errs := make(chan error, opts.Concurrency)
		for i := 0; i < opts.Concurrency; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer func() {
					if r := recover(); r != nil {
						errs <- panicErr(r)
					}
				}()
				if err := m.Mutate(context.Background(),
					cloneRequest(opts.Request),
					cloneIdentity(opts.Identity),
					cloneDecision(opts.Decision)); err != nil {
					errs <- err
				}
			}()
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			t.Errorf("concurrent Mutate: %v", err)
		}
	})
}
