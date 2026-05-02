// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package conformance

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/mikeappsec/lightweightauth/pkg/module"
)

// AuthorizerOpts configures AuthorizerContract.
type AuthorizerOpts struct {
	// AllowRequest + AllowIdentity must yield a Decision with Allow == true.
	AllowRequest  *module.Request
	AllowIdentity *module.Identity

	// DenyRequest + DenyIdentity, if both non-nil, must yield either
	// (Decision{Allow:false}, nil) or (nil, errors.Is(_, ErrForbidden)).
	DenyRequest  *module.Request
	DenyIdentity *module.Identity

	Concurrency int
	MaxLatency  time.Duration
}

// AuthorizerContract asserts that az honours the module.Authorizer contract.
func AuthorizerContract(t *testing.T, az module.Authorizer, opts AuthorizerOpts) {
	t.Helper()
	if az == nil {
		t.Fatal("conformance: nil Authorizer")
	}
	if opts.AllowRequest == nil || opts.AllowIdentity == nil {
		t.Fatal("conformance: AuthorizerOpts.AllowRequest + AllowIdentity required")
	}
	if opts.Concurrency <= 0 {
		opts.Concurrency = 32
	}
	if opts.MaxLatency <= 0 {
		opts.MaxLatency = 2 * time.Second
	}

	t.Run("Name_NonEmpty_Stable", func(t *testing.T) {
		n1 := az.Name()
		if n1 == "" {
			t.Fatal("Name() returned empty string")
		}
		if n2 := az.Name(); n1 != n2 {
			t.Fatalf("Name() not stable: %q then %q", n1, n2)
		}
	})

	t.Run("NilRequest_NoPanic", func(t *testing.T) {
		// The pipeline never passes a nil Identity to Authorize, so we
		// only require defence against nil *Request here. We use a
		// minimal non-nil identity to exercise the path.
		defer mustNotPanic(t, "Authorize(nil request)")
		_, _ = az.Authorize(context.Background(), nil, cloneIdentity(opts.AllowIdentity))
	})

	t.Run("Allow_ReturnsAllowDecision", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), opts.MaxLatency)
		defer cancel()
		start := time.Now()
		dec, err := az.Authorize(ctx,
			cloneRequest(opts.AllowRequest), cloneIdentity(opts.AllowIdentity))
		if err != nil {
			t.Fatalf("Authorize(allow): %v", err)
		}
		if dec == nil {
			t.Fatal("Authorize returned nil Decision with nil error")
		}
		if !dec.Allow {
			t.Errorf("expected Allow=true, got Allow=false reason=%q", dec.Reason)
		}
		if d := time.Since(start); d > opts.MaxLatency {
			t.Errorf("Authorize took %s, exceeds MaxLatency %s", d, opts.MaxLatency)
		}
	})

	if opts.DenyRequest != nil && opts.DenyIdentity != nil {
		t.Run("Deny_AllowFalseOrForbidden", func(t *testing.T) {
			dec, err := az.Authorize(context.Background(),
				cloneRequest(opts.DenyRequest), cloneIdentity(opts.DenyIdentity))
			switch {
			case err == nil && dec != nil && !dec.Allow:
				// Soft deny — perfectly fine.
			case errors.Is(err, module.ErrForbidden):
				// Sentinel deny — also fine.
			default:
				t.Fatalf("expected Allow=false or ErrForbidden; got dec=%+v err=%v", dec, err)
			}
		})
	}

	t.Run("CancelledContext_NoPanic", func(t *testing.T) {
		defer mustNotPanic(t, "Authorize(cancelled ctx)")
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, _ = az.Authorize(ctx,
			cloneRequest(opts.AllowRequest), cloneIdentity(opts.AllowIdentity))
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
				dec, err := az.Authorize(context.Background(),
					cloneRequest(opts.AllowRequest), cloneIdentity(opts.AllowIdentity))
				if err != nil {
					errs <- err
					return
				}
				if dec == nil || !dec.Allow {
					errs <- fmt.Errorf("unexpected non-allow under concurrency: %+v", dec)
				}
			}()
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			t.Errorf("concurrent Authorize: %v", err)
		}
	})
}
