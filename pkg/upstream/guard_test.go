// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package upstream

import (
	"context"
	"errors"
	"testing"
	"time"
)

var errBoom = errors.New("boom")

func TestGuard_HappyPath(t *testing.T) {
	g := NewGuard(GuardConfig{})
	calls := 0
	err := g.Do(context.Background(), func(ctx context.Context) error {
		calls++
		return nil
	})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if calls != 1 {
		t.Fatalf("calls = %d, want 1", calls)
	}
}

func TestGuard_NonRetryableErrorReturnsImmediately(t *testing.T) {
	notRetryable := errors.New("definitive")
	g := NewGuard(GuardConfig{
		MaxRetries: 5,
		Retryable:  func(err error) bool { return !errors.Is(err, notRetryable) },
	})
	calls := 0
	err := g.Do(context.Background(), func(ctx context.Context) error {
		calls++
		return notRetryable
	})
	if !errors.Is(err, notRetryable) {
		t.Fatalf("err = %v, want %v", err, notRetryable)
	}
	if calls != 1 {
		t.Fatalf("calls = %d, want 1 (no retries on non-retryable)", calls)
	}
	// Non-retryable must NOT count against the breaker.
	if g.Breaker.State() != StateClosed {
		t.Fatalf("breaker = %s, want closed", g.Breaker.State())
	}
}

func TestGuard_RetriesUntilSuccess(t *testing.T) {
	g := NewGuard(GuardConfig{
		MaxRetries: 3,
		// BackoffBase = 0 → no sleeping.
		Budget: RetryBudgetConfig{Capacity: 10, RefillPerSec: 1},
	})
	calls := 0
	err := g.Do(context.Background(), func(ctx context.Context) error {
		calls++
		if calls < 3 {
			return errBoom
		}
		return nil
	})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if calls != 3 {
		t.Fatalf("calls = %d, want 3", calls)
	}
}

func TestGuard_GivesUpAfterMaxRetries(t *testing.T) {
	g := NewGuard(GuardConfig{
		MaxRetries: 2,
		Budget:     RetryBudgetConfig{Capacity: 10, RefillPerSec: 1},
	})
	calls := 0
	err := g.Do(context.Background(), func(ctx context.Context) error {
		calls++
		return errBoom
	})
	if !errors.Is(err, errBoom) {
		t.Fatalf("err = %v, want errBoom", err)
	}
	if calls != 3 { // 1 initial + 2 retries
		t.Fatalf("calls = %d, want 3", calls)
	}
}

func TestGuard_CircuitOpenRejectsImmediately(t *testing.T) {
	g := NewGuard(GuardConfig{
		Breaker:    BreakerConfig{FailureThreshold: 2, CoolDown: time.Hour},
		MaxRetries: 0,
	})
	// Trip via Do.
	for i := 0; i < 2; i++ {
		_ = g.Do(context.Background(), func(ctx context.Context) error { return errBoom })
	}
	if g.Breaker.State() != StateOpen {
		t.Fatalf("breaker = %s, want open", g.Breaker.State())
	}
	calls := 0
	err := g.Do(context.Background(), func(ctx context.Context) error {
		calls++
		return nil
	})
	if !errors.Is(err, ErrCircuitOpen) {
		t.Fatalf("err = %v, want ErrCircuitOpen", err)
	}
	if calls != 0 {
		t.Fatalf("calls = %d, want 0 (breaker should reject without dialing)", calls)
	}
}

func TestGuard_RetryBudgetExhaustionStopsRetries(t *testing.T) {
	g := NewGuard(GuardConfig{
		MaxRetries: 5,
		Budget:     RetryBudgetConfig{Capacity: 1, RefillPerSec: 0.0001},
	})
	calls := 0
	err := g.Do(context.Background(), func(ctx context.Context) error {
		calls++
		return errBoom
	})
	if !errors.Is(err, ErrRetryBudgetExceeded) {
		t.Fatalf("err = %v, want ErrRetryBudgetExceeded", err)
	}
	// 1 initial + 1 retry (capacity=1) = 2 calls before budget runs out.
	if calls != 2 {
		t.Fatalf("calls = %d, want 2", calls)
	}
	// Last fn error must still be reachable via errors.Is.
	if !errors.Is(err, errBoom) {
		t.Fatalf("err = %v, expected to wrap errBoom too", err)
	}
}

func TestGuard_ContextCancelledDuringBackoff(t *testing.T) {
	g := NewGuard(GuardConfig{
		MaxRetries:  3,
		BackoffBase: 50 * time.Millisecond,
		BackoffMax:  100 * time.Millisecond,
		Budget:      RetryBudgetConfig{Capacity: 10, RefillPerSec: 1},
	})
	ctx, cancel := context.WithCancel(context.Background())
	calls := 0
	go func() {
		time.Sleep(10 * time.Millisecond)
		cancel()
	}()
	err := g.Do(ctx, func(ctx context.Context) error {
		calls++
		return errBoom
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
}

func TestGuard_ContextCancelledBeforeStart(t *testing.T) {
	g := NewGuard(GuardConfig{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	calls := 0
	err := g.Do(ctx, func(ctx context.Context) error {
		calls++
		return nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if calls != 0 {
		t.Fatalf("calls = %d, want 0", calls)
	}
}

func TestGuard_BackoffSchedule(t *testing.T) {
	g := NewGuard(GuardConfig{
		BackoffBase: 100 * time.Millisecond,
		BackoffMax:  500 * time.Millisecond,
	})
	got := []time.Duration{
		g.backoff(1),
		g.backoff(2),
		g.backoff(3),
		g.backoff(4),
		g.backoff(50),
	}
	want := []time.Duration{
		100 * time.Millisecond,
		200 * time.Millisecond,
		400 * time.Millisecond,
		500 * time.Millisecond, // capped
		500 * time.Millisecond, // overflow guard
	}
	for i, w := range want {
		if got[i] != w {
			t.Errorf("backoff(%d) = %v, want %v", i+1, got[i], w)
		}
	}
}

func TestDefaultRetryable(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"random error", errors.New("x"), true},
		{"context.Canceled", context.Canceled, false},
		{"context.DeadlineExceeded", context.DeadlineExceeded, false},
		{"wrapped canceled", errors.Join(errors.New("foo"), context.Canceled), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := DefaultRetryable(tc.err); got != tc.want {
				t.Fatalf("DefaultRetryable(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}
