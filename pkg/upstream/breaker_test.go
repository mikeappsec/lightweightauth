// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package upstream

import (
	"errors"
	"testing"
	"time"
)

// fakeClock returns a function value that reads from a *time.Time so
// tests can advance time without sleeping.
func fakeClock(t *time.Time) func() time.Time {
	return func() time.Time { return *t }
}

func TestBreaker_TripsAfterThreshold(t *testing.T) {
	now := time.Unix(0, 0)
	b := NewBreaker(BreakerConfig{
		FailureThreshold: 3,
		CoolDown:         10 * time.Second,
		Now:              fakeClock(&now),
	})

	if got := b.State(); got != StateClosed {
		t.Fatalf("initial state = %s, want closed", got)
	}
	for i := 0; i < 2; i++ {
		if err := b.Allow(); err != nil {
			t.Fatalf("Allow #%d: %v", i, err)
		}
		b.OnFailure()
	}
	if got := b.State(); got != StateClosed {
		t.Fatalf("after 2 failures: state = %s, want closed", got)
	}
	if err := b.Allow(); err != nil {
		t.Fatalf("3rd Allow: %v", err)
	}
	b.OnFailure()
	if got := b.State(); got != StateOpen {
		t.Fatalf("after 3 failures: state = %s, want open", got)
	}
	if err := b.Allow(); !errors.Is(err, ErrCircuitOpen) {
		t.Fatalf("Allow on open: err = %v, want ErrCircuitOpen", err)
	}
}

func TestBreaker_HalfOpenSuccessCloses(t *testing.T) {
	now := time.Unix(0, 0)
	b := NewBreaker(BreakerConfig{
		FailureThreshold:  2,
		CoolDown:          5 * time.Second,
		HalfOpenSuccesses: 2,
		Now:               fakeClock(&now),
	})
	// Trip.
	for i := 0; i < 2; i++ {
		_ = b.Allow()
		b.OnFailure()
	}
	if b.State() != StateOpen {
		t.Fatal("not open after 2 failures")
	}
	// Within cool-down: still rejects.
	now = now.Add(4 * time.Second)
	if err := b.Allow(); !errors.Is(err, ErrCircuitOpen) {
		t.Fatalf("within cool-down: err = %v, want ErrCircuitOpen", err)
	}
	// After cool-down: transitions to half-open and admits trial.
	now = now.Add(2 * time.Second)
	if err := b.Allow(); err != nil {
		t.Fatalf("after cool-down: err = %v, want nil", err)
	}
	if b.State() != StateHalfOpen {
		t.Fatalf("state = %s, want half_open", b.State())
	}
	b.OnSuccess() // 1st of 2
	if b.State() != StateHalfOpen {
		t.Fatalf("after 1 success: state = %s, want half_open", b.State())
	}
	b.OnSuccess() // 2nd of 2 -> close
	if b.State() != StateClosed {
		t.Fatalf("after 2 successes: state = %s, want closed", b.State())
	}
}

func TestBreaker_HalfOpenFailureReopens(t *testing.T) {
	now := time.Unix(0, 0)
	b := NewBreaker(BreakerConfig{
		FailureThreshold: 1,
		CoolDown:         time.Second,
		Now:              fakeClock(&now),
	})
	_ = b.Allow()
	b.OnFailure()
	now = now.Add(2 * time.Second)
	if err := b.Allow(); err != nil {
		t.Fatalf("trial Allow: %v", err)
	}
	if b.State() != StateHalfOpen {
		t.Fatal("expected half-open")
	}
	b.OnFailure()
	if b.State() != StateOpen {
		t.Fatalf("state after half-open failure = %s, want open", b.State())
	}
	// Cool-down restarted at the new openedAt.
	now = now.Add(500 * time.Millisecond)
	if err := b.Allow(); !errors.Is(err, ErrCircuitOpen) {
		t.Fatalf("expected ErrCircuitOpen after re-open, got %v", err)
	}
}

func TestBreaker_SuccessResetsFailures(t *testing.T) {
	b := NewBreaker(BreakerConfig{FailureThreshold: 3})
	_ = b.Allow()
	b.OnFailure()
	_ = b.Allow()
	b.OnFailure()
	b.OnSuccess() // reset
	for i := 0; i < 2; i++ {
		_ = b.Allow()
		b.OnFailure()
	}
	if b.State() != StateClosed {
		t.Fatalf("state = %s, want closed (reset should have prevented trip)", b.State())
	}
}

func TestBreaker_Defaults(t *testing.T) {
	b := NewBreaker(BreakerConfig{})
	if b.cfg.FailureThreshold != 5 || b.cfg.CoolDown != 30*time.Second || b.cfg.HalfOpenSuccesses != 1 {
		t.Fatalf("defaults = %+v", b.cfg)
	}
}
