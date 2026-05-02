// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package upstream

import (
	"context"
	"errors"
	"math"
	"time"
)

// Retryable is the predicate Guard uses to decide whether a non-nil
// error returned by fn should (a) count as a breaker failure and
// (b) be eligible for retry. Returning false means the error is a
// definitive answer from the upstream (4xx, validation error, ...) —
// neither retried nor counted against the breaker.
//
// The default (used when Retryable is nil) classifies every error
// as retryable EXCEPT context.Canceled and context.DeadlineExceeded
// from the parent ctx — those are caller-driven and must not erode
// breaker health.
type Retryable func(error) bool

// DefaultRetryable is the predicate used when GuardConfig.Retryable
// is nil.
func DefaultRetryable(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	return true
}

// GuardConfig combines a breaker, a retry budget, and bounded
// exponential backoff into one resilience policy.
type GuardConfig struct {
	Breaker BreakerConfig
	Budget  RetryBudgetConfig
	// MaxRetries is the maximum number of *additional* attempts after
	// the first call (so MaxRetries=2 means up to 3 total attempts).
	// Defaults to 0 (no retries; pure circuit breaker).
	MaxRetries int
	// BackoffBase is the initial sleep before the second attempt.
	// The Nth retry waits BackoffBase * 2^(N-1), capped at BackoffMax.
	// A zero value disables backoff entirely (used by unit tests for
	// fast retry loops).
	BackoffBase time.Duration
	// BackoffMax bounds the per-retry sleep. Ignored when BackoffBase
	// is zero.
	BackoffMax time.Duration
	// Retryable classifies errors; see Retryable. Default = DefaultRetryable.
	Retryable Retryable
}

func (c *GuardConfig) withDefaults() {
	if c.Retryable == nil {
		c.Retryable = DefaultRetryable
	}
}

// Guard composes a Breaker + RetryBudget and runs a function under
// both. It is goroutine-safe and intended to be long-lived (one Guard
// per upstream target — e.g. one per IdP, one per OpenFGA store).
type Guard struct {
	cfg     GuardConfig
	Breaker *Breaker
	Budget  *RetryBudget
}

// NewGuard returns a Guard with its breaker and budget pre-built from
// cfg. Both can be inspected via the public Breaker / Budget fields,
// which is useful for metrics (e.g. expose .State() as a gauge).
func NewGuard(cfg GuardConfig) *Guard {
	cfg.withDefaults()
	return &Guard{
		cfg:     cfg,
		Breaker: NewBreaker(cfg.Breaker),
		Budget:  NewRetryBudget(cfg.Budget),
	}
}

// Do runs fn under the breaker + budget policy. It returns nil on the
// first success; ErrCircuitOpen if the breaker rejected the very first
// attempt; or the last error fn returned (which may itself wrap
// ErrRetryBudgetExceeded if retries were denied by the budget).
//
// fn MUST honor ctx — Do itself does not enforce a per-attempt
// timeout; that is the caller's responsibility (typically a
// context.WithTimeout() shared by all attempts, or a per-attempt
// timeout established inside fn).
func (g *Guard) Do(ctx context.Context, fn func(context.Context) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := g.Breaker.Allow(); err != nil {
		return err
	}
	var lastErr error
	for attempt := 0; attempt <= g.cfg.MaxRetries; attempt++ {
		if attempt > 0 {
			if !g.Budget.TryAcquire() {
				if lastErr != nil {
					return errors.Join(lastErr, ErrRetryBudgetExceeded)
				}
				return ErrRetryBudgetExceeded
			}
			if d := g.backoff(attempt); d > 0 {
				if !sleepCtx(ctx, d) {
					return ctx.Err()
				}
			}
			// Re-check the breaker — it may have tripped on a
			// concurrent failure while we slept.
			if err := g.Breaker.Allow(); err != nil {
				return err
			}
		}
		err := fn(ctx)
		if err == nil {
			g.Breaker.OnSuccess()
			return nil
		}
		lastErr = err
		if !g.cfg.Retryable(err) {
			// Definitive answer; do not count against breaker
			// health and do not retry.
			return err
		}
		g.Breaker.OnFailure()
		// Don't loop again if the parent ctx is done.
		if ctx.Err() != nil {
			return err
		}
	}
	return lastErr
}

func (g *Guard) backoff(retry int) time.Duration {
	if g.cfg.BackoffBase <= 0 {
		return 0
	}
	shift := retry - 1
	if shift < 0 {
		shift = 0
	}
	if shift > 30 {
		return g.cfg.BackoffMax
	}
	d := time.Duration(float64(g.cfg.BackoffBase) * math.Pow(2, float64(shift)))
	if g.cfg.BackoffMax > 0 && (d > g.cfg.BackoffMax || d <= 0) {
		return g.cfg.BackoffMax
	}
	return d
}

// sleepCtx sleeps for d, returning false if ctx is cancelled first.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-ctx.Done():
		return false
	}
}
