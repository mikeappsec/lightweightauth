// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package upstream

import (
	"sync"
	"time"
)

// RetryBudgetConfig configures a token-bucket retry budget.
//
// The budget is decoupled from request rate: callers acquire a token
// before each retry attempt (the *first* attempt is always free).
// Tokens refill at RefillPerSec up to Capacity. This matches the
// gRPC-LB retry budget intent — bound the worst-case retry traffic to
// a constant fraction of the steady-state request rate, regardless of
// how many concurrent failures stack up.
type RetryBudgetConfig struct {
	// Capacity is the maximum number of retry tokens the bucket holds.
	// Defaults to 10.
	Capacity float64
	// RefillPerSec is the steady-state retry rate. Defaults to 1.
	RefillPerSec float64
	// Now overrides time.Now for deterministic tests.
	Now func() time.Time
}

func (c *RetryBudgetConfig) withDefaults() {
	if c.Capacity <= 0 {
		c.Capacity = 10
	}
	if c.RefillPerSec <= 0 {
		c.RefillPerSec = 1
	}
	if c.Now == nil {
		c.Now = time.Now
	}
}

// RetryBudget is a thread-safe token bucket gating retry attempts.
// The zero value is not usable; construct via NewRetryBudget.
type RetryBudget struct {
	cfg RetryBudgetConfig

	mu     sync.Mutex
	tokens float64
	last   time.Time
}

// NewRetryBudget returns a budget filled to capacity.
func NewRetryBudget(cfg RetryBudgetConfig) *RetryBudget {
	cfg.withDefaults()
	return &RetryBudget{cfg: cfg, tokens: cfg.Capacity, last: cfg.Now()}
}

// TryAcquire returns true if a retry token was available and consumed.
// Callers must NOT call this for the first attempt — only for the
// 2nd, 3rd, ... attempt of the same logical request.
func (b *RetryBudget) TryAcquire() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.cfg.Now()
	elapsed := now.Sub(b.last).Seconds()
	if elapsed > 0 {
		b.tokens += elapsed * b.cfg.RefillPerSec
		if b.tokens > b.cfg.Capacity {
			b.tokens = b.cfg.Capacity
		}
		b.last = now
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// Tokens returns the (refill-aware) number of tokens currently in the
// bucket. Useful for metrics; not for control flow.
func (b *RetryBudget) Tokens() float64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.cfg.Now()
	elapsed := now.Sub(b.last).Seconds()
	t := b.tokens
	if elapsed > 0 {
		t += elapsed * b.cfg.RefillPerSec
		if t > b.cfg.Capacity {
			t = b.cfg.Capacity
		}
	}
	return t
}
