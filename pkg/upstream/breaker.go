package upstream

import (
	"sync"
	"time"
)

// State is the breaker's current circuit state.
type State int

const (
	// StateClosed is the normal state: calls flow through, failures are
	// counted, and the breaker trips to StateOpen once the configured
	// FailureThreshold is reached.
	StateClosed State = iota
	// StateOpen rejects every call with ErrCircuitOpen until CoolDown
	// has elapsed since the trip; the next Allow then transitions to
	// StateHalfOpen.
	StateOpen
	// StateHalfOpen lets through a single trial call; success
	// increments a counter that closes the circuit once
	// HalfOpenSuccesses is reached, while a failure re-opens it
	// immediately and resets the cool-down.
	StateHalfOpen
)

// String renders the state for logs and metrics labels.
func (s State) String() string {
	switch s {
	case StateClosed:
		return "closed"
	case StateOpen:
		return "open"
	case StateHalfOpen:
		return "half_open"
	default:
		return "unknown"
	}
}

// BreakerConfig is the operator-tunable knob set for a single circuit
// breaker. Zero values pick safe defaults so callers can construct a
// breaker with `NewBreaker(BreakerConfig{})` for tests.
type BreakerConfig struct {
	// FailureThreshold is the number of consecutive failed calls that
	// trips a closed breaker into StateOpen. Defaults to 5.
	FailureThreshold int
	// CoolDown is the duration the breaker spends in StateOpen before
	// it admits a single trial call (transitioning to StateHalfOpen).
	// Defaults to 30s.
	CoolDown time.Duration
	// HalfOpenSuccesses is the number of consecutive successful trial
	// calls in StateHalfOpen required to fully close the breaker.
	// Defaults to 1 — the first success closes the circuit.
	HalfOpenSuccesses int
	// Now overrides time.Now for deterministic tests.
	Now func() time.Time
}

func (c *BreakerConfig) withDefaults() {
	if c.FailureThreshold <= 0 {
		c.FailureThreshold = 5
	}
	if c.CoolDown <= 0 {
		c.CoolDown = 30 * time.Second
	}
	if c.HalfOpenSuccesses <= 0 {
		c.HalfOpenSuccesses = 1
	}
	if c.Now == nil {
		c.Now = time.Now
	}
}

// Breaker is a thread-safe Hystrix-style circuit breaker. The zero
// value is not usable; construct via NewBreaker.
type Breaker struct {
	cfg BreakerConfig

	mu        sync.Mutex
	state     State
	failures  int
	successes int // half-open trial successes
	openedAt  time.Time
}

// NewBreaker returns a breaker initialized in StateClosed.
func NewBreaker(cfg BreakerConfig) *Breaker {
	cfg.withDefaults()
	return &Breaker{cfg: cfg, state: StateClosed}
}

// State returns the current circuit state without mutating it.
func (b *Breaker) State() State {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.state
}

// Allow returns nil if the breaker permits a call, or ErrCircuitOpen
// if the circuit is open and the cool-down has not yet elapsed. A
// successful Allow in StateOpen transitions the breaker to
// StateHalfOpen; subsequent concurrent Allow calls in half-open still
// return nil so multiple goroutines can race the trial — the first
// failure / success result wins.
func (b *Breaker) Allow() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.state == StateOpen {
		if b.cfg.Now().Sub(b.openedAt) < b.cfg.CoolDown {
			return ErrCircuitOpen
		}
		// cool-down elapsed: admit trial calls.
		b.state = StateHalfOpen
		b.successes = 0
	}
	return nil
}

// OnSuccess records a successful upstream call. In StateClosed it
// resets the failure counter; in StateHalfOpen it increments the
// success counter and closes the circuit once the configured
// HalfOpenSuccesses is reached.
func (b *Breaker) OnSuccess() {
	b.mu.Lock()
	defer b.mu.Unlock()
	switch b.state {
	case StateClosed:
		b.failures = 0
	case StateHalfOpen:
		b.successes++
		if b.successes >= b.cfg.HalfOpenSuccesses {
			b.state = StateClosed
			b.failures = 0
			b.successes = 0
		}
	}
}

// OnFailure records a failed upstream call. In StateClosed it
// increments the failure counter and trips the breaker once the
// configured FailureThreshold is reached. In StateHalfOpen any single
// failure re-opens the breaker and restarts the cool-down.
func (b *Breaker) OnFailure() {
	b.mu.Lock()
	defer b.mu.Unlock()
	switch b.state {
	case StateClosed:
		b.failures++
		if b.failures >= b.cfg.FailureThreshold {
			b.state = StateOpen
			b.openedAt = b.cfg.Now()
		}
	case StateHalfOpen:
		b.state = StateOpen
		b.openedAt = b.cfg.Now()
		b.successes = 0
	}
}
