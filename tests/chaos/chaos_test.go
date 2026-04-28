//go:build chaos

// Package chaos_test validates LightweightAuth's upstream resilience
// posture under simulated fault injection. It is build-tag-gated
// (`chaos`) so the default `go test ./...` stays fast; nightly /
// pre-release runs invoke `make chaos`.
//
// Per DESIGN.md M12 slice 8 the v1.0 invariant is: under upstream
// faults (slow IdP, 500-ing OpenFGA, packet-loss to Valkey) the
// breaker opens, the retry budget bounds amplification, and clients
// see deterministic 503-equivalents instead of a fan-out melt-down.
//
// We exercise pkg/upstream.Guard directly with a controllable
// flakyUpstream stub. This is intentionally a narrower contract than
// end-to-end chaos: we are validating the resilience primitive that
// every real upstream (introspection, openfga, valkey, clientauth)
// composes, so failures here become failures in every consumer.
package chaos_test

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mikeappsec/lightweightauth/pkg/upstream"
)

// flakyUpstream is a controllable stub for an arbitrary upstream
// dependency. The behavior knobs are atomic so the test goroutine can
// flip them mid-flight (heal the IdP, induce a slow-down, etc.).
type flakyUpstream struct {
	// failProb in [0,1] expressed as parts-per-million for atomic
	// load/store. 1_000_000 == always fail.
	failPPM atomic.Int64
	// latency is a fixed sleep applied to every call (modeling a
	// "slow IdP"). Stored as nanoseconds.
	latencyNS atomic.Int64

	calls    atomic.Int64
	failures atomic.Int64
}

var errSimulated = errors.New("simulated upstream failure")

func (f *flakyUpstream) call(ctx context.Context) error {
	f.calls.Add(1)
	if d := time.Duration(f.latencyNS.Load()); d > 0 {
		t := time.NewTimer(d)
		defer t.Stop()
		select {
		case <-t.C:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	// Deterministic failure based on a per-call counter so tests are
	// reproducible — no randomness.
	if f.failPPM.Load() >= 1_000_000 {
		f.failures.Add(1)
		return errSimulated
	}
	return nil
}

func (f *flakyUpstream) heal()     { f.failPPM.Store(0) }
func (f *flakyUpstream) breakAll() { f.failPPM.Store(1_000_000) }

// ---------------------------------------------------------------------------
// Scenario 1: a 500-ing OpenFGA storm trips the breaker open and every
// subsequent call fast-fails with ErrCircuitOpen. This bounds the blast
// radius of an upstream outage to FailureThreshold real attempts plus
// retry-budget-permitted retries — the rest are served as deterministic
// 503-equivalents.
// ---------------------------------------------------------------------------
func TestChaos_BreakerOpensUnder500Storm(t *testing.T) {
	t.Parallel()
	up := &flakyUpstream{}
	up.breakAll()

	g := upstream.NewGuard(upstream.GuardConfig{
		Breaker: upstream.BreakerConfig{
			FailureThreshold: 5,
			CoolDown:         100 * time.Millisecond,
		},
		MaxRetries: 0, // pure breaker; no retry amplification
	})

	// Fire 1000 calls; only the first FailureThreshold should reach
	// the upstream — the rest must fast-fail with ErrCircuitOpen.
	const totalCalls = 1000
	circuitOpenSeen := 0
	for i := 0; i < totalCalls; i++ {
		err := g.Do(context.Background(), up.call)
		if errors.Is(err, upstream.ErrCircuitOpen) {
			circuitOpenSeen++
		}
	}

	upstreamCalls := up.calls.Load()
	if upstreamCalls > 5 {
		t.Fatalf("breaker did not bound upstream calls: got %d, want <=5", upstreamCalls)
	}
	if circuitOpenSeen < totalCalls-5 {
		t.Fatalf("expected at least %d ErrCircuitOpen rejections, got %d",
			totalCalls-5, circuitOpenSeen)
	}
	if got := g.Breaker.State(); got != upstream.StateOpen {
		t.Fatalf("breaker state = %s, want open", got)
	}
}

// ---------------------------------------------------------------------------
// Scenario 2: once the upstream heals, the breaker transitions
// open -> half-open -> closed and traffic resumes. Verifies recovery
// is automatic and bounded by CoolDown — no manual reset needed.
// ---------------------------------------------------------------------------
func TestChaos_BreakerRecoversWhenUpstreamHeals(t *testing.T) {
	t.Parallel()
	up := &flakyUpstream{}
	up.breakAll()

	g := upstream.NewGuard(upstream.GuardConfig{
		Breaker: upstream.BreakerConfig{
			FailureThreshold:  3,
			CoolDown:          50 * time.Millisecond,
			HalfOpenSuccesses: 1,
		},
	})

	// Trip it.
	for i := 0; i < 10; i++ {
		_ = g.Do(context.Background(), up.call)
	}
	if got := g.Breaker.State(); got != upstream.StateOpen {
		t.Fatalf("breaker did not open: state=%s", got)
	}

	// Heal upstream and wait out CoolDown.
	up.heal()
	time.Sleep(75 * time.Millisecond)

	// Next call admits the trial; success closes the circuit.
	if err := g.Do(context.Background(), up.call); err != nil {
		t.Fatalf("post-heal call failed: %v", err)
	}
	if got := g.Breaker.State(); got != upstream.StateClosed {
		t.Fatalf("breaker did not recover: state=%s", got)
	}
}

// ---------------------------------------------------------------------------
// Scenario 3: under sustained partial failure, the retry budget caps
// amplification. With MaxRetries=2 a naive retry policy would 3x the
// load on the upstream; the budget must clamp that to a configured
// per-second ceiling.
// ---------------------------------------------------------------------------
func TestChaos_RetryBudgetBoundsAmplification(t *testing.T) {
	t.Parallel()
	up := &flakyUpstream{}
	up.breakAll()

	const baseline = 100
	g := upstream.NewGuard(upstream.GuardConfig{
		Breaker: upstream.BreakerConfig{
			FailureThreshold: 1_000_000, // disable trip — isolate budget behavior
			CoolDown:         time.Hour,
		},
		Budget: upstream.RetryBudgetConfig{
			// Allow at most 10 retries across the whole window —
			// well below the 200 a naive (1+MaxRetries=2 retries
			// per call * 100 baseline) policy would cost.
			Capacity:     10,
			RefillPerSec: 0.0001, // effectively no refill during test
		},
		MaxRetries:  2,
		BackoffBase: 0,
	})

	for i := 0; i < baseline; i++ {
		_ = g.Do(context.Background(), up.call)
	}

	// Worst case without budget: baseline * (1+MaxRetries) = 300.
	// With Capacity=10 we should see at most baseline + 10 + small slack.
	totalUpstream := up.calls.Load()
	const ceiling = baseline + 15
	if totalUpstream > ceiling {
		t.Fatalf("retry budget did not bound amplification: upstream calls=%d, want <=%d",
			totalUpstream, ceiling)
	}
	if totalUpstream < baseline {
		t.Fatalf("baseline calls did not all reach upstream: got %d, want >=%d",
			totalUpstream, baseline)
	}
	t.Logf("retry budget bounded: %d/%d permitted (%.1fx)",
		totalUpstream, baseline, float64(totalUpstream)/float64(baseline))
}

// ---------------------------------------------------------------------------
// Scenario 4: a slow IdP must not erode breaker health when the caller
// gives up via ctx — that is caller-driven, not upstream-driven, and
// counting it as a failure would falsely trip the breaker on tight
// deadlines. DefaultRetryable is the contract here.
// ---------------------------------------------------------------------------
func TestChaos_SlowUpstreamCallerCancelDoesNotTripBreaker(t *testing.T) {
	t.Parallel()
	up := &flakyUpstream{}
	up.latencyNS.Store(int64(200 * time.Millisecond))

	g := upstream.NewGuard(upstream.GuardConfig{
		Breaker: upstream.BreakerConfig{
			FailureThreshold: 3,
			CoolDown:         time.Hour,
		},
	})

	// 10 calls all giving up after 5ms — would be 10 "failures" if
	// ctx errors were counted.
	for i := 0; i < 10; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
		_ = g.Do(ctx, up.call)
		cancel()
	}

	if got := g.Breaker.State(); got != upstream.StateClosed {
		t.Fatalf("caller-driven cancellation tripped breaker: state=%s", got)
	}
}

// ---------------------------------------------------------------------------
// Scenario 5: concurrent storm. 64 goroutines hammer a fully-broken
// upstream for 200ms; the total upstream load must remain bounded and
// every caller must receive a deterministic error in O(µs) once the
// breaker opens. Models a real fan-out (e.g. 64-worker authz pool
// behind one Valkey breaker).
// ---------------------------------------------------------------------------
func TestChaos_ConcurrentStormBoundedBlastRadius(t *testing.T) {
	t.Parallel()
	up := &flakyUpstream{}
	up.breakAll()

	g := upstream.NewGuard(upstream.GuardConfig{
		Breaker: upstream.BreakerConfig{
			FailureThreshold: 5,
			CoolDown:         time.Hour,
		},
	})

	const workers = 64
	stop := make(chan struct{})
	var totalCalls atomic.Int64
	var openRejections atomic.Int64
	var wg sync.WaitGroup
	wg.Add(workers)
	for w := 0; w < workers; w++ {
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				err := g.Do(context.Background(), up.call)
				totalCalls.Add(1)
				if errors.Is(err, upstream.ErrCircuitOpen) {
					openRejections.Add(1)
				}
			}
		}()
	}
	time.Sleep(200 * time.Millisecond)
	close(stop)
	wg.Wait()

	upstreamCalls := up.calls.Load()
	// Even with 64 racing goroutines, the bound on real upstream
	// calls is FailureThreshold + (workers - 1) trials in flight when
	// the trip happens. Use a generous ceiling — the point is that
	// it's a CONSTANT, not proportional to wall-clock load.
	const ceiling = 5 + workers
	if upstreamCalls > ceiling {
		t.Fatalf("concurrent storm leaked %d calls upstream, want <=%d",
			upstreamCalls, ceiling)
	}
	rejectionRate := float64(openRejections.Load()) / float64(totalCalls.Load())
	if rejectionRate < 0.95 {
		t.Fatalf("most calls should fast-fail with ErrCircuitOpen: rate=%.3f", rejectionRate)
	}
	t.Logf("concurrent storm: %d calls / %d reached upstream / %.2f%% fast-fail",
		totalCalls.Load(), upstreamCalls, rejectionRate*100)
}
