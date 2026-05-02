package cache

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mikeappsec/lightweightauth/pkg/module"
)

// mockLocker is a test double for DistSFLocker.
type mockLocker struct {
	mu       sync.Mutex
	held     map[string]bool
	lockErr  error
	unlockCt atomic.Int64
}

func newMockLocker() *mockLocker {
	return &mockLocker{held: make(map[string]bool)}
}

func (m *mockLocker) TryLock(_ context.Context, key string, _ time.Duration) (bool, error) {
	if m.lockErr != nil {
		return false, m.lockErr
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.held[key] {
		return false, nil
	}
	m.held[key] = true
	return true, nil
}

func (m *mockLocker) Unlock(_ context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.held, key)
	m.unlockCt.Add(1)
	return nil
}

func TestDistSF_NilIsNoop(t *testing.T) {
	t.Parallel()
	var d *DistSF
	won, raw, err := d.Do(context.Background(), "key")
	if !won || raw != nil || err != nil {
		t.Fatalf("nil DistSF should return (true, nil, nil), got (%v, %v, %v)", won, raw, err)
	}
}

func TestDistSF_WinnerEvaluates(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	locker := newMockLocker()
	// Use a real LRU as L2 so poll can find results.
	l2, _ := NewLRU(100, 0, &Stats{})

	dsf := NewDistSF(DistSFOptions{
		Locker:       locker,
		L2:           l2,
		HoldDuration: 100 * time.Millisecond,
		PollInterval: 2 * time.Millisecond,
	})

	won, raw, err := dsf.Do(ctx, "test-key")
	if err != nil {
		t.Fatal(err)
	}
	if !won {
		t.Fatal("expected to win the lock")
	}
	if raw != nil {
		t.Fatal("expected nil raw for winner")
	}
}

func TestDistSF_LoserGetsResult(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	locker := newMockLocker()
	l2, _ := NewLRU(100, 0, &Stats{})

	dsf := NewDistSF(DistSFOptions{
		Locker:       locker,
		L2:           l2,
		HoldDuration: 200 * time.Millisecond,
		PollInterval: 2 * time.Millisecond,
	})

	// Pre-acquire the lock to simulate another replica holding it.
	locker.mu.Lock()
	locker.held["sf:some-key"] = true
	locker.mu.Unlock()

	// Write "result" to L2 after a short delay (simulates winner writing).
	go func() {
		time.Sleep(10 * time.Millisecond)
		_ = l2.Set(ctx, "some-key", []byte("winner-result"), time.Minute)
	}()

	won, raw, err := dsf.Do(ctx, "some-key")
	if err != nil {
		t.Fatal(err)
	}
	if won {
		t.Fatal("expected to lose the lock")
	}
	if string(raw) != "winner-result" {
		t.Fatalf("expected 'winner-result', got %q", string(raw))
	}
}

func TestDistSF_LoserTimesOut(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	locker := newMockLocker()
	l2, _ := NewLRU(100, 0, &Stats{})

	dsf := NewDistSF(DistSFOptions{
		Locker:       locker,
		L2:           l2,
		HoldDuration: 30 * time.Millisecond,
		PollInterval: 5 * time.Millisecond,
	})

	// Lock is held, no result ever appears.
	locker.mu.Lock()
	locker.held["sf:timeout-key"] = true
	locker.mu.Unlock()

	_, _, err := dsf.Do(ctx, "timeout-key")
	if !errors.Is(err, ErrDistSFLost) {
		t.Fatalf("expected ErrDistSFLost, got %v", err)
	}
}

func TestDistSF_LockErrorFallsBack(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	locker := newMockLocker()
	locker.lockErr = errors.New("valkey unreachable")
	l2, _ := NewLRU(100, 0, &Stats{})

	dsf := NewDistSF(DistSFOptions{
		Locker:       locker,
		L2:           l2,
		HoldDuration: 100 * time.Millisecond,
	})

	won, raw, err := dsf.Do(ctx, "fallback-key")
	if err != nil {
		t.Fatal(err)
	}
	if !won {
		t.Fatal("expected graceful fallback (won=true)")
	}
	if raw != nil {
		t.Fatal("expected nil raw on fallback")
	}
}

func TestDecision_DistSFIntegration(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	// Shared HMAC key so both "replicas" can verify.
	sharedKey := []byte("test-shared-key-32-bytes-long!!!")

	locker := newMockLocker()
	l2, _ := NewLRU(100, 0, &Stats{})

	dsf := NewDistSF(DistSFOptions{
		Locker:       locker,
		L2:           l2,
		HoldDuration: 200 * time.Millisecond,
		PollInterval: 2 * time.Millisecond,
	})

	d, err := NewDecision(DecisionOptions{
		Size:          100,
		PositiveTTL:   time.Minute,
		KeyFields:     []string{"sub"},
		DistSF:        dsf,
		SharedHMACKey: sharedKey,
	})
	if err != nil {
		t.Fatal(err)
	}

	// First call: should win the lock and evaluate.
	var calls atomic.Int64
	dec, cached, err := d.Do(ctx, "integration-key", nil, func() (*module.Decision, error) {
		calls.Add(1)
		return &module.Decision{Allow: true}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !dec.Allow || cached {
		t.Fatalf("expected (Allow=true, cached=false), got (%v, %v)", dec.Allow, cached)
	}
	if calls.Load() != 1 {
		t.Fatalf("expected 1 fn call, got %d", calls.Load())
	}

	// Verify the lock was released.
	if locker.unlockCt.Load() != 1 {
		t.Fatalf("expected unlock to be called once, got %d", locker.unlockCt.Load())
	}

	// Second call: should hit cache (no distSF needed).
	dec2, cached2, err := d.Do(ctx, "integration-key", nil, func() (*module.Decision, error) {
		calls.Add(1)
		return &module.Decision{Allow: false}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !dec2.Allow || !cached2 {
		t.Fatalf("expected cached hit, got (Allow=%v, cached=%v)", dec2.Allow, cached2)
	}
	if calls.Load() != 1 {
		t.Fatalf("expected still 1 fn call, got %d", calls.Load())
	}
}

func TestDecision_DistSFStatsCounter(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	sharedKey := []byte("test-shared-key-32-bytes-long!!!")
	locker := newMockLocker()
	l2, _ := NewLRU(100, 0, &Stats{})

	dsf := NewDistSF(DistSFOptions{
		Locker:       locker,
		L2:           l2,
		HoldDuration: 200 * time.Millisecond,
		PollInterval: 2 * time.Millisecond,
	})

	d, err := NewDecision(DecisionOptions{
		Size:          100,
		PositiveTTL:   time.Minute,
		KeyFields:     []string{"sub"},
		DistSF:        dsf,
		SharedHMACKey: sharedKey,
	})
	if err != nil {
		t.Fatal(err)
	}

	_, _, _ = d.Do(ctx, "stats-key", nil, func() (*module.Decision, error) {
		return &module.Decision{Allow: true}, nil
	})

	if got := d.stats.DistSFWon.Load(); got != 1 {
		t.Fatalf("expected DistSFWon=1, got %d", got)
	}
}
