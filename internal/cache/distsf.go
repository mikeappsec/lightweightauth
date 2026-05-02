package cache

import (
	"context"
	"errors"
	"time"
)

// DistSFLocker abstracts the distributed lock primitive needed for
// cross-replica singleflight. The implementation speaks Valkey
// SET NX PX (or equivalent) under the hood.
type DistSFLocker interface {
	// TryLock attempts to acquire a distributed lock for the given key.
	// Returns true if this caller won the lock (and should evaluate),
	// false if another replica already holds it (caller should poll L2).
	// The lock auto-expires after holdDuration even if the winner crashes.
	TryLock(ctx context.Context, key string, holdDuration time.Duration) (won bool, err error)

	// Unlock releases the lock early after the winner writes the result.
	// Best-effort: if it fails (network blip), the hold TTL guarantees
	// automatic release.
	Unlock(ctx context.Context, key string) error
}

// DistSF is the cross-replica singleflight coordinator (E4). When a
// cache miss occurs and distributed singleflight is enabled, only one
// replica evaluates the authorizer while others wait for the result to
// appear in L2. Falls back to per-pod singleflight when:
//   - locker is nil (no Valkey configured)
//   - TryLock returns an error (Valkey unreachable)
//   - context is cancelled before the result appears
type DistSF struct {
	locker       DistSFLocker
	l2           Backend
	holdDuration time.Duration
	pollInterval time.Duration
}

// DistSFOptions configures cross-replica singleflight.
type DistSFOptions struct {
	// Locker is the distributed lock backend. nil disables E4.
	Locker DistSFLocker
	// L2 is the shared cache backend to poll for results.
	L2 Backend
	// HoldDuration is how long the SETNX lock lives. Should be > p99
	// evaluation latency but short enough that a crash doesn't block
	// all replicas for long. Default 200ms.
	HoldDuration time.Duration
	// PollInterval is how often losing replicas check L2 for the winner's
	// result. Default 5ms.
	PollInterval time.Duration
}

const (
	defaultHoldDuration = 200 * time.Millisecond
	defaultPollInterval = 5 * time.Millisecond
)

// NewDistSF constructs a distributed singleflight coordinator.
// Returns nil if Locker or L2 is nil (disabled path).
func NewDistSF(opts DistSFOptions) *DistSF {
	if opts.Locker == nil || opts.L2 == nil {
		return nil
	}
	hold := opts.HoldDuration
	if hold <= 0 {
		hold = defaultHoldDuration
	}
	poll := opts.PollInterval
	if poll <= 0 {
		poll = defaultPollInterval
	}
	return &DistSF{
		locker:       opts.Locker,
		l2:          opts.L2,
		holdDuration: hold,
		pollInterval: poll,
	}
}

// ErrDistSFLost is returned when this replica lost the distributed lock
// race but the winner's result did not appear in L2 within the hold window.
// The caller should fall back to local evaluation.
var ErrDistSFLost = errors.New("distsf: winner result not found in L2")

// Do attempts distributed singleflight. Returns:
//   - (true, nil): this replica won the lock → caller must evaluate and store to L2
//   - (false, raw): another replica won → raw is the L2 result the caller should use
//   - (false, ErrDistSFLost): lost but winner result not found → fall back to local eval
//   - (true, err): lock error → fall back to local eval
//
// The key should be the cache key (already includes sflockPrefix).
func (d *DistSF) Do(ctx context.Context, key string) (won bool, raw []byte, err error) {
	if d == nil {
		return true, nil, nil // disabled → always "win" (use local singleflight)
	}

	lockKey := "sf:" + key
	won, err = d.locker.TryLock(ctx, lockKey, d.holdDuration)
	if err != nil {
		// Valkey unreachable → fall back to local.
		return true, nil, nil
	}
	if won {
		return true, nil, nil
	}

	// Lost the race — poll L2 for the winner's result.
	raw, err = d.pollL2(ctx, key)
	if err != nil {
		return false, nil, ErrDistSFLost
	}
	return false, raw, nil
}

// Release unlocks the distributed lock after the winner writes the result.
// Best-effort; callers ignore errors.
func (d *DistSF) Release(ctx context.Context, key string) {
	if d == nil {
		return
	}
	_ = d.locker.Unlock(ctx, "sf:"+key)
}

// pollL2 polls the L2 backend until the key appears or the context/hold
// window expires.
func (d *DistSF) pollL2(ctx context.Context, key string) ([]byte, error) {
	deadline := time.Now().Add(d.holdDuration)
	ticker := time.NewTicker(d.pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ticker.C:
			if time.Now().After(deadline) {
				return nil, ErrDistSFLost
			}
			raw, ok, err := d.l2.Get(ctx, key)
			if err != nil {
				// L2 error during poll — give up, fall back.
				return nil, err
			}
			if ok {
				return raw, nil
			}
		}
	}
}
