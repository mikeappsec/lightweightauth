// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package configstream

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/mikeappsec/lightweightauth/internal/config"
)

// TestBrokerStress hammers the broker with a fast publisher and many
// concurrent subscribers and asserts:
//
//   - every subscriber that observes any snapshot eventually observes the
//     latest version published (latest-wins, no permanently stuck
//     subscriber);
//   - delivered versions are monotonically non-decreasing per subscriber;
//   - subscribe / unsubscribe churn does not leak goroutines (asserted
//     with goleak after ctx is cancelled).
//
// Single-publisher variant. The multi-writer fan-in case (lifted in
// M12-BROKER-MW) is covered by [TestBrokerStress_MultiWriter] below.
//
// Run with -race to catch any data races on the subscription pending slot.
func TestBrokerStress(t *testing.T) {
	const (
		subscribers = 32
		publishes   = 2000
	)

	b := NewBroker()

	rootCtx, cancel := context.WithCancel(context.Background())

	var subWG sync.WaitGroup
	maxSeen := make([]uint64, subscribers)
	for i := 0; i < subscribers; i++ {
		subWG.Add(1)
		i := i
		go func() {
			defer subWG.Done()
			ch := b.Subscribe(rootCtx)
			var last uint64
			for snap := range ch {
				if snap.Version < last {
					t.Errorf("subscriber %d: versions went backwards %d -> %d",
						i, last, snap.Version)
					return
				}
				last = snap.Version
				atomic.StoreUint64(&maxSeen[i], last)
			}
		}()
	}

	var totalPublished atomic.Uint64
	var pubWG sync.WaitGroup
	pubWG.Add(1)
	go func() {
		defer pubWG.Done()
		for k := 0; k < publishes; k++ {
			b.Publish(&config.AuthConfig{TenantID: "stress"})
			totalPublished.Add(1)
		}
	}()
	pubWG.Wait()

	finalVersion, ok := b.Latest()
	if !ok {
		t.Fatal("Latest() empty after publishes")
	}
	if got := totalPublished.Load(); finalVersion.Version != got {
		t.Errorf("expected final version == publish count (%d), got %d",
			got, finalVersion.Version)
	}

	// Give subscribers a moment to drain to the final version.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		allCaughtUp := true
		for i := 0; i < subscribers; i++ {
			if atomic.LoadUint64(&maxSeen[i]) < finalVersion.Version {
				allCaughtUp = false
				break
			}
		}
		if allCaughtUp {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	for i := 0; i < subscribers; i++ {
		if got := atomic.LoadUint64(&maxSeen[i]); got < finalVersion.Version {
			t.Errorf("subscriber %d stuck at version %d, expected >= %d",
				i, got, finalVersion.Version)
		}
	}

	cancel()
	subWG.Wait()

	// Any leaked goroutine here would indicate a stuck subscription pump.
	goleak.VerifyNone(t)
}

// TestBrokerSubscriberChurn exercises rapid subscribe / cancel cycles
// against a steady stream of publishes. This is the path a flapping xDS
// client takes during a network partition.
func TestBrokerSubscriberChurn(t *testing.T) {
	b := NewBroker()

	pubCtx, pubCancel := context.WithCancel(context.Background())
	pubDone := make(chan struct{})
	go func() {
		defer close(pubDone)
		t := time.NewTicker(200 * time.Microsecond)
		defer t.Stop()
		for {
			select {
			case <-pubCtx.Done():
				return
			case <-t.C:
				b.Publish(&config.AuthConfig{TenantID: "churn"})
			}
		}
	}()

	const churnRounds = 200
	var wg sync.WaitGroup
	for i := 0; i < churnRounds; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			ch := b.Subscribe(ctx)
			// Read at most a handful of snapshots, then cancel.
			for n := 0; n < 3; n++ {
				select {
				case _, ok := <-ch:
					if !ok {
						return
					}
				case <-time.After(500 * time.Millisecond):
					t.Error("subscriber timed out waiting for snapshot")
					cancel()
					return
				}
			}
			cancel()
			// Drain the close so the pump goroutine exits before we
			// move on.
			for range ch {
			}
		}()
	}
	wg.Wait()

	pubCancel()
	<-pubDone

	goleak.VerifyNone(t)
}

// TestBrokerStress_MultiWriter exercises the M12-BROKER-MW contract:
// many goroutines call Publish concurrently. The broker must hand out
// unique monotonic versions, the per-subscriber stream must remain
// strictly non-decreasing, and the final version every subscriber sees
// must equal the total number of publishes.
//
// This is the regression fence for the deliver()-reorder bug the old
// godoc warned about: with N writers, a slow goroutine could deliver
// an older snapshot to a subscription's pending slot AFTER a faster
// goroutine had already deposited a newer one. The version-compare in
// subscription.deliver makes that case a no-op.
func TestBrokerStress_MultiWriter(t *testing.T) {
	const (
		writers           = 8
		publishesPerWriter = 500
		subscribers       = 16
	)
	want := uint64(writers * publishesPerWriter)

	b := NewBroker()
	rootCtx, cancel := context.WithCancel(context.Background())

	var subWG sync.WaitGroup
	maxSeen := make([]uint64, subscribers)
	for i := 0; i < subscribers; i++ {
		subWG.Add(1)
		i := i
		go func() {
			defer subWG.Done()
			ch := b.Subscribe(rootCtx)
			var last uint64
			for snap := range ch {
				if snap.Version < last {
					t.Errorf("subscriber %d: versions went backwards %d -> %d",
						i, last, snap.Version)
					return
				}
				last = snap.Version
				atomic.StoreUint64(&maxSeen[i], last)
			}
		}()
	}

	// Multi-writer fan-in.
	var pubWG sync.WaitGroup
	for w := 0; w < writers; w++ {
		pubWG.Add(1)
		go func() {
			defer pubWG.Done()
			for k := 0; k < publishesPerWriter; k++ {
				b.Publish(&config.AuthConfig{TenantID: "mw"})
			}
		}()
	}
	pubWG.Wait()

	final, ok := b.Latest()
	if !ok {
		t.Fatal("Latest() empty after publishes")
	}
	if final.Version != want {
		t.Fatalf("final version = %d, want %d (writers=%d × per-writer=%d)",
			final.Version, want, writers, publishesPerWriter)
	}

	// Subscribers eventually drain to the final version.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		all := true
		for i := 0; i < subscribers; i++ {
			if atomic.LoadUint64(&maxSeen[i]) < final.Version {
				all = false
				break
			}
		}
		if all {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	for i := 0; i < subscribers; i++ {
		if got := atomic.LoadUint64(&maxSeen[i]); got < final.Version {
			t.Errorf("subscriber %d stuck at version %d, expected >= %d",
				i, got, final.Version)
		}
	}

	cancel()
	subWG.Wait()
	goleak.VerifyNone(t)
}

// TestBrokerDeliver_RejectsStaleVersion is a small, deterministic
// fence on the version-compare logic in subscription.deliver. It
// fabricates two out-of-order deliver() calls (newer first, then
// older) and asserts the older one is dropped — i.e. the pending slot
// never moves backwards.
func TestBrokerDeliver_RejectsStaleVersion(t *testing.T) {
	t.Parallel()
	b := NewBroker()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch := b.Subscribe(ctx)

	// Reach into the broker to grab the lone subscription. There is
	// exactly one (we just created it).
	b.mu.Lock()
	if len(b.subs) != 1 {
		b.mu.Unlock()
		t.Fatalf("expected 1 subscription, got %d", len(b.subs))
	}
	var sub *subscription
	for s := range b.subs {
		sub = s
	}
	b.mu.Unlock()

	// Simulate two out-of-order deliveries: a fast writer's v=5 lands
	// first, a slow writer's stale v=3 lands second.
	sub.deliver(Snapshot{Version: 5, Spec: &config.AuthConfig{TenantID: "v5"}})
	sub.deliver(Snapshot{Version: 3, Spec: &config.AuthConfig{TenantID: "v3"}})

	got := waitFor(t, ch)
	if got.Version != 5 || got.Spec.TenantID != "v5" {
		t.Fatalf("got %+v, want v5/'v5' (stale v3 must have been dropped)", got)
	}

	// And no second snapshot should be queued — the v3 was rejected,
	// not buffered.
	select {
	case extra := <-ch:
		t.Fatalf("unexpected extra snapshot: %+v", extra)
	case <-time.After(50 * time.Millisecond):
	}
}
