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
// The broker's API contract is single-writer (see Broker.Publish doc). We
// therefore use a single publisher here. A separate test would be needed
// to characterise multi-writer behaviour, which is currently not part of
// the contract.
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
