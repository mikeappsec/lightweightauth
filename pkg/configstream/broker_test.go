// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package configstream

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mikeappsec/lightweightauth/internal/config"
)

func waitFor(t *testing.T, ch <-chan Snapshot) Snapshot {
	t.Helper()
	select {
	case s, ok := <-ch:
		if !ok {
			t.Fatalf("channel closed unexpectedly")
		}
		return s
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for snapshot")
	}
	return Snapshot{}
}

func TestBroker_PublishFanOut(t *testing.T) {
	b := NewBroker()
	ctxA, cancelA := context.WithCancel(context.Background())
	ctxB, cancelB := context.WithCancel(context.Background())
	defer cancelA()
	defer cancelB()
	a := b.Subscribe(ctxA)
	bb := b.Subscribe(ctxB)

	spec := &config.AuthConfig{TenantID: "t1"}
	snap := b.Publish(spec)
	if snap.Version != 1 {
		t.Fatalf("first publish version = %d, want 1", snap.Version)
	}

	if got := waitFor(t, a); got.Version != 1 || got.Spec.TenantID != "t1" {
		t.Fatalf("a = %+v", got)
	}
	if got := waitFor(t, bb); got.Version != 1 || got.Spec.TenantID != "t1" {
		t.Fatalf("b = %+v", got)
	}
}

func TestBroker_LateSubscriberGetsLatest(t *testing.T) {
	b := NewBroker()
	b.Publish(&config.AuthConfig{TenantID: "old"})
	b.Publish(&config.AuthConfig{TenantID: "new"})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sub := b.Subscribe(ctx)

	got := waitFor(t, sub)
	if got.Version != 2 || got.Spec.TenantID != "new" {
		t.Fatalf("late subscriber got %+v, want v2/new", got)
	}
}

func TestBroker_SlowSubscriberConflates(t *testing.T) {
	b := NewBroker()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sub := b.Subscribe(ctx)

	// Publisher must not block even though no one is reading.
	done := make(chan struct{})
	go func() {
		for i := 0; i < 100; i++ {
			b.Publish(&config.AuthConfig{TenantID: "t"})
		}
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Publish blocked on slow subscriber")
	}

	// Drain — eventually we must observe the final version (100).
	deadline := time.After(2 * time.Second)
	var last Snapshot
	for last.Version < 100 {
		select {
		case s := <-sub:
			last = s
		case <-deadline:
			t.Fatalf("did not receive final snapshot; last = %d", last.Version)
		}
	}
}

func TestBroker_CancelClosesChannel(t *testing.T) {
	b := NewBroker()
	ctx, cancel := context.WithCancel(context.Background())
	sub := b.Subscribe(ctx)
	cancel()

	select {
	case _, ok := <-sub:
		if ok {
			// drain primed snapshot if any; next read must close
			select {
			case _, ok2 := <-sub:
				if ok2 {
					t.Fatal("channel still open after cancel")
				}
			case <-time.After(time.Second):
				t.Fatal("channel did not close after cancel")
			}
		}
	case <-time.After(time.Second):
		t.Fatal("channel did not close after cancel")
	}
}

func TestBroker_LatestEmptyAndAfterPublish(t *testing.T) {
	b := NewBroker()
	if _, ok := b.Latest(); ok {
		t.Fatal("Latest on empty broker should return ok=false")
	}
	b.Publish(&config.AuthConfig{TenantID: "x"})
	snap, ok := b.Latest()
	if !ok || snap.Version != 1 || snap.Spec.TenantID != "x" {
		t.Fatalf("Latest = %+v ok=%v", snap, ok)
	}
}

func TestBroker_ConcurrentSubscribers(t *testing.T) {
	b := NewBroker()
	const N = 16
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var wg sync.WaitGroup
	var observed atomic.Int64
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sub := b.Subscribe(ctx)
			for s := range sub {
				if s.Version >= 1 {
					observed.Add(1)
					return
				}
			}
		}()
	}

	// Give subscribers a moment to register.
	time.Sleep(50 * time.Millisecond)
	b.Publish(&config.AuthConfig{TenantID: "broadcast"})

	doneAll := make(chan struct{})
	go func() { wg.Wait(); close(doneAll) }()
	select {
	case <-doneAll:
	case <-time.After(2 * time.Second):
		t.Fatalf("only %d/%d subscribers observed", observed.Load(), N)
	}
	if observed.Load() != N {
		t.Fatalf("observed = %d, want %d", observed.Load(), N)
	}
}
