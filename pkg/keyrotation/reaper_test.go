// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package keyrotation_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/mikeappsec/lightweightauth/pkg/keyrotation"
)

func TestReaper_PrunesRetiredKeys(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }

	ks := keyrotation.NewKeySet[string](clock)
	// Add a key that is already retired (notAfter + grace in the past).
	ks.Put(keyrotation.KeyMeta{
		KID:         "old-key",
		NotBefore:   now.Add(-48 * time.Hour),
		NotAfter:    now.Add(-25 * time.Hour),
		GracePeriod: 1 * time.Hour,
	}, "secret-old")

	// Add an active key.
	ks.Put(keyrotation.KeyMeta{
		KID:       "active-key",
		NotBefore: now.Add(-1 * time.Hour),
		NotAfter:  now.Add(23 * time.Hour),
	}, "secret-active")

	pruneCh := make(chan string, 10)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	keyrotation.NewReaper(ctx, ks, keyrotation.ReaperConfig{
		Interval: 10 * time.Millisecond,
		OnPrune: func(kids []string) {
			for _, kid := range kids {
				pruneCh <- kid
			}
		},
	})

	// Wait for the prune callback with a generous timeout.
	select {
	case kid := <-pruneCh:
		if kid != "old-key" {
			t.Fatalf("expected 'old-key' to be pruned, got %q", kid)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for reaper to prune retired key")
	}
	cancel()

	// active-key should still exist.
	if _, ok := ks.Get("active-key"); !ok {
		t.Fatal("active-key should not have been pruned")
	}
}

func TestReaper_DetectsTransitions(t *testing.T) {
	start := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	var mu sync.Mutex
	now := start
	clock := func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return now
	}

	ks := keyrotation.NewKeySet[string](clock)
	// Add a key that will transition from active to retiring.
	ks.Put(keyrotation.KeyMeta{
		KID:         "transitioning",
		NotBefore:   start.Add(-1 * time.Hour),
		NotAfter:    start.Add(10 * time.Millisecond),
		GracePeriod: 1 * time.Hour,
	}, "secret")

	transitionCh := make(chan string, 10)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	keyrotation.NewReaper(ctx, ks, keyrotation.ReaperConfig{
		Interval: 5 * time.Millisecond,
		Clock:    clock,
		OnTransition: func(kid string, from, to keyrotation.KeyState) {
			transitionCh <- kid + ":" + string(from) + "->" + string(to)
		},
	})

	// Wait for at least one tick to record the initial "active" state.
	time.Sleep(30 * time.Millisecond)

	// Advance time past notAfter to trigger retiring.
	mu.Lock()
	now = start.Add(50 * time.Millisecond)
	mu.Unlock()

	// Wait for transition with a generous timeout.
	select {
	case got := <-transitionCh:
		if got == "" {
			t.Fatal("empty transition")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for state transition")
	}
}
