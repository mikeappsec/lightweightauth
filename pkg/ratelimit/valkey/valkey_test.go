// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package ratelimitvalkey

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/valkey-io/valkey-go"
)

func newTestBackend(t *testing.T, prefix string) (*Backend, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	client, err := valkey.NewClient(valkey.ClientOption{
		InitAddress:  []string{mr.Addr()},
		DisableCache: true,
		AlwaysRESP2:  true,
	})
	if err != nil {
		t.Fatalf("valkey.NewClient: %v", err)
	}
	t.Cleanup(client.Close)
	return New(client, prefix), mr
}

func TestAllow_AdmitsUnderLimit(t *testing.T) {
	b, _ := newTestBackend(t, "lwauth-rl/")
	ctx := context.Background()
	now := time.UnixMilli(1_000_000)

	for i := 0; i < 5; i++ {
		ok, err := b.Allow(ctx, "acme", 5, time.Second, now)
		if err != nil {
			t.Fatalf("Allow #%d: %v", i, err)
		}
		if !ok {
			t.Fatalf("Allow #%d denied within limit", i)
		}
	}
}

func TestAllow_DeniesAtLimit(t *testing.T) {
	b, _ := newTestBackend(t, "")
	ctx := context.Background()
	now := time.UnixMilli(2_000_000)

	for i := 0; i < 3; i++ {
		ok, err := b.Allow(ctx, "acme", 3, time.Second, now)
		if err != nil || !ok {
			t.Fatalf("setup #%d: ok=%v err=%v", i, ok, err)
		}
	}
	ok, err := b.Allow(ctx, "acme", 3, time.Second, now)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if ok {
		t.Fatal("expected denial at limit")
	}
}

func TestAllow_SlidingWindowExpiresEntries(t *testing.T) {
	b, _ := newTestBackend(t, "")
	ctx := context.Background()
	t0 := time.UnixMilli(3_000_000)

	// Fill the window at t0.
	for i := 0; i < 3; i++ {
		ok, err := b.Allow(ctx, "acme", 3, time.Second, t0)
		if err != nil || !ok {
			t.Fatalf("fill #%d: ok=%v err=%v", i, ok, err)
		}
	}
	// Same instant: denied.
	ok, _ := b.Allow(ctx, "acme", 3, time.Second, t0)
	if ok {
		t.Fatal("expected denial inside window")
	}
	// Advance past window: old entries fall out.
	t1 := t0.Add(1100 * time.Millisecond)
	ok, err := b.Allow(ctx, "acme", 3, time.Second, t1)
	if err != nil {
		t.Fatalf("post-window err: %v", err)
	}
	if !ok {
		t.Fatal("expected admission after window slides")
	}
}

func TestAllow_TenantsAreIsolated(t *testing.T) {
	b, _ := newTestBackend(t, "")
	ctx := context.Background()
	now := time.UnixMilli(4_000_000)

	for i := 0; i < 2; i++ {
		ok, err := b.Allow(ctx, "acme", 2, time.Second, now)
		if err != nil || !ok {
			t.Fatalf("acme #%d: %v", i, err)
		}
	}
	if ok, _ := b.Allow(ctx, "acme", 2, time.Second, now); ok {
		t.Fatal("acme should be capped")
	}
	// Different tenant must have its own bucket.
	ok, err := b.Allow(ctx, "globex", 2, time.Second, now)
	if err != nil {
		t.Fatalf("globex err: %v", err)
	}
	if !ok {
		t.Fatal("globex should be admitted (separate bucket)")
	}
}

func TestAllow_KeyPrefixIsolation(t *testing.T) {
	mr := miniredis.RunT(t)
	mk := func(prefix string) *Backend {
		c, err := valkey.NewClient(valkey.ClientOption{
			InitAddress:  []string{mr.Addr()},
			DisableCache: true,
			AlwaysRESP2:  true,
		})
		if err != nil {
			t.Fatalf("client: %v", err)
		}
		t.Cleanup(c.Close)
		return New(c, prefix)
	}
	a := mk("envA/")
	b := mk("envB/")
	ctx := context.Background()
	now := time.UnixMilli(5_000_000)

	for i := 0; i < 2; i++ {
		ok, _ := a.Allow(ctx, "tenant", 2, time.Second, now)
		if !ok {
			t.Fatalf("envA #%d should admit", i)
		}
	}
	// envA capped, envB independent.
	if ok, _ := a.Allow(ctx, "tenant", 2, time.Second, now); ok {
		t.Fatal("envA should be capped")
	}
	if ok, _ := b.Allow(ctx, "tenant", 2, time.Second, now); !ok {
		t.Fatal("envB should be independent")
	}
}

func TestAllow_TTLBoundsKeyLifetime(t *testing.T) {
	b, mr := newTestBackend(t, "")
	ctx := context.Background()
	t0 := time.UnixMilli(6_000_000)

	if _, err := b.Allow(ctx, "expiring", 5, 100*time.Millisecond, t0); err != nil {
		t.Fatal(err)
	}
	if !mr.Exists("expiring") {
		t.Fatal("key should exist after admit")
	}
	mr.FastForward(200 * time.Millisecond)
	if mr.Exists("expiring") {
		t.Fatal("key should have expired after TTL")
	}
}

func TestAllow_ConcurrentAdmissionsAreAtomic(t *testing.T) {
	// 50 concurrent goroutines × 10 attempts each, limit=20: after the
	// dust settles, exactly 20 should have been admitted (the script
	// is atomic).
	b, _ := newTestBackend(t, "")
	ctx := context.Background()
	now := time.UnixMilli(7_000_000)

	const limit = 20
	const goroutines = 50
	const attempts = 10
	var (
		wg       sync.WaitGroup
		admitted = make(chan struct{}, goroutines*attempts)
	)
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < attempts; i++ {
				ok, err := b.Allow(ctx, "race", limit, time.Second, now)
				if err != nil {
					t.Errorf("err: %v", err)
					return
				}
				if ok {
					admitted <- struct{}{}
				}
			}
		}()
	}
	wg.Wait()
	close(admitted)
	got := 0
	for range admitted {
		got++
	}
	if got != limit {
		t.Errorf("admitted = %d, want %d (script not atomic?)", got, limit)
	}
}

func TestAllow_ZeroLimitAdmits(t *testing.T) {
	b, _ := newTestBackend(t, "")
	ctx := context.Background()
	ok, err := b.Allow(ctx, "k", 0, time.Second, time.Now())
	if err != nil || !ok {
		t.Fatalf("zero limit: ok=%v err=%v", ok, err)
	}
}

func TestAllow_ZeroWindowErrors(t *testing.T) {
	b, _ := newTestBackend(t, "")
	ctx := context.Background()
	if _, err := b.Allow(ctx, "k", 5, 0, time.Now()); err == nil {
		t.Fatal("expected error for zero window")
	}
}
