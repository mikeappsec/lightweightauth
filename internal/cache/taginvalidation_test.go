// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package cache

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/mikeappsec/lightweightauth/pkg/module"
)

func TestTagIndex_AssociateAndLookup(t *testing.T) {
	t.Parallel()
	ti := NewTagIndex()
	ti.Associate("k1", []string{"tenant:acme", "subject:alice"})
	ti.Associate("k2", []string{"tenant:acme", "subject:bob"})
	ti.Associate("k3", []string{"tenant:other"})

	got := ti.KeysForTag("tenant:acme")
	if len(got) != 2 {
		t.Fatalf("expected 2 keys for tenant:acme, got %d", len(got))
	}
	got = ti.KeysForTag("subject:alice")
	if len(got) != 1 || got[0] != "k1" {
		t.Fatalf("expected [k1] for subject:alice, got %v", got)
	}
}

func TestTagIndex_ReassociateReplacesOld(t *testing.T) {
	t.Parallel()
	ti := NewTagIndex()
	ti.Associate("k1", []string{"tag:a", "tag:b"})
	ti.Associate("k1", []string{"tag:c"}) // replace

	if keys := ti.KeysForTag("tag:a"); len(keys) != 0 {
		t.Fatalf("expected 0 keys for tag:a after reassociate, got %v", keys)
	}
	if keys := ti.KeysForTag("tag:c"); len(keys) != 1 {
		t.Fatalf("expected 1 key for tag:c, got %v", keys)
	}
}

func TestTagIndex_Remove(t *testing.T) {
	t.Parallel()
	ti := NewTagIndex()
	ti.Associate("k1", []string{"tag:x"})
	ti.Remove("k1")

	if keys := ti.KeysForTag("tag:x"); len(keys) != 0 {
		t.Fatalf("expected 0 keys after remove, got %v", keys)
	}
	if ti.Len() != 0 {
		t.Fatalf("expected Len=0, got %d", ti.Len())
	}
}

func TestDecision_TagBasedInvalidation(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	d, err := NewDecision(DecisionOptions{
		Size:        100,
		PositiveTTL: time.Minute,
		KeyFields:   []string{"sub", "tenant"},
	})
	if err != nil {
		t.Fatal(err)
	}

	// Populate entries with tags.
	_, _, _ = d.Do(ctx, "key-alice-acme", []string{"tenant:acme", "subject:alice"}, func() (*module.Decision, error) {
		return &module.Decision{Allow: true}, nil
	})
	_, _, _ = d.Do(ctx, "key-bob-acme", []string{"tenant:acme", "subject:bob"}, func() (*module.Decision, error) {
		return &module.Decision{Allow: true}, nil
	})
	_, _, _ = d.Do(ctx, "key-alice-other", []string{"tenant:other", "subject:alice"}, func() (*module.Decision, error) {
		return &module.Decision{Allow: true}, nil
	})

	// Invalidate by tenant tag.
	evicted := d.InvalidateByTags(ctx, []string{"tenant:acme"})
	if evicted != 2 {
		t.Fatalf("expected 2 evicted, got %d", evicted)
	}

	// Verify invalidated entries are misses.
	calls := 0
	_, hit, _ := d.Do(ctx, "key-alice-acme", nil, func() (*module.Decision, error) {
		calls++
		return &module.Decision{Allow: false}, nil
	})
	if hit {
		t.Fatal("expected miss after invalidation")
	}
	if calls != 1 {
		t.Fatalf("expected fn called, got calls=%d", calls)
	}

	// Non-invalidated entry is still a hit.
	_, hit, _ = d.Do(ctx, "key-alice-other", nil, func() (*module.Decision, error) {
		t.Fatal("fn should not be called for non-invalidated key")
		return nil, nil
	})
	if !hit {
		t.Fatal("expected hit for non-invalidated key")
	}
}

func TestDecision_StaleWhileRevalidate(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	d, err := NewDecision(DecisionOptions{
		Size:              100,
		PositiveTTL:       50 * time.Millisecond,
		KeyFields:         []string{"sub"},
		ServeStaleOnError: true,
		MaxStaleness:      5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Populate cache.
	_, _, err = d.Do(ctx, "stale-key", nil, func() (*module.Decision, error) {
		return &module.Decision{Allow: true, Status: 200}, nil
	})
	if err != nil {
		t.Fatal(err)
	}

	// Wait for entry to become stale (past FreshUntil but still in backend).
	time.Sleep(60 * time.Millisecond)

	// Now authorizer returns upstream error — should get stale entry.
	dec, hit, err := d.Do(ctx, "stale-key", nil, func() (*module.Decision, error) {
		return nil, module.ErrUpstream
	})
	if err != nil {
		t.Fatalf("expected stale serve, got error: %v", err)
	}
	if !hit {
		t.Fatal("expected fromCache=true for stale serve")
	}
	if !dec.Allow {
		t.Fatal("expected stale allow decision")
	}
}

func TestDecision_StaleNotServedWhenDisabled(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	d, err := NewDecision(DecisionOptions{
		Size:              100,
		PositiveTTL:       50 * time.Millisecond,
		KeyFields:         []string{"sub"},
		ServeStaleOnError: false, // disabled
	})
	if err != nil {
		t.Fatal(err)
	}

	_, _, _ = d.Do(ctx, "no-stale-key", nil, func() (*module.Decision, error) {
		return &module.Decision{Allow: true}, nil
	})

	time.Sleep(60 * time.Millisecond)

	// Upstream error should propagate.
	_, _, err = d.Do(ctx, "no-stale-key", nil, func() (*module.Decision, error) {
		return nil, module.ErrUpstream
	})
	if !errors.Is(err, module.ErrUpstream) {
		t.Fatalf("expected ErrUpstream, got %v", err)
	}
}

func TestDecision_MaxStalenessRespected(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	d, err := NewDecision(DecisionOptions{
		Size:              100,
		PositiveTTL:       50 * time.Millisecond,
		KeyFields:         []string{"sub"},
		ServeStaleOnError: true,
		MaxStaleness:      30 * time.Millisecond, // very short
	})
	if err != nil {
		t.Fatal(err)
	}

	_, _, _ = d.Do(ctx, "max-stale-key", nil, func() (*module.Decision, error) {
		return &module.Decision{Allow: true}, nil
	})

	// Wait long enough that entry is past both freshUntil AND maxStaleness.
	time.Sleep(100 * time.Millisecond)

	_, _, err = d.Do(ctx, "max-stale-key", nil, func() (*module.Decision, error) {
		return nil, module.ErrUpstream
	})
	if !errors.Is(err, module.ErrUpstream) {
		t.Fatalf("expected ErrUpstream (entry too stale), got %v", err)
	}
}

func TestDecision_EvictionCleansTagIndex(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	// Size=3 so eviction kicks in quickly.
	d, err := NewDecision(DecisionOptions{
		Size:        3,
		PositiveTTL: time.Minute,
		KeyFields:   []string{"sub"},
	})
	if err != nil {
		t.Fatal(err)
	}

	// Fill cache with 3 tagged entries.
	for _, key := range []string{"k1", "k2", "k3"} {
		_, _, _ = d.Do(ctx, key, []string{"tag:" + key}, func() (*module.Decision, error) {
			return &module.Decision{Allow: true}, nil
		})
	}
	if d.tagIndex.Len() != 3 {
		t.Fatalf("expected 3 tracked keys, got %d", d.tagIndex.Len())
	}

	// Add a 4th entry — should evict one LRU entry and clean its tag.
	_, _, _ = d.Do(ctx, "k4", []string{"tag:k4"}, func() (*module.Decision, error) {
		return &module.Decision{Allow: true}, nil
	})

	// TagIndex should have at most 3 entries (the evicted key was cleaned).
	if got := d.tagIndex.Len(); got > 3 {
		t.Fatalf("expected tagIndex.Len() <= 3 after eviction, got %d (memory leak)", got)
	}
}

func TestDecision_StaleServedCounter(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	d, err := NewDecision(DecisionOptions{
		Size:              100,
		PositiveTTL:       50 * time.Millisecond,
		KeyFields:         []string{"sub"},
		ServeStaleOnError: true,
		MaxStaleness:      5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Populate.
	_, _, _ = d.Do(ctx, "metric-key", nil, func() (*module.Decision, error) {
		return &module.Decision{Allow: true}, nil
	})

	time.Sleep(60 * time.Millisecond)

	// Trigger stale serve.
	_, _, _ = d.Do(ctx, "metric-key", nil, func() (*module.Decision, error) {
		return nil, module.ErrUpstream
	})

	if got := d.stats.StaleServed.Load(); got != 1 {
		t.Fatalf("expected StaleServed=1, got %d", got)
	}
}

func TestDecision_DefaultMaxStalenessWhenEnabled(t *testing.T) {
	t.Parallel()

	// When serveStaleOnError is true but MaxStaleness is 0,
	// the constructor should default to 5 minutes.
	d, err := NewDecision(DecisionOptions{
		Size:              100,
		PositiveTTL:       time.Minute,
		KeyFields:         []string{"sub"},
		ServeStaleOnError: true,
		MaxStaleness:      0, // should default
	})
	if err != nil {
		t.Fatal(err)
	}
	if d.maxStaleness != 5*time.Minute {
		t.Fatalf("expected default maxStaleness=5m, got %v", d.maxStaleness)
	}
}
