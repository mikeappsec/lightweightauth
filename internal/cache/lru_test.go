package cache

import (
	"context"
	"testing"
	"time"
)

func TestLRU_SetGetDelete(t *testing.T) {
	t.Parallel()
	c, err := NewLRU(8, 0, nil)
	if err != nil {
		t.Fatalf("NewLRU: %v", err)
	}
	ctx := context.Background()

	if err := c.Set(ctx, "k", []byte("v"), 0); err != nil {
		t.Fatalf("Set: %v", err)
	}
	got, ok, err := c.Get(ctx, "k")
	if err != nil || !ok || string(got) != "v" {
		t.Fatalf("Get(k) = (%q, %v, %v), want (v, true, nil)", got, ok, err)
	}

	if err := c.Delete(ctx, "k"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, ok, _ := c.Get(ctx, "k"); ok {
		t.Fatal("Get after Delete: ok=true, want false")
	}
}

func TestLRU_PerEntryTTL(t *testing.T) {
	t.Parallel()
	c, _ := NewLRU(8, 0, nil)
	ctx := context.Background()

	_ = c.Set(ctx, "k", []byte("v"), 5*time.Millisecond)
	time.Sleep(15 * time.Millisecond)

	if _, ok, _ := c.Get(ctx, "k"); ok {
		t.Fatal("Get after ttl expiry: ok=true, want false")
	}
}

func TestLRU_StatsCount(t *testing.T) {
	t.Parallel()
	stats := &Stats{}
	c, _ := NewLRU(8, 0, stats)
	ctx := context.Background()

	_, _, _ = c.Get(ctx, "missing") // miss
	_ = c.Set(ctx, "k", []byte("v"), 0)
	_, _, _ = c.Get(ctx, "k") // hit
	_, _, _ = c.Get(ctx, "k") // hit

	if h := stats.Hits.Load(); h != 2 {
		t.Errorf("Hits = %d, want 2", h)
	}
	if m := stats.Misses.Load(); m != 1 {
		t.Errorf("Misses = %d, want 1", m)
	}
}

func TestLRU_RejectsBadSize(t *testing.T) {
	if _, err := NewLRU(0, 0, nil); err == nil {
		t.Fatal("NewLRU(0) should error")
	}
}

// TestLRU_EvictionOrder pins the in-house simpleLRU's MRU/LRU semantics:
// once at capacity, the least-recently-used key is dropped on insert,
// and Get bumps a key back to MRU.
func TestLRU_EvictionOrder(t *testing.T) {
	t.Parallel()
	stats := &Stats{}
	c, _ := NewLRU(2, 0, stats)
	ctx := context.Background()

	_ = c.Set(ctx, "a", []byte("1"), 0)
	_ = c.Set(ctx, "b", []byte("2"), 0)
	// Touch "a" so "b" becomes the LRU.
	if _, ok, _ := c.Get(ctx, "a"); !ok {
		t.Fatal("a should be present")
	}
	_ = c.Set(ctx, "c", []byte("3"), 0)

	if _, ok, _ := c.Get(ctx, "b"); ok {
		t.Error("b should have been evicted")
	}
	if _, ok, _ := c.Get(ctx, "a"); !ok {
		t.Error("a should still be present (it was MRU)")
	}
	if got := stats.Evictions.Load(); got != 1 {
		t.Errorf("Evictions = %d, want 1", got)
	}
}

// TestLRU_DefaultTTLFallback verifies that ttl==0 on Set falls back to
// the cache's defaultTTL configured at NewLRU.
func TestLRU_DefaultTTLFallback(t *testing.T) {
	t.Parallel()
	c, _ := NewLRU(8, 5*time.Millisecond, nil)
	ctx := context.Background()
	_ = c.Set(ctx, "k", []byte("v"), 0) // 0 → defaultTTL
	time.Sleep(15 * time.Millisecond)
	if _, ok, _ := c.Get(ctx, "k"); ok {
		t.Fatal("default TTL did not apply")
	}
}
