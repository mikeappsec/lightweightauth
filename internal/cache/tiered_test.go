package cache

import (
	"context"
	"testing"
	"time"
)

func TestTieredGet_L1Hit(t *testing.T) {
	l1, _ := NewLRU(100, 0, &Stats{})
	l2, _ := NewLRU(100, 0, &Stats{})
	ts := &TieredStats{}
	agg := &Stats{}
	tiered, err := NewTiered(TieredOptions{L1: l1, L2: l2, Stats: ts, AggStats: agg})
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	// Seed L1 directly.
	_ = l1.Set(ctx, "k1", []byte("v1"), time.Minute)

	val, ok, err := tiered.Get(ctx, "k1")
	if err != nil {
		t.Fatal(err)
	}
	if !ok || string(val) != "v1" {
		t.Fatalf("expected L1 hit, got ok=%v val=%q", ok, val)
	}
	if ts.L1Hits.Load() != 1 {
		t.Fatalf("L1Hits = %d, want 1", ts.L1Hits.Load())
	}
	if ts.L2Hits.Load() != 0 {
		t.Fatalf("L2Hits = %d, want 0", ts.L2Hits.Load())
	}
	if agg.Hits.Load() != 1 {
		t.Fatalf("aggHits = %d, want 1", agg.Hits.Load())
	}
}

func TestTieredGet_L2HitWriteBack(t *testing.T) {
	l1, _ := NewLRU(100, 0, &Stats{})
	l2, _ := NewLRU(100, 0, &Stats{})
	ts := &TieredStats{}
	agg := &Stats{}
	tiered, err := NewTiered(TieredOptions{L1: l1, L2: l2, Stats: ts, AggStats: agg})
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	// Seed L2 only.
	_ = l2.Set(ctx, "k2", []byte("v2"), time.Minute)

	val, ok, err := tiered.Get(ctx, "k2")
	if err != nil {
		t.Fatal(err)
	}
	if !ok || string(val) != "v2" {
		t.Fatalf("expected L2 hit, got ok=%v val=%q", ok, val)
	}
	if ts.L1Misses.Load() != 1 {
		t.Fatalf("L1Misses = %d, want 1", ts.L1Misses.Load())
	}
	if ts.L2Hits.Load() != 1 {
		t.Fatalf("L2Hits = %d, want 1", ts.L2Hits.Load())
	}
	if agg.Hits.Load() != 1 {
		t.Fatalf("aggHits = %d, want 1", agg.Hits.Load())
	}

	// Verify write-back: L1 should now have the value.
	val2, ok2, _ := l1.Get(ctx, "k2")
	if !ok2 || string(val2) != "v2" {
		t.Fatalf("write-back to L1 failed: ok=%v val=%q", ok2, val2)
	}
}

func TestTieredGet_BothMiss(t *testing.T) {
	l1, _ := NewLRU(100, 0, &Stats{})
	l2, _ := NewLRU(100, 0, &Stats{})
	ts := &TieredStats{}
	agg := &Stats{}
	tiered, err := NewTiered(TieredOptions{L1: l1, L2: l2, Stats: ts, AggStats: agg})
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	_, ok, err := tiered.Get(ctx, "missing")
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("expected miss on both layers")
	}
	if ts.L1Misses.Load() != 1 {
		t.Fatalf("L1Misses = %d, want 1", ts.L1Misses.Load())
	}
	if ts.L2Misses.Load() != 1 {
		t.Fatalf("L2Misses = %d, want 1", ts.L2Misses.Load())
	}
	if agg.Misses.Load() != 1 {
		t.Fatalf("aggMisses = %d, want 1", agg.Misses.Load())
	}
}

func TestTieredSet_WriteThrough(t *testing.T) {
	l1, _ := NewLRU(100, 0, &Stats{})
	l2, _ := NewLRU(100, 0, &Stats{})
	tiered, err := NewTiered(TieredOptions{L1: l1, L2: l2})
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	if err := tiered.Set(ctx, "k", []byte("v"), time.Minute); err != nil {
		t.Fatal(err)
	}

	// Both layers should have the value.
	v1, ok1, _ := l1.Get(ctx, "k")
	v2, ok2, _ := l2.Get(ctx, "k")
	if !ok1 || string(v1) != "v" {
		t.Fatalf("L1 missing after Set: ok=%v val=%q", ok1, v1)
	}
	if !ok2 || string(v2) != "v" {
		t.Fatalf("L2 missing after Set: ok=%v val=%q", ok2, v2)
	}
}

func TestTieredDelete_BothLayers(t *testing.T) {
	l1, _ := NewLRU(100, 0, &Stats{})
	l2, _ := NewLRU(100, 0, &Stats{})
	tiered, err := NewTiered(TieredOptions{L1: l1, L2: l2})
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	_ = l1.Set(ctx, "k", []byte("v"), time.Minute)
	_ = l2.Set(ctx, "k", []byte("v"), time.Minute)

	if err := tiered.Delete(ctx, "k"); err != nil {
		t.Fatal(err)
	}

	_, ok1, _ := l1.Get(ctx, "k")
	_, ok2, _ := l2.Get(ctx, "k")
	if ok1 {
		t.Fatal("L1 still has key after Delete")
	}
	if ok2 {
		t.Fatal("L2 still has key after Delete")
	}
}

func TestTieredWarm(t *testing.T) {
	l1, _ := NewLRU(100, 0, &Stats{})
	l2, _ := NewLRU(100, 0, &Stats{})
	tiered, err := NewTiered(TieredOptions{L1: l1, L2: l2})
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	_ = l2.Set(ctx, "a", []byte("1"), time.Minute)
	_ = l2.Set(ctx, "b", []byte("2"), time.Minute)

	loaded := tiered.Warm(ctx, []string{"a", "b", "c"}) // c is missing in L2
	if loaded != 2 {
		t.Fatalf("Warm loaded %d, want 2", loaded)
	}

	// Verify L1 was populated.
	v, ok, _ := l1.Get(ctx, "a")
	if !ok || string(v) != "1" {
		t.Fatalf("L1[a] after Warm: ok=%v val=%q", ok, v)
	}
	v, ok, _ = l1.Get(ctx, "b")
	if !ok || string(v) != "2" {
		t.Fatalf("L1[b] after Warm: ok=%v val=%q", ok, v)
	}
}

func TestNewTiered_NilL1(t *testing.T) {
	l2, _ := NewLRU(100, 0, &Stats{})
	_, err := NewTiered(TieredOptions{L1: nil, L2: l2})
	if err == nil {
		t.Fatal("expected error for nil L1")
	}
}

func TestNewTiered_NilL2(t *testing.T) {
	l1, _ := NewLRU(100, 0, &Stats{})
	_, err := NewTiered(TieredOptions{L1: l1, L2: nil})
	if err == nil {
		t.Fatal("expected error for nil L2")
	}
}
