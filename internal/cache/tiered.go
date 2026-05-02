package cache

import (
	"context"
	"sync/atomic"
	"time"
)

// defaultL1MaxTTL is the maximum time an L1 write-back entry lives before
// it must be re-validated against L2. This prevents stale entries persisting
// indefinitely under low-cardinality workloads where LRU eviction is rare.
const defaultL1MaxTTL = 60 * time.Second

// TieredStats holds per-layer hit/miss counters for a two-tier cache.
// These are separate from the aggregate Stats so operators can distinguish
// L1 (in-process) hits from L2 (shared/Valkey) hits.
type TieredStats struct {
	L1Hits   atomic.Uint64
	L1Misses atomic.Uint64
	L2Hits   atomic.Uint64
	L2Misses atomic.Uint64
}

// Tiered is the ENT-CACHE-1 two-tier read-through / write-through Backend.
//
// Get: L1 → on miss → L2 → on L2 hit → write-back to L1 (read-through).
// Set: write to both L1 and L2 (write-through).
// Delete: evict from both layers.
//
// L1 is an in-process LRU (fast, per-replica). L2 is a shared store
// (typically Valkey) that survives pod restarts and is shared across
// replicas. New pods warm their L1 organically from L2 hits; an optional
// Warm method preloads hot keys on startup (E1 §11.3).
type Tiered struct {
	l1    Backend
	l2    Backend
	stats *TieredStats
	// aggStats is the aggregate Stats (L1+L2 combined) that the existing
	// metrics registration (RegisterCacheStats) uses. A hit on either
	// layer is an aggregate hit; a miss on both is an aggregate miss.
	aggStats *Stats
	// l1MaxTTL bounds how long an L1 write-back entry lives. Prevents
	// stale entries persisting after L2 expiry or invalidation. A race
	// between Get (write-back) and Delete is bounded by this TTL rather
	// than living indefinitely until LRU eviction.
	l1MaxTTL time.Duration
}

// TieredOptions configures a two-tier backend.
type TieredOptions struct {
	// L1 is the in-process cache (typically an LRU). Required.
	L1 Backend
	// L2 is the shared remote cache (typically Valkey). Required.
	L2 Backend
	// Stats receives per-layer counters. If nil, a new TieredStats is allocated.
	Stats *TieredStats
	// AggStats receives aggregate counters compatible with RegisterCacheStats.
	// If nil, a new Stats is allocated.
	AggStats *Stats
	// L1MaxTTL caps the lifetime of L1 write-back entries. This bounds
	// the stale window when a concurrent Delete races with a read-through
	// write-back. Zero uses defaultL1MaxTTL (60s).
	L1MaxTTL time.Duration
}

// NewTiered constructs a two-tier read-through/write-through Backend.
func NewTiered(opts TieredOptions) (*Tiered, error) {
	if opts.L1 == nil {
		return nil, errNilL1
	}
	if opts.L2 == nil {
		return nil, errNilL2
	}
	ts := opts.Stats
	if ts == nil {
		ts = &TieredStats{}
	}
	agg := opts.AggStats
	if agg == nil {
		agg = &Stats{}
	}
	l1Max := opts.L1MaxTTL
	if l1Max <= 0 {
		l1Max = defaultL1MaxTTL
	}
	return &Tiered{l1: opts.L1, l2: opts.L2, stats: ts, aggStats: agg, l1MaxTTL: l1Max}, nil
}

var (
	errNilL1 = errorf("tiered: L1 backend must not be nil")
	errNilL2 = errorf("tiered: L2 backend must not be nil")
)

type constErr string

func errorf(s string) constErr { return constErr(s) }
func (e constErr) Error() string { return string(e) }

// Get checks L1 first; on miss it checks L2 and writes-back to L1 on hit.
func (t *Tiered) Get(ctx context.Context, key string) ([]byte, bool, error) {
	// L1 lookup (in-process, fast, never errors meaningfully).
	val, ok, err := t.l1.Get(ctx, key)
	if err != nil {
		// L1 errors are unexpected (LRU is in-memory). Treat as miss.
		ok = false
	}
	if ok {
		t.stats.L1Hits.Add(1)
		t.aggStats.Hits.Add(1)
		return val, true, nil
	}
	t.stats.L1Misses.Add(1)

	// L2 lookup (shared store, may error on network issues).
	val, ok, err = t.l2.Get(ctx, key)
	if err != nil {
		// L2 error: count as miss, propagate error so callers can
		// decide whether to degrade (E3 stale-while-revalidate).
		t.stats.L2Misses.Add(1)
		t.aggStats.Misses.Add(1)
		return nil, false, err
	}
	if !ok {
		t.stats.L2Misses.Add(1)
		t.aggStats.Misses.Add(1)
		return nil, false, nil
	}

	// L2 hit → read-through: write back to L1 with bounded TTL so stale
	// entries expire even if LRU eviction doesn't reach them. This also
	// bounds the race window between a concurrent Get write-back and Delete.
	t.stats.L2Hits.Add(1)
	t.aggStats.Hits.Add(1)
	_ = t.l1.Set(ctx, key, val, t.l1MaxTTL)
	return val, true, nil
}

// Set writes to both L1 and L2 (write-through).
func (t *Tiered) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	// Write L1 first (fast, in-process).
	_ = t.l1.Set(ctx, key, value, ttl)
	// Write L2 (authoritative TTL).
	return t.l2.Set(ctx, key, value, ttl)
}

// Delete removes from both layers.
func (t *Tiered) Delete(ctx context.Context, key string) error {
	_ = t.l1.Delete(ctx, key)
	return t.l2.Delete(ctx, key)
}

// TieredLayerStats returns the per-layer stats. Used by the metrics layer
// to expose lwauth_cache_layer_hits_total{cache, layer}.
func (t *Tiered) TieredLayerStats() *TieredStats { return t.stats }

// AggStats returns the aggregate Stats (compatible with RegisterCacheStats).
func (t *Tiered) AggStats() *Stats { return t.aggStats }

// L2 returns the L2 (shared) backend. Used by the config layer to build
// the distributed singleflight locker (E4) using the same Valkey client.
func (t *Tiered) L2() Backend { return t.l2 }

// Warm preloads L1 from L2 for the given keys. This is called on pod
// startup so new replicas avoid a cold L1 causing p99 misses. Keys that
// are missing or expired in L2 are silently skipped. Entries are stored
// with l1MaxTTL to ensure they expire and are re-validated.
func (t *Tiered) Warm(ctx context.Context, keys []string) (loaded int) {
	for _, key := range keys {
		if ctx.Err() != nil {
			break
		}
		val, ok, err := t.l2.Get(ctx, key)
		if err != nil || !ok {
			continue
		}
		_ = t.l1.Set(ctx, key, val, t.l1MaxTTL)
		loaded++
	}
	return loaded
}
