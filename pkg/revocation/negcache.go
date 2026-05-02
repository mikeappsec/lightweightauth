// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package revocation

import (
	"context"
	"sync"
	"time"
)

// NegCache wraps a Store with a local negative TTL cache. For the
// common case (credential is NOT revoked), a cache hit avoids a
// network round-trip to the backing store.
//
// When a revocation is added, the negative cache entry (if any) is
// evicted immediately for the local replica. Cross-replica invalidation
// is handled by the event bus (pubsub) calling Evict().
type NegCache struct {
	inner    Store
	mu       sync.RWMutex
	cache    map[string]time.Time // key → expiry of the "not-revoked" entry
	ttl      time.Duration
	maxSize  int // 0 = unlimited; when full, oldest entries are evicted
	done     chan struct{}
}

// NegCacheOption configures a NegCache.
type NegCacheOption func(*NegCache)

// WithNegCacheTTL sets the lifetime of a "not-revoked" cache entry.
// Default is 2 seconds. Set to 0 to disable negative caching entirely
// (every check hits the backing store — suitable for high-security deployments).
func WithNegCacheTTL(d time.Duration) NegCacheOption {
	return func(nc *NegCache) { nc.ttl = d }
}

// WithNegCacheMaxSize caps the number of entries in the negative cache.
// Default 100,000. When full, the oldest entry is evicted on insert.
func WithNegCacheMaxSize(n int) NegCacheOption {
	return func(nc *NegCache) { nc.maxSize = n }
}

// NewNegCache wraps inner with a local negative-result cache.
func NewNegCache(inner Store, opts ...NegCacheOption) *NegCache {
	nc := &NegCache{
		inner:   inner,
		cache:   make(map[string]time.Time),
		ttl:     2 * time.Second,
		maxSize: 100_000,
		done:    make(chan struct{}),
	}
	for _, o := range opts {
		o(nc)
	}
	go nc.reaper()
	return nc
}

// Exists checks the local negative cache first. On cache hit (entry is
// "known not-revoked" and fresh), returns false without touching the
// backing store. On miss, queries inner and caches a negative result.
// When ttl is 0, caching is disabled and every call hits the store.
func (nc *NegCache) Exists(ctx context.Context, key string) (bool, error) {
	// ttl == 0 disables negative caching entirely.
	if nc.ttl <= 0 {
		return nc.inner.Exists(ctx, key)
	}

	nc.mu.RLock()
	exp, ok := nc.cache[key]
	nc.mu.RUnlock()
	if ok && time.Now().Before(exp) {
		// Cached "not-revoked" — skip network call.
		return false, nil
	}

	revoked, err := nc.inner.Exists(ctx, key)
	if err != nil {
		return false, err
	}
	if !revoked {
		// Cache the negative result, enforcing max size.
		nc.mu.Lock()
		if nc.maxSize > 0 && len(nc.cache) >= nc.maxSize {
			// Evict one expired or oldest entry to make room.
			nc.evictOneLocked()
		}
		nc.cache[key] = time.Now().Add(nc.ttl)
		nc.mu.Unlock()
	}
	return revoked, nil
}

// evictOneLocked removes one entry. Prefers expired entries; falls back
// to any arbitrary entry. Caller must hold nc.mu write lock.
func (nc *NegCache) evictOneLocked() {
	now := time.Now()
	for k, exp := range nc.cache {
		if now.After(exp) {
			delete(nc.cache, k)
			return
		}
	}
	// No expired entry found — evict an arbitrary entry.
	for k := range nc.cache {
		delete(nc.cache, k)
		return
	}
}

// Add delegates to inner and evicts the local negative cache entry.
func (nc *NegCache) Add(ctx context.Context, e Entry) error {
	if err := nc.inner.Add(ctx, e); err != nil {
		return err
	}
	nc.Evict(e.Key)
	return nil
}

// Remove delegates to inner.
func (nc *NegCache) Remove(ctx context.Context, key string) error {
	return nc.inner.Remove(ctx, key)
}

// List delegates to inner.
func (nc *NegCache) List(ctx context.Context, prefix string, limit int, cursor string) ([]Entry, string, error) {
	return nc.inner.List(ctx, prefix, limit, cursor)
}

// Close stops the reaper and closes the inner store.
func (nc *NegCache) Close() error {
	select {
	case <-nc.done:
	default:
		close(nc.done)
	}
	return nc.inner.Close()
}

// Evict removes a key from the local negative cache. Called by the
// event bus subscriber when a remote replica publishes a revocation.
func (nc *NegCache) Evict(key string) {
	nc.mu.Lock()
	delete(nc.cache, key)
	nc.mu.Unlock()
}

// EvictPrefix removes all negative cache entries matching a prefix.
// Used for subject-level revocations.
func (nc *NegCache) EvictPrefix(prefix string) {
	nc.mu.Lock()
	for k := range nc.cache {
		if len(k) >= len(prefix) && k[:len(prefix)] == prefix {
			delete(nc.cache, k)
		}
	}
	nc.mu.Unlock()
}

// reaper removes expired negative cache entries periodically.
func (nc *NegCache) reaper() {
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-nc.done:
			return
		case <-t.C:
			nc.sweep()
		}
	}
}

func (nc *NegCache) sweep() {
	now := time.Now()
	nc.mu.Lock()
	for k, exp := range nc.cache {
		if now.After(exp) {
			delete(nc.cache, k)
		}
	}
	nc.mu.Unlock()
}
