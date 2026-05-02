package cache

import (
	"context"
	"fmt"
	"time"
)

// LRU is an in-process Backend backed by a small in-house LRU
// (see [lru]).
//
// It is the default implementation used by the JWKS, introspection, and
// decision caches when no external backend (Redis, groupcache, ...) is
// configured. Safe for concurrent use.
type LRU struct {
	c          *lru[lruEntry]
	defaultTTL time.Duration
	stats      *Stats
	onEvict    func(key string) // optional callback for tag cleanup
}

type lruEntry struct {
	value  []byte
	expiry time.Time // zero = no per-entry TTL
}

// NewLRU returns an in-process Backend with a hard size cap and a default
// TTL applied when callers pass ttl == 0 to Set. Pass defaultTTL == 0 to
// disable the default (entries then live until the size cap evicts them).
func NewLRU(size int, defaultTTL time.Duration, stats *Stats) (*LRU, error) {
	if size <= 0 {
		return nil, fmt.Errorf("cache: lru size must be > 0, got %d", size)
	}
	if stats == nil {
		stats = &Stats{}
	}
	l := &LRU{defaultTTL: defaultTTL, stats: stats}
	onEvict := func(key string, _ lruEntry) {
		stats.Evictions.Add(1)
		if l.onEvict != nil {
			l.onEvict(key)
		}
	}
	l.c = newLRU[lruEntry](size, onEvict)
	return l, nil
}

// SetEvictCallback registers a function called whenever an entry is
// evicted by capacity pressure. Used by the Decision cache to clean
// the TagIndex on eviction (TC2).
func (l *LRU) SetEvictCallback(fn func(key string)) {
	l.onEvict = fn
}

// Get returns the cached value or ok=false on miss/expiry.
func (l *LRU) Get(_ context.Context, key string) ([]byte, bool, error) {
	e, ok := l.c.Get(key)
	if !ok {
		l.stats.Misses.Add(1)
		return nil, false, nil
	}
	if !e.expiry.IsZero() && time.Now().After(e.expiry) {
		l.c.Remove(key)
		l.stats.Misses.Add(1)
		// Notify tag cleanup on TTL expiry.
		if l.onEvict != nil {
			l.onEvict(key)
		}
		return nil, false, nil
	}
	l.stats.Hits.Add(1)
	return e.value, true, nil
}

// Set stores a value with an optional per-entry TTL. ttl == 0 falls back
// to the LRU's default TTL configured in NewLRU.
func (l *LRU) Set(_ context.Context, key string, value []byte, ttl time.Duration) error {
	e := lruEntry{value: value}
	if ttl == 0 {
		ttl = l.defaultTTL
	}
	if ttl > 0 {
		e.expiry = time.Now().Add(ttl)
	}
	l.c.Add(key, e)
	return nil
}

// Delete removes a key. It is not an error if the key is missing.
func (l *LRU) Delete(_ context.Context, key string) error {
	l.c.Remove(key)
	return nil
}

// Len returns the current number of entries (useful for tests/metrics).
func (l *LRU) Len() int { return l.c.Len() }
