package cache

import (
	"context"
	"fmt"
	"time"

	lru "github.com/hashicorp/golang-lru/v2/expirable"
)

// LRU is an in-process Backend backed by an expirable LRU cache.
//
// It is the default implementation used by the JWKS, introspection, and
// decision caches when no external backend (Redis, groupcache, ...) is
// configured. Safe for concurrent use.
type LRU struct {
	c     *lru.LRU[string, lruEntry]
	stats *Stats
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
	onEvict := func(_ string, _ lruEntry) { stats.Evictions.Add(1) }
	c := lru.NewLRU[string, lruEntry](size, onEvict, defaultTTL)
	return &LRU{c: c, stats: stats}, nil
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
		return nil, false, nil
	}
	l.stats.Hits.Add(1)
	return e.value, true, nil
}

// Set stores a value with an optional per-entry TTL. ttl == 0 falls back
// to the LRU's default TTL configured in NewLRU.
func (l *LRU) Set(_ context.Context, key string, value []byte, ttl time.Duration) error {
	e := lruEntry{value: value}
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
