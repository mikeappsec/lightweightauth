// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package cache

import (
	"container/list"
	"context"
	"fmt"
	"strconv"
	"sync"
	"time"
)

// memoryCache is the default in-process backend registered as "memory". It is
// a bounded LRU with per-entry TTL and tag invalidation. It implements [Cache],
// [TagInvalidator] and [Atomic]: the atomic primitives execute under the
// single mutex, giving true compare-and-set semantics for a single replica
// (e.g. jti replay single-use). [Locker] remains a remote-only capability —
// cross-replica mutual exclusion is meaningless within one process — so it is
// still reserved for backends such as Valkey.
type memoryCache struct {
	mu    sync.Mutex
	max   int
	ll    *list.List                     // front = most recently used
	items map[string]*list.Element       // key -> element holding *memoryEntry
	tags  map[string]map[string]struct{} // tag -> set of keys
	stats *Stats
	now   func() time.Time // injectable clock for tests
}

type memoryEntry struct {
	key      string
	value    []byte
	expireAt time.Time // zero = no expiry
	tags     []string
}

func newMemoryCache(size int, stats *Stats) *memoryCache {
	if size <= 0 {
		size = 10_000
	}
	if stats == nil {
		stats = &Stats{}
	}
	return &memoryCache{
		max:   size,
		ll:    list.New(),
		items: make(map[string]*list.Element, size),
		tags:  make(map[string]map[string]struct{}),
		stats: stats,
		now:   time.Now,
	}
}

func (m *memoryCache) Get(_ context.Context, key string) ([]byte, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	el, ok := m.items[key]
	if !ok {
		m.stats.Misses.Add(1)
		return nil, false, nil
	}
	ent := el.Value.(*memoryEntry)
	if !ent.expireAt.IsZero() && m.now().After(ent.expireAt) {
		m.removeElement(el)
		m.stats.Misses.Add(1)
		return nil, false, nil
	}
	m.ll.MoveToFront(el)
	m.stats.Hits.Add(1)
	// Return a copy so callers cannot mutate stored bytes.
	out := make([]byte, len(ent.value))
	copy(out, ent.value)
	return out, true, nil
}

func (m *memoryCache) Set(_ context.Context, key string, value []byte, ttl time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.setLocked(key, value, ttl)
	return nil
}

// setLocked stores value under key for ttl. The caller must hold m.mu.
func (m *memoryCache) setLocked(key string, value []byte, ttl time.Duration) {
	stored := make([]byte, len(value))
	copy(stored, value)
	var exp time.Time
	if ttl > 0 {
		exp = m.now().Add(ttl)
	}

	if el, ok := m.items[key]; ok {
		ent := el.Value.(*memoryEntry)
		m.untagLocked(ent)
		ent.value = stored
		ent.expireAt = exp
		ent.tags = nil
		m.ll.MoveToFront(el)
		return
	}

	ent := &memoryEntry{key: key, value: stored, expireAt: exp}
	el := m.ll.PushFront(ent)
	m.items[key] = el
	for m.ll.Len() > m.max {
		m.evictOldest()
	}
}

// liveEntryLocked returns the unexpired entry for key, lazily evicting it if
// it has expired. The caller must hold m.mu.
func (m *memoryCache) liveEntryLocked(key string) (*list.Element, *memoryEntry, bool) {
	el, ok := m.items[key]
	if !ok {
		return nil, nil, false
	}
	ent := el.Value.(*memoryEntry)
	if !ent.expireAt.IsZero() && m.now().After(ent.expireAt) {
		m.removeElement(el)
		return nil, nil, false
	}
	return el, ent, true
}

// SetNX stores value under key only if no live entry exists, returning true
// when the value was stored. Part of the [Atomic] capability: it runs under
// m.mu so concurrent callers racing the same key get genuine compare-and-set
// semantics within this process.
func (m *memoryCache) SetNX(_ context.Context, key string, value []byte, ttl time.Duration) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, _, ok := m.liveEntryLocked(key); ok {
		return false, nil
	}
	m.setLocked(key, value, ttl)
	return true, nil
}

// Incr atomically increments the decimal integer stored at key, treating a
// missing or expired key as 0 and applying ttl only on first creation, then
// returns the new value. A stored value that is not a base-10 integer yields
// an error, mirroring Valkey's INCR.
func (m *memoryCache) Incr(_ context.Context, key string, ttl time.Duration) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if el, ent, ok := m.liveEntryLocked(key); ok {
		n, err := strconv.ParseInt(string(ent.value), 10, 64)
		if err != nil {
			return 0, fmt.Errorf("cache: Incr on non-integer value at key %q", key)
		}
		next := n + 1
		ent.value = []byte(strconv.FormatInt(next, 10))
		m.ll.MoveToFront(el)
		return next, nil
	}
	m.setLocked(key, []byte("1"), ttl)
	return 1, nil
}

func (m *memoryCache) Delete(_ context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if el, ok := m.items[key]; ok {
		m.removeElement(el)
	}
	return nil
}

// Tag associates key with the given tags. Tagging a missing key is a no-op.
func (m *memoryCache) Tag(_ context.Context, key string, tags ...string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	el, ok := m.items[key]
	if !ok {
		return nil
	}
	ent := el.Value.(*memoryEntry)
	ent.tags = append(ent.tags, tags...)
	for _, t := range tags {
		set, ok := m.tags[t]
		if !ok {
			set = make(map[string]struct{})
			m.tags[t] = set
		}
		set[key] = struct{}{}
	}
	return nil
}

// InvalidateTag deletes every key associated with tag.
func (m *memoryCache) InvalidateTag(_ context.Context, tag string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	set, ok := m.tags[tag]
	if !ok {
		return 0, nil
	}
	n := 0
	for key := range set {
		if el, ok := m.items[key]; ok {
			m.removeElement(el)
			n++
		}
	}
	return n, nil
}

func (m *memoryCache) evictOldest() {
	el := m.ll.Back()
	if el == nil {
		return
	}
	m.removeElement(el)
	m.stats.Evictions.Add(1)
}

func (m *memoryCache) removeElement(el *list.Element) {
	ent := el.Value.(*memoryEntry)
	m.ll.Remove(el)
	delete(m.items, ent.key)
	m.untagLocked(ent)
}

func (m *memoryCache) untagLocked(ent *memoryEntry) {
	for _, t := range ent.tags {
		if set, ok := m.tags[t]; ok {
			delete(set, ent.key)
			if len(set) == 0 {
				delete(m.tags, t)
			}
		}
	}
}

func init() {
	RegisterBackend("memory", func(spec BackendSpec, stats *Stats) (Cache, error) {
		return newMemoryCache(spec.Size, stats), nil
	})
}

// Capability guards.
var (
	_ Cache          = (*memoryCache)(nil)
	_ TagInvalidator = (*memoryCache)(nil)
	_ Atomic         = (*memoryCache)(nil)
)
