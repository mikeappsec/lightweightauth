package cache

import (
	"container/list"
	"sync"
)

// lru is a minimal thread-safe LRU map used by [LRU]. It is
// deliberately not exported: the public Backend surface is the only API
// other packages should consume.
//
// Implementation: a doubly-linked list + map[K]*list.Element. Most-
// recently-used at the front, least at the back. All operations are
// O(1). The `onEvict` callback fires when a key is dropped due to
// capacity (not when it is overwritten or explicitly removed; matches
// the behaviour of the previous hashicorp/golang-lru/v2 implementation).
//
// We carry our own LRU rather than depend on hashicorp/golang-lru
// because (a) the surface we use is tiny (Add/Get/Remove/Len + eviction
// callback) and (b) per-entry TTL is enforced one layer up in [LRU.Get],
// so the library's "expirable" feature was redundant.
type lru[V any] struct {
	mu      sync.Mutex
	cap     int
	ll      *list.List
	idx     map[string]*list.Element
	onEvict func(string, V)
}

type lruNode[V any] struct {
	key string
	val V
}

func newLRU[V any](capacity int, onEvict func(string, V)) *lru[V] {
	return &lru[V]{
		cap:     capacity,
		ll:      list.New(),
		idx:     make(map[string]*list.Element, capacity),
		onEvict: onEvict,
	}
}

// Add inserts or updates key. Returns true when an existing entry was
// evicted to make room (i.e. the cache was at capacity).
func (c *lru[V]) Add(key string, value V) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.idx[key]; ok {
		// Update + bump to MRU. No eviction.
		el.Value.(*lruNode[V]).val = value
		c.ll.MoveToFront(el)
		return false
	}
	c.idx[key] = c.ll.PushFront(&lruNode[V]{key: key, val: value})
	if c.ll.Len() <= c.cap {
		return false
	}
	// Evict LRU.
	tail := c.ll.Back()
	if tail == nil {
		return false
	}
	n := tail.Value.(*lruNode[V])
	c.ll.Remove(tail)
	delete(c.idx, n.key)
	if c.onEvict != nil {
		c.onEvict(n.key, n.val)
	}
	return true
}

// Get fetches the value for key, bumping it to MRU on hit.
func (c *lru[V]) Get(key string) (V, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.idx[key]
	if !ok {
		var zero V
		return zero, false
	}
	c.ll.MoveToFront(el)
	return el.Value.(*lruNode[V]).val, true
}

// Remove drops key. Returns true if it was present. Does NOT fire
// onEvict (matching upstream semantics: explicit removal is not eviction).
func (c *lru[V]) Remove(key string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.idx[key]
	if !ok {
		return false
	}
	c.ll.Remove(el)
	delete(c.idx, key)
	return true
}

// Len returns the current entry count.
func (c *lru[V]) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ll.Len()
}
