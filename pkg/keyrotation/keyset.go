package keyrotation

import (
	"sync"
	"time"
)

// KeySet is a concurrency-safe collection of keyed credentials with
// rotation lifecycle management. It is generic over the secret material
// ([]byte for HMAC, *x509.Certificate for mTLS, etc.) — callers store
// an opaque value alongside each KeyMeta.
//
// KeySet handles:
//   - Adding new keys (pending until notBefore).
//   - Expiring old keys (retiring → retired).
//   - Lookup by kid, filtering out keys that are not currently valid.
//   - Reporting which kids are active/retiring/retired for metrics.
type KeySet[T any] struct {
	mu      sync.RWMutex
	entries map[string]*entry[T]
	now     func() time.Time
}

type entry[T any] struct {
	meta  KeyMeta
	value T
}

// NewKeySet creates an empty KeySet. The clock function is injectable
// for testing; pass nil for time.Now.
func NewKeySet[T any](clock func() time.Time) *KeySet[T] {
	if clock == nil {
		clock = time.Now
	}
	return &KeySet[T]{
		entries: make(map[string]*entry[T]),
		now:     clock,
	}
}

// Put adds or replaces a key in the set. If the key already exists its
// metadata and value are updated atomically.
func (ks *KeySet[T]) Put(meta KeyMeta, value T) {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	ks.entries[meta.KID] = &entry[T]{meta: meta, value: value}
}

// Get returns the value and true if kid exists and is currently valid
// (active or retiring). Returns zero-value and false otherwise.
func (ks *KeySet[T]) Get(kid string) (T, bool) {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	e, ok := ks.entries[kid]
	if !ok {
		var zero T
		return zero, false
	}
	if !e.meta.IsValid(ks.now()) {
		var zero T
		return zero, false
	}
	return e.value, true
}

// ActiveKIDs returns the kids of all keys in the active state.
func (ks *KeySet[T]) ActiveKIDs() []string {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	now := ks.now()
	var out []string
	for kid, e := range ks.entries {
		if e.meta.State(now) == KeyStateActive {
			out = append(out, kid)
		}
	}
	return out
}

// RetiringKIDs returns the kids of all keys in the retiring state.
func (ks *KeySet[T]) RetiringKIDs() []string {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	now := ks.now()
	var out []string
	for kid, e := range ks.entries {
		if e.meta.State(now) == KeyStateRetiring {
			out = append(out, kid)
		}
	}
	return out
}

// Prune removes all retired keys and returns their kids.
func (ks *KeySet[T]) Prune() []string {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	now := ks.now()
	var pruned []string
	for kid, e := range ks.entries {
		if e.meta.State(now) == KeyStateRetired {
			delete(ks.entries, kid)
			pruned = append(pruned, kid)
		}
	}
	return pruned
}

// All returns metadata for every key in the set (any state).
func (ks *KeySet[T]) All() []KeyMeta {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	out := make([]KeyMeta, 0, len(ks.entries))
	for _, e := range ks.entries {
		out = append(out, e.meta)
	}
	return out
}

// Len returns the total number of keys (all states).
func (ks *KeySet[T]) Len() int {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	return len(ks.entries)
}
