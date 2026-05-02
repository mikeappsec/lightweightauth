package revocation

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// memEntry is a revocation entry with its expiry time.
type memEntry struct {
	Entry
	expiresAt time.Time
}

// MemoryStore is an in-process revocation store backed by a map with
// TTL-based expiry. Suitable for single-replica deployments and tests.
type MemoryStore struct {
	mu         sync.RWMutex
	entries    map[string]memEntry
	defaultTTL time.Duration
	maxEntries int // 0 = unlimited

	done chan struct{}
}

// MemoryOption configures a MemoryStore.
type MemoryOption func(*MemoryStore)

// WithDefaultTTL sets the default TTL for entries that don't specify one.
func WithDefaultTTL(d time.Duration) MemoryOption {
	return func(s *MemoryStore) { s.defaultTTL = d }
}

// WithMaxEntries sets the maximum number of entries. When full, Add
// returns an error. Zero means unlimited.
func WithMaxEntries(n int) MemoryOption {
	return func(s *MemoryStore) { s.maxEntries = n }
}

// NewMemoryStore creates an in-process revocation store. Expired entries
// are reaped every sweepInterval. Call Close() to stop the reaper.
func NewMemoryStore(opts ...MemoryOption) *MemoryStore {
	s := &MemoryStore{
		entries:    make(map[string]memEntry),
		defaultTTL: 24 * time.Hour,
		done:       make(chan struct{}),
	}
	for _, o := range opts {
		o(s)
	}
	go s.reaper()
	return s
}

// Add records a revocation entry. Returns an error if the store is at
// capacity (maxEntries > 0 and all slots are occupied by non-expired entries).
func (s *MemoryStore) Add(_ context.Context, e Entry) error {
	ttl := e.TTL
	if ttl <= 0 {
		ttl = s.defaultTTL
	}
	if e.RevokedAt.IsZero() {
		e.RevokedAt = time.Now()
	}
	s.mu.Lock()
	// Allow overwrites of existing keys without checking cap.
	if s.maxEntries > 0 && len(s.entries) >= s.maxEntries {
		if _, exists := s.entries[e.Key]; !exists {
			s.mu.Unlock()
			return fmt.Errorf("revocation/memory: store full (%d entries)", s.maxEntries)
		}
	}
	s.entries[e.Key] = memEntry{Entry: e, expiresAt: time.Now().Add(ttl)}
	s.mu.Unlock()
	return nil
}

// Exists returns true if the key is currently in the revocation set.
func (s *MemoryStore) Exists(_ context.Context, key string) (bool, error) {
	s.mu.RLock()
	me, ok := s.entries[key]
	s.mu.RUnlock()
	if !ok {
		return false, nil
	}
	if time.Now().After(me.expiresAt) {
		// Lazy eviction — the reaper will clean it up.
		return false, nil
	}
	return true, nil
}

// Remove deletes a revocation entry.
func (s *MemoryStore) Remove(_ context.Context, key string) error {
	s.mu.Lock()
	delete(s.entries, key)
	s.mu.Unlock()
	return nil
}

// List returns entries whose key starts with the given prefix, with pagination.
// For the memory store, cursor is the last key seen (lexicographic ordering).
func (s *MemoryStore) List(_ context.Context, prefix string, limit int, cursor string) ([]Entry, string, error) {
	if limit <= 0 || limit > DefaultListLimit {
		limit = DefaultListLimit
	}
	now := time.Now()
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []Entry
	for _, me := range s.entries {
		if now.After(me.expiresAt) {
			continue
		}
		if prefix != "" && (len(me.Key) < len(prefix) || me.Key[:len(prefix)] != prefix) {
			continue
		}
		// Cursor: skip entries <= cursor key (simple lexicographic pagination).
		if cursor != "" && me.Key <= cursor {
			continue
		}
		out = append(out, me.Entry)
		if len(out) >= limit {
			break
		}
	}
	nextCursor := ""
	if len(out) == limit {
		nextCursor = out[len(out)-1].Key
	}
	return out, nextCursor, nil
}

// Close stops the background reaper.
func (s *MemoryStore) Close() error {
	select {
	case <-s.done:
	default:
		close(s.done)
	}
	return nil
}

// reaper periodically removes expired entries.
func (s *MemoryStore) reaper() {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-s.done:
			return
		case <-t.C:
			s.sweep()
		}
	}
}

func (s *MemoryStore) sweep() {
	now := time.Now()
	s.mu.Lock()
	for k, me := range s.entries {
		if now.After(me.expiresAt) {
			delete(s.entries, k)
		}
	}
	s.mu.Unlock()
}
