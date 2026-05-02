package cache

import "sync"

// TagIndex maintains a reverse mapping from tags to cache keys, enabling
// efficient tag-based invalidation (E3). When a cache entry is written
// with tags, those tags are recorded here. When an invalidation event
// arrives for a tag, all keys associated with that tag can be evicted.
//
// Thread-safe for concurrent use.
type TagIndex struct {
	mu       sync.RWMutex
	tagToKeys map[string]map[string]struct{} // tag → set of keys
	keyToTags map[string]map[string]struct{} // key → set of tags
}

// NewTagIndex creates a tag index.
func NewTagIndex() *TagIndex {
	return &TagIndex{
		tagToKeys: make(map[string]map[string]struct{}),
		keyToTags: make(map[string]map[string]struct{}),
	}
}

// Associate records that key is tagged with the given tags. Replaces any
// prior tag set for that key.
func (ti *TagIndex) Associate(key string, tags []string) {
	if len(tags) == 0 {
		return
	}
	ti.mu.Lock()
	defer ti.mu.Unlock()

	// Remove prior associations for this key.
	if old, ok := ti.keyToTags[key]; ok {
		for t := range old {
			if m, ok := ti.tagToKeys[t]; ok {
				delete(m, key)
				if len(m) == 0 {
					delete(ti.tagToKeys, t)
				}
			}
		}
	}

	// Record new associations.
	tagSet := make(map[string]struct{}, len(tags))
	for _, t := range tags {
		tagSet[t] = struct{}{}
		if _, ok := ti.tagToKeys[t]; !ok {
			ti.tagToKeys[t] = make(map[string]struct{})
		}
		ti.tagToKeys[t][key] = struct{}{}
	}
	ti.keyToTags[key] = tagSet
}

// KeysForTag returns all cache keys associated with the given tag.
func (ti *TagIndex) KeysForTag(tag string) []string {
	ti.mu.RLock()
	defer ti.mu.RUnlock()
	m, ok := ti.tagToKeys[tag]
	if !ok {
		return nil
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// KeysForTags returns the union of all cache keys associated with any of
// the given tags.
func (ti *TagIndex) KeysForTags(tags []string) []string {
	ti.mu.RLock()
	defer ti.mu.RUnlock()
	seen := make(map[string]struct{})
	for _, tag := range tags {
		if m, ok := ti.tagToKeys[tag]; ok {
			for k := range m {
				seen[k] = struct{}{}
			}
		}
	}
	keys := make([]string, 0, len(seen))
	for k := range seen {
		keys = append(keys, k)
	}
	return keys
}

// Remove cleans up all tag associations for a key (called on eviction/delete).
func (ti *TagIndex) Remove(key string) {
	ti.mu.Lock()
	defer ti.mu.Unlock()
	tags, ok := ti.keyToTags[key]
	if !ok {
		return
	}
	for t := range tags {
		if m, ok := ti.tagToKeys[t]; ok {
			delete(m, key)
			if len(m) == 0 {
				delete(ti.tagToKeys, t)
			}
		}
	}
	delete(ti.keyToTags, key)
}

// Len returns the number of tracked keys (useful for metrics/tests).
func (ti *TagIndex) Len() int {
	ti.mu.RLock()
	defer ti.mu.RUnlock()
	return len(ti.keyToTags)
}
