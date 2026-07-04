// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package revocation

import (
	"context"
	"errors"
	"time"
)

// Cache is the minimal key-value contract a revocation store needs from a
// pkg/cache pool backend. It is intentionally a structural subset of
// pkg/cache.Cache (Get/Set/Delete), so a pool-supplied Cache satisfies it
// without this package importing pkg/cache — the config layer bridges the two.
type Cache interface {
	Get(ctx context.Context, key string) ([]byte, bool, error)
	Set(ctx context.Context, key string, value []byte, ttl time.Duration) error
	Delete(ctx context.Context, key string) error
}

// ErrListUnsupported is returned by a pool-backed store's List: a generic
// pkg/cache backend exposes no enumeration (SCAN) capability, so listing
// active revocations requires the dedicated "valkey" backend instead.
var ErrListUnsupported = errors.New("revocation: List is not supported on a pool-backed store; use backend=valkey for enumeration")

// CacheStore is a revocation Store that folds its storage onto a pkg/cache
// pool backend (P6). Each revocation is a single key with a TTL; existence
// checks are a plain Get. This lets multiple modules share one pool's
// backend infrastructure (e.g. a single shared Valkey connection) while the
// retained [Store] facade keeps every call site unchanged.
//
// Enumeration (List) is unsupported because the pkg/cache contract is a flat
// key-value store with no SCAN. Deployments that need to enumerate active
// revocations should use the dedicated backend=valkey path.
type CacheStore struct {
	cache      Cache
	defaultTTL time.Duration
}

// NewCacheStore wraps a pool-supplied cache as a revocation Store. A
// non-positive defaultTTL falls back to 24h, matching the other backends.
func NewCacheStore(c Cache, defaultTTL time.Duration) *CacheStore {
	if defaultTTL <= 0 {
		defaultTTL = 24 * time.Hour
	}
	return &CacheStore{cache: c, defaultTTL: defaultTTL}
}

// revokedMarker is the value stored when an entry carries no reason. The
// value is never interpreted on read — existence is all that matters — but a
// non-empty payload keeps the entry meaningful in store inspectors.
const revokedMarker = "revoked"

// Add records a revocation as a key with TTL.
func (s *CacheStore) Add(ctx context.Context, e Entry) error {
	ttl := e.TTL
	if ttl <= 0 {
		ttl = s.defaultTTL
	}
	val := e.Reason
	if val == "" {
		val = revokedMarker
	}
	return s.cache.Set(ctx, e.Key, []byte(val), ttl)
}

// Exists reports whether a revocation key is currently present.
func (s *CacheStore) Exists(ctx context.Context, key string) (bool, error) {
	_, ok, err := s.cache.Get(ctx, key)
	if err != nil {
		return false, err
	}
	return ok, nil
}

// Remove deletes a revocation entry (un-revoke).
func (s *CacheStore) Remove(ctx context.Context, key string) error {
	return s.cache.Delete(ctx, key)
}

// List always returns [ErrListUnsupported]: a pool backend offers no
// enumeration. See the type doc for the rationale.
func (s *CacheStore) List(_ context.Context, _ string, _ int, _ string) ([]Entry, string, error) {
	return nil, "", ErrListUnsupported
}

// Close is a no-op: the pool owns the backend's lifecycle.
func (s *CacheStore) Close() error { return nil }
