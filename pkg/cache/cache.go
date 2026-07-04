// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

// Package cache is the public, backend-agnostic cache contract that every
// lwauth module relies on. It is the module-native replacement for the
// internal, pipeline-only cache described in the legacy cache architecture.
//
// The design has three layers:
//
//   - [Cache] is the universal, mandatory surface (Get/Set/Delete). Every
//     backend implements it and every module can depend on it.
//   - The capability interfaces ([Locker], [TagInvalidator], [Atomic]) are
//     optional. A backend advertises richer behavior by implementing them;
//     a module opts in with a type assertion. This is how "Valkey is one of
//     the cache modules that implements specific methods" — the base
//     interface is universal, the specific methods live behind assertions.
//   - [Provider] hands each module a namespaced [Cache] resolved from an
//     operator-declared pool (see the design doc, §5/§6).
//
// See docs/design/cache-layer-redesign.md for the full rationale.
package cache

import (
	"context"
	"errors"
	"time"
)

// ErrConfig is returned when cache configuration is invalid (for example a
// module references a pool that was never declared). It mirrors the module
// package's ErrConfig sentinel so loaders can treat configuration failures
// uniformly.
var ErrConfig = errors.New("cache: invalid configuration")

// Cache is the generic, backend-agnostic contract every module relies on.
// Implementations MUST be safe for concurrent use by multiple goroutines.
type Cache interface {
	// Get returns the stored bytes for key. ok=false is a clean miss; err
	// is reserved for transport/backend failures and is never used to
	// signal "not found".
	Get(ctx context.Context, key string) (value []byte, ok bool, err error)

	// Set stores value under key for ttl. A ttl <= 0 means "no explicit
	// expiry; rely on the backend's own eviction policy".
	Set(ctx context.Context, key string, value []byte, ttl time.Duration) error

	// Delete removes key. Deleting a missing key is not an error.
	Delete(ctx context.Context, key string) error
}

// Locker provides cross-replica mutual exclusion, enabling distributed
// singleflight. A typical implementation is Valkey SET NX PX with a
// token-checked release so only the lock owner can unlock.
type Locker interface {
	// TryLock attempts to acquire key for ttl. On success it returns a
	// unique token that must be presented to Unlock. acquired=false means
	// the lock is held elsewhere; err is reserved for backend failures.
	TryLock(ctx context.Context, key string, ttl time.Duration) (token string, acquired bool, err error)

	// Unlock releases key only if token matches the current holder.
	Unlock(ctx context.Context, key, token string) error
}

// TagInvalidator allows dropping many entries by a logical tag, e.g.
// invalidating every cached decision for sub=alice on logout.
type TagInvalidator interface {
	// Tag associates key with one or more tags.
	Tag(ctx context.Context, key string, tags ...string) error

	// InvalidateTag deletes every key associated with tag and returns the
	// number of entries removed.
	InvalidateTag(ctx context.Context, tag string) (removed int, err error)
}

// Atomic exposes compare-and-set style primitives for counters and
// idempotency keys, e.g. id-jag jti single-use enforcement or rate-limit
// windows.
type Atomic interface {
	// SetNX stores value under key only if key does not already exist.
	// It returns true when the value was stored.
	SetNX(ctx context.Context, key string, value []byte, ttl time.Duration) (bool, error)

	// Incr atomically increments the integer stored at key, setting ttl on
	// first creation, and returns the new value.
	Incr(ctx context.Context, key string, ttl time.Duration) (int64, error)
}
