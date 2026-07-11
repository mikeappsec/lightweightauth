// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package cache

import (
	"context"
	"strings"
	"time"
)

// namespaced wraps a [Cache] and transparently prefixes every key with a
// fixed namespace, so two modules that ask the same pool for the logical
// name "tokens" never collide. The prefix is derived from the requesting
// module's identity by the [Provider] (e.g. "i/jwt/my-jwt/tokens/").
//
// Capability interfaces are forwarded with prefixing applied, so a module
// that type-asserts the handle to [Locker], [TagInvalidator], or [Atomic]
// still operates within its namespace.
type namespaced struct {
	inner  Cache
	prefix string
}

// Namespaced returns a view of c whose keys are prefixed with prefix. An
// empty prefix returns c unchanged. The returned value implements the same
// capability interfaces (Locker/TagInvalidator/Atomic) that c does.
func Namespaced(c Cache, prefix string) Cache {
	if prefix == "" || c == nil {
		return c
	}
	if !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}
	n := &namespaced{inner: c, prefix: prefix}
	// Preserve the richest capability set the inner cache offers so type
	// assertions on the returned handle keep working.
	_, lock := c.(Locker)
	_, tag := c.(TagInvalidator)
	_, atom := c.(Atomic)
	switch {
	case lock && tag && atom:
		return &namespacedFull{namespaced: n}
	case lock && atom:
		return &namespacedLockAtomic{namespaced: n}
	case tag && atom:
		return &namespacedTagAtomic{namespaced: n}
	case lock && tag:
		return &namespacedLockTag{namespaced: n}
	case lock:
		return &namespacedLocker{namespaced: n}
	case tag:
		return &namespacedTag{namespaced: n}
	case atom:
		return &namespacedAtomic{namespaced: n}
	default:
		return n
	}
}

func (n *namespaced) key(k string) string { return n.prefix + k }

func (n *namespaced) Get(ctx context.Context, key string) ([]byte, bool, error) {
	return n.inner.Get(ctx, n.key(key))
}

func (n *namespaced) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	return n.inner.Set(ctx, n.key(key), value, ttl)
}

func (n *namespaced) Delete(ctx context.Context, key string) error {
	return n.inner.Delete(ctx, n.key(key))
}

// --- capability forwarders -------------------------------------------------

func (n *namespaced) tryLock(ctx context.Context, key string, ttl time.Duration) (string, bool, error) {
	return n.inner.(Locker).TryLock(ctx, n.key(key), ttl)
}

func (n *namespaced) unlock(ctx context.Context, key, token string) error {
	return n.inner.(Locker).Unlock(ctx, n.key(key), token)
}

func (n *namespaced) tag(ctx context.Context, key string, tags ...string) error {
	// Tags are a logical dimension, not keys, so they are namespaced too —
	// and must use the same prefix invalidateTag applies, or a namespaced
	// Tag/InvalidateTag pair would address different membership sets.
	prefixed := make([]string, len(tags))
	for i, t := range tags {
		prefixed[i] = n.prefix + t
	}
	return n.inner.(TagInvalidator).Tag(ctx, n.key(key), prefixed...)
}

func (n *namespaced) invalidateTag(ctx context.Context, t string) (int, error) {
	// Tags are a logical dimension, not keys, so they are namespaced too.
	return n.inner.(TagInvalidator).InvalidateTag(ctx, n.prefix+t)
}

func (n *namespaced) setNX(ctx context.Context, key string, value []byte, ttl time.Duration) (bool, error) {
	return n.inner.(Atomic).SetNX(ctx, n.key(key), value, ttl)
}

func (n *namespaced) incr(ctx context.Context, key string, ttl time.Duration) (int64, error) {
	return n.inner.(Atomic).Incr(ctx, n.key(key), ttl)
}

// The variants below expose exactly the capability set of the inner cache.

type namespacedLocker struct{ *namespaced }

func (n *namespacedLocker) TryLock(ctx context.Context, key string, ttl time.Duration) (string, bool, error) {
	return n.tryLock(ctx, key, ttl)
}
func (n *namespacedLocker) Unlock(ctx context.Context, key, token string) error {
	return n.unlock(ctx, key, token)
}

type namespacedTag struct{ *namespaced }

func (n *namespacedTag) Tag(ctx context.Context, key string, tags ...string) error {
	return n.tag(ctx, key, tags...)
}
func (n *namespacedTag) InvalidateTag(ctx context.Context, t string) (int, error) {
	return n.invalidateTag(ctx, t)
}

type namespacedAtomic struct{ *namespaced }

func (n *namespacedAtomic) SetNX(ctx context.Context, key string, value []byte, ttl time.Duration) (bool, error) {
	return n.setNX(ctx, key, value, ttl)
}
func (n *namespacedAtomic) Incr(ctx context.Context, key string, ttl time.Duration) (int64, error) {
	return n.incr(ctx, key, ttl)
}

type namespacedLockTag struct {
	*namespaced
}

func (n *namespacedLockTag) TryLock(ctx context.Context, key string, ttl time.Duration) (string, bool, error) {
	return n.tryLock(ctx, key, ttl)
}
func (n *namespacedLockTag) Unlock(ctx context.Context, key, token string) error {
	return n.unlock(ctx, key, token)
}
func (n *namespacedLockTag) Tag(ctx context.Context, key string, tags ...string) error {
	return n.tag(ctx, key, tags...)
}
func (n *namespacedLockTag) InvalidateTag(ctx context.Context, t string) (int, error) {
	return n.invalidateTag(ctx, t)
}

type namespacedLockAtomic struct {
	*namespaced
}

func (n *namespacedLockAtomic) TryLock(ctx context.Context, key string, ttl time.Duration) (string, bool, error) {
	return n.tryLock(ctx, key, ttl)
}
func (n *namespacedLockAtomic) Unlock(ctx context.Context, key, token string) error {
	return n.unlock(ctx, key, token)
}
func (n *namespacedLockAtomic) SetNX(ctx context.Context, key string, value []byte, ttl time.Duration) (bool, error) {
	return n.setNX(ctx, key, value, ttl)
}
func (n *namespacedLockAtomic) Incr(ctx context.Context, key string, ttl time.Duration) (int64, error) {
	return n.incr(ctx, key, ttl)
}

type namespacedTagAtomic struct {
	*namespaced
}

func (n *namespacedTagAtomic) Tag(ctx context.Context, key string, tags ...string) error {
	return n.tag(ctx, key, tags...)
}
func (n *namespacedTagAtomic) InvalidateTag(ctx context.Context, t string) (int, error) {
	return n.invalidateTag(ctx, t)
}
func (n *namespacedTagAtomic) SetNX(ctx context.Context, key string, value []byte, ttl time.Duration) (bool, error) {
	return n.setNX(ctx, key, value, ttl)
}
func (n *namespacedTagAtomic) Incr(ctx context.Context, key string, ttl time.Duration) (int64, error) {
	return n.incr(ctx, key, ttl)
}

type namespacedFull struct {
	*namespaced
}

func (n *namespacedFull) TryLock(ctx context.Context, key string, ttl time.Duration) (string, bool, error) {
	return n.tryLock(ctx, key, ttl)
}
func (n *namespacedFull) Unlock(ctx context.Context, key, token string) error {
	return n.unlock(ctx, key, token)
}
func (n *namespacedFull) Tag(ctx context.Context, key string, tags ...string) error {
	return n.tag(ctx, key, tags...)
}
func (n *namespacedFull) InvalidateTag(ctx context.Context, t string) (int, error) {
	return n.invalidateTag(ctx, t)
}
func (n *namespacedFull) SetNX(ctx context.Context, key string, value []byte, ttl time.Duration) (bool, error) {
	return n.setNX(ctx, key, value, ttl)
}
func (n *namespacedFull) Incr(ctx context.Context, key string, ttl time.Duration) (int64, error) {
	return n.incr(ctx, key, ttl)
}
