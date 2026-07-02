// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package cachevalkey

import (
	"context"
	"slices"
	"testing"
	"time"

	pkgcache "github.com/mikeappsec/lightweightauth/pkg/cache"
)

// TestPkgCache_Registered confirms the init() side-effect registered the
// backend into the public pkg/cache registry and that its factory still
// rejects an empty address.
func TestPkgCache_Registered(t *testing.T) {
	if !slices.Contains(pkgcache.RegisteredBackends(), "valkey") {
		t.Fatalf("valkey not in pkg/cache registry: %v", pkgcache.RegisteredBackends())
	}
	if _, err := pkgcache.BuildBackend(pkgcache.BackendSpec{Type: "valkey"}, nil); err == nil {
		t.Fatalf("expected error when addr is empty")
	}
}

// TestPkgCache_Capabilities pins that a Valkey backend satisfies every
// optional pkg/cache capability, so pools backed by it expose locks, tags
// and atomics to modules that type-assert their handle.
func TestPkgCache_Capabilities(t *testing.T) {
	b, _ := newTestBackend(t, "lwauth/")
	var c pkgcache.Cache = b
	if _, ok := c.(pkgcache.Locker); !ok {
		t.Fatal("valkey backend does not implement Locker")
	}
	if _, ok := c.(pkgcache.TagInvalidator); !ok {
		t.Fatal("valkey backend does not implement TagInvalidator")
	}
	if _, ok := c.(pkgcache.Atomic); !ok {
		t.Fatal("valkey backend does not implement Atomic")
	}
}

func TestPkgCache_Locker(t *testing.T) {
	b, _ := newTestBackend(t, "lwauth/")
	ctx := context.Background()

	token, acquired, err := b.TryLock(ctx, "job", time.Minute)
	if err != nil || !acquired || token == "" {
		t.Fatalf("first TryLock = (%q, %v, %v); want non-empty token, true, nil", token, acquired, err)
	}

	// A second acquire while held must fail without error.
	if _, acquired2, err := b.TryLock(ctx, "job", time.Minute); err != nil || acquired2 {
		t.Fatalf("contended TryLock = (%v, %v); want false, nil", acquired2, err)
	}

	// Unlock with the wrong token must NOT release the lock.
	if err := b.Unlock(ctx, "job", "not-the-token"); err != nil {
		t.Fatalf("Unlock(wrong token): %v", err)
	}
	if _, acquired3, _ := b.TryLock(ctx, "job", time.Minute); acquired3 {
		t.Fatal("lock released by a non-owner token")
	}

	// Unlock with the correct token releases it.
	if err := b.Unlock(ctx, "job", token); err != nil {
		t.Fatalf("Unlock(owner token): %v", err)
	}
	if _, acquired4, err := b.TryLock(ctx, "job", time.Minute); err != nil || !acquired4 {
		t.Fatalf("re-acquire after unlock = (%v, %v); want true, nil", acquired4, err)
	}
}

func TestPkgCache_SetNX(t *testing.T) {
	b, mr := newTestBackend(t, "")
	ctx := context.Background()

	stored, err := b.SetNX(ctx, "once", []byte("v"), 50*time.Millisecond)
	if err != nil || !stored {
		t.Fatalf("first SetNX = (%v, %v); want true, nil", stored, err)
	}
	// Second SetNX on the live key is rejected.
	if stored2, err := b.SetNX(ctx, "once", []byte("w"), time.Minute); err != nil || stored2 {
		t.Fatalf("second SetNX = (%v, %v); want false, nil", stored2, err)
	}
	// After expiry the slot is free again.
	mr.FastForward(100 * time.Millisecond)
	if stored3, err := b.SetNX(ctx, "once", []byte("x"), time.Minute); err != nil || !stored3 {
		t.Fatalf("post-expiry SetNX = (%v, %v); want true, nil", stored3, err)
	}
}

func TestPkgCache_Incr(t *testing.T) {
	b, mr := newTestBackend(t, "")
	ctx := context.Background()

	for want := int64(1); want <= 3; want++ {
		got, err := b.Incr(ctx, "counter", time.Minute)
		if err != nil || got != want {
			t.Fatalf("Incr #%d = (%d, %v); want %d, nil", want, got, err, want)
		}
	}

	// TTL is applied on creation: the counter disappears after expiry and
	// the next Incr starts from 1 again.
	mr.FastForward(2 * time.Minute)
	if got, err := b.Incr(ctx, "counter", time.Minute); err != nil || got != 1 {
		t.Fatalf("post-expiry Incr = (%d, %v); want 1, nil", got, err)
	}

	// Incrementing a non-integer value is an error (matches memory backend).
	if err := b.Set(ctx, "text", []byte("abc"), time.Minute); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if _, err := b.Incr(ctx, "text", time.Minute); err == nil {
		t.Fatal("expected error incrementing a non-integer value")
	}
}

func TestPkgCache_TagInvalidation(t *testing.T) {
	b, _ := newTestBackend(t, "lwauth/")
	ctx := context.Background()

	for _, k := range []string{"u1", "u2"} {
		if err := b.Set(ctx, k, []byte("v"), time.Minute); err != nil {
			t.Fatalf("Set %s: %v", k, err)
		}
		if err := b.Tag(ctx, k, "sub:alice"); err != nil {
			t.Fatalf("Tag %s: %v", k, err)
		}
	}
	// A key tagged differently must survive the invalidation below.
	if err := b.Set(ctx, "u3", []byte("v"), time.Minute); err != nil {
		t.Fatalf("Set u3: %v", err)
	}
	if err := b.Tag(ctx, "u3", "sub:bob"); err != nil {
		t.Fatalf("Tag u3: %v", err)
	}

	n, err := b.InvalidateTag(ctx, "sub:alice")
	if err != nil || n != 2 {
		t.Fatalf("InvalidateTag = (%d, %v); want 2, nil", n, err)
	}
	for _, k := range []string{"u1", "u2"} {
		if _, ok, _ := b.Get(ctx, k); ok {
			t.Fatalf("%s survived tag invalidation", k)
		}
	}
	if _, ok, _ := b.Get(ctx, "u3"); !ok {
		t.Fatal("u3 (different tag) was wrongly invalidated")
	}

	// Invalidating an unknown tag is a clean no-op.
	if n, err := b.InvalidateTag(ctx, "sub:nobody"); err != nil || n != 0 {
		t.Fatalf("InvalidateTag(unknown) = (%d, %v); want 0, nil", n, err)
	}
}

// TestPkgCache_NamespacedCapabilities verifies the capabilities still work
// when the backend is wrapped by pkg/cache's per-module namespace, which is
// how modules actually receive their handle from a Provider.
func TestPkgCache_NamespacedCapabilities(t *testing.T) {
	b, _ := newTestBackend(t, "lwauth/")
	ctx := context.Background()
	ns := pkgcache.Namespaced(b, "i/jwt/my-jwt/replay")

	atom, ok := ns.(pkgcache.Atomic)
	if !ok {
		t.Fatal("namespaced valkey handle lost Atomic capability")
	}
	stored, err := atom.SetNX(ctx, "jti-1", []byte{1}, time.Minute)
	if err != nil || !stored {
		t.Fatalf("namespaced SetNX = (%v, %v); want true, nil", stored, err)
	}
	if stored2, err := atom.SetNX(ctx, "jti-1", []byte{1}, time.Minute); err != nil || stored2 {
		t.Fatalf("namespaced replay SetNX = (%v, %v); want false, nil", stored2, err)
	}

	lock, ok := ns.(pkgcache.Locker)
	if !ok {
		t.Fatal("namespaced valkey handle lost Locker capability")
	}
	token, acquired, err := lock.TryLock(ctx, "sf-key", time.Minute)
	if err != nil || !acquired {
		t.Fatalf("namespaced TryLock = (%v, %v); want true, nil", acquired, err)
	}
	if err := lock.Unlock(ctx, "sf-key", token); err != nil {
		t.Fatalf("namespaced Unlock: %v", err)
	}
}
