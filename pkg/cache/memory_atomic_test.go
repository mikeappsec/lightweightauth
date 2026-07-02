// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package cache_test

import (
	"context"
	"testing"
	"time"

	"github.com/mikeappsec/lightweightauth/pkg/cache"
)

func TestMemoryImplementsAtomic(t *testing.T) {
	c, _ := cache.BuildBackend(cache.BackendSpec{Type: "memory"}, &cache.Stats{})
	if _, ok := c.(cache.Atomic); !ok {
		t.Fatal("memory backend must implement Atomic")
	}
}

func TestMemorySetNX(t *testing.T) {
	ctx := context.Background()
	c, _ := cache.BuildBackend(cache.BackendSpec{Type: "memory"}, &cache.Stats{})
	a := c.(cache.Atomic)

	first, err := a.SetNX(ctx, "k", []byte("v"), time.Minute)
	if err != nil || !first {
		t.Fatalf("first SetNX = %v, %v; want true, nil", first, err)
	}
	again, err := a.SetNX(ctx, "k", []byte("v2"), time.Minute)
	if err != nil || again {
		t.Fatalf("second SetNX = %v, %v; want false, nil", again, err)
	}
	// The original value must not be overwritten by the failed SetNX.
	got, ok, _ := c.Get(ctx, "k")
	if !ok || string(got) != "v" {
		t.Fatalf("value after failed SetNX = %q (ok=%v); want \"v\"", got, ok)
	}
}

func TestMemoryIncr(t *testing.T) {
	ctx := context.Background()
	c, _ := cache.BuildBackend(cache.BackendSpec{Type: "memory"}, &cache.Stats{})
	a := c.(cache.Atomic)

	for want := int64(1); want <= 3; want++ {
		got, err := a.Incr(ctx, "ctr", time.Minute)
		if err != nil || got != want {
			t.Fatalf("Incr = %d, %v; want %d", got, err, want)
		}
	}
	v, _, _ := c.Get(ctx, "ctr")
	if string(v) != "3" {
		t.Fatalf("stored counter = %q; want \"3\"", v)
	}
}

func TestMemoryIncrNonInteger(t *testing.T) {
	ctx := context.Background()
	c, _ := cache.BuildBackend(cache.BackendSpec{Type: "memory"}, &cache.Stats{})
	_ = c.Set(ctx, "x", []byte("not-a-number"), time.Minute)
	a := c.(cache.Atomic)
	if _, err := a.Incr(ctx, "x", time.Minute); err == nil {
		t.Fatal("expected an error incrementing a non-integer value")
	}
}

func TestNamespacePreservesAtomicAndIsolates(t *testing.T) {
	ctx := context.Background()
	c, _ := cache.BuildBackend(cache.BackendSpec{Type: "memory"}, &cache.Stats{})

	aHandle := cache.Namespaced(c, "i/idjag/a/replay/")
	bHandle := cache.Namespaced(c, "i/idjag/b/replay/")
	a, ok := aHandle.(cache.Atomic)
	if !ok {
		t.Fatal("namespaced memory cache must still expose Atomic")
	}
	b := bHandle.(cache.Atomic)

	if first, _ := a.SetNX(ctx, "jti", []byte{1}, time.Minute); !first {
		t.Fatal("first SetNX in namespace a should succeed")
	}
	if again, _ := a.SetNX(ctx, "jti", []byte{1}, time.Minute); again {
		t.Fatal("replayed SetNX in namespace a should fail")
	}
	// The same jti in a different module namespace must be independent.
	if first, _ := b.SetNX(ctx, "jti", []byte{1}, time.Minute); !first {
		t.Fatal("SetNX of same key in namespace b should succeed (isolated)")
	}
}
