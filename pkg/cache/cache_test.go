// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package cache_test

import (
	"context"
	"testing"
	"time"

	"github.com/mikeappsec/lightweightauth/pkg/cache"
)

func TestMemoryBackendGetSetDelete(t *testing.T) {
	ctx := context.Background()
	c, err := cache.BuildBackend(cache.BackendSpec{Type: "memory", Size: 8}, &cache.Stats{})
	if err != nil {
		t.Fatalf("BuildBackend: %v", err)
	}

	if _, ok, _ := c.Get(ctx, "missing"); ok {
		t.Fatal("expected miss on empty cache")
	}
	if err := c.Set(ctx, "k", []byte("v"), 0); err != nil {
		t.Fatalf("Set: %v", err)
	}
	got, ok, err := c.Get(ctx, "k")
	if err != nil || !ok || string(got) != "v" {
		t.Fatalf("Get = %q, %v, %v; want v,true,nil", got, ok, err)
	}
	if err := c.Delete(ctx, "k"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, ok, _ := c.Get(ctx, "k"); ok {
		t.Fatal("expected miss after delete")
	}
}

func TestMemoryBackendTTLExpiry(t *testing.T) {
	ctx := context.Background()
	c, _ := cache.BuildBackend(cache.BackendSpec{Type: "memory"}, &cache.Stats{})
	if err := c.Set(ctx, "k", []byte("v"), time.Millisecond); err != nil {
		t.Fatalf("Set: %v", err)
	}
	time.Sleep(5 * time.Millisecond)
	if _, ok, _ := c.Get(ctx, "k"); ok {
		t.Fatal("expected entry to expire")
	}
}

func TestMemoryBackendLRUEviction(t *testing.T) {
	ctx := context.Background()
	stats := &cache.Stats{}
	c, _ := cache.BuildBackend(cache.BackendSpec{Type: "memory", Size: 2}, stats)
	_ = c.Set(ctx, "a", []byte("1"), 0)
	_ = c.Set(ctx, "b", []byte("2"), 0)
	_, _, _ = c.Get(ctx, "a")           // make "a" most-recently-used
	_ = c.Set(ctx, "c", []byte("3"), 0) // should evict "b"
	if _, ok, _ := c.Get(ctx, "b"); ok {
		t.Fatal("expected b to be evicted")
	}
	if _, ok, _ := c.Get(ctx, "a"); !ok {
		t.Fatal("expected a to survive")
	}
	if got := stats.Evictions.Load(); got != 1 {
		t.Fatalf("Evictions = %d; want 1", got)
	}
}

func TestMemoryBackendTagInvalidation(t *testing.T) {
	ctx := context.Background()
	c, _ := cache.BuildBackend(cache.BackendSpec{Type: "memory"}, &cache.Stats{})
	ti, ok := c.(cache.TagInvalidator)
	if !ok {
		t.Fatal("memory backend should implement TagInvalidator")
	}
	_ = c.Set(ctx, "u1", []byte("a"), 0)
	_ = c.Set(ctx, "u2", []byte("b"), 0)
	_ = ti.Tag(ctx, "u1", "sub:alice")
	_ = ti.Tag(ctx, "u2", "sub:alice")
	n, err := ti.InvalidateTag(ctx, "sub:alice")
	if err != nil || n != 2 {
		t.Fatalf("InvalidateTag = %d, %v; want 2,nil", n, err)
	}
	if _, ok, _ := c.Get(ctx, "u1"); ok {
		t.Fatal("u1 should be invalidated")
	}
}

func TestTypedRoundTrip(t *testing.T) {
	ctx := context.Background()
	type claims struct {
		Sub   string
		Scope []string
	}
	c, _ := cache.BuildBackend(cache.BackendSpec{Type: "memory"}, &cache.Stats{})
	for _, codec := range []cache.Codec{cache.Gob, cache.JSON} {
		typed := cache.NewTyped[claims](c, codec)
		want := claims{Sub: "alice", Scope: []string{"read", "write"}}
		if err := typed.Set(ctx, "k-"+codec.Name(), want, 0); err != nil {
			t.Fatalf("Set(%s): %v", codec.Name(), err)
		}
		got, ok, err := typed.Get(ctx, "k-"+codec.Name())
		if err != nil || !ok {
			t.Fatalf("Get(%s) = ok=%v err=%v", codec.Name(), ok, err)
		}
		if got.Sub != want.Sub || len(got.Scope) != 2 {
			t.Fatalf("Get(%s) = %+v; want %+v", codec.Name(), got, want)
		}
	}
}

func TestNamespaceIsolation(t *testing.T) {
	ctx := context.Background()
	c, _ := cache.BuildBackend(cache.BackendSpec{Type: "memory"}, &cache.Stats{})
	a := cache.Namespaced(c, "i/jwt/a/tokens/")
	b := cache.Namespaced(c, "i/jwt/b/tokens/")
	_ = a.Set(ctx, "x", []byte("from-a"), 0)
	_ = b.Set(ctx, "x", []byte("from-b"), 0)
	got, _, _ := a.Get(ctx, "x")
	if string(got) != "from-a" {
		t.Fatalf("namespace a leaked: got %q", got)
	}
	// Underlying keys are distinct.
	if _, ok, _ := c.Get(ctx, "i/jwt/a/tokens/x"); !ok {
		t.Fatal("expected prefixed key in underlying cache")
	}
}

func TestNamespacePreservesTagCapability(t *testing.T) {
	c, _ := cache.BuildBackend(cache.BackendSpec{Type: "memory"}, &cache.Stats{})
	ns := cache.Namespaced(c, "i/jwt/a/tokens/")
	if _, ok := ns.(cache.TagInvalidator); !ok {
		t.Fatal("namespaced memory cache should still expose TagInvalidator")
	}
	if _, ok := ns.(cache.Locker); ok {
		t.Fatal("namespaced memory cache should NOT expose Locker")
	}
}

// TestNamespacedTagInvalidationRoundTrip guards against the Tag/InvalidateTag
// prefix asymmetry: a tag written through a namespaced handle must be
// invalidatable through the same handle.
func TestNamespacedTagInvalidationRoundTrip(t *testing.T) {
	ctx := context.Background()
	c, _ := cache.BuildBackend(cache.BackendSpec{Type: "memory"}, &cache.Stats{})
	ns := cache.Namespaced(c, "i/jwt/a/tokens/")
	ti, ok := ns.(cache.TagInvalidator)
	if !ok {
		t.Fatal("namespaced memory cache should expose TagInvalidator")
	}
	if err := ns.Set(ctx, "u1", []byte("a"), 0); err != nil {
		t.Fatalf("Set u1: %v", err)
	}
	if err := ns.Set(ctx, "u2", []byte("b"), 0); err != nil {
		t.Fatalf("Set u2: %v", err)
	}
	if err := ti.Tag(ctx, "u1", "sub:alice"); err != nil {
		t.Fatalf("Tag u1: %v", err)
	}
	if err := ti.Tag(ctx, "u2", "sub:alice"); err != nil {
		t.Fatalf("Tag u2: %v", err)
	}
	n, err := ti.InvalidateTag(ctx, "sub:alice")
	if err != nil || n != 2 {
		t.Fatalf("InvalidateTag = %d, %v; want 2,nil (namespaced tag round-trip)", n, err)
	}
	if _, ok, _ := ns.Get(ctx, "u1"); ok {
		t.Fatal("u1 should be invalidated through the namespaced handle")
	}
	if _, ok, _ := ns.Get(ctx, "u2"); ok {
		t.Fatal("u2 should be invalidated through the namespaced handle")
	}
}

// TestNamespacedTagIsolation confirms two namespaces sharing the same backend
// and the same logical tag name do not invalidate each other's entries.
func TestNamespacedTagIsolation(t *testing.T) {
	ctx := context.Background()
	c, _ := cache.BuildBackend(cache.BackendSpec{Type: "memory"}, &cache.Stats{})
	a := cache.Namespaced(c, "i/jwt/a/tokens/")
	b := cache.Namespaced(c, "i/jwt/b/tokens/")
	ta := a.(cache.TagInvalidator)
	tb := b.(cache.TagInvalidator)

	_ = a.Set(ctx, "x", []byte("from-a"), 0)
	_ = b.Set(ctx, "x", []byte("from-b"), 0)
	_ = ta.Tag(ctx, "x", "sub:alice")
	_ = tb.Tag(ctx, "x", "sub:alice")

	n, err := ta.InvalidateTag(ctx, "sub:alice")
	if err != nil || n != 1 {
		t.Fatalf("InvalidateTag(a) = %d, %v; want 1,nil", n, err)
	}
	if _, ok, _ := a.Get(ctx, "x"); ok {
		t.Fatal("namespace a entry should be invalidated")
	}
	if _, ok, _ := b.Get(ctx, "x"); !ok {
		t.Fatal("namespace b entry must survive a's tag invalidation")
	}
}

func TestBuildPoolsSynthesizesDefault(t *testing.T) {
	pools, err := cache.BuildPools(nil)
	if err != nil {
		t.Fatalf("BuildPools: %v", err)
	}
	if !pools.Has(cache.DefaultPool) {
		t.Fatal("expected implicit default pool")
	}
}

func TestBuildPoolsDuplicateName(t *testing.T) {
	_, err := cache.BuildPools([]cache.PoolConfig{
		{Name: "tokens", BackendSpec: cache.BackendSpec{Type: "memory"}},
		{Name: "tokens", BackendSpec: cache.BackendSpec{Type: "memory"}},
	})
	if err == nil {
		t.Fatal("expected duplicate pool error")
	}
}

func TestProviderRoutingAndNamespace(t *testing.T) {
	ctx := context.Background()
	pools, _ := cache.BuildPools([]cache.PoolConfig{
		{Name: "tokens", BackendSpec: cache.BackendSpec{Type: "memory"}},
	})
	p := pools.For("i/introspection/my", "tokens", nil)
	h := p.Cache("positive")
	_ = h.Set(ctx, "tok", []byte("claims"), 0)

	// Same logical name from a different module must not collide.
	p2 := pools.For("i/introspection/other", "tokens", nil)
	if _, ok, _ := p2.Cache("positive").Get(ctx, "tok"); ok {
		t.Fatal("modules sharing a pool leaked through identical logical names")
	}
}

func TestValidatePools(t *testing.T) {
	if err := cache.ValidatePools([]string{"tokens"}, []string{"tokens", "default"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := cache.ValidatePools([]string{"tokens"}, []string{"missing"}); err == nil {
		t.Fatal("expected ErrConfig for undeclared pool")
	}
}

func TestUnknownBackendIsConfigError(t *testing.T) {
	_, err := cache.BuildBackend(cache.BackendSpec{Type: "does-not-exist"}, nil)
	if err == nil {
		t.Fatal("expected error for unknown backend")
	}
}

func TestSingleflightCoalesces(t *testing.T) {
	ctx := context.Background()
	var g cache.Group[int]
	var calls int
	fn := func(context.Context) (int, error) {
		calls++
		time.Sleep(10 * time.Millisecond)
		return 42, nil
	}
	const n = 20
	done := make(chan int, n)
	for i := 0; i < n; i++ {
		go func() {
			v, _ := g.Do(ctx, "k", fn)
			done <- v
		}()
	}
	for i := 0; i < n; i++ {
		if v := <-done; v != 42 {
			t.Fatalf("got %d; want 42", v)
		}
	}
	if calls == 0 || calls > n {
		t.Fatalf("calls = %d; expected coalescing (1..%d)", calls, n)
	}
}

func TestNoOpCache(t *testing.T) {
	ctx := context.Background()
	c := cache.NoOpCache()
	if err := c.Set(ctx, "k", []byte("v"), 0); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if _, ok, _ := c.Get(ctx, "k"); ok {
		t.Fatal("no-op cache should always miss")
	}
}
