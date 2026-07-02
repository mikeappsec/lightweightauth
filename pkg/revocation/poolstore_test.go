// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package revocation_test

import (
	"context"
	"errors"
	"testing"
	"time"

	pkgcache "github.com/mikeappsec/lightweightauth/pkg/cache"
	"github.com/mikeappsec/lightweightauth/pkg/revocation"
)

// poolCache returns a pkg/cache memory backend, which structurally satisfies
// revocation.Cache (Get/Set/Delete).
func poolCache(t *testing.T) revocation.Cache {
	t.Helper()
	c, err := pkgcache.BuildBackend(pkgcache.BackendSpec{Type: "memory", Size: 64}, nil)
	if err != nil {
		t.Fatalf("BuildBackend: %v", err)
	}
	return c
}

func TestCacheStore_AddExistsRemove(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := revocation.NewCacheStore(poolCache(t), time.Hour)

	if ok, err := s.Exists(ctx, "jti:abc"); err != nil || ok {
		t.Fatalf("Exists before Add = %v, %v; want false,nil", ok, err)
	}
	if err := s.Add(ctx, revocation.Entry{Key: "jti:abc", Reason: "compromised"}); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if ok, err := s.Exists(ctx, "jti:abc"); err != nil || !ok {
		t.Fatalf("Exists after Add = %v, %v; want true,nil", ok, err)
	}
	if err := s.Remove(ctx, "jti:abc"); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if ok, err := s.Exists(ctx, "jti:abc"); err != nil || ok {
		t.Fatalf("Exists after Remove = %v, %v; want false,nil", ok, err)
	}
}

func TestCacheStore_TTLExpiry(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := revocation.NewCacheStore(poolCache(t), time.Hour)

	if err := s.Add(ctx, revocation.Entry{Key: "jti:short", TTL: 20 * time.Millisecond}); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if ok, _ := s.Exists(ctx, "jti:short"); !ok {
		t.Fatal("entry should exist immediately after Add")
	}
	time.Sleep(40 * time.Millisecond)
	if ok, _ := s.Exists(ctx, "jti:short"); ok {
		t.Fatal("entry should have expired after its TTL")
	}
}

func TestCacheStore_ListUnsupported(t *testing.T) {
	t.Parallel()
	s := revocation.NewCacheStore(poolCache(t), time.Hour)
	_, _, err := s.List(context.Background(), "jti:", 0, "")
	if !errors.Is(err, revocation.ErrListUnsupported) {
		t.Fatalf("List error = %v; want ErrListUnsupported", err)
	}
}

func TestCacheStore_CloseIsNoop(t *testing.T) {
	t.Parallel()
	s := revocation.NewCacheStore(poolCache(t), time.Hour)
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

// TestCacheStore_SatisfiesStore is a compile-time guard that CacheStore (and a
// NegCache wrapping it) implement the Store facade.
func TestCacheStore_SatisfiesStore(t *testing.T) {
	t.Parallel()
	var _ revocation.Store = revocation.NewCacheStore(poolCache(t), time.Hour)
	var _ revocation.Store = revocation.NewNegCache(revocation.NewCacheStore(poolCache(t), time.Hour))
}
