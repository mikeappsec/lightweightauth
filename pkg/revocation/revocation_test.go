package revocation_test

import (
	"context"
	"testing"
	"time"

	"github.com/mikeappsec/lightweightauth/pkg/revocation"
)

func TestMemoryStore_AddAndExists(t *testing.T) {
	s := revocation.NewMemoryStore(revocation.WithDefaultTTL(1 * time.Hour))
	defer s.Close()

	ctx := context.Background()

	// Initially not revoked.
	revoked, err := s.Exists(ctx, "jti:abc-123")
	if err != nil {
		t.Fatal(err)
	}
	if revoked {
		t.Fatal("expected not revoked")
	}

	// Add revocation.
	err = s.Add(ctx, revocation.Entry{Key: "jti:abc-123", Reason: "test"})
	if err != nil {
		t.Fatal(err)
	}

	// Now revoked.
	revoked, err = s.Exists(ctx, "jti:abc-123")
	if err != nil {
		t.Fatal(err)
	}
	if !revoked {
		t.Fatal("expected revoked")
	}
}

func TestMemoryStore_TTLExpiry(t *testing.T) {
	s := revocation.NewMemoryStore(revocation.WithDefaultTTL(50 * time.Millisecond))
	defer s.Close()

	ctx := context.Background()

	err := s.Add(ctx, revocation.Entry{Key: "jti:short-lived"})
	if err != nil {
		t.Fatal(err)
	}

	// Immediately exists.
	revoked, _ := s.Exists(ctx, "jti:short-lived")
	if !revoked {
		t.Fatal("expected revoked immediately after add")
	}

	// Wait for expiry.
	time.Sleep(60 * time.Millisecond)

	revoked, _ = s.Exists(ctx, "jti:short-lived")
	if revoked {
		t.Fatal("expected not revoked after TTL expiry")
	}
}

func TestMemoryStore_Remove(t *testing.T) {
	s := revocation.NewMemoryStore()
	defer s.Close()

	ctx := context.Background()

	_ = s.Add(ctx, revocation.Entry{Key: "sub:acme:alice"})

	revoked, _ := s.Exists(ctx, "sub:acme:alice")
	if !revoked {
		t.Fatal("expected revoked")
	}

	_ = s.Remove(ctx, "sub:acme:alice")

	revoked, _ = s.Exists(ctx, "sub:acme:alice")
	if revoked {
		t.Fatal("expected not revoked after removal")
	}
}

func TestMemoryStore_List(t *testing.T) {
	s := revocation.NewMemoryStore()
	defer s.Close()

	ctx := context.Background()

	_ = s.Add(ctx, revocation.Entry{Key: "jti:aaa", Reason: "r1"})
	_ = s.Add(ctx, revocation.Entry{Key: "jti:bbb", Reason: "r2"})
	_ = s.Add(ctx, revocation.Entry{Key: "sub:acme:alice", Reason: "r3"})

	entries, _, err := s.List(ctx, "jti:", 0, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries with prefix jti:, got %d", len(entries))
	}

	all, _, _ := s.List(ctx, "", 0, "")
	if len(all) != 3 {
		t.Fatalf("expected 3 total entries, got %d", len(all))
	}
}

func TestNegCache_CachesNegativeResult(t *testing.T) {
	inner := revocation.NewMemoryStore()
	defer inner.Close()

	nc := revocation.NewNegCache(inner, revocation.WithNegCacheTTL(100*time.Millisecond))
	defer nc.Close()

	ctx := context.Background()

	// First call goes to inner.
	revoked, _ := nc.Exists(ctx, "jti:xyz")
	if revoked {
		t.Fatal("expected not revoked")
	}

	// Now add directly to inner (bypass negcache).
	_ = inner.Add(ctx, revocation.Entry{Key: "jti:xyz"})

	// Should still see "not revoked" because of negcache.
	revoked, _ = nc.Exists(ctx, "jti:xyz")
	if revoked {
		t.Fatal("expected not revoked due to negcache")
	}

	// Wait for negcache to expire.
	time.Sleep(110 * time.Millisecond)

	// Now should see the revocation.
	revoked, _ = nc.Exists(ctx, "jti:xyz")
	if !revoked {
		t.Fatal("expected revoked after negcache expiry")
	}
}

func TestNegCache_EvictOnAdd(t *testing.T) {
	inner := revocation.NewMemoryStore()
	defer inner.Close()

	nc := revocation.NewNegCache(inner, revocation.WithNegCacheTTL(10*time.Second))
	defer nc.Close()

	ctx := context.Background()

	// Warm the negative cache.
	revoked, _ := nc.Exists(ctx, "jti:abc")
	if revoked {
		t.Fatal("expected not revoked")
	}

	// Add via NegCache (should evict the neg entry).
	_ = nc.Add(ctx, revocation.Entry{Key: "jti:abc"})

	// Should immediately see revoked.
	revoked, _ = nc.Exists(ctx, "jti:abc")
	if !revoked {
		t.Fatal("expected revoked immediately after Add (neg cache evicted)")
	}
}

func TestNegCache_EvictPrefix(t *testing.T) {
	inner := revocation.NewMemoryStore()
	defer inner.Close()

	nc := revocation.NewNegCache(inner, revocation.WithNegCacheTTL(10*time.Second))
	defer nc.Close()

	ctx := context.Background()

	// Warm neg cache for multiple keys.
	_, _ = nc.Exists(ctx, "sub:acme:alice")
	_, _ = nc.Exists(ctx, "sub:acme:bob")
	_, _ = nc.Exists(ctx, "jti:other")

	// Add revocation for alice directly to inner.
	_ = inner.Add(ctx, revocation.Entry{Key: "sub:acme:alice"})
	_ = inner.Add(ctx, revocation.Entry{Key: "sub:acme:bob"})

	// Still cached as not-revoked.
	revoked, _ := nc.Exists(ctx, "sub:acme:alice")
	if revoked {
		t.Fatal("expected cached not-revoked")
	}

	// Evict by prefix.
	nc.EvictPrefix("sub:acme:")

	// Now should hit inner.
	revoked, _ = nc.Exists(ctx, "sub:acme:alice")
	if !revoked {
		t.Fatal("expected revoked after prefix eviction")
	}

	// jti:other should still be negcached.
	revoked, _ = nc.Exists(ctx, "jti:other")
	if revoked {
		t.Fatal("expected jti:other still negcached")
	}
}
