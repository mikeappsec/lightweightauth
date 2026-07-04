// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package replay_test

import (
	"context"
	"testing"
	"time"

	"github.com/mikeappsec/lightweightauth/internal/replay"
	"github.com/mikeappsec/lightweightauth/pkg/cache"
)

// consumeRejectsReplay is the shared behavioral contract for both backings.
func consumeRejectsReplay(t *testing.T, g *replay.Guard) {
	t.Helper()
	ctx := context.Background()
	first, err := g.Consume(ctx, "jti-1", time.Minute)
	if err != nil || !first {
		t.Fatalf("first Consume = %v, %v; want true, nil", first, err)
	}
	again, err := g.Consume(ctx, "jti-1", time.Minute)
	if err != nil || again {
		t.Fatalf("replayed Consume = %v, %v; want false, nil", again, err)
	}
	// A distinct key is independent.
	other, err := g.Consume(ctx, "jti-2", time.Minute)
	if err != nil || !other {
		t.Fatalf("distinct-key Consume = %v, %v; want true, nil", other, err)
	}
}

func TestGuard_LocalFallback(t *testing.T) {
	// A nil cache forces the in-process fallback.
	consumeRejectsReplay(t, replay.New(nil))
}

func TestGuard_CacheBacked(t *testing.T) {
	c, _ := cache.BuildBackend(cache.BackendSpec{Type: "memory"}, &cache.Stats{})
	consumeRejectsReplay(t, replay.New(c))
}

func TestGuard_LocalExpiry(t *testing.T) {
	ctx := context.Background()
	g := replay.New(nil)
	if first, _ := g.Consume(ctx, "k", time.Millisecond); !first {
		t.Fatal("first Consume should succeed")
	}
	time.Sleep(5 * time.Millisecond)
	// After the window elapses the key may be consumed again.
	if reused, err := g.Consume(ctx, "k", time.Millisecond); err != nil || !reused {
		t.Fatalf("post-expiry Consume = %v, %v; want true, nil", reused, err)
	}
}

// recordingLocal is a LocalStore with real single-use semantics that also
// counts calls, so tests can observe whether Consume routed to the local
// fallback.
type recordingLocal struct {
	calls int
	seen  map[string]bool
}

func (r *recordingLocal) Consume(key string, _ time.Duration) bool {
	r.calls++
	if r.seen == nil {
		r.seen = map[string]bool{}
	}
	if r.seen[key] {
		return false
	}
	r.seen[key] = true
	return true
}

// remoteCache implements Cache, Atomic and Locker, modelling a genuinely
// remote, cross-replica backend (e.g. Valkey). Only SetNX is exercised.
type remoteCache struct {
	seen map[string]bool
}

func (c *remoteCache) Get(context.Context, string) ([]byte, bool, error) { return nil, false, nil }
func (c *remoteCache) Set(context.Context, string, []byte, time.Duration) error {
	return nil
}
func (c *remoteCache) Delete(context.Context, string) error { return nil }
func (c *remoteCache) SetNX(_ context.Context, key string, _ []byte, _ time.Duration) (bool, error) {
	if c.seen == nil {
		c.seen = map[string]bool{}
	}
	if c.seen[key] {
		return false, nil
	}
	c.seen[key] = true
	return true, nil
}
func (c *remoteCache) Incr(context.Context, string, time.Duration) (int64, error) { return 0, nil }
func (c *remoteCache) TryLock(context.Context, string, time.Duration) (string, bool, error) {
	return "", true, nil
}
func (c *remoteCache) Unlock(context.Context, string, string) error { return nil }

// TestNewWithLocal_NilUsesLocal: a nil cache routes through the supplied
// LocalStore (the bounded fail-closed cache for SAML).
func TestNewWithLocal_NilUsesLocal(t *testing.T) {
	local := &recordingLocal{}
	g := replay.NewWithLocal(nil, local)
	consumeRejectsReplay(t, g)
	if local.calls == 0 {
		t.Fatal("expected the local store to be used when cache is nil")
	}
}

// TestNewWithLocal_MemoryStaysLocal pins the G9-VULN-07 contract: the
// in-process memory backend implements Atomic but not Locker, so NewWithLocal
// must keep using the bounded local store rather than memory's SetNX (which
// would evict live entries under a flood).
func TestNewWithLocal_MemoryStaysLocal(t *testing.T) {
	c, _ := cache.BuildBackend(cache.BackendSpec{Type: "memory"}, &cache.Stats{})
	local := &recordingLocal{}
	g := replay.NewWithLocal(c, local)
	if _, err := g.Consume(context.Background(), "k", time.Minute); err != nil {
		t.Fatalf("Consume error: %v", err)
	}
	if local.calls != 1 {
		t.Fatalf("local.calls = %d; want 1 (memory must not engage the Atomic path)", local.calls)
	}
}

// TestNewWithLocal_RemoteUsesAtomic: a Locker-capable (remote) cache engages
// the cross-replica SetNX path and bypasses the local store.
func TestNewWithLocal_RemoteUsesAtomic(t *testing.T) {
	local := &recordingLocal{}
	g := replay.NewWithLocal(&remoteCache{}, local)
	ctx := context.Background()
	if first, err := g.Consume(ctx, "k", time.Minute); err != nil || !first {
		t.Fatalf("first Consume = %v, %v; want true, nil", first, err)
	}
	if again, err := g.Consume(ctx, "k", time.Minute); err != nil || again {
		t.Fatalf("replay Consume = %v, %v; want false, nil", again, err)
	}
	if local.calls != 0 {
		t.Fatalf("local.calls = %d; want 0 (remote backend must use SetNX)", local.calls)
	}
}
