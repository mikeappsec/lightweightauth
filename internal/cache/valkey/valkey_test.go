// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package cachevalkey

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/valkey-io/valkey-go"

	"github.com/mikeappsec/lightweightauth/internal/cache"
)

// newTestBackend boots a miniredis (RESP2) server and returns a Backend
// pointed at it. miniredis does not implement CLIENT TRACKING, so we set
// DisableCache + AlwaysRESP2 — the production server (Valkey) speaks
// RESP3 so client-side caching stays on by default there.
func newTestBackend(t *testing.T, prefix string) (*Backend, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	client, err := valkey.NewClient(valkey.ClientOption{
		InitAddress:  []string{mr.Addr()},
		DisableCache: true,
		AlwaysRESP2:  true,
	})
	if err != nil {
		t.Fatalf("valkey.NewClient: %v", err)
	}
	t.Cleanup(client.Close)
	return New(client, prefix), mr
}

func TestBackend_RoundTrip(t *testing.T) {
	b, _ := newTestBackend(t, "lwauth/")
	ctx := context.Background()

	// Miss on empty key.
	if _, ok, err := b.Get(ctx, "missing"); err != nil || ok {
		t.Fatalf("expected clean miss, got ok=%v err=%v", ok, err)
	}

	// Set + Get round trip.
	if err := b.Set(ctx, "k1", []byte("hello"), 0); err != nil {
		t.Fatalf("Set: %v", err)
	}
	v, ok, err := b.Get(ctx, "k1")
	if err != nil || !ok || string(v) != "hello" {
		t.Fatalf("Get returned (%q, %v, %v)", v, ok, err)
	}

	// Delete clears the key.
	if err := b.Delete(ctx, "k1"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, ok, _ := b.Get(ctx, "k1"); ok {
		t.Fatalf("expected miss after delete")
	}
}

func TestBackend_TTLExpiry(t *testing.T) {
	b, mr := newTestBackend(t, "")
	ctx := context.Background()

	if err := b.Set(ctx, "expiring", []byte("v"), 50*time.Millisecond); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if _, ok, _ := b.Get(ctx, "expiring"); !ok {
		t.Fatalf("expected hit before TTL")
	}
	mr.FastForward(100 * time.Millisecond)
	if _, ok, _ := b.Get(ctx, "expiring"); ok {
		t.Fatalf("expected miss after TTL expiry")
	}
}

func TestBackend_KeyPrefixIsolation(t *testing.T) {
	// Two backends sharing the same server but different prefixes should
	// not see each other's keys — this is what lets multiple AuthConfigs
	// share a Valkey deployment.
	mr := miniredis.RunT(t)
	mk := func(prefix string) *Backend {
		c, err := valkey.NewClient(valkey.ClientOption{
			InitAddress:  []string{mr.Addr()},
			DisableCache: true,
			AlwaysRESP2:  true,
		})
		if err != nil {
			t.Fatalf("client: %v", err)
		}
		t.Cleanup(c.Close)
		return New(c, prefix)
	}
	a := mk("tenantA/")
	b := mk("tenantB/")
	ctx := context.Background()

	if err := a.Set(ctx, "user:1", []byte("from-a"), time.Minute); err != nil {
		t.Fatalf("a.Set: %v", err)
	}
	if _, ok, _ := b.Get(ctx, "user:1"); ok {
		t.Fatalf("tenantB leaked tenantA's key")
	}
	v, ok, _ := a.Get(ctx, "user:1")
	if !ok || string(v) != "from-a" {
		t.Fatalf("tenantA lost its own key: %q ok=%v", v, ok)
	}
}

func TestBackend_BinarySafe(t *testing.T) {
	b, _ := newTestBackend(t, "")
	ctx := context.Background()

	// Decision payloads are gob/JSON bytes that may include NULs; verify
	// the binary path survives a Valkey round trip unmangled.
	payload := []byte{0x00, 0x01, 0xff, 0xfe, 'a', 0x00, 'b'}
	if err := b.Set(ctx, "binary", payload, time.Minute); err != nil {
		t.Fatalf("Set: %v", err)
	}
	got, ok, err := b.Get(ctx, "binary")
	if err != nil || !ok {
		t.Fatalf("Get: ok=%v err=%v", ok, err)
	}
	if string(got) != string(payload) {
		t.Fatalf("binary mismatch: %x vs %x", got, payload)
	}
}

func TestBackend_RegisteredFactoryRequiresAddr(t *testing.T) {
	// The init() side-effect should have registered "valkey".
	if _, err := cache.BuildBackend(cache.BackendSpec{Type: "valkey"}, nil); err == nil {
		t.Fatalf("expected error when addr is empty")
	}
}
