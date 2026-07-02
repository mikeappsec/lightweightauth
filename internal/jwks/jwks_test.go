// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package jwks

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

// jwksServer spins up an in-memory JWKS endpoint and returns its URL.
func jwksServer(t *testing.T) string {
	t.Helper()
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa gen: %v", err)
	}
	pub, err := jwk.PublicKeyOf(rsaKey)
	if err != nil {
		t.Fatalf("PublicKeyOf: %v", err)
	}
	_ = pub.Set(jwk.KeyIDKey, "kid-1")
	_ = pub.Set(jwk.AlgorithmKey, jwa.RS256)
	set := jwk.NewSet()
	_ = set.AddKey(pub)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(set)
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

// waitForRefs polls until url's refcount equals want (or the entry is gone for
// want=-1), bounded by a short deadline since releases run asynchronously.
func waitForRefs(url string, want int) bool {
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if refCount(url) == want {
			return true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return refCount(url) == want
}

// TestAcquireShared_DedupAndLifecycle verifies §12 Option A: acquirers for the
// same URL share one poller entry, and the entry is torn down only once the
// last referencing context is cancelled.
func TestAcquireShared_DedupAndLifecycle(t *testing.T) {
	url := jwksServer(t)

	ctxA, cancelA := context.WithCancel(context.Background())
	ctxB, cancelB := context.WithCancel(context.Background())

	ksA, err := AcquireShared(ctxA, url, time.Minute)
	if err != nil {
		t.Fatalf("AcquireShared A: %v", err)
	}
	ksB, err := AcquireShared(ctxB, url, time.Minute)
	if err != nil {
		t.Fatalf("AcquireShared B: %v", err)
	}
	if ksA != ksB {
		t.Fatal("expected both acquirers to share one keyset")
	}
	if got := refCount(url); got != 2 {
		t.Fatalf("refs after two acquires = %d, want 2", got)
	}

	// Cancelling one engine drops the refcount but keeps the poller alive.
	cancelA()
	if !waitForRefs(url, 1) {
		t.Fatalf("refs after first cancel = %d, want 1", refCount(url))
	}

	// Cancelling the last engine tears the entry down entirely.
	cancelB()
	if !waitForRefs(url, -1) {
		t.Fatalf("refs after final cancel = %d, want entry removed", refCount(url))
	}
}

// TestStandalone_NotRegistered verifies the standalone path never registers in
// the shared registry.
func TestStandalone_NotRegistered(t *testing.T) {
	url := jwksServer(t)
	ks, err := Standalone(context.Background(), url, time.Minute)
	if err != nil {
		t.Fatalf("Standalone: %v", err)
	}
	if ks == nil {
		t.Fatal("Standalone returned nil keyset")
	}
	if got := refCount(url); got != -1 {
		t.Fatalf("standalone must not register, refs = %d", got)
	}
}

// TestAcquireShared_FetchError surfaces a fetch failure as ErrFetch and leaves
// no registry entry behind.
func TestAcquireShared_FetchError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, err := AcquireShared(ctx, srv.URL, time.Minute)
	if err == nil {
		t.Fatal("expected fetch error, got nil")
	}
	if got := refCount(srv.URL); got != -1 {
		t.Fatalf("failed acquire must not leave a registry entry, refs = %d", got)
	}
}
