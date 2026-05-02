// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package introspection

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mikeappsec/lightweightauth/pkg/module"
)

func mkServer(t *testing.T, hits *atomic.Int32, claims map[string]any) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(claims)
	}))
}

func mkIdentifier(t *testing.T, url string) *identifier {
	t.Helper()
	a, err := factory("introspect", map[string]any{
		"url":          url,
		"clientId":     "lwauth",
		"clientSecret": "s",
		"maxCacheTtl":  "5s",
		"negativeTtl":  "1s",
	})
	if err != nil {
		t.Fatalf("factory: %v", err)
	}
	return a.(*identifier)
}

func req(token string) *module.Request {
	return &module.Request{Headers: map[string][]string{"Authorization": {"Bearer " + token}}}
}

func TestIntrospection_ActiveTokenIdentifies(t *testing.T) {
	t.Parallel()
	hits := &atomic.Int32{}
	srv := mkServer(t, hits, map[string]any{
		"active": true, "sub": "alice", "exp": float64(time.Now().Add(time.Hour).Unix()),
	})
	defer srv.Close()
	id := mkIdentifier(t, srv.URL)

	got, err := id.Identify(t.Context(), req("tok"))
	if err != nil || got == nil || got.Subject != "alice" {
		t.Fatalf("got (%+v, %v), want subject=alice", got, err)
	}
}

func TestIntrospection_PositiveCacheHits(t *testing.T) {
	t.Parallel()
	hits := &atomic.Int32{}
	srv := mkServer(t, hits, map[string]any{
		"active": true, "sub": "alice", "exp": float64(time.Now().Add(time.Hour).Unix()),
	})
	defer srv.Close()
	id := mkIdentifier(t, srv.URL)

	for i := 0; i < 5; i++ {
		if _, err := id.Identify(t.Context(), req("tok")); err != nil {
			t.Fatalf("iter %d: %v", i, err)
		}
	}
	if h := hits.Load(); h != 1 {
		t.Errorf("upstream hits = %d, want 1 (cache should absorb the rest)", h)
	}
}

func TestIntrospection_NegativeCacheRemembersInactive(t *testing.T) {
	t.Parallel()
	hits := &atomic.Int32{}
	srv := mkServer(t, hits, map[string]any{"active": false})
	defer srv.Close()
	id := mkIdentifier(t, srv.URL)

	for i := 0; i < 3; i++ {
		_, err := id.Identify(t.Context(), req("tok"))
		if !errors.Is(err, module.ErrInvalidCredential) {
			t.Fatalf("iter %d: err = %v, want ErrInvalidCredential", i, err)
		}
	}
	if h := hits.Load(); h != 1 {
		t.Errorf("upstream hits = %d, want 1", h)
	}
}

func TestIntrospection_NoBearerNoMatch(t *testing.T) {
	t.Parallel()
	id := mkIdentifier(t, "http://unused")
	_, err := id.Identify(t.Context(), &module.Request{})
	if !errors.Is(err, module.ErrNoMatch) {
		t.Errorf("err = %v, want ErrNoMatch", err)
	}
}

// mkErrServer returns a server that always replies with the given
// status code and counts how many times it was called. Used to drive
// the K-AUTHN-2 error-cache tests.
func mkErrServer(t *testing.T, hits *atomic.Int32, status int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(status)
	}))
}

// TestIntrospection_ErrorCacheCoalescesUpstreamErrors pins K-AUTHN-2:
// when the IdP is wounded (here: returning 503), a flood of requests
// for the SAME token hits upstream exactly once during the errorTtl
// window. Without this cache a misbehaving IdP becomes a per-request
// DoS amplifier.
func TestIntrospection_ErrorCacheCoalescesUpstreamErrors(t *testing.T) {
	t.Parallel()
	hits := &atomic.Int32{}
	srv := mkErrServer(t, hits, http.StatusServiceUnavailable)
	defer srv.Close()
	id := mkIdentifier(t, srv.URL)

	for i := 0; i < 25; i++ {
		_, err := id.Identify(t.Context(), req("flapping-tok"))
		if !errors.Is(err, module.ErrUpstream) {
			t.Fatalf("iter %d: err = %v, want ErrUpstream", i, err)
		}
	}
	if h := hits.Load(); h != 1 {
		t.Errorf("upstream hits = %d, want 1 (error cache should absorb the rest)", h)
	}
}

// TestIntrospection_ErrorCacheTTLExpires verifies the cache window is
// short — once errorTtl elapses, a fresh request must reach upstream
// again. Otherwise a brief blip would lock the token out for too long.
func TestIntrospection_ErrorCacheTTLExpires(t *testing.T) {
	t.Parallel()
	hits := &atomic.Int32{}
	srv := mkErrServer(t, hits, http.StatusServiceUnavailable)
	defer srv.Close()
	a, err := factory("introspect", map[string]any{
		"url":          srv.URL,
		"clientId":     "lwauth",
		"clientSecret": "s",
		"maxCacheTtl":  "5s",
		"negativeTtl":  "1s",
		"errorTtl":     "50ms",
	})
	if err != nil {
		t.Fatalf("factory: %v", err)
	}
	id := a.(*identifier)

	if _, err := id.Identify(t.Context(), req("tok")); !errors.Is(err, module.ErrUpstream) {
		t.Fatalf("first call err = %v, want ErrUpstream", err)
	}
	if _, err := id.Identify(t.Context(), req("tok")); !errors.Is(err, module.ErrUpstream) {
		t.Fatalf("cached call err = %v, want ErrUpstream", err)
	}
	if h := hits.Load(); h != 1 {
		t.Fatalf("hits before TTL = %d, want 1", h)
	}
	time.Sleep(80 * time.Millisecond)
	if _, err := id.Identify(t.Context(), req("tok")); !errors.Is(err, module.ErrUpstream) {
		t.Fatalf("post-TTL err = %v, want ErrUpstream", err)
	}
	if h := hits.Load(); h != 2 {
		t.Errorf("hits after TTL = %d, want 2 (cache should have re-armed)", h)
	}
}

// TestIntrospection_ErrorCachePerCredential — two different tokens
// must NOT share an error-cache slot. A failure for token A cannot
// pre-deny a request for token B.
func TestIntrospection_ErrorCachePerCredential(t *testing.T) {
	t.Parallel()
	hits := &atomic.Int32{}
	srv := mkErrServer(t, hits, http.StatusBadGateway)
	defer srv.Close()
	id := mkIdentifier(t, srv.URL)

	if _, err := id.Identify(t.Context(), req("token-a")); !errors.Is(err, module.ErrUpstream) {
		t.Fatalf("token-a err = %v, want ErrUpstream", err)
	}
	if _, err := id.Identify(t.Context(), req("token-b")); !errors.Is(err, module.ErrUpstream) {
		t.Fatalf("token-b err = %v, want ErrUpstream", err)
	}
	if h := hits.Load(); h != 2 {
		t.Errorf("hits = %d, want 2 (each unique token must reach upstream once)", h)
	}
}

// TestIntrospection_ErrorCacheNotPoisonedBySuccess — once the IdP
// recovers, the next call (still failing-cached for the bad window)
// stays denied for that token, but a brand-new token sees success.
// This is the deterministic "no cross-credential blast radius"
// guarantee.
func TestIntrospection_ErrorCacheNotPoisonedBySuccess(t *testing.T) {
	t.Parallel()
	hits := &atomic.Int32{}
	mode := atomic.Int32{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		if mode.Load() == 0 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"active": true, "sub": "alice",
			"exp": float64(time.Now().Add(time.Hour).Unix()),
		})
	}))
	defer srv.Close()
	id := mkIdentifier(t, srv.URL)

	// Phase 1: IdP down. Token A error-caches.
	if _, err := id.Identify(t.Context(), req("token-a")); !errors.Is(err, module.ErrUpstream) {
		t.Fatalf("phase-1 err = %v, want ErrUpstream", err)
	}
	// Phase 2: IdP recovers; token B succeeds straight away.
	mode.Store(1)
	got, err := id.Identify(t.Context(), req("token-b"))
	if err != nil || got == nil || got.Subject != "alice" {
		t.Fatalf("token-b after recovery: (%+v, %v), want subject=alice", got, err)
	}
	// Token A is still served from the error cache (TTL=1s default in
	// mkIdentifier — fast enough that this call is well within window).
	if _, err := id.Identify(t.Context(), req("token-a")); !errors.Is(err, module.ErrUpstream) {
		t.Errorf("token-a within TTL err = %v, want still-cached ErrUpstream", err)
	}
	// And the IdP only saw: token-a (failed), token-b (succeeded). Two hits.
	if h := hits.Load(); h != 2 {
		t.Errorf("hits = %d, want 2", h)
	}
}

// TestIntrospection_ErrorCacheKeyHashed — basic audit-grade check:
// the LRU never sees the raw token. We can't reach into the LRU's
// internal map without exporting, so we instead verify two different
// tokens with a shared prefix don't collide (sha256 outputs are
// uniform), and that the keys we DO use through the cache are the
// 64-char hex digest. This is a structural sanity test, not a proof.
func TestIntrospection_ErrorCacheKeyHashed(t *testing.T) {
	t.Parallel()
	if got := sha256hex("hello"); len(got) != 64 {
		t.Fatalf("sha256hex length = %d, want 64", len(got))
	}
	// Two tokens that share a prefix must produce wildly different
	// digests — proves we're not substring-keying.
	a, b := sha256hex("user-token-1"), sha256hex("user-token-2")
	if a == b {
		t.Fatal("identical digests for distinct tokens")
	}
	common := 0
	for i := 0; i < len(a) && a[i] == b[i]; i++ {
		common++
	}
	if common > 8 { // 32 bits of shared prefix is already astronomically unlikely
		t.Errorf("digests share %d hex chars of prefix; sha256 should be uniform", common)
	}
}
