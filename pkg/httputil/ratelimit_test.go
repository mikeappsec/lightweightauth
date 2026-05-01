package httputil

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func TestTokenBucketLimiter_AllowBurst(t *testing.T) {
	l := NewTokenBucketLimiter(10, 3) // 10 rps, burst 3
	key := "127.0.0.1"

	// First 3 should be allowed (burst).
	for i := range 3 {
		if !l.Allow(key) {
			t.Fatalf("request %d should be allowed within burst", i+1)
		}
	}
	// 4th should be denied.
	if l.Allow(key) {
		t.Fatal("request 4 should be denied after burst exhausted")
	}
}

func TestTokenBucketLimiter_Refill(t *testing.T) {
	now := time.Now()
	mu := sync.Mutex{}
	clock := func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return now
	}
	advance := func(d time.Duration) {
		mu.Lock()
		now = now.Add(d)
		mu.Unlock()
	}

	l := NewTokenBucketLimiter(10, 1, WithClock(clock))
	key := "10.0.0.1"

	if !l.Allow(key) {
		t.Fatal("first request should pass")
	}
	if l.Allow(key) {
		t.Fatal("second request should be denied (burst=1)")
	}
	// Advance 100ms → refill 1 token (10 rps × 0.1s).
	advance(100 * time.Millisecond)
	if !l.Allow(key) {
		t.Fatal("should pass after refill")
	}
}

func TestTokenBucketLimiter_PerKey(t *testing.T) {
	l := NewTokenBucketLimiter(1, 1)
	if !l.Allow("a") {
		t.Fatal("key a should pass")
	}
	if !l.Allow("b") {
		t.Fatal("key b should pass independently")
	}
	if l.Allow("a") {
		t.Fatal("key a should be denied after burst")
	}
}

func TestRateLimitMiddleware_Returns429(t *testing.T) {
	// Limiter with burst=0 denies everything.
	l := NewTokenBucketLimiter(0, 0)

	handler := RateLimitMiddleware(l, IPKeyFunc, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "1.2.3.4:5678"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d", rec.Code)
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Fatal("missing Retry-After header")
	}
}

func TestIPKeyFunc_StripsPort(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.1:12345"
	if got := IPKeyFunc(req); got != "10.0.0.1" {
		t.Fatalf("expected 10.0.0.1, got %q", got)
	}

	// IPv6
	req.RemoteAddr = "[::1]:9999"
	if got := IPKeyFunc(req); got != "::1" {
		t.Fatalf("expected ::1, got %q", got)
	}
}

func TestRateLimitMiddleware_PassesThrough(t *testing.T) {
	l := NewTokenBucketLimiter(100, 10)

	called := false
	handler := RateLimitMiddleware(l, IPKeyFunc, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "1.2.3.4:5678"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if !called {
		t.Fatal("next handler should have been called")
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
}
