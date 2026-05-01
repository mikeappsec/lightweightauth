// Package httputil provides reusable HTTP middleware building blocks
// (rate limiting, request guards, etc.) that are independent of the
// authentication engine. They are consumed by the admin plane, the
// optional IdP sidecar, and any future HTTP surface that needs
// per-key request gating.
package httputil

import (
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"
)

// KeyedLimiter is the interface any per-key rate limiter must satisfy.
// Implementations may use token-bucket, sliding-window, or distributed
// backends. The key is typically a client IP or username.
type KeyedLimiter interface {
	// Allow returns true if the request identified by key is permitted.
	Allow(key string) bool
}

// ---------- token-bucket implementation ----------

// TokenBucketLimiter is a goroutine-safe, per-key token-bucket rate
// limiter suitable for in-process use. For distributed (multi-replica)
// limiting, see [pkg/ratelimit] which speaks to a Valkey backend.
type TokenBucketLimiter struct {
	mu      sync.Mutex
	buckets map[string]*tokenBucket
	rps     float64
	burst   int
	now     func() time.Time // injectable for tests
}

type tokenBucket struct {
	tokens   float64
	lastTime time.Time
}

// TokenBucketOption configures a TokenBucketLimiter.
type TokenBucketOption func(*TokenBucketLimiter)

// WithClock overrides the time source (useful for deterministic tests).
func WithClock(fn func() time.Time) TokenBucketOption {
	return func(l *TokenBucketLimiter) { l.now = fn }
}

// NewTokenBucketLimiter returns a KeyedLimiter backed by per-key token
// buckets refilling at rps tokens/sec with a maximum burst capacity.
// A background goroutine evicts idle buckets every 60 s (buckets not
// seen for ≥ 2× the full-refill period are removed).
func NewTokenBucketLimiter(rps float64, burst int, opts ...TokenBucketOption) *TokenBucketLimiter {
	l := &TokenBucketLimiter{
		buckets: make(map[string]*tokenBucket),
		rps:     rps,
		burst:   burst,
		now:     time.Now,
	}
	for _, o := range opts {
		o(l)
	}
	// RL2: start background eviction to bound memory.
	go l.evictLoop()
	return l
}

// evictLoop removes buckets that have been idle long enough to be
// fully refilled (i.e. they would start at max burst anyway).
func (l *TokenBucketLimiter) evictLoop() {
	// Evict every 60s; idle threshold = time to fully refill burst.
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	var idleThreshold time.Duration
	if l.rps > 0 {
		idleThreshold = time.Duration(float64(l.burst)/l.rps*1e9) * time.Nanosecond
		if idleThreshold < 60*time.Second {
			idleThreshold = 60 * time.Second
		}
	} else {
		idleThreshold = 60 * time.Second
	}
	for range ticker.C {
		now := l.now()
		l.mu.Lock()
		for k, b := range l.buckets {
			if now.Sub(b.lastTime) > idleThreshold {
				delete(l.buckets, k)
			}
		}
		l.mu.Unlock()
	}
}

// Allow implements KeyedLimiter.
func (l *TokenBucketLimiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	b, ok := l.buckets[key]
	if !ok {
		b = &tokenBucket{tokens: float64(l.burst), lastTime: now}
		l.buckets[key] = b
	}

	elapsed := now.Sub(b.lastTime).Seconds()
	b.tokens += elapsed * l.rps
	if b.tokens > float64(l.burst) {
		b.tokens = float64(l.burst)
	}
	b.lastTime = now

	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// ---------- HTTP middleware ----------

// KeyFunc extracts the rate-limit key from a request (e.g. RemoteAddr).
type KeyFunc func(r *http.Request) string

// IPKeyFunc extracts the client IP from RemoteAddr, stripping the
// ephemeral port so all connections from the same IP share one bucket.
func IPKeyFunc(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr // fallback (e.g. unix socket)
	}
	return host
}

// RateLimitMiddleware returns an http.Handler that gates requests
// through limiter. Denied requests receive 429 with Retry-After.
// keyFn determines the bucket key; pass IPKeyFunc for per-IP limiting.
func RateLimitMiddleware(limiter KeyedLimiter, keyFn KeyFunc, next http.Handler) http.Handler {
	// Compute a sensible Retry-After from the limiter if possible.
	retryAfter := "1"
	if tb, ok := limiter.(*TokenBucketLimiter); ok && tb.rps > 0 {
		secs := 1.0 / tb.rps
		if secs < 1 {
			retryAfter = "1"
		} else {
			retryAfter = fmt.Sprintf("%d", int(secs)+1)
		}
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := keyFn(r)
		if !limiter.Allow(key) {
			w.Header().Set("Retry-After", retryAfter)
			http.Error(w, `{"error":"rate limit exceeded"}`, http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// RateLimitHandler is a convenience wrapper that applies RateLimitMiddleware
// to a single handler.
func RateLimitHandler(limiter KeyedLimiter, keyFn KeyFunc, next http.HandlerFunc) http.Handler {
	return RateLimitMiddleware(limiter, keyFn, next)
}
