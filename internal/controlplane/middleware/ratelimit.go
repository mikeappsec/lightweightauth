// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package middleware

import (
	"net/http"
	"sync"
	"time"
)

// RateLimitConfig configures the rate limiter middleware.
type RateLimitConfig struct {
	// Enabled turns on rate limiting.
	Enabled bool

	// RequestsPerSecond is the steady-state allowed requests/second per client.
	RequestsPerSecond float64

	// Burst is the maximum burst size above the steady-state rate.
	Burst int

	// MaxClients caps the number of tracked client buckets. Oldest buckets
	// are evicted when this limit is reached. Zero means 10000.
	MaxClients int

	// CleanupInterval is how often idle buckets are swept. Zero means 1 minute.
	CleanupInterval time.Duration
}

// DefaultRateLimitConfig returns a default rate limiting config.
func DefaultRateLimitConfig() RateLimitConfig {
	return RateLimitConfig{
		Enabled:           true,
		RequestsPerSecond: 100,
		Burst:             200,
		MaxClients:        10000,
		CleanupInterval:   time.Minute,
	}
}

// tokenBucket implements a simple token bucket rate limiter.
type tokenBucket struct {
	tokens    float64
	max       float64
	rate      float64 // tokens per second
	lastCheck time.Time
}

func newTokenBucket(rate float64, burst int) *tokenBucket {
	return &tokenBucket{
		tokens:    float64(burst),
		max:       float64(burst),
		rate:      rate,
		lastCheck: time.Now(),
	}
}

func (tb *tokenBucket) allow() bool {
	now := time.Now()
	elapsed := now.Sub(tb.lastCheck).Seconds()
	tb.lastCheck = now

	// Refill tokens.
	tb.tokens += elapsed * tb.rate
	if tb.tokens > tb.max {
		tb.tokens = tb.max
	}

	if tb.tokens < 1 {
		return false
	}
	tb.tokens--
	return true
}

// rateLimiter manages per-client rate limiting.
type rateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*tokenBucket
	cfg     RateLimitConfig
}

func newRateLimiter(cfg RateLimitConfig) *rateLimiter {
	rl := &rateLimiter{
		buckets: make(map[string]*tokenBucket),
		cfg:     cfg,
	}
	go rl.cleanup()
	return rl
}

func (rl *rateLimiter) allow(clientID string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	bucket, ok := rl.buckets[clientID]
	if !ok {
		// Evict oldest if at capacity.
		maxClients := rl.cfg.MaxClients
		if maxClients == 0 {
			maxClients = 10000
		}
		if len(rl.buckets) >= maxClients {
			rl.evictOldest()
		}
		bucket = newTokenBucket(rl.cfg.RequestsPerSecond, rl.cfg.Burst)
		rl.buckets[clientID] = bucket
	}
	return bucket.allow()
}

func (rl *rateLimiter) evictOldest() {
	var oldestKey string
	var oldestTime time.Time
	first := true
	for k, b := range rl.buckets {
		if first || b.lastCheck.Before(oldestTime) {
			oldestKey = k
			oldestTime = b.lastCheck
			first = false
		}
	}
	if oldestKey != "" {
		delete(rl.buckets, oldestKey)
	}
}

func (rl *rateLimiter) cleanup() {
	interval := rl.cfg.CleanupInterval
	if interval == 0 {
		interval = time.Minute
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for range ticker.C {
		rl.mu.Lock()
		threshold := time.Now().Add(-5 * time.Minute)
		for k, b := range rl.buckets {
			if b.lastCheck.Before(threshold) {
				delete(rl.buckets, k)
			}
		}
		rl.mu.Unlock()
	}
}

// clientKey extracts a rate-limit key from the request.
// Priority: authenticated subject > X-Forwarded-For > RemoteAddr.
func clientKey(r *http.Request) string {
	if id := IdentityFromContext(r.Context()); id != nil {
		return "subj:" + id.Subject
	}
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return "ip:" + xff
	}
	return "ip:" + r.RemoteAddr
}

// RateLimit returns middleware that enforces per-client rate limits.
func RateLimit(cfg RateLimitConfig) func(http.Handler) http.Handler {
	rl := newRateLimiter(cfg)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !cfg.Enabled {
				next.ServeHTTP(w, r)
				return
			}

			// Skip health probes and the deploy-identity endpoint.
			if r.URL.Path == "/healthz" || r.URL.Path == "/readyz" || r.URL.Path == "/version" {
				next.ServeHTTP(w, r)
				return
			}

			key := clientKey(r)
			if !rl.allow(key) {
				w.Header().Set("Retry-After", "1")
				writeAuthError(w, http.StatusTooManyRequests, "rate limit exceeded")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
