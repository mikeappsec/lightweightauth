// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

// Package ratelimit provides a goroutine-safe token-bucket rate limiter
// keyed by tenant. It is consumed by internal/pipeline at the entry of
// Evaluate so a misbehaving tenant cannot exhaust shared module
// resources (an OPA hot loop, an OpenFGA call, an introspection RPC).
//
// The bucket is operator-tunable via AuthConfig:
//
//	rateLimit:
//	  perTenant:
//	    rps: 200       # steady-state allowed requests/second
//	    burst: 400     # short-term burst capacity
//	  default:         # fallback when Request.TenantID is empty
//	    rps: 50
//	    burst: 100
//
// A nil Limiter is a no-op (every call returns ok=true), which is the
// behaviour for AuthConfigs that don't opt in.
//
// Limiter satisfies pkg/httputil.KeyedLimiter so it can be used as a
// drop-in for HTTP middleware rate limiting when keyed by tenant ID.
package ratelimit

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"
	"unicode"
)

// Spec is the YAML/CRD shape AuthConfig.RateLimit accepts.
type Spec struct {
	// PerTenant applies one bucket per Request.TenantID. Zero RPS
	// disables it.
	PerTenant Bucket `json:"perTenant,omitempty" yaml:"perTenant,omitempty"`
	// Default applies when Request.TenantID is empty (single-tenant
	// deployments, or tenants that haven't been stamped). Zero RPS
	// disables it.
	Default Bucket `json:"default,omitempty" yaml:"default,omitempty"`
	// Overrides allows per-tenant quota customization (E6). Keys are
	// tenant IDs; values override PerTenant for that specific tenant.
	// This enables premium tenants to have higher quotas while shared
	// tenants remain at the default rate.
	Overrides map[string]Bucket `json:"overrides,omitempty" yaml:"overrides,omitempty"`
	// MaxBuckets caps the number of in-memory tenant buckets. When the
	// limit is reached, the oldest-accessed bucket is evicted. Zero
	// means 100 000 (safe default to prevent unbounded growth).
	MaxBuckets int `json:"maxBuckets,omitempty" yaml:"maxBuckets,omitempty"`
	// BucketIdleTTL is the duration after which an idle bucket is
	// reaped. Zero means 5 minutes. Prevents memory exhaustion from
	// transient tenant IDs.
	BucketIdleTTL time.Duration `json:"bucketIdleTTL,omitempty" yaml:"bucketIdleTTL,omitempty"`
	// Distributed opts into cluster-wide aggregation for the per-
	// tenant bucket (K-DOS-1). nil = per-replica only (v1.0 default);
	// non-nil = the named backend caps per-tenant requests across
	// every lwauth replica in the deployment. The local bucket
	// continues to act as a per-replica floor; see [DistributedSpec]
	// for details.
	Distributed *DistributedSpec `json:"distributed,omitempty" yaml:"distributed,omitempty"`
}

// Bucket configures one token bucket: RPS is the steady-state refill
// rate, Burst is the bucket capacity (max instant burst).
type Bucket struct {
	RPS   float64 `json:"rps,omitempty" yaml:"rps,omitempty"`
	Burst float64 `json:"burst,omitempty" yaml:"burst,omitempty"`
	// Unlimited explicitly disables rate limiting for this bucket.
	// Must be set to true when RPS is 0 in an override; otherwise a
	// zero-RPS override is rejected as a configuration error.
	Unlimited bool `json:"unlimited,omitempty" yaml:"unlimited,omitempty"`
}

func (b Bucket) enabled() bool { return b.RPS > 0 }

// Limiter is a tenant-keyed rate limiter. Construct via New; the zero
// value is not usable. A nil *Limiter is treated as "disabled" by
// Allow, so callers can pass through unconditionally.
type Limiter struct {
	spec Spec

	mu      sync.Mutex
	buckets map[string]*bucket // keyed by tenant ID; "" → default bucket

	maxBuckets    int
	bucketIdleTTL time.Duration
	stopReaper    chan struct{} // closed by Close to stop the reaper goroutine

	now func() time.Time

	// Distributed aggregator (K-DOS-1). nil = per-replica only.
	dist          DistributedBackend
	distWindow    time.Duration
	distTimeout   time.Duration
	distFailOpen  bool
	distKeyPrefix string
	distLimit     int // computed once: PerTenant.Burst or RPS*window/1s
}

// defaultMaxBuckets is used when Spec.MaxBuckets is 0.
const defaultMaxBuckets = 100_000

// defaultBucketIdleTTL is used when Spec.BucketIdleTTL is 0.
const defaultBucketIdleTTL = 5 * time.Minute

// maxOverrideKeyLen caps override key length to prevent memory abuse.
const maxOverrideKeyLen = 128

// New returns a Limiter that enforces spec. If neither PerTenant nor
// Default has RPS > 0 AND no distributed backend is configured,
// returns nil (a no-op limiter the caller can pass through).
//
// When spec.Distributed is set, New dispatches to the registered
// backend factory. A factory failure surfaces as an error; the engine
// fails compile so misconfiguration is caught at boot.
func New(spec Spec) (*Limiter, error) {
	if !spec.PerTenant.enabled() && !spec.Default.enabled() && spec.Distributed == nil && len(spec.Overrides) == 0 {
		return nil, nil
	}
	// Validate override keys (SLO6 hardening).
	for key, bkt := range spec.Overrides {
		if err := validateOverrideKey(key); err != nil {
			return nil, fmt.Errorf("rateLimit.overrides: %w", err)
		}
		// SLO3 hardening: RPS=0 without Unlimited is a config error.
		if !bkt.enabled() && !bkt.Unlimited {
			return nil, fmt.Errorf("rateLimit.overrides[%q]: RPS is 0 without unlimited: true; set unlimited: true for intentional bypass or set a positive RPS", key)
		}
	}

	maxBk := spec.MaxBuckets
	if maxBk <= 0 {
		maxBk = defaultMaxBuckets
	}
	idleTTL := spec.BucketIdleTTL
	if idleTTL <= 0 {
		idleTTL = defaultBucketIdleTTL
	}

	l := &Limiter{
		spec:          spec,
		buckets:       map[string]*bucket{},
		maxBuckets:    maxBk,
		bucketIdleTTL: idleTTL,
		stopReaper:    make(chan struct{}),
		now:           time.Now,
	}
	if spec.Distributed != nil {
		back, err := BuildBackend(spec.Distributed)
		if err != nil {
			return nil, err
		}
		l.dist = back
		l.distWindow = spec.Distributed.Window
		if l.distWindow <= 0 {
			l.distWindow = time.Second
		}
		l.distTimeout = spec.Distributed.Timeout
		if l.distTimeout <= 0 {
			l.distTimeout = 50 * time.Millisecond
		}
		l.distFailOpen = spec.Distributed.FailOpen
		l.distKeyPrefix = spec.Distributed.KeyPrefix
		// Cluster-wide cap: explicit Burst, else RPS scaled to window.
		if spec.PerTenant.Burst > 0 {
			l.distLimit = int(spec.PerTenant.Burst)
		} else if spec.PerTenant.RPS > 0 {
			l.distLimit = int(spec.PerTenant.RPS * l.distWindow.Seconds())
			if l.distLimit < 1 {
				l.distLimit = 1
			}
		}
	}

	// Start background reaper to evict idle tenant buckets.
	go l.reapLoop()

	return l, nil
}

// validateOverrideKey ensures an override key is well-formed.
func validateOverrideKey(key string) error {
	if key == "" {
		return errors.New("empty override key; use the 'default' bucket for empty-tenant routing")
	}
	if len(key) > maxOverrideKeyLen {
		return fmt.Errorf("override key %q exceeds maximum length %d", key[:32]+"...", maxOverrideKeyLen)
	}
	for _, r := range key {
		if !unicode.IsPrint(r) || r > 127 {
			return fmt.Errorf("override key %q contains non-printable or non-ASCII character", key)
		}
	}
	return nil
}

// reapLoop periodically removes idle buckets to bound memory usage.
func (l *Limiter) reapLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-l.stopReaper:
			return
		case <-ticker.C:
			l.reap()
		}
	}
}

// reap removes buckets that haven't been accessed within bucketIdleTTL.
func (l *Limiter) reap() {
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	for id, b := range l.buckets {
		b.mu.Lock()
		idle := now.Sub(b.lastAccess) > l.bucketIdleTTL
		b.mu.Unlock()
		if idle {
			delete(l.buckets, id)
		}
	}
}

// logUnlimitedOverrides emits a warning for every override that has
// unlimited: true. Call from the config loader at startup for visibility.
func LogUnlimitedOverrides(log *slog.Logger, spec Spec) {
	for key, bkt := range spec.Overrides {
		if bkt.Unlimited {
			log.Warn("rate limit override grants unlimited access",
				"tenant", key, "hint", "ensure this is intentional")
		}
	}
}

// MustNew is the panicking variant for tests and tightly-scoped
// callers that have already validated spec.
func MustNew(spec Spec) *Limiter {
	l, err := New(spec)
	if err != nil {
		panic(err)
	}
	return l
}

// Allow reports whether a request from tenantID may proceed. nil
// receiver = always allow. The empty tenantID falls through to
// spec.Default; if Default is disabled, the empty tenant always passes.
//
// SECURITY: tenantID must come from a trusted source (e.g., the
// AuthConfig's static tenantId field or infrastructure-level routing)
// rather than directly from client-supplied headers. Rate limiting
// runs before authentication; if tenantID is attacker-controlled, a
// malicious client could exhaust another tenant's quota or spoof a
// premium tenant's override bucket.
//
// When a distributed backend is configured AND tenantID is non-empty,
// the backend is consulted first with a per-call deadline. On success
// the local bucket is also charged so a single replica still cannot
// exceed its configured RPS during a burst the cluster-wide cap
// allowed. On backend error the limiter falls back to the local
// bucket (or, with failOpen, allows unconditionally).
func (l *Limiter) Allow(tenantID string) bool {
	if l == nil {
		return true
	}
	if l.dist != nil && tenantID != "" && l.distLimit > 0 {
		ctx, cancel := context.WithTimeout(context.Background(), l.distTimeout)
		ok, err := l.dist.Allow(ctx, l.distKeyPrefix+tenantID, l.distLimit, l.distWindow, l.now())
		cancel()
		switch {
		case err != nil:
			if l.distFailOpen {
				return true
			}
			// Fall through to local bucket as a per-replica floor.
		case !ok:
			return false
		default:
			// Distributed allowed; still charge the local bucket so a
			// single replica's RPS stays bounded even if the cluster
			// cap had headroom.
		}
	}
	bk := l.bucketFor(tenantID)
	if bk == nil {
		return true
	}
	return bk.take(l.now())
}

// Close releases any resources held by a configured distributed
// backend and stops the background reaper. Safe to call on a nil receiver.
func (l *Limiter) Close() {
	if l == nil {
		return
	}
	close(l.stopReaper)
	if l.dist != nil {
		l.dist.Close()
	}
}

func (l *Limiter) bucketFor(tenantID string) *bucket {
	var spec Bucket
	if tenantID == "" {
		spec = l.spec.Default
	} else if override, ok := l.spec.Overrides[tenantID]; ok {
		// Explicit unlimited override — no bucket needed.
		if override.Unlimited {
			return nil
		}
		spec = override
	} else {
		spec = l.spec.PerTenant
	}
	if !spec.enabled() {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	b, ok := l.buckets[tenantID]
	if !ok {
		// Enforce max-buckets cap: if at limit, evict oldest-accessed.
		if len(l.buckets) >= l.maxBuckets {
			l.evictOldestLocked()
		}
		burst := spec.Burst
		if burst <= 0 {
			burst = spec.RPS
		}
		now := l.now()
		b = &bucket{capacity: burst, rps: spec.RPS, tokens: burst, last: now, lastAccess: now}
		l.buckets[tenantID] = b
	}
	return b
}

// evictOldestLocked removes the bucket with the oldest lastAccess.
// Must be called with l.mu held.
func (l *Limiter) evictOldestLocked() {
	var oldestID string
	var oldestTime time.Time
	first := true
	for id, b := range l.buckets {
		b.mu.Lock()
		la := b.lastAccess
		b.mu.Unlock()
		if first || la.Before(oldestTime) {
			oldestID = id
			oldestTime = la
			first = false
		}
	}
	if !first {
		delete(l.buckets, oldestID)
	}
}

type bucket struct {
	mu         sync.Mutex
	capacity   float64
	rps        float64
	tokens     float64
	last       time.Time
	lastAccess time.Time
}

func (b *bucket) take(now time.Time) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.lastAccess = now
	elapsed := now.Sub(b.last).Seconds()
	if elapsed > 0 {
		b.tokens += elapsed * b.rps
		if b.tokens > b.capacity {
			b.tokens = b.capacity
		}
		b.last = now
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}
