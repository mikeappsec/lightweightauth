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
package ratelimit

import (
	"sync"
	"time"
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
}

// Bucket configures one token bucket: RPS is the steady-state refill
// rate, Burst is the bucket capacity (max instant burst).
type Bucket struct {
	RPS   float64 `json:"rps,omitempty" yaml:"rps,omitempty"`
	Burst float64 `json:"burst,omitempty" yaml:"burst,omitempty"`
}

func (b Bucket) enabled() bool { return b.RPS > 0 }

// Limiter is a tenant-keyed rate limiter. Construct via New; the zero
// value is not usable. A nil *Limiter is treated as "disabled" by
// Allow, so callers can pass through unconditionally.
type Limiter struct {
	spec Spec

	mu      sync.Mutex
	buckets map[string]*bucket // keyed by tenant ID; "" → default bucket

	now func() time.Time
}

// New returns a Limiter that enforces spec. If neither PerTenant nor
// Default has RPS > 0, returns nil (a no-op limiter the caller can pass
// through).
func New(spec Spec) *Limiter {
	if !spec.PerTenant.enabled() && !spec.Default.enabled() {
		return nil
	}
	return &Limiter{
		spec:    spec,
		buckets: map[string]*bucket{},
		now:     time.Now,
	}
}

// Allow reports whether a request from tenantID may proceed. nil
// receiver = always allow. The empty tenantID falls through to
// spec.Default; if Default is disabled, the empty tenant always passes.
func (l *Limiter) Allow(tenantID string) bool {
	if l == nil {
		return true
	}
	bk := l.bucketFor(tenantID)
	if bk == nil {
		return true
	}
	return bk.take(l.now())
}

func (l *Limiter) bucketFor(tenantID string) *bucket {
	var spec Bucket
	if tenantID == "" {
		spec = l.spec.Default
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
		burst := spec.Burst
		if burst <= 0 {
			burst = spec.RPS
		}
		b = &bucket{capacity: burst, rps: spec.RPS, tokens: burst, last: l.now()}
		l.buckets[tenantID] = b
	}
	return b
}

type bucket struct {
	mu       sync.Mutex
	capacity float64
	rps      float64
	tokens   float64
	last     time.Time
}

func (b *bucket) take(now time.Time) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
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
