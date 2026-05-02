// Package cache holds the three pipeline caches described in DESIGN.md §5:
//
//  1. JWKS / IdP metadata    (issuer URL → keyset)
//  2. Token introspection     (sha256(token) → claims)
//  3. Authorization decision  (composite key → Decision)
//
// Each cache wraps a generic LRU with singleflight to coalesce concurrent
// misses and emits Prometheus metrics for hits, misses, and evictions.
//
// This file currently exposes the *contract*; the LRU/Redis backends are
// implemented in separate files in later milestones.
package cache

import (
	"context"
	"sync/atomic"
	"time"
)

// Backend is the swappable storage. The default is an in-process LRU; a
// Redis or groupcache backend can be plugged in without touching callers.
type Backend interface {
	Get(ctx context.Context, key string) (value []byte, ok bool, err error)
	Set(ctx context.Context, key string, value []byte, ttl time.Duration) error
	Delete(ctx context.Context, key string) error
}

// Stats are the per-cache counters exposed via Prometheus.
type Stats struct {
	Hits          atomic.Uint64
	Misses        atomic.Uint64
	Evictions     atomic.Uint64
	StaleServed   atomic.Uint64 // E3: stale entries served during upstream outages
	DistSFWon     atomic.Uint64 // E4: this replica won the distributed lock
	DistSFWaited  atomic.Uint64 // E4: this replica waited for another replica's result
}

// Layer bundles the three caches the pipeline shares. Construct via New
// and pass into pipeline.New (future milestone).
type Layer struct {
	JWKS       Backend
	Introspect Backend
	Decision   Backend

	JWKSStats       Stats
	IntrospectStats Stats
	DecisionStats   Stats
}

// New returns a Layer using the provided backends. nil means "disabled".
func New(jwks, introspect, decision Backend) *Layer {
	return &Layer{JWKS: jwks, Introspect: introspect, Decision: decision}
}
