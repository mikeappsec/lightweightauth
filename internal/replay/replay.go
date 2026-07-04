// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

// Package replay is the shared single-use enforcement facade used by every
// identifier that must reject a credential replay within a bounded window —
// id-jag (jti), DPoP (jti), and SAML (assertion ID).
//
// It unifies replay onto pkg/cache per the cache layer redesign (§8.1): when
// the injected cache advertises the cache.Atomic capability it uses SetNX for
// genuine compare-and-set (cross-replica when the backend is remote, e.g.
// Valkey). When no Atomic-capable cache is available — no cache injected, or a
// backend without atomics — it falls back to an in-process TTL set that is
// correct for a single replica.
package replay

import (
	"context"
	"sync"
	"time"

	"github.com/mikeappsec/lightweightauth/pkg/cache"
)

// sentinel is the stored marker for a consumed key; its value is irrelevant,
// only presence matters.
var sentinel = []byte{1}

// LocalStore is an in-process single-use enforcer. Consume reports whether key
// was used for the first time within ttl (true) or is a replay (false). A
// module may supply its own LocalStore via [NewWithLocal] when it needs
// stronger in-process semantics than the default (e.g. SAML's bounded,
// fail-closed-at-capacity assertion cache).
type LocalStore interface {
	Consume(key string, ttl time.Duration) bool
}

// Guard enforces single-use of opaque keys (jti, assertion IDs) within a TTL.
type Guard struct {
	atomic cache.Atomic // non-nil when the Atomic path is engaged
	local  LocalStore   // always present as the single-replica fallback
}

// New builds a Guard backed by c. When c implements cache.Atomic, Consume
// uses the cross-replica-safe SetNX path; otherwise (including a nil c) it
// uses the in-process fallback.
func New(c cache.Cache) *Guard {
	g := &Guard{local: newLocalGuard()}
	if a, ok := c.(cache.Atomic); ok {
		g.atomic = a
	}
	return g
}

// NewWithLocal builds a Guard that uses the supplied LocalStore for the
// in-process path and only routes through c.SetNX when c is a genuinely
// remote, cross-replica backend — detected via the cache.Locker capability,
// which is remote-only (the in-process memory backend implements Atomic for
// LRU-style replay but deliberately not Locker). This lets callers that need
// a fail-closed-at-capacity local cache (SAML, G9-VULN-07) keep that behavior
// on the default in-process pool while still gaining cross-replica
// enforcement when a remote pool (e.g. Valkey) is configured.
func NewWithLocal(c cache.Cache, local LocalStore) *Guard {
	g := &Guard{local: local}
	if a, ok := c.(cache.Atomic); ok {
		if _, remote := c.(cache.Locker); remote {
			g.atomic = a
		}
	}
	return g
}

// Consume marks key as used for ttl. It returns true on first use and false
// if key was already consumed within ttl (a replay). A non-nil error is a
// backend failure (only possible on the Atomic path) and the caller should
// fail closed rather than treat it as a clean first use.
func (g *Guard) Consume(ctx context.Context, key string, ttl time.Duration) (firstUse bool, err error) {
	if g.atomic != nil {
		return g.atomic.SetNX(ctx, key, sentinel, ttl)
	}
	return g.local.Consume(key, ttl), nil
}

// localGuard is an in-process TTL set of consumed keys, guarded by a mutex so
// concurrent Consume calls racing the same key get true compare-and-set
// semantics within a single replica.
type localGuard struct {
	mu   sync.Mutex
	seen map[string]time.Time
}

func newLocalGuard() *localGuard {
	return &localGuard{seen: make(map[string]time.Time)}
}

// consume records key as used for ttl. Returns false if key was already
// consumed within ttl.
func (g *localGuard) Consume(key string, ttl time.Duration) bool {
	now := time.Now()
	g.mu.Lock()
	defer g.mu.Unlock()
	// Opportunistic sweep of expired entries so the map cannot grow without
	// bound under a stream of distinct keys.
	for k, exp := range g.seen {
		if now.After(exp) {
			delete(g.seen, k)
		}
	}
	if exp, ok := g.seen[key]; ok && !now.After(exp) {
		return false
	}
	g.seen[key] = now.Add(ttl)
	return true
}
