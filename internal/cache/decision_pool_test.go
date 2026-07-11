// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package cache_test

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	icache "github.com/mikeappsec/lightweightauth/internal/cache"
	pkgcache "github.com/mikeappsec/lightweightauth/pkg/cache"
	"github.com/mikeappsec/lightweightauth/pkg/module"
)

// poolBackend builds a pkg/cache memory backend wrapped in the same namespace
// the loader applies, mirroring how the decision cache draws its backend from
// a pool Provider. The returned Cache satisfies the internal cache.Backend
// interface structurally (Get/Set/Delete).
func poolBackend(t *testing.T) pkgcache.Cache {
	t.Helper()
	c, err := pkgcache.BuildBackend(pkgcache.BackendSpec{Type: "memory", Size: 64}, nil)
	if err != nil {
		t.Fatalf("BuildBackend: %v", err)
	}
	return pkgcache.Namespaced(c, "decision/decisions")
}

func TestNewDecisionWithBackend_NilBackendErrors(t *testing.T) {
	t.Parallel()
	if _, err := icache.NewDecisionWithBackend(icache.DecisionOptions{PositiveTTL: time.Minute}, nil, nil); err == nil {
		t.Fatal("expected error for nil backend")
	}
}

func TestNewDecisionWithBackend_DisabledByZeroTTL(t *testing.T) {
	t.Parallel()
	d, err := icache.NewDecisionWithBackend(icache.DecisionOptions{PositiveTTL: 0}, poolBackend(t), nil)
	if err != nil || d != nil {
		t.Fatalf("expected nil cache, got %+v err=%v", d, err)
	}
}

func TestNewDecisionWithBackend_CachesThroughPool(t *testing.T) {
	t.Parallel()
	d, err := icache.NewDecisionWithBackend(icache.DecisionOptions{
		PositiveTTL: time.Minute,
		NegativeTTL: time.Minute,
		KeyFields:   []string{"sub"},
	}, poolBackend(t), nil)
	if err != nil {
		t.Fatalf("NewDecisionWithBackend: %v", err)
	}

	// Allow decisions are cached: only the first call hits the authorizer.
	var allowCalls atomic.Int32
	allowFn := func(_ context.Context) (*module.Decision, error) {
		allowCalls.Add(1)
		return &module.Decision{Allow: true}, nil
	}
	allowKey := d.Key(&module.Request{}, &module.Identity{Subject: "alice"})
	for i := 0; i < 5; i++ {
		dec, _, derr := d.Do(context.Background(), allowKey, nil, allowFn)
		if derr != nil || !dec.Allow {
			t.Fatalf("allow iter %d: %+v %v", i, dec, derr)
		}
	}
	if got := allowCalls.Load(); got != 1 {
		t.Errorf("allow authorizer calls = %d, want 1 (pool backend must cache)", got)
	}

	// Deny decisions are cached under the negative TTL.
	var denyCalls atomic.Int32
	denyFn := func(_ context.Context) (*module.Decision, error) {
		denyCalls.Add(1)
		return &module.Decision{Allow: false, Status: 403}, nil
	}
	denyKey := d.Key(&module.Request{}, &module.Identity{Subject: "bob"})
	for i := 0; i < 4; i++ {
		dec, _, derr := d.Do(context.Background(), denyKey, nil, denyFn)
		if derr != nil || dec.Allow {
			t.Fatalf("deny iter %d: %+v %v", i, dec, derr)
		}
	}
	if got := denyCalls.Load(); got != 1 {
		t.Errorf("deny authorizer calls = %d, want 1", got)
	}

	// Upstream errors must never be cached.
	var errCalls atomic.Int32
	errFn := func(_ context.Context) (*module.Decision, error) {
		errCalls.Add(1)
		return nil, module.ErrUpstream
	}
	errKey := d.Key(&module.Request{}, &module.Identity{Subject: "carol"})
	for i := 0; i < 3; i++ {
		if _, _, derr := d.Do(context.Background(), errKey, nil, errFn); !errors.Is(derr, module.ErrUpstream) {
			t.Fatalf("err iter %d: err = %v", i, derr)
		}
	}
	if got := errCalls.Load(); got != 3 {
		t.Errorf("error authorizer calls = %d, want 3 (errors must not cache)", got)
	}
}

// TestNewDecisionWithBackend_DelegatesTagInvalidation confirms that a pool
// backend implementing TagInvalidator owns tag membership: tagged entries are
// invalidated through the backend (Option A), so InvalidateByTags purges them
// without relying on the in-process tagIndex.
func TestNewDecisionWithBackend_DelegatesTagInvalidation(t *testing.T) {
	t.Parallel()
	d, err := icache.NewDecisionWithBackend(icache.DecisionOptions{
		PositiveTTL: time.Minute,
		NegativeTTL: time.Minute,
		KeyFields:   []string{"sub"},
	}, poolBackend(t), nil)
	if err != nil {
		t.Fatalf("NewDecisionWithBackend: %v", err)
	}

	var calls atomic.Int32
	fn := func(_ context.Context) (*module.Decision, error) {
		calls.Add(1)
		return &module.Decision{Allow: true}, nil
	}
	key := d.Key(&module.Request{}, &module.Identity{Subject: "alice"})
	tags := []string{"sub:alice"}

	// First call populates the cache and tags the entry in the backend.
	if _, _, derr := d.Do(context.Background(), key, tags, fn); derr != nil {
		t.Fatalf("first Do: %v", derr)
	}
	// Second call is served from cache (no new authorizer call).
	if _, _, derr := d.Do(context.Background(), key, tags, fn); derr != nil {
		t.Fatalf("second Do: %v", derr)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("authorizer calls before invalidation = %d, want 1", got)
	}

	// The in-process tagIndex must be empty — delegation went to the backend.
	if ti := d.TagIndex(); ti != nil {
		if keys := ti.KeysForTags(tags); len(keys) != 0 {
			t.Errorf("tagIndex tracked %d keys; want 0 (backend owns tags)", len(keys))
		}
	}

	// Invalidating the tag must drop the entry via the backend.
	if removed := d.InvalidateByTags(context.Background(), tags); removed != 1 {
		t.Errorf("InvalidateByTags removed = %d, want 1", removed)
	}

	// Next call re-runs the authorizer (cache was invalidated).
	if _, _, derr := d.Do(context.Background(), key, tags, fn); derr != nil {
		t.Fatalf("post-invalidation Do: %v", derr)
	}
	if got := calls.Load(); got != 2 {
		t.Errorf("authorizer calls after invalidation = %d, want 2", got)
	}
}
