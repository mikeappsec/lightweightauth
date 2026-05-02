package ratelimit

import (
	"sync"
	"testing"
	"time"
)

func TestNil_IsAlwaysAllow(t *testing.T) {
	var l *Limiter
	if !l.Allow("any") {
		t.Fatal("nil limiter rejected")
	}
}

func TestNew_DisabledWhenNoRPS(t *testing.T) {
	l, err := New(Spec{})
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if l != nil {
		t.Fatal("expected nil limiter when spec disables both buckets")
	}
}

func TestPerTenant_BurstThenRefill(t *testing.T) {
	now := time.Unix(0, 0)
	l := MustNew(Spec{PerTenant: Bucket{RPS: 10, Burst: 3}})
	l.now = func() time.Time { return now }

	for i := 0; i < 3; i++ {
		if !l.Allow("acme") {
			t.Fatalf("burst #%d denied", i)
		}
	}
	if l.Allow("acme") {
		t.Fatal("expected denial after burst")
	}
	// 100ms at 10/s = 1 token.
	now = now.Add(100 * time.Millisecond)
	if !l.Allow("acme") {
		t.Fatal("expected refilled token to allow")
	}
	if l.Allow("acme") {
		t.Fatal("expected immediate denial after refill consumed")
	}
}

func TestTenantsAreIsolated(t *testing.T) {
	now := time.Unix(0, 0)
	l := MustNew(Spec{PerTenant: Bucket{RPS: 1, Burst: 1}})
	l.now = func() time.Time { return now }

	if !l.Allow("a") {
		t.Fatal("tenant a first call denied")
	}
	if l.Allow("a") {
		t.Fatal("tenant a second call allowed")
	}
	if !l.Allow("b") {
		t.Fatal("tenant b first call denied (sharing tenant a's bucket?)")
	}
}

func TestDefaultBucketUsedForEmptyTenant(t *testing.T) {
	now := time.Unix(0, 0)
	l := MustNew(Spec{Default: Bucket{RPS: 5, Burst: 2}})
	l.now = func() time.Time { return now }

	if !l.Allow("") || !l.Allow("") {
		t.Fatal("default bucket denied within burst")
	}
	if l.Allow("") {
		t.Fatal("default bucket should be empty")
	}
	// Per-tenant disabled → named tenant always passes.
	for i := 0; i < 100; i++ {
		if !l.Allow("acme") {
			t.Fatalf("named tenant denied at #%d (per-tenant disabled, should pass)", i)
		}
	}
}

func TestConcurrent(t *testing.T) {
	l := MustNew(Spec{PerTenant: Bucket{RPS: 1_000_000, Burst: 1_000_000}})
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 1000; j++ {
				_ = l.Allow("t")
			}
		}()
	}
	wg.Wait()
	// No data race / panic = success.
}

func TestOverrides_TenantGetsCustomBucket(t *testing.T) {
	now := time.Unix(0, 0)
	l := MustNew(Spec{
		PerTenant: Bucket{RPS: 1, Burst: 1},
		Overrides: map[string]Bucket{
			"premium": {RPS: 10, Burst: 5},
		},
	})
	l.now = func() time.Time { return now }

	// "premium" gets its override bucket (burst=5).
	for i := 0; i < 5; i++ {
		if !l.Allow("premium") {
			t.Fatalf("premium burst #%d denied", i)
		}
	}
	if l.Allow("premium") {
		t.Fatal("premium should be denied after burst=5 exhausted")
	}

	// "basic" gets the PerTenant bucket (burst=1).
	if !l.Allow("basic") {
		t.Fatal("basic burst #1 denied")
	}
	if l.Allow("basic") {
		t.Fatal("basic should be denied after burst=1 exhausted")
	}
}

func TestOverrides_DisabledOverridePassesThrough(t *testing.T) {
	now := time.Unix(0, 0)
	l := MustNew(Spec{
		PerTenant: Bucket{RPS: 1, Burst: 1},
		Overrides: map[string]Bucket{
			// RPS=0 means disabled for this tenant → always allow.
			"vip": {RPS: 0, Burst: 0},
		},
	})
	l.now = func() time.Time { return now }

	// "vip" override has RPS=0 which means disabled (no rate limiting).
	for i := 0; i < 100; i++ {
		if !l.Allow("vip") {
			t.Fatalf("vip denied at #%d; override with RPS=0 should pass through", i)
		}
	}

	// Non-override tenant still limited.
	if !l.Allow("other") {
		t.Fatal("other burst #1 denied")
	}
	if l.Allow("other") {
		t.Fatal("other should be denied after burst=1")
	}
}
