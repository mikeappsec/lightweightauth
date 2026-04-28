package ratelimit

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeBackend records calls and returns scripted results.
type fakeBackend struct {
	mu       sync.Mutex
	allow    bool
	err      error
	calls    int
	lastKey  string
	lastLim  int
	lastWin  time.Duration
	closeN   atomic.Int32
}

func (f *fakeBackend) Allow(_ context.Context, key string, limit int, window time.Duration, _ time.Time) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.lastKey = key
	f.lastLim = limit
	f.lastWin = window
	return f.allow, f.err
}

func (f *fakeBackend) Close() { f.closeN.Add(1) }

// regBackend registers fakeBackend under a unique name per test so
// parallel tests don't collide. Returns the type name.
func regBackend(t *testing.T, fb *fakeBackend) string {
	t.Helper()
	name := "fake-" + t.Name()
	RegisterBackend(name, func(_ DistributedSpec) (DistributedBackend, error) {
		return fb, nil
	})
	t.Cleanup(func() {
		backendRegMu.Lock()
		delete(backendReg, name)
		backendRegMu.Unlock()
	})
	return name
}

func TestNew_DistributedDispatchesToFactory(t *testing.T) {
	fb := &fakeBackend{allow: true}
	name := regBackend(t, fb)

	l, err := New(Spec{
		PerTenant:   Bucket{RPS: 100, Burst: 200},
		Distributed: &DistributedSpec{Type: name, Window: time.Second},
	})
	if err != nil {
		t.Fatal(err)
	}
	if l == nil || l.dist != fb {
		t.Fatal("distributed backend not wired")
	}
	if l.distLimit != 200 {
		t.Errorf("distLimit = %d, want 200 (Burst)", l.distLimit)
	}
}

func TestNew_DistributedLimitFromRPSWhenBurstZero(t *testing.T) {
	fb := &fakeBackend{allow: true}
	name := regBackend(t, fb)

	l, err := New(Spec{
		PerTenant:   Bucket{RPS: 30},
		Distributed: &DistributedSpec{Type: name, Window: 2 * time.Second},
	})
	if err != nil {
		t.Fatal(err)
	}
	if l.distLimit != 60 {
		t.Errorf("distLimit = %d, want 60 (RPS*window)", l.distLimit)
	}
}

func TestNew_DistributedUnknownBackend(t *testing.T) {
	_, err := New(Spec{
		PerTenant:   Bucket{RPS: 1},
		Distributed: &DistributedSpec{Type: "no-such-backend"},
	})
	if err == nil {
		t.Fatal("expected error for unknown backend")
	}
}

func TestAllow_DistributedDeniesAuthoritatively(t *testing.T) {
	fb := &fakeBackend{allow: false}
	name := regBackend(t, fb)

	l, err := New(Spec{
		PerTenant:   Bucket{RPS: 1000, Burst: 1000}, // local would allow
		Distributed: &DistributedSpec{Type: name, Window: time.Second},
	})
	if err != nil {
		t.Fatal(err)
	}
	if l.Allow("acme") {
		t.Fatal("distributed denial should be authoritative")
	}
	if fb.calls != 1 {
		t.Errorf("backend calls = %d, want 1", fb.calls)
	}
	if fb.lastKey != "acme" {
		t.Errorf("backend key = %q, want %q", fb.lastKey, "acme")
	}
}

func TestAllow_DistributedKeyPrefix(t *testing.T) {
	fb := &fakeBackend{allow: true}
	name := regBackend(t, fb)

	l, err := New(Spec{
		PerTenant:   Bucket{RPS: 100, Burst: 100},
		Distributed: &DistributedSpec{Type: name, KeyPrefix: "rl/", Window: time.Second},
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = l.Allow("acme")
	if fb.lastKey != "rl/acme" {
		t.Errorf("backend key = %q, want %q", fb.lastKey, "rl/acme")
	}
}

func TestAllow_DistributedFallsBackToLocalOnError(t *testing.T) {
	fb := &fakeBackend{err: errors.New("network blip")}
	name := regBackend(t, fb)

	now := time.Unix(0, 0)
	l, err := New(Spec{
		PerTenant:   Bucket{RPS: 10, Burst: 2},
		Distributed: &DistributedSpec{Type: name, Window: time.Second},
	})
	if err != nil {
		t.Fatal(err)
	}
	l.now = func() time.Time { return now }
	// Local burst=2 is the floor on backend error.
	if !l.Allow("acme") {
		t.Fatal("first call should pass via local floor")
	}
	if !l.Allow("acme") {
		t.Fatal("second call should pass via local floor")
	}
	if l.Allow("acme") {
		t.Fatal("third call should hit local burst exhaustion")
	}
}

func TestAllow_DistributedFailOpenSkipsLocal(t *testing.T) {
	fb := &fakeBackend{err: errors.New("network blip")}
	name := regBackend(t, fb)

	l, err := New(Spec{
		PerTenant:   Bucket{RPS: 1, Burst: 1}, // local would deny after 1
		Distributed: &DistributedSpec{Type: name, Window: time.Second, FailOpen: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 10; i++ {
		if !l.Allow("acme") {
			t.Fatalf("failOpen #%d should always allow", i)
		}
	}
}

func TestAllow_DistributedSuccessAlsoChargesLocal(t *testing.T) {
	fb := &fakeBackend{allow: true}
	name := regBackend(t, fb)

	now := time.Unix(0, 0)
	l, err := New(Spec{
		PerTenant:   Bucket{RPS: 10, Burst: 2}, // tight local floor
		Distributed: &DistributedSpec{Type: name, Window: time.Second},
	})
	if err != nil {
		t.Fatal(err)
	}
	l.now = func() time.Time { return now }
	if !l.Allow("acme") || !l.Allow("acme") {
		t.Fatal("first two should pass within burst")
	}
	if l.Allow("acme") {
		t.Fatal("third should be denied by local floor even though distributed says yes")
	}
}

func TestAllow_DistributedSkippedWhenTenantEmpty(t *testing.T) {
	fb := &fakeBackend{allow: false}
	name := regBackend(t, fb)

	l, err := New(Spec{
		Default:     Bucket{RPS: 100, Burst: 100},
		Distributed: &DistributedSpec{Type: name, Window: time.Second},
	})
	if err != nil {
		t.Fatal(err)
	}
	// Empty tenant routes to Default bucket only — distributed should
	// not be consulted (cluster-wide-cap-per-tenant doesn't make sense
	// without a tenant key).
	if !l.Allow("") {
		t.Fatal("empty tenant should pass via Default")
	}
	if fb.calls != 0 {
		t.Errorf("backend should not be called for empty tenant; calls=%d", fb.calls)
	}
}

func TestClose_PassesThroughToBackend(t *testing.T) {
	fb := &fakeBackend{allow: true}
	name := regBackend(t, fb)

	l, err := New(Spec{
		PerTenant:   Bucket{RPS: 10, Burst: 10},
		Distributed: &DistributedSpec{Type: name, Window: time.Second},
	})
	if err != nil {
		t.Fatal(err)
	}
	l.Close()
	if got := fb.closeN.Load(); got != 1 {
		t.Errorf("backend Close calls = %d, want 1", got)
	}
}

func TestClose_NilLimiterIsSafe(t *testing.T) {
	var l *Limiter
	l.Close() // must not panic
}

func TestRegisterBackend_DuplicatePanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic on duplicate registration")
		}
	}()
	name := "dup-" + t.Name()
	RegisterBackend(name, func(DistributedSpec) (DistributedBackend, error) { return nil, nil })
	t.Cleanup(func() {
		backendRegMu.Lock()
		delete(backendReg, name)
		backendRegMu.Unlock()
	})
	RegisterBackend(name, func(DistributedSpec) (DistributedBackend, error) { return nil, nil })
}
