// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package cache

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mikeappsec/lightweightauth/pkg/module"
)

func mkDec(t *testing.T, pos, neg time.Duration, keys ...string) *Decision {
	t.Helper()
	d, err := NewDecision(DecisionOptions{Size: 16, PositiveTTL: pos, NegativeTTL: neg, KeyFields: keys})
	if err != nil {
		t.Fatalf("NewDecision: %v", err)
	}
	return d
}

func TestDecision_DisabledByZeroTTL(t *testing.T) {
	t.Parallel()
	d, err := NewDecision(DecisionOptions{Size: 8, PositiveTTL: 0})
	if err != nil || d != nil {
		t.Fatalf("expected nil cache, got %+v err=%v", d, err)
	}
}

func TestDecision_HitsPositive(t *testing.T) {
	t.Parallel()
	d := mkDec(t, time.Minute, 5*time.Second, "sub")
	calls := atomic.Int32{}
	fn := func() (*module.Decision, error) {
		calls.Add(1)
		return &module.Decision{Allow: true}, nil
	}
	id := &module.Identity{Subject: "alice"}
	r := &module.Request{}
	key := d.Key(r, id)

	for i := 0; i < 5; i++ {
		dec, _, err := d.Do(context.Background(), key, nil, fn)
		if err != nil || !dec.Allow {
			t.Fatalf("iter %d: %+v %v", i, dec, err)
		}
	}
	if calls.Load() != 1 {
		t.Errorf("authorizer calls = %d, want 1", calls.Load())
	}
}

func TestDecision_HitsNegative(t *testing.T) {
	t.Parallel()
	d := mkDec(t, time.Minute, time.Minute, "sub")
	calls := atomic.Int32{}
	fn := func() (*module.Decision, error) {
		calls.Add(1)
		return &module.Decision{Allow: false, Status: 403, Reason: "nope"}, nil
	}
	id := &module.Identity{Subject: "bob"}
	key := d.Key(&module.Request{}, id)

	for i := 0; i < 4; i++ {
		dec, _, err := d.Do(context.Background(), key, nil, fn)
		if err != nil || dec.Allow {
			t.Fatalf("iter %d: %+v %v", i, dec, err)
		}
	}
	if calls.Load() != 1 {
		t.Errorf("authorizer calls = %d, want 1", calls.Load())
	}
}

func TestDecision_UpstreamErrorNotCached(t *testing.T) {
	t.Parallel()
	d := mkDec(t, time.Minute, time.Minute, "sub")
	calls := atomic.Int32{}
	fn := func() (*module.Decision, error) {
		calls.Add(1)
		return nil, module.ErrUpstream
	}
	id := &module.Identity{Subject: "alice"}
	key := d.Key(&module.Request{}, id)

	for i := 0; i < 3; i++ {
		_, _, err := d.Do(context.Background(), key, nil, fn)
		if !errors.Is(err, module.ErrUpstream) {
			t.Fatalf("iter %d: err = %v", i, err)
		}
	}
	if c := calls.Load(); c != 3 {
		t.Errorf("authorizer calls = %d, want 3 (errors must not cache)", c)
	}
}

func TestDecision_KeysIncludeRequestFields(t *testing.T) {
	t.Parallel()
	d := mkDec(t, time.Minute, time.Minute, "sub", "method", "path")
	id := &module.Identity{Subject: "alice"}
	k1 := d.Key(&module.Request{Method: "GET", Path: "/a"}, id)
	k2 := d.Key(&module.Request{Method: "GET", Path: "/b"}, id)
	if k1 == "" || k2 == "" || k1 == k2 {
		t.Fatalf("keys should differ on path: %q vs %q", k1, k2)
	}
}

func TestDecision_EmptyKeyFieldsDisablesKey(t *testing.T) {
	t.Parallel()
	d := mkDec(t, time.Minute, time.Minute) // no fields
	if k := d.Key(&module.Request{}, &module.Identity{Subject: "alice"}); k != "" {
		t.Errorf("expected empty key, got %q", k)
	}
}

func TestDecision_SingleflightCoalesces(t *testing.T) {
	t.Parallel()
	d := mkDec(t, time.Minute, time.Minute, "sub")
	calls := atomic.Int32{}
	gate := make(chan struct{})
	fn := func() (*module.Decision, error) {
		calls.Add(1)
		<-gate
		return &module.Decision{Allow: true}, nil
	}
	id := &module.Identity{Subject: "racer"}
	key := d.Key(&module.Request{}, id)

	const N = 20
	var wg sync.WaitGroup
	wg.Add(N)
	for i := 0; i < N; i++ {
		go func() {
			defer wg.Done()
			_, _, _ = d.Do(context.Background(), key, nil, fn)
		}()
	}
	time.Sleep(20 * time.Millisecond)
	close(gate)
	wg.Wait()
	if c := calls.Load(); c != 1 {
		t.Errorf("under singleflight, fn calls = %d, want 1", c)
	}
}
