// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package pipeline

import (
	"context"
	"errors"
	"testing"

	"github.com/mikeappsec/lightweightauth/pkg/module"
	"github.com/mikeappsec/lightweightauth/pkg/ratelimit"
)

// --- test doubles ----------------------------------------------------------

type fakeID struct {
	name string
	id   *module.Identity
	err  error
}

func (f *fakeID) Name() string { return f.name }
func (f *fakeID) Identify(_ context.Context, _ *module.Request) (*module.Identity, error) {
	return f.id, f.err
}

type fakeAZ struct {
	dec *module.Decision
	err error
}

func (f *fakeAZ) Name() string { return "az" }
func (f *fakeAZ) Authorize(_ context.Context, _ *module.Request, _ *module.Identity) (*module.Decision, error) {
	return f.dec, f.err
}

type fakeMut struct {
	called bool
	err    error
}

func (f *fakeMut) Name() string { return "mut" }
func (f *fakeMut) Mutate(_ context.Context, _ *module.Request, _ *module.Identity, d *module.Decision) error {
	f.called = true
	if d.ResponseHeaders == nil {
		d.ResponseHeaders = map[string]string{}
	}
	d.ResponseHeaders["X-Mut"] = "1"
	return f.err
}

// --- tests -----------------------------------------------------------------

func TestEngine_FirstMatchAllowsViaSecondIdentifier(t *testing.T) {
	t.Parallel()
	e, err := New(Options{
		Identifiers: []module.Identifier{
			&fakeID{name: "a", err: module.ErrNoMatch},
			&fakeID{name: "b", id: &module.Identity{Subject: "alice"}},
		},
		Authorizer: &fakeAZ{dec: &module.Decision{Allow: true}},
		Mutators:   []module.ResponseMutator{&fakeMut{}},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	dec, id, err := e.Evaluate(context.Background(), &module.Request{})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if !dec.Allow {
		t.Fatal("expected allow")
	}
	if id.Source != "b" {
		t.Errorf("Source = %q, want b", id.Source)
	}
	if dec.ResponseHeaders["X-Mut"] != "1" {
		t.Error("mutator was not invoked on allow")
	}
}

func TestEngine_AllIdentifiersNoMatchYields401(t *testing.T) {
	t.Parallel()
	e, _ := New(Options{
		Identifiers: []module.Identifier{
			&fakeID{name: "a", err: module.ErrNoMatch},
			&fakeID{name: "b", err: module.ErrNoMatch},
		},
		Authorizer: &fakeAZ{dec: &module.Decision{Allow: true}},
	})
	dec, _, err := e.Evaluate(context.Background(), &module.Request{})
	if err == nil || !errors.Is(err, module.ErrInvalidCredential) {
		t.Fatalf("err = %v, want ErrInvalidCredential", err)
	}
	if dec.Status != 401 {
		t.Errorf("Status = %d, want 401", dec.Status)
	}
}

func TestEngine_AuthorizerDenyDoesNotRunMutators(t *testing.T) {
	t.Parallel()
	mut := &fakeMut{}
	e, _ := New(Options{
		Identifiers: []module.Identifier{&fakeID{name: "a", id: &module.Identity{Subject: "alice"}}},
		Authorizer:  &fakeAZ{dec: &module.Decision{Allow: false, Status: 403, Reason: "nope"}},
		Mutators:    []module.ResponseMutator{mut},
	})
	dec, _, err := e.Evaluate(context.Background(), &module.Request{})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if dec.Allow {
		t.Fatal("expected deny")
	}
	if mut.called {
		t.Error("mutator should not run on deny")
	}
}

func TestEngine_AllMustMergesClaims(t *testing.T) {
	t.Parallel()
	e, _ := New(Options{
		IdentifierMode: AllMust,
		Identifiers: []module.Identifier{
			&fakeID{name: "a", id: &module.Identity{Subject: "alice", Claims: map[string]any{"x": 1}}},
			&fakeID{name: "b", id: &module.Identity{Subject: "alice", Claims: map[string]any{"y": 2}}},
		},
		Authorizer: &fakeAZ{dec: &module.Decision{Allow: true}},
	})
	_, id, err := e.Evaluate(context.Background(), &module.Request{})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if id.Claims["x"] != 1 || id.Claims["y"] != 2 {
		t.Errorf("merged claims = %v, want both x and y", id.Claims)
	}
}

func TestEngine_RequiresIdentifierAndAuthorizer(t *testing.T) {
	t.Parallel()
	if _, err := New(Options{Authorizer: &fakeAZ{}}); !errors.Is(err, module.ErrConfig) {
		t.Errorf("missing identifier: err = %v, want ErrConfig", err)
	}
	if _, err := New(Options{Identifiers: []module.Identifier{&fakeID{}}}); !errors.Is(err, module.ErrConfig) {
		t.Errorf("missing authorizer: err = %v, want ErrConfig", err)
	}
}

func TestEngine_RateLimitDeniesWith429(t *testing.T) {
	t.Parallel()
	az := &fakeAZ{dec: &module.Decision{Allow: true}}
	id := &fakeID{name: "a", id: &module.Identity{Subject: "alice"}}
	lim := ratelimit.MustNew(ratelimit.Spec{
		PerTenant: ratelimit.Bucket{RPS: 100, Burst: 2},
	})
	e, _ := New(Options{
		Identifiers: []module.Identifier{id},
		Authorizer:  az,
		RateLimiter: lim,
	})
	r := func() *module.Request { return &module.Request{TenantID: "acme"} }

	// Burst 2 allowed.
	for i := 0; i < 2; i++ {
		dec, _, err := e.Evaluate(context.Background(), r())
		if err != nil || !dec.Allow {
			t.Fatalf("call #%d: dec=%+v err=%v", i, dec, err)
		}
	}
	// Third call exceeds burst.
	dec, _, err := e.Evaluate(context.Background(), r())
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if dec.Allow || dec.Status != 429 {
		t.Fatalf("expected 429 deny, got %+v", dec)
	}
	// Other tenants are unaffected.
	r2 := &module.Request{TenantID: "globex"}
	if dec, _, _ := e.Evaluate(context.Background(), r2); !dec.Allow {
		t.Fatalf("tenant globex was throttled by tenant acme: %+v", dec)
	}
}
