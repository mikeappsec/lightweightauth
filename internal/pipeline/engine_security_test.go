// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package pipeline

// Security regression tests for the FirstMatch identifier pipeline.
//
// These fence the rule that only ErrNoMatch falls through: a request
// with an *invalid* DPoP / mTLS / HMAC credential must not silently
// downgrade to a weaker later identifier and authenticate. See the
// FirstMatch case in identify() for the full rationale.

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/mikeappsec/lightweightauth/pkg/module"
)

// TestEngine_FirstMatch_InvalidCredentialIsTerminal: identifier A
// finds a credential and rejects it as invalid; identifier B would
// have matched on the same request. The engine MUST stop at A and
// return ErrInvalidCredential — it must not silently downgrade to B.
//
// Real-world shape this models: a `dpop` identifier wrapping `jwt`
// at position 0, and a plain `jwt` at position 1 for compatibility.
// Without the fix, a valid bearer token without a DPoP proof would
// authenticate via plain JWT, defeating the proof-of-possession
// requirement.
func TestEngine_FirstMatch_InvalidCredentialIsTerminal(t *testing.T) {
	t.Parallel()
	bWasCalled := false
	e, _ := New(Options{
		Identifiers: []module.Identifier{
			&fakeID{name: "dpop", err: fmt.Errorf("%w: bad proof", module.ErrInvalidCredential)},
			&trackedID{name: "jwt", id: &module.Identity{Subject: "alice"}, called: &bWasCalled},
		},
		Authorizer: &fakeAZ{dec: &module.Decision{Allow: true}},
	})
	dec, _, err := e.Evaluate(context.Background(), &module.Request{})
	if !errors.Is(err, module.ErrInvalidCredential) {
		t.Fatalf("err = %v, want ErrInvalidCredential", err)
	}
	if dec.Allow {
		t.Fatal("expected deny, got allow")
	}
	if bWasCalled {
		t.Fatal("second identifier ran after invalid credential — fall-through bug regressed")
	}
}

// TestEngine_FirstMatch_UpstreamErrorIsTerminal: an identifier whose
// upstream is unreachable (5xx, network) should not silently fall
// through either. ErrUpstream typically means "we don't know" — a
// fall-through to a weaker identifier could authenticate a request
// the strong identifier would otherwise have rejected.
func TestEngine_FirstMatch_UpstreamErrorIsTerminal(t *testing.T) {
	t.Parallel()
	bWasCalled := false
	e, _ := New(Options{
		Identifiers: []module.Identifier{
			&fakeID{name: "introspection", err: fmt.Errorf("%w: idp 503", module.ErrUpstream)},
			&trackedID{name: "apikey", id: &module.Identity{Subject: "alice"}, called: &bWasCalled},
		},
		Authorizer: &fakeAZ{dec: &module.Decision{Allow: true}},
	})
	_, _, err := e.Evaluate(context.Background(), &module.Request{})
	if !errors.Is(err, module.ErrUpstream) {
		t.Fatalf("err = %v, want ErrUpstream", err)
	}
	if bWasCalled {
		t.Fatal("second identifier ran after upstream error — fall-through bug regressed")
	}
}

// TestEngine_FirstMatch_NoMatchStillFallsThrough: ErrNoMatch is the
// one error that MUST keep iterating — that's the whole point of
// FirstMatch. This is a positive control on the fix: we tightened
// the loop, but the legitimate "this identifier doesn't apply"
// signal still works.
func TestEngine_FirstMatch_NoMatchStillFallsThrough(t *testing.T) {
	t.Parallel()
	e, _ := New(Options{
		Identifiers: []module.Identifier{
			&fakeID{name: "a", err: module.ErrNoMatch},
			&fakeID{name: "b", err: module.ErrNoMatch},
			&fakeID{name: "c", id: &module.Identity{Subject: "alice"}},
		},
		Authorizer: &fakeAZ{dec: &module.Decision{Allow: true}},
	})
	dec, id, err := e.Evaluate(context.Background(), &module.Request{})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if !dec.Allow {
		t.Fatal("expected allow")
	}
	if id.Source != "c" {
		t.Errorf("Source = %q, want c", id.Source)
	}
}

// trackedID is a fakeID that records whether Identify was called.
// Used to assert that earlier-terminal errors short-circuit the loop.
type trackedID struct {
	name   string
	id     *module.Identity
	err    error
	called *bool
}

func (t *trackedID) Name() string { return t.name }
func (t *trackedID) Identify(_ context.Context, _ *module.Request) (*module.Identity, error) {
	*t.called = true
	return t.id, t.err
}
