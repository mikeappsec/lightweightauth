// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package pipeline

import (
	"context"
	"testing"

	"github.com/mikeappsec/lightweightauth/pkg/module"
)

func TestExplain_Allow(t *testing.T) {
	t.Parallel()
	mut := &fakeMut{}
	e, err := New(Options{
		Identifiers: []module.Identifier{
			&fakeID{name: "jwt", id: &module.Identity{Subject: "alice", Source: "jwt"}},
		},
		Authorizer:    &fakeAZ{dec: &module.Decision{Allow: true, Status: 200}},
		Mutators:      []module.ResponseMutator{mut},
		PolicyVersion: "v2.1",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	result := e.Explain(context.Background(), &module.Request{
		Method: "GET",
		Path:   "/api/data",
	})

	if !result.FinalDecision.Allow {
		t.Fatalf("expected allow, got deny: %s", result.FinalDecision.Reason)
	}
	if result.FinalDecision.Status != 200 {
		t.Errorf("status = %d, want 200", result.FinalDecision.Status)
	}
	if result.PolicyVersion != "v2.1" {
		t.Errorf("PolicyVersion = %q, want v2.1", result.PolicyVersion)
	}
	if result.Identity == nil {
		t.Fatal("expected identity")
	}
	if result.Identity.Subject != "alice" {
		t.Errorf("Subject = %q, want alice", result.Identity.Subject)
	}
	if result.Identity.Source != "jwt" {
		t.Errorf("Source = %q, want jwt", result.Identity.Source)
	}

	// Verify stages: identifier + authorizer + mutator.
	if len(result.Stages) != 3 {
		t.Fatalf("len(Stages) = %d, want 3", len(result.Stages))
	}
	if result.Stages[0].Name != "identifier" || result.Stages[0].Result != "match" {
		t.Errorf("stage[0] = %+v, want identifier/match", result.Stages[0])
	}
	if result.Stages[1].Name != "authorizer" || result.Stages[1].Result != "allow" {
		t.Errorf("stage[1] = %+v, want authorizer/allow", result.Stages[1])
	}
	if result.Stages[2].Name != "mutator" || result.Stages[2].Result != "applied" {
		t.Errorf("stage[2] = %+v, want mutator/applied", result.Stages[2])
	}
	if result.TotalLatency < 0 {
		t.Error("expected non-negative TotalLatency")
	}
}

func TestExplain_Deny(t *testing.T) {
	t.Parallel()
	e, err := New(Options{
		Identifiers: []module.Identifier{
			&fakeID{name: "jwt", id: &module.Identity{Subject: "bob", Source: "jwt"}},
		},
		Authorizer: &fakeAZ{dec: &module.Decision{Allow: false, Status: 403, Reason: "not in admin group"}},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	result := e.Explain(context.Background(), &module.Request{
		Method: "DELETE",
		Path:   "/admin/users/42",
	})

	if result.FinalDecision.Allow {
		t.Fatal("expected deny")
	}
	if result.FinalDecision.Status != 403 {
		t.Errorf("status = %d, want 403", result.FinalDecision.Status)
	}
	if result.FinalDecision.Reason != "not in admin group" {
		t.Errorf("reason = %q, want 'not in admin group'", result.FinalDecision.Reason)
	}
	if len(result.Stages) != 2 {
		t.Fatalf("len(Stages) = %d, want 2 (identifier + authorizer)", len(result.Stages))
	}
	if result.Stages[1].Result != "deny" {
		t.Errorf("authorizer stage result = %q, want deny", result.Stages[1].Result)
	}
	if result.Stages[1].Detail != "not in admin group" {
		t.Errorf("authorizer stage detail = %q, want 'not in admin group'", result.Stages[1].Detail)
	}
}

func TestExplain_IdentifierNoMatch(t *testing.T) {
	t.Parallel()
	e, err := New(Options{
		Identifiers: []module.Identifier{
			&fakeID{name: "jwt", err: module.ErrNoMatch},
			&fakeID{name: "apikey", err: module.ErrNoMatch},
		},
		Authorizer: &fakeAZ{dec: &module.Decision{Allow: true}},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	result := e.Explain(context.Background(), &module.Request{
		Method: "GET",
		Path:   "/public",
	})

	// With no identity, the authorizer still runs (with nil identity).
	// Check that both identifiers reported no_match.
	if len(result.Stages) < 2 {
		t.Fatalf("expected at least 2 stages, got %d", len(result.Stages))
	}
	if result.Stages[0].Result != "no_match" || result.Stages[0].Module != "jwt" {
		t.Errorf("stage[0] = %+v, want jwt/no_match", result.Stages[0])
	}
	if result.Stages[1].Result != "no_match" || result.Stages[1].Module != "apikey" {
		t.Errorf("stage[1] = %+v, want apikey/no_match", result.Stages[1])
	}
	if result.Identity != nil {
		t.Errorf("expected nil identity, got %+v", result.Identity)
	}
}

func TestExplain_FirstMatchSkipsRemainingIdentifiers(t *testing.T) {
	t.Parallel()
	e, err := New(Options{
		Identifiers: []module.Identifier{
			&fakeID{name: "jwt", err: module.ErrNoMatch},
			&fakeID{name: "apikey", id: &module.Identity{Subject: "svc-1", Source: "apikey"}},
			&fakeID{name: "mtls", id: &module.Identity{Subject: "never-reached"}},
		},
		Authorizer: &fakeAZ{dec: &module.Decision{Allow: true, Status: 200}},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	result := e.Explain(context.Background(), &module.Request{Method: "GET", Path: "/"})

	// Should have: jwt(no_match) + apikey(match) + authorizer(allow)
	if len(result.Stages) != 3 {
		t.Fatalf("len(Stages) = %d, want 3", len(result.Stages))
	}
	if result.Stages[0].Module != "jwt" || result.Stages[0].Result != "no_match" {
		t.Errorf("stage[0] = %+v", result.Stages[0])
	}
	if result.Stages[1].Module != "apikey" || result.Stages[1].Result != "match" {
		t.Errorf("stage[1] = %+v", result.Stages[1])
	}
	if result.Identity.Subject != "svc-1" {
		t.Errorf("identity = %+v, want svc-1", result.Identity)
	}
}

func TestExplain_MutatorError(t *testing.T) {
	t.Parallel()
	badMut := &fakeMut{err: module.ErrConfig}
	e, err := New(Options{
		Identifiers: []module.Identifier{
			&fakeID{name: "jwt", id: &module.Identity{Subject: "alice"}},
		},
		Authorizer: &fakeAZ{dec: &module.Decision{Allow: true}},
		Mutators:   []module.ResponseMutator{badMut},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	result := e.Explain(context.Background(), &module.Request{Method: "GET", Path: "/"})

	if result.FinalDecision.Allow {
		t.Fatal("expected deny from mutator error")
	}
	if result.FinalDecision.Status != 500 {
		t.Errorf("status = %d, want 500", result.FinalDecision.Status)
	}
	found := false
	for _, s := range result.Stages {
		if s.Name == "mutator" && s.Result == "error" {
			found = true
		}
	}
	if !found {
		t.Error("expected mutator error stage")
	}
}

func TestExplain_ACR_AMR(t *testing.T) {
	t.Parallel()
	e, err := New(Options{
		Identifiers: []module.Identifier{
			&fakeID{name: "jwt", id: &module.Identity{
				Subject: "alice",
				Source:  "jwt",
				ACR:     "urn:mfa",
				AMR:     []string{"pwd", "otp"},
			}},
		},
		Authorizer: &fakeAZ{dec: &module.Decision{Allow: true, Status: 200}},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	result := e.Explain(context.Background(), &module.Request{Method: "GET", Path: "/"})

	if result.Identity == nil {
		t.Fatal("expected identity")
	}
	if result.Identity.ACR != "urn:mfa" {
		t.Errorf("ACR = %q, want urn:mfa", result.Identity.ACR)
	}
	if result.Identity.AMR != "pwd otp" {
		t.Errorf("AMR = %q, want 'pwd otp'", result.Identity.AMR)
	}
}
