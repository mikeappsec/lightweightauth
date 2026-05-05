// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package lwauthd

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/mikeappsec/lightweightauth/internal/server"
	"github.com/mikeappsec/lightweightauth/pkg/observability/audit"

	_ "github.com/mikeappsec/lightweightauth/pkg/builtins"
)

const cfgAuditA = `
tenantId: team-a
audit:
  redaction:
    fields:
      - name: subject
        action: drop
identifierMode: firstMatch
identifiers:
  - name: dev-apikey
    type: apikey
    config:
      headerName: X-Api-Key
      static:
        k1: { subject: alice, roles: [admin] }
authorizers:
  - name: rbac
    type: rbac
    config:
      rolesFrom: claim:roles
      allow: [admin]
`

const cfgAuditB = `
tenantId: team-b
audit:
  redaction:
    fields:
      - name: subject
        action: hash
identifierMode: firstMatch
identifiers:
  - name: dev-apikey
    type: apikey
    config:
      headerName: X-Api-Key
      static:
        k2: { subject: bob, roles: [editor] }
authorizers:
  - name: rbac
    type: rbac
    config:
      rolesFrom: claim:roles
      allow: [editor]
`

type recordingSink struct {
	mu     sync.Mutex
	events []audit.Event
}

func (r *recordingSink) Record(_ context.Context, e *audit.Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, *e)
}

func (r *recordingSink) snapshot() []audit.Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]audit.Event, len(r.events))
	copy(out, r.events)
	return out
}

func TestConfigApply_SerializesEngineAndAuditPolicy(t *testing.T) {
	dir := t.TempDir()
	pathA := filepath.Join(dir, "a.yaml")
	pathB := filepath.Join(dir, "b.yaml")
	if err := os.WriteFile(pathA, []byte(cfgAuditA), 0o600); err != nil {
		t.Fatalf("write config A: %v", err)
	}
	if err := os.WriteFile(pathB, []byte(cfgAuditB), 0o600); err != nil {
		t.Fatalf("write config B: %v", err)
	}

	engA, acA, err := loadEngineWithConfig(pathA)
	if err != nil {
		t.Fatalf("loadEngineWithConfig(A): %v", err)
	}
	engB, acB, err := loadEngineWithConfig(pathB)
	if err != nil {
		t.Fatalf("loadEngineWithConfig(B): %v", err)
	}

	prev := audit.Default()
	rec := &recordingSink{}
	audit.SetDefault(rec)
	t.Cleanup(func() { audit.SetDefault(prev) })

	// Ensure this test starts from a clean audit-policy cache state.
	auditPolicyMu.Lock()
	auditBaseSink = nil
	auditSeed = nil
	auditPolicyMu.Unlock()

	holder := server.NewEngineHolder(nil)
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))

	enteredA := make(chan struct{})
	releaseA := make(chan struct{})
	doneA := make(chan error, 1)
	doneB := make(chan error, 1)

	go func() {
		server.ConfigApplyMu.Lock()
		defer server.ConfigApplyMu.Unlock()
		if err := applyAuditPolicy(acA, log); err != nil {
			doneA <- err
			return
		}
		close(enteredA)
		<-releaseA
		holder.Swap(engA)
		doneA <- nil
	}()

	select {
	case <-enteredA:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for apply A to enter critical section")
	}

	go func() {
		server.ConfigApplyMu.Lock()
		defer server.ConfigApplyMu.Unlock()
		if err := applyAuditPolicy(acB, log); err != nil {
			doneB <- err
			return
		}
		holder.Swap(engB)
		doneB <- nil
	}()

	select {
	case err := <-doneB:
		t.Fatalf("apply B completed while A held lock: %v", err)
	case <-time.After(150 * time.Millisecond):
		// expected: B is blocked on ConfigApplyMu
	}

	close(releaseA)
	if err := <-doneA; err != nil {
		t.Fatalf("apply A failed: %v", err)
	}
	if err := <-doneB; err != nil {
		t.Fatalf("apply B failed: %v", err)
	}

	if got := holder.Load(); got != engB {
		t.Fatal("holder does not point to the last-applied engine (B)")
	}

	// Validate that the final audit policy corresponds to config B:
	// team-a subject should be unchanged; team-b subject should be hashed.
	sink := audit.Default()
	sink.Record(context.Background(), &audit.Event{Tenant: "team-a", Subject: "alice"})
	sink.Record(context.Background(), &audit.Event{Tenant: "team-b", Subject: "bob"})

	events := rec.snapshot()
	if len(events) < 2 {
		t.Fatalf("expected at least 2 captured events, got %d", len(events))
	}
	lastTwo := events[len(events)-2:]

	seenA := false
	seenB := false
	for _, e := range lastTwo {
		switch e.Tenant {
		case "team-a":
			seenA = true
			if e.Subject != "alice" {
				t.Fatalf("team-a subject unexpectedly redacted under config B policy: %q", e.Subject)
			}
		case "team-b":
			seenB = true
			if e.Subject == "bob" || e.Subject == "" {
				t.Fatalf("team-b subject not hashed under config B policy: %q", e.Subject)
			}
			if len(e.Subject) != 64 {
				t.Fatalf("team-b hash length = %d, want 64", len(e.Subject))
			}
		default:
			t.Fatalf("unexpected tenant in captured event: %s", e.Tenant)
		}
	}
	if !seenA || !seenB {
		t.Fatalf("did not observe both tenants in captured events: seenA=%t seenB=%t", seenA, seenB)
	}

}
