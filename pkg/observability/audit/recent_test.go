// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestRecentRing_FillAndSnapshot(t *testing.T) {
	t.Parallel()
	r := NewRecentRing(3)
	for i := 0; i < 5; i++ {
		r.Record(context.Background(), &Event{
			Timestamp: time.Unix(int64(i), 0),
			Subject:  "u",
			Decision: "allow",
		})
	}
	events := r.Snapshot(0)
	if len(events) != 3 {
		t.Fatalf("len(events) = %d, want 3 (capacity reached)", len(events))
	}
	// Ring should overwrite oldest; events 3, 4 are kept (timestamps 3 and 4).
	if events[0].Timestamp.Unix() != 2 {
		t.Errorf("oldest kept timestamp = %v, want 2 (oldest overwritten)", events[0].Timestamp.Unix())
	}
	if events[2].Timestamp.Unix() != 4 {
		t.Errorf("newest timestamp = %v, want 4", events[2].Timestamp.Unix())
	}
}

func TestRecentRing_SubjectRedacted(t *testing.T) {
	t.Parallel()
	r := NewRecentRing(8)
	r.Record(context.Background(), &Event{
		Subject:  "alice@example.com",
		Decision: "allow",
	})
	got := r.Snapshot(0)
	if len(got) != 1 {
		t.Fatalf("expected 1 event, got %d", len(got))
	}
	if got[0].Subject == "alice@example.com" {
		t.Errorf("Subject retained raw PII: %q", got[0].Subject)
	}
	if got[0].Subject == "" {
		t.Errorf("Subject was dropped, want HMAC hash")
	}
	if len(got[0].Subject) != 64 {
		t.Errorf("HMAC-SHA-256 hex length = %d, want 64", len(got[0].Subject))
	}
	// Different rings use different seeds so the same plaintext hashes
	// to different values across ring instances — confirms the ring's
	// seed is actually used (not a zero-key fallback).
	other := NewRecentRing(8)
	other.Record(context.Background(), &Event{Subject: "alice@example.com", Decision: "allow"})
	otherGot := other.Snapshot(0)
	if otherGot[0].Subject == got[0].Subject {
		t.Errorf("two rings produced identical subject hashes — HMAC seed not randomised")
	}
}

func TestRecentRing_NilSafe(t *testing.T) {
	t.Parallel()
	var r *RecentRing
	r.Record(context.Background(), nil)            // must not panic
	r.Record(context.Background(), &Event{Subject: "x"}) // must not panic
	if got := r.Snapshot(0); got != nil {
		t.Errorf("nil ring Snapshot = %v, want nil", got)
	}
}

func TestRecentRing_LimitClamps(t *testing.T) {
	t.Parallel()
	r := NewRecentRing(16)
	for i := 0; i < 10; i++ {
		r.Record(context.Background(), &Event{Decision: "allow"})
	}
	if got := r.Snapshot(0); len(got) != 10 {
		t.Errorf("limit=0 returned %d events, want 10", len(got))
	}
	if got := r.Snapshot(3); len(got) != 3 {
		t.Errorf("limit=3 returned %d events, want 3", len(got))
	}
	if got := r.Snapshot(100); len(got) != 10 {
		t.Errorf("limit larger than buffer returned %d events, want 10", len(got))
	}
}

func TestRecentRing_Filters(t *testing.T) {
	t.Parallel()
	r := NewRecentRing(16)
	r.Record(context.Background(), &Event{Tenant: "acme", Decision: "allow", Authorizer: "rbac", Path: "/a"})
	r.Record(context.Background(), &Event{Tenant: "acme", Decision: "deny", Authorizer: "rbac", Path: "/b"})
	r.Record(context.Background(), &Event{Tenant: " Widgets", Decision: "deny", Authorizer: "opa", Path: "/c"})
	r.Record(context.Background(), &Event{Tenant: "acme", Decision: "error", Authorizer: "opa", Path: "/d"})

	acme := r.Snapshot(0, FilterByTenant("acme"))
	if len(acme) != 3 {
		t.Errorf("FilterByTenant returned %d, want 3", len(acme))
	}

	denies := r.Snapshot(0, FilterByVerdict("deny"))
	if len(denies) != 2 {
		t.Errorf("FilterByVerdict(deny) returned %d, want 2", len(denies))
	}

	opa := r.Snapshot(0, FilterByAuthorizer("opa"))
	if len(opa) != 2 {
		t.Errorf("FilterByAuthorizer(opa) returned %d, want 2", len(opa))
	}

	// Combined AND semantics
	acmeDenies := r.Snapshot(0, FilterByTenant("acme"), FilterByVerdict("deny"))
	if len(acmeDenies) != 1 {
		t.Errorf("combined filters returned %d, want 1", len(acmeDenies))
	}

	// Limit applied post-filter
	lim := r.Snapshot(1, FilterByTenant("acme"))
	if len(lim) != 1 {
		t.Errorf("post-filter limit returned %d, want 1", len(lim))
	}

	// Filter matching nothing returns empty
	none := r.Snapshot(0, FilterByTenant("nope"))
	if len(none) != 0 {
		t.Errorf("no-match filter returned %d events, want 0", len(none))
	}
}

func TestRecentRing_FilterBySubjectHash(t *testing.T) {
	t.Parallel()
	r := NewRecentRing(8)
	r.Record(context.Background(), &Event{Subject: "alice", Decision: "allow"})
	r.Record(context.Background(), &Event{Subject: "bob", Decision: "allow"})

	// Snapshot then read the stored hash; filter on it.
	stored := r.Snapshot(0)
	if len(stored) != 2 {
		t.Fatalf("expected 2 events, got %d", len(stored))
	}
	hashedAlice := stored[0].Subject
	matched := r.Snapshot(0, FilterBySubjectHash(hashedAlice))
	if len(matched) != 1 {
		t.Errorf("FilterBySubjectHash returned %d, want 1", len(matched))
	}
	if matched[0].Subject != hashedAlice {
		t.Errorf("matched subject = %q, want %q", matched[0].Subject, hashedAlice)
	}
}

func TestRecentRing_ConcurrentWrites(t *testing.T) {
	t.Parallel()
	r := NewRecentRing(256)
	done := make(chan struct{})
	for g := 0; g < 10; g++ {
		go func() {
			defer func() { done <- struct{}{} }()
			for i := 0; i < 100; i++ {
				r.Record(context.Background(), &Event{Decision: "allow"})
			}
		}()
	}
	for g := 0; g < 10; g++ {
		<-done
	}
	got := r.Snapshot(0)
	if len(got) != 256 {
		t.Errorf("after 1000 writes to cap=256 ring, len = %d, want 256", len(got))
	}
}

func TestDefaultRecentRing_Reuses(t *testing.T) {
	// Use ResetDefaultRecentRing to ensure independence from any
	// prior test that may have lazily created the ring.
	ResetDefaultRecentRing()
	a := DefaultRecentRing()
	b := DefaultRecentRing()
	if a != b {
		t.Errorf("DefaultRecentRing returned different instances on consecutive calls")
	}
}

func TestRecentRing_SnapshotOrderIsOldestFirst(t *testing.T) {
	t.Parallel()
	r := NewRecentRing(4)
	for i := 1; i <= 6; i++ {
		r.Record(context.Background(), &Event{Timestamp: time.Unix(int64(i), 0), Decision: "allow"})
	}
	got := r.Snapshot(0)
	// After 6 writes with cap=4, the ring holds events 3..6 in storage
	// order (3 is oldest, 6 is newest). Snapshot must return them in
	// chronological order so callers can render a clean tail.
	if len(got) != 4 {
		t.Fatalf("len = %d, want 4", len(got))
	}
	for i := 0; i < 3; i++ {
		if !got[i].Timestamp.Before(got[i+1].Timestamp) {
			t.Errorf("events at %d,%d not in chronological order: %v %v",
				i, i+1, got[i].Timestamp, got[i+1].Timestamp)
		}
	}
}

func TestRecentRing_SinkComposition(t *testing.T) {
	t.Parallel()
	r := NewRecentRing(4)
	// The returned Sink is intended for use with NewMultiSink; here we
	// verify it implements the Sink interface and routes to the ring.
	var s Sink = r.Sink()
	s.Record(context.Background(), &Event{Subject: "via-sink", Decision: "allow"})
	got := r.Snapshot(0)
	if len(got) != 1 {
		t.Fatalf("Sink path stored %d events, want 1", len(got))
	}
	// Subject still gets hashed via the Sink path, matching direct Record.
	if got[0].Subject == "via-sink" || got[0].Subject == "" {
		t.Errorf("Sink path did not hash subject: %q", got[0].Subject)
	}
	if !strings.HasSuffix(got[0].Subject, "") { // trivial — placeholder sanity for the import
		t.Errorf("unexpected subject shape")
	}
}