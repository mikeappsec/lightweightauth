// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"
)

// collectSink is a test helper that records all events it receives.
type collectSink struct {
	mu     sync.Mutex
	events []*Event
}

func (c *collectSink) Record(_ context.Context, e *Event) {
	c.mu.Lock()
	defer c.mu.Unlock()
	cp := *e
	c.events = append(c.events, &cp)
}

func (c *collectSink) last() *Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.events) == 0 {
		return nil
	}
	return c.events[len(c.events)-1]
}

func (c *collectSink) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.events)
}

func sampleEvent() *Event {
	return &Event{
		Timestamp:      time.Now().UTC(),
		Tenant:         "acme",
		Subject:        "alice@example.com",
		IdentitySource: "jwt",
		Authorizer:     "rbac",
		Decision:       "allow",
		HTTPStatus:     200,
		Method:         "GET",
		Host:           "api.acme.com",
		Path:           "/users/alice/profile",
		LatencyMs:      1.5,
		TraceID:        "abc123def456",
	}
}

// --- RedactingSink tests ---

func TestRedactingSink_DropFields(t *testing.T) {
	inner := &collectSink{}
	sink := NewRedactingSink(inner, []RedactionField{
		{Name: "subject", Action: RedactDrop},
		{Name: "path", Action: RedactDrop},
	}, nil)

	e := sampleEvent()
	origSubject := e.Subject
	sink.Record(context.Background(), e)

	got := inner.last()
	if got.Subject != "" {
		t.Fatalf("subject should be empty, got %q", got.Subject)
	}
	if got.Path != "" {
		t.Fatalf("path should be empty, got %q", got.Path)
	}
	// Original event should be unchanged.
	if e.Subject != origSubject {
		t.Fatal("original event was mutated")
	}
}

func TestRedactingSink_HashFields(t *testing.T) {
	inner := &collectSink{}
	hmacKey := []byte("test-key-32-bytes-long-enough!!!")
	sink := NewRedactingSink(inner, []RedactionField{
		{Name: "subject", Action: RedactHash},
	}, hmacKey)

	e := sampleEvent()
	sink.Record(context.Background(), e)

	got := inner.last()
	if got.Subject == "" {
		t.Fatal("hashed subject should not be empty")
	}
	if got.Subject == "alice@example.com" {
		t.Fatal("subject was not hashed")
	}
	// Should be hex-encoded HMAC-SHA-256 (64 chars).
	if len(got.Subject) != 64 {
		t.Fatalf("expected 64-char hex hash, got %d chars: %s", len(got.Subject), got.Subject)
	}
}

func TestRedactingSink_HashIsDeterministic(t *testing.T) {
	inner := &collectSink{}
	hmacKey := []byte("stable-key")
	sink := NewRedactingSink(inner, []RedactionField{
		{Name: "subject", Action: RedactHash},
	}, hmacKey)

	e1 := sampleEvent()
	e2 := sampleEvent()
	sink.Record(context.Background(), e1)
	sink.Record(context.Background(), e2)

	if inner.events[0].Subject != inner.events[1].Subject {
		t.Fatal("same input should produce same hash")
	}
}

func TestRedactingSink_DifferentKeysProduceDifferentHashes(t *testing.T) {
	inner1 := &collectSink{}
	inner2 := &collectSink{}
	sink1 := NewRedactingSink(inner1, []RedactionField{
		{Name: "subject", Action: RedactHash},
	}, []byte("key-A"))
	sink2 := NewRedactingSink(inner2, []RedactionField{
		{Name: "subject", Action: RedactHash},
	}, []byte("key-B"))

	e := sampleEvent()
	sink1.Record(context.Background(), e)
	sink2.Record(context.Background(), e)

	if inner1.last().Subject == inner2.last().Subject {
		t.Fatal("different keys should produce different hashes")
	}
}

func TestRedactingSink_EmptyFieldSkipped(t *testing.T) {
	inner := &collectSink{}
	sink := NewRedactingSink(inner, []RedactionField{
		{Name: "deny_reason", Action: RedactHash},
	}, []byte("key"))

	e := sampleEvent()
	e.DenyReason = "" // already empty
	sink.Record(context.Background(), e)

	got := inner.last()
	if got.DenyReason != "" {
		t.Fatalf("empty field should stay empty, got %q", got.DenyReason)
	}
}

func TestRedactingSink_UnknownFieldIgnored(t *testing.T) {
	inner := &collectSink{}
	sink := NewRedactingSink(inner, []RedactionField{
		{Name: "nonexistent_field", Action: RedactDrop},
	}, nil)

	e := sampleEvent()
	sink.Record(context.Background(), e)

	got := inner.last()
	if got.Subject != "alice@example.com" {
		t.Fatal("unknown field name should not affect known fields")
	}
}

func TestRedactingSink_NoFieldsPassthrough(t *testing.T) {
	inner := &collectSink{}
	sink := NewRedactingSink(inner, nil, nil)

	e := sampleEvent()
	sink.Record(context.Background(), e)

	got := inner.last()
	if got.Subject != "alice@example.com" {
		t.Fatal("no redaction rules should pass through unchanged")
	}
}

func TestRedactingSink_AllStringFields(t *testing.T) {
	// Verify all documented field names are handled.
	fields := []string{"subject", "path", "host", "deny_reason", "identity_source", "trace_id"}
	for _, name := range fields {
		inner := &collectSink{}
		sink := NewRedactingSink(inner, []RedactionField{
			{Name: name, Action: RedactDrop},
		}, nil)

		e := sampleEvent()
		e.DenyReason = "some reason" // ensure non-empty
		sink.Record(context.Background(), e)

		got := inner.last()
		ptr := sink.fieldPtr(got, name)
		if ptr == nil {
			t.Fatalf("field %q should be handled", name)
		}
		if *ptr != "" {
			t.Fatalf("field %q should have been dropped, got %q", name, *ptr)
		}
	}
}

// --- RegionRoutingSink tests ---

func TestRegionRoutingSink_RoutesToCorrectRegion(t *testing.T) {
	euSink := &collectSink{}
	usSink := &collectSink{}

	router := NewRegionRoutingSink(
		map[string]string{"acme": "eu", "globex": "us"},
		map[string]Sink{"eu": euSink, "us": usSink},
	)

	euEvent := sampleEvent()
	euEvent.Tenant = "acme"
	router.Record(context.Background(), euEvent)

	usEvent := sampleEvent()
	usEvent.Tenant = "globex"
	router.Record(context.Background(), usEvent)

	if euSink.count() != 1 {
		t.Fatalf("EU sink expected 1 event, got %d", euSink.count())
	}
	if usSink.count() != 1 {
		t.Fatalf("US sink expected 1 event, got %d", usSink.count())
	}
	// Cross-check: EU sink should NOT have the US event.
	if euSink.last().Tenant != "acme" {
		t.Fatal("EU sink got wrong tenant")
	}
	if usSink.last().Tenant != "globex" {
		t.Fatal("US sink got wrong tenant")
	}
}

func TestRegionRoutingSink_UnknownTenantGoesToFallback(t *testing.T) {
	euSink := &collectSink{}
	fallback := &collectSink{}

	router := NewRegionRoutingSink(
		map[string]string{"acme": "eu"},
		map[string]Sink{"eu": euSink},
		WithFallbackSink(fallback),
	)

	e := sampleEvent()
	e.Tenant = "unknown-corp"
	router.Record(context.Background(), e)

	if euSink.count() != 0 {
		t.Fatal("EU sink should not receive unknown tenant events")
	}
	if fallback.count() != 1 {
		t.Fatal("fallback should receive unknown tenant events")
	}
}

func TestRegionRoutingSink_UnknownRegionGoesToFallback(t *testing.T) {
	fallback := &collectSink{}

	router := NewRegionRoutingSink(
		map[string]string{"acme": "ap"}, // region "ap" has no sink
		map[string]Sink{},               // no sinks registered
		WithFallbackSink(fallback),
	)

	e := sampleEvent()
	e.Tenant = "acme"
	router.Record(context.Background(), e)

	if fallback.count() != 1 {
		t.Fatal("fallback should receive events when region sink is missing")
	}
}

func TestRegionRoutingSink_NoFallbackDrops(t *testing.T) {
	router := NewRegionRoutingSink(
		map[string]string{},
		map[string]Sink{},
	)

	e := sampleEvent()
	// Should not panic — goes to Discard.
	router.Record(context.Background(), e)
}

// --- TenantAwareSink tests ---

func TestTenantAwareSink_RedactsConfiguredTenants(t *testing.T) {
	inner := &collectSink{}
	tas := NewTenantAwareSink(inner)
	tas.SetTenantRedaction("acme", []RedactionField{
		{Name: "subject", Action: RedactDrop},
	}, nil)

	e := sampleEvent()
	e.Tenant = "acme"
	tas.Record(context.Background(), e)

	got := inner.last()
	if got.Subject != "" {
		t.Fatalf("acme tenant subject should be redacted, got %q", got.Subject)
	}
}

func TestTenantAwareSink_PassesThroughUnconfigured(t *testing.T) {
	inner := &collectSink{}
	tas := NewTenantAwareSink(inner)
	tas.SetTenantRedaction("acme", []RedactionField{
		{Name: "subject", Action: RedactDrop},
	}, nil)

	e := sampleEvent()
	e.Tenant = "globex" // not configured
	tas.Record(context.Background(), e)

	got := inner.last()
	if got.Subject != "alice@example.com" {
		t.Fatal("unconfigured tenant should pass through")
	}
}

func TestTenantAwareSink_RemoveTenant(t *testing.T) {
	inner := &collectSink{}
	tas := NewTenantAwareSink(inner)
	tas.SetTenantRedaction("acme", []RedactionField{
		{Name: "subject", Action: RedactDrop},
	}, nil)
	tas.RemoveTenant("acme")

	e := sampleEvent()
	e.Tenant = "acme"
	tas.Record(context.Background(), e)

	got := inner.last()
	if got.Subject != "alice@example.com" {
		t.Fatal("removed tenant should pass through")
	}
}

func TestTenantAwareSink_ConcurrentAccess(t *testing.T) {
	inner := &collectSink{}
	tas := NewTenantAwareSink(inner)
	tas.SetTenantRedaction("acme", []RedactionField{
		{Name: "subject", Action: RedactDrop},
	}, nil)

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			e := sampleEvent()
			e.Tenant = "acme"
			tas.Record(context.Background(), e)
		}()
	}
	wg.Wait()

	if inner.count() != 100 {
		t.Fatalf("expected 100 events, got %d", inner.count())
	}
	for _, ev := range inner.events {
		if ev.Subject != "" {
			t.Fatal("all acme events should have redacted subject")
		}
	}
}

func TestRedactingSink_MixedActions(t *testing.T) {
	inner := &collectSink{}
	sink := NewRedactingSink(inner, []RedactionField{
		{Name: "subject", Action: RedactHash},
		{Name: "path", Action: RedactDrop},
		{Name: "host", Action: RedactHash},
	}, []byte("mix-key"))

	e := sampleEvent()
	sink.Record(context.Background(), e)

	got := inner.last()
	// Subject: hashed (64 hex chars).
	if len(got.Subject) != 64 || got.Subject == "alice@example.com" {
		t.Fatalf("subject should be hashed, got %q", got.Subject)
	}
	// Path: dropped.
	if got.Path != "" {
		t.Fatalf("path should be empty, got %q", got.Path)
	}
	// Host: hashed.
	if len(got.Host) != 64 || got.Host == "api.acme.com" {
		t.Fatalf("host should be hashed, got %q", got.Host)
	}
	// Non-redacted fields unchanged.
	if got.Decision != "allow" {
		t.Fatal("non-redacted field changed")
	}
}

// --- Integration test: redaction + region routing ---

func TestRedactionWithRegionRouting(t *testing.T) {
	euSink := &collectSink{}
	usSink := &collectSink{}

	// EU gets redacted, US gets plain.
	euRedacted := NewRedactingSink(euSink, []RedactionField{
		{Name: "subject", Action: RedactHash},
	}, []byte("eu-key"))

	router := NewRegionRoutingSink(
		map[string]string{"acme": "eu", "globex": "us"},
		map[string]Sink{"eu": euRedacted, "us": usSink},
	)

	euEvent := sampleEvent()
	euEvent.Tenant = "acme"
	router.Record(context.Background(), euEvent)

	usEvent := sampleEvent()
	usEvent.Tenant = "globex"
	router.Record(context.Background(), usEvent)

	// EU event: subject should be hashed.
	euGot := euSink.last()
	if euGot.Subject == "alice@example.com" || len(euGot.Subject) != 64 {
		t.Fatalf("EU subject should be hashed, got %q", euGot.Subject)
	}

	// US event: subject should be plaintext.
	usGot := usSink.last()
	if usGot.Subject != "alice@example.com" {
		t.Fatalf("US subject should be plaintext, got %q", usGot.Subject)
	}

	// Cross-region isolation: hashes should not appear in US.
	if strings.Contains(usGot.Subject, euGot.Subject) {
		t.Fatal("US sink should not contain EU hashes")
	}
}
