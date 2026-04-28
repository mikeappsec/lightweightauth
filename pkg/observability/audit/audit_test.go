package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"testing"
	"time"
)

func TestSlogSink_EmitsJSONLine(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&buf, nil))
	s := NewSlogSink(log)

	s.Record(context.Background(), &Event{
		Timestamp:      time.Date(2026, 4, 28, 10, 0, 0, 0, time.UTC),
		Tenant:         "acme",
		Subject:        "alice",
		IdentitySource: "jwt",
		Authorizer:     "rbac",
		Decision:       "allow",
		HTTPStatus:     200,
		Method:         "GET",
		Host:           "api.example.com",
		Path:           "/things",
		LatencyMs:      1.234,
	})

	var rec map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &rec); err != nil {
		t.Fatalf("emitted line is not JSON: %v\n%s", err, buf.String())
	}
	if rec["msg"] != "audit" {
		t.Errorf("msg = %v, want audit", rec["msg"])
	}
	want := map[string]any{
		"tenant":          "acme",
		"subject":         "alice",
		"identity_source": "jwt",
		"authorizer":      "rbac",
		"decision":        "allow",
		"method":          "GET",
		"host":            "api.example.com",
		"path":            "/things",
	}
	for k, v := range want {
		if got := rec[k]; got != v {
			t.Errorf("rec[%q] = %v, want %v", k, got, v)
		}
	}
}

func TestDiscardSinkIsSafe(t *testing.T) {
	t.Parallel()
	Discard.Record(context.Background(), &Event{Decision: "allow"})
}

// TestDiscardIsComparable guards against a regression where Discard
// was a SinkFunc (function type, uncomparable) and `Default() ==
// Discard` panicked at runtime. lwauthd.Run uses that exact comparison
// to decide whether to install a default slog sink.
func TestDiscardIsComparable(t *testing.T) {
	t.Parallel()
	prev := Default()
	t.Cleanup(func() { SetDefault(prev) })

	SetDefault(nil) // resets to Discard
	if Default() != Discard {
		t.Fatalf("Default() != Discard after SetDefault(nil)")
	}
	SetDefault(SinkFunc(func(context.Context, *Event) {}))
	if Default() == Discard {
		t.Fatalf("Default() == Discard after installing custom sink")
	}
}

func TestSetDefault(t *testing.T) {
	prev := Default()
	t.Cleanup(func() { SetDefault(prev) })

	called := 0
	SetDefault(SinkFunc(func(context.Context, *Event) { called++ }))
	Default().Record(context.Background(), &Event{})
	if called != 1 {
		t.Fatalf("called = %d, want 1", called)
	}
	SetDefault(nil)
	// After SetDefault(nil), Default() should be a no-op equivalent to
	// Discard. Calling Record must not panic and must not invoke the
	// previous sink.
	Default().Record(context.Background(), &Event{})
	if called != 1 {
		t.Errorf("called = %d after reset, want still 1 (Discard should be a no-op)", called)
	}
}
