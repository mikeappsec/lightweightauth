// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package alerting

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/mikeappsec/lightweightauth/pkg/observability/audit"
)

// promServer returns an httptest server that always responds with the
// supplied PromQL query vectors. Used to mock the Prometheus backend
// in engine tests.
func promServer(t *testing.T, vectors [][]any) (*httptest.Server, *PromClient) {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/query", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"vector","result":[`))
		for i, v := range vectors {
			if i > 0 {
				_, _ = w.Write([]byte(","))
			}
			// v is [metric-map-as-JSON, value-pair-as-JSON]
			_, _ = w.Write([]byte(`{"metric":`))
			_, _ = w.Write(v[0].([]byte))
			_, _ = w.Write([]byte(`,"value":`))
			_, _ = w.Write(v[1].([]byte))
			_, _ = w.Write([]byte(`}`))
		}
		_, _ = w.Write([]byte(`]}}`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, &PromClient{BaseURL: srv.URL, HTTP: srv.Client()}
}

func metricJSON(s string) []byte { return []byte(s) }

// tick synchronously runs one engine tick. Engine.Run runs the tick
// loop in a goroutine; tests call tick directly to assert against
// deterministic ordering.
func (e *Engine) tickSync(ctx context.Context) error { return e.tick(ctx) }

func TestEngine_DegradedPromNoOpsCleanly(t *testing.T) {
	t.Parallel()
	var prom *PromClient // nil ⇒ degraded
	eng := NewEngine("local", prom, nil, nil, []Rule{
		{
			Name: "r", Severity: SeverityCritical, Source: SourcePrometheus,
			Query: "up", Comparator: ComparatorGreaterThan, Threshold: 0,
			For: 0, Window: 5 * time.Minute, ScopeLabels: []string{"cluster"},
			Enabled: true,
		},
	})
	if err := eng.tickSync(context.Background()); err != nil {
		t.Fatalf("tick should be silent under degraded Prom: %v", err)
	}
	if alerts := eng.ListAlerts("", AlertFilter{}); len(alerts) != 0 {
		t.Errorf("degraded Prom produced %d alerts, want 0", len(alerts))
	}
	if degraded, _ := eng.IsDegraded(); !degraded {
		t.Errorf("IsDegraded expected prom=true when nil")
	}
}

func TestEngine_FireAfterForSustained(t *testing.T) {
	t.Parallel()
	// PromQL "vector" with one row breaching; the rule's `for` is 0 so
	// the alert opens on the first tick.
	_, prom := promServer(t, [][]any{
		{
			[]byte(`{"identifier":"jwt"}`),
			[]byte(`[1700000000,"0.08"]`),
		},
	})
	eng := NewEngine("local", prom, nil, nil, []Rule{
		{
			Name: "identifier_upstream_error", Severity: SeverityCritical,
			Source: SourcePrometheus,
			Query:  "sum by (identifier) (rate(...))",
			Comparator: ComparatorGreaterThan, Threshold: 0.05,
			For: 0, Window: 5 * time.Minute,
			ScopeLabels: []string{"cluster", "identifier"},
			Enabled: true,
		},
	})
	if err := eng.tickSync(context.Background()); err != nil {
		t.Fatalf("tick: %v", err)
	}
	alerts := eng.ListAlerts("", AlertFilter{})
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert after first tick, got %d", len(alerts))
	}
	a := alerts[0]
	if a.Rule != "identifier_upstream_error" || a.State != AlertStateOpen {
		t.Errorf("wrong state/rule: %+v", a)
	}
	if a.Scope["identifier"] != "jwt" {
		t.Errorf("scope missing identifier: %+v", a.Scope)
	}
	if a.Metric == nil || a.Metric.Value != 0.08 {
		t.Errorf("metric snapshot missing or wrong: %+v", a.Metric)
	}
}

func TestEngine_DedupKeepsOneOpenAcrossTicks(t *testing.T) {
	t.Parallel()
	_, prom := promServer(t, [][]any{
		{
			[]byte(`{"identifier":"jwt"}`),
			[]byte(`[1700000000,"0.1"]`),
		},
	})
	eng := NewEngine("local", prom, nil, nil, []Rule{
		{
			Name: "identifier_upstream_error", Severity: SeverityCritical,
			Source: SourcePrometheus, Query: "rate",
			Comparator: ComparatorGreaterThan, Threshold: 0.05,
			For: 0, Window: 5 * time.Minute,
			ScopeLabels: []string{"cluster", "identifier"},
			Enabled: true,
		},
	})
	for i := 0; i < 3; i++ {
		if err := eng.tickSync(context.Background()); err != nil {
			t.Fatalf("tick %d: %v", i, err)
		}
	}
	alerts := eng.ListAlerts("", AlertFilter{})
	if len(alerts) != 1 {
		t.Fatalf("expected 1 deduplicated alert across 3 ticks, got %d", len(alerts))
	}
}

func TestEngine_ResolveWhenBreachFallsOut(t *testing.T) {
	t.Parallel()
	// First batch: one row breaches.
	vectors := [][]any{
		{[]byte(`{"identifier":"jwt"}`), []byte(`[1700000000,"0.1"]`)},
	}
	srv, prom := promServer(t, vectors)
	_ = prom
	defer srv.Close()
	eng := NewEngine("local", prom, nil, nil, []Rule{
		{
			Name: "identifier_upstream_error", Severity: SeverityCritical,
			Source: SourcePrometheus, Query: "rate",
			Comparator: ComparatorGreaterThan, Threshold: 0.05,
			For: 0, Window: 5 * time.Minute,
			ScopeLabels: []string{"cluster", "identifier"},
			Enabled: true,
		},
	})
	_ = eng.tickSync(context.Background())
	if len(eng.ListAlerts("", AlertFilter{})) != 1 {
		t.Fatal("setup: alert should open on tick1")
	}

	// Replace the prom fixture with an empty vector (no breaches).
	// httptest server's handler is fixed at construction time; we
	// build a fresh fixture-bearing engine by pointing the engine's
	// Prom at a new server.
	vectors2 := [][]any{}
	srv2, prom2 := promServer(t, vectors2)
	defer srv2.Close()
	eng.Prom = prom2
	_ = eng.tickSync(context.Background())

	alerts := eng.ListAlerts("", AlertFilter{})
	if len(alerts) != 1 || alerts[0].State != AlertStateResolved {
		t.Fatalf("expected 1 resolved alert, got %+v", alerts)
	}
}

func TestEngine_AckSnoozesAndReopensOnCooldown(t *testing.T) {
	t.Parallel()
	_, prom := promServer(t, [][]any{
		{[]byte(`{"identifier":"jwt"}`), []byte(`[1700000000,"0.1"]`)},
	})
	eng := NewEngine("local", prom, nil, nil, []Rule{
		{
			Name: "identifier_upstream_error", Severity: SeverityCritical,
			Source: SourcePrometheus, Query: "rate",
			Comparator: ComparatorGreaterThan, Threshold: 0.05,
			For: 0, Window: 5 * time.Minute,
			ScopeLabels: []string{"cluster", "identifier"},
			Enabled: true,
		},
	})
	eng.AckCooldown = 50 * time.Millisecond
	_ = eng.tickSync(context.Background())
	alerts := eng.ListAlerts("", AlertFilter{})
	if len(alerts) != 1 {
		t.Fatalf("setup: want 1 alert, got %d", len(alerts))
	}
	a := alerts[0]
	if err := eng.Ack(a.ID, "alice", "investigating"); err != nil {
		t.Fatalf("Ack: %v", err)
	}

	acked := eng.ListAlerts("", AlertFilter{})
	if len(acked) != 1 || acked[0].State != AlertStateAcknowledged {
		t.Fatalf("expected acked alert, got %+v", acked)
	}
	if acked[0].AckedBy != "alice" {
		t.Errorf("AckedBy = %q", acked[0].AckedBy)
	}

	// Re-ack by same operator → ErrAlertAlreadyAcked.
	if err := eng.Ack(a.ID, "alice", ""); err != ErrAlertAlreadyAcked {
		t.Errorf("re-ack err = %v, want ErrAlertAlreadyAcked", err)
	}

	// Wait for the cooldown to elapse and tick again — the rule still
	// breaches so the alert reopens.
	time.Sleep(80 * time.Millisecond)
	_ = eng.tickSync(context.Background())
	reopened := eng.ListAlerts("", AlertFilter{})
	// may include historical resolved+new open view; filter for open.
	var open *Alert
	for i := range reopened {
		if reopened[i].State == AlertStateOpen {
			open = &reopened[i]
		}
	}
	if open == nil {
		t.Fatalf("expected alert to reopen after cooldown, got %+v", reopened)
	}
	if open.AckedBy != "" {
		t.Errorf("reopen should clear AckedBy, got %q", open.AckedBy)
	}
}

func TestEngine_AckMissingAlert(t *testing.T) {
	t.Parallel()
	eng := NewEngine("local", nil, nil, nil, nil)
	if err := eng.Ack("missing", "alice", ""); err != ErrAlertNotFound {
		t.Errorf("Ack missing err = %v, want ErrAlertNotFound", err)
	}
}

func TestEngine_SinkDeliveryOnFire(t *testing.T) {
	t.Parallel()
	_, prom := promServer(t, [][]any{
		{[]byte(`{"identifier":"jwt"}`), []byte(`[1700000000,"0.1"]`)},
	})
	var mu sync.Mutex
	var got []Alert
	sink := SinkFunc(func(_ context.Context, a Alert, eventType string) error {
		mu.Lock()
		got = append(got, a)
		mu.Unlock()
		if eventType != EventOpen {
			t.Errorf("expected event_type=%q, got %q", EventOpen, eventType)
		}
		return nil
	})
	eng := NewEngine("local", prom, nil, sink, []Rule{
		{
			Name: "identifier_upstream_error", Severity: SeverityCritical,
			Source: SourcePrometheus, Query: "rate",
			Comparator: ComparatorGreaterThan, Threshold: 0.05,
			For: 0, Window: 5 * time.Minute,
			ScopeLabels: []string{"cluster", "identifier"},
			Enabled: true,
		},
	})
	_ = eng.tickSync(context.Background())
	// Sink delivery happens in a goroutine — wait briefly for it.
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		if len(got) >= 1 {
			mu.Unlock()
			break
		}
		mu.Unlock()
		time.Sleep(10 * time.Millisecond)
	}
	mu.Lock()
	if len(got) != 1 {
		t.Fatalf("expected 1 sink delivery, got %d", len(got))
	}
	mu.Unlock()
}

func TestEngine_WSSubscribersReceiveOpen(t *testing.T) {
	t.Parallel()
	_, prom := promServer(t, [][]any{
		{[]byte(`{"identifier":"jwt"}`), []byte(`[1700000000,"0.1"]`)},
	})
	eng := NewEngine("local", prom, nil, nil, []Rule{
		{
			Name: "identifier_upstream_error", Severity: SeverityCritical,
			Source: SourcePrometheus, Query: "rate",
			Comparator: ComparatorGreaterThan, Threshold: 0.05,
			For: 0, Window: 5 * time.Minute,
			ScopeLabels: []string{"cluster", "identifier"},
			Enabled: true,
		},
	})
	ch := eng.Subscribe(AlertFilter{})
	defer eng.Unsubscribe(ch)
	_ = eng.tickSync(context.Background())
	select {
	case evt := <-ch:
		if evt.Type != EventOpen || evt.Alert.Rule != "identifier_upstream_error" {
			t.Errorf("unexpected event: %+v", evt)
		}
	case <-time.After(time.Second):
		t.Fatal("no WS event received")
	}
}

func TestEngine_HistoryRingCappedAtMaxEvents(t *testing.T) {
	t.Parallel()
	_, prom := promServer(t, [][]any{
		{[]byte(`{"identifier":"jwt"}`), []byte(`[1700000000,"0.1"]`)},
	})
	eng := NewEngine("local", prom, nil, nil, []Rule{
		{
			Name: "x", Severity: SeverityWarning, Source: SourcePrometheus,
			Query: "rate", Comparator: ComparatorGreaterThan, Threshold: 0,
			For: 0, Window: 5 * time.Minute,
			ScopeLabels: []string{"cluster"}, Enabled: true,
		},
	})
	// Fire + resolve many cycles (promServer is static so we can't
	// easily toggle; this test exercises the cap directly via
	// appendHistoryLocked).
	eng.mu.Lock()
	for i := 0; i < historyMaxEvents+100; i++ {
		now := time.Now()
		a := Alert{
			ID: "fake", Rule: "x", State: AlertStateResolved,
			FiredAt: now, ResolvedAt: &now,
		}
		eng.appendHistoryLocked(a)
	}
	got := len(eng.history)
	eng.mu.Unlock()
	if got > historyMaxEvents {
		t.Errorf("history grew to %d, must stay ≤ %d", got, historyMaxEvents)
	}
}

func TestAlertID_StableForSameScope(t *testing.T) {
	t.Parallel()
	s1 := Scope{"cluster": "a", "tenant": "t1"}
	s2 := Scope{"tenant": "t1", "cluster": "a"} // iteration order varies
	id1 := alertID("r", s1)
	id2 := alertID("r", s2)
	if id1 != id2 {
		t.Errorf("alertID not order-independent: %q vs %q", id1, id2)
	}
	if id1 == alertID("r2", s1) {
		t.Errorf("alertID collision across distinct rules")
	}
}

// Enricher tests
func TestEnricher_BuildReasonPerRule(t *testing.T) {
	t.Parallel()
	events := []audit.Event{
		{Tenant: "acme", Decision: "deny", Subject: "hash1", Path: "/x", Method: "GET", IdentitySource: "jwt"},
		{Tenant: "acme", Decision: "deny", Subject: "hash2", Path: "/y", Method: "POST"},
		{Tenant: "acme", Decision: "error", Subject: "hash3", IdentitySource: "jwt"},
	}
	en := NewEnricher(func(scope Scope, limit int) []audit.Event {
		return events
	})
	a := Alert{
		Rule: "identifier_upstream_error",
		Scope: Scope{"identifier": "jwt", "cluster": "local"},
		Metric: &MetricValue{Value: 0.08, Threshold: 0.05},
	}
	reason := en.BuildReason(a, nil)
	if reason == nil {
		t.Fatal("reason is nil")
	}
	if reason.Headline == "" {
		t.Error("headline must be populated")
	}
	if len(reason.RecentFailures) == 0 {
		t.Errorf("expected recent failures: %+v", reason)
	}
	if len(reason.RecentFailures) > 5 {
		t.Errorf("recent failures should be capped at 5, got %d", len(reason.RecentFailures))
	}
}

func TestEnricher_FallbackWhenRingUnavailable(t *testing.T) {
	t.Parallel()
	var en *Enricher // nil
	a := Alert{Rule: "r", Scope: Scope{}}
	reason := en.BuildReason(a, nil)
	if reason == nil {
		t.Fatal("nil enricher should still return a fallback")
	}
	if reason.Headline == "" {
		t.Error("fallback headline must be populated")
	}
	if len(reason.RecentFailures) != 0 {
		t.Errorf("fallback should not report recent failures")
	}
}

func TestEnricher_CorrelatedAttachesSiblingAlerts(t *testing.T) {
	t.Parallel()
	en := NewEnricher(func(_ Scope, _ int) []audit.Event { return nil })
	target := Alert{
		ID:    "t", Rule: "identifier_upstream_error",
		Scope: Scope{"cluster": "local"},
		Metric: &MetricValue{Value: 0.08, Threshold: 0.05, Window: 5 * time.Minute, Comparator: ComparatorGreaterThan},
	}
	siblings := []Alert{
		{
			ID: "p99", Rule: "pipeline_p99_latency", State: AlertStateOpen,
			Scope: Scope{"cluster": "local"}, Severity: SeverityCritical,
			Metric: &MetricValue{Value: 0.7, Threshold: 0.5, Window: 5 * time.Minute, Comparator: ComparatorGreaterThan},
		},
	}
	reason := en.BuildReason(target, siblings)
	if len(reason.Correlated) != 1 {
		t.Fatalf("expected 1 correlated alert, got %d", len(reason.Correlated))
	}
	if reason.Correlated[0].Rule != "pipeline_p99_latency" {
		t.Errorf("wrong correlated rule: %+v", reason.Correlated[0])
	}
	if reason.Correlated[0].Note != "presenting symptom" {
		t.Errorf("critical sibling should be flagged symptom: %+v", reason.Correlated[0])
	}
}