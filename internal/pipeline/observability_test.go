package pipeline

import (
	"context"
	"io"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mikeappsec/lightweightauth/pkg/module"
	"github.com/mikeappsec/lightweightauth/pkg/observability/audit"
	"github.com/mikeappsec/lightweightauth/pkg/observability/metrics"
)

// TestEvaluate_EmitsMetricsAndAudit exercises the M9 observability
// fan-out: every Evaluate call must produce one decisions_total sample
// and one audit Event with the right shape.
func TestEvaluate_EmitsMetricsAndAudit(t *testing.T) {
	// Replace process-wide defaults with isolated test instances.
	rec := metrics.New()
	prevMetrics := metrics.Default()
	metrics.SetDefault(rec)
	t.Cleanup(func() { metrics.SetDefault(prevMetrics) })

	var got []audit.Event
	prevAudit := audit.Default()
	audit.SetDefault(audit.SinkFunc(func(_ context.Context, e *audit.Event) {
		got = append(got, *e)
	}))
	t.Cleanup(func() { audit.SetDefault(prevAudit) })

	e, err := New(Options{
		Identifiers: []module.Identifier{
			&fakeID{name: "jwt", id: &module.Identity{Subject: "alice", Source: "jwt"}},
		},
		Authorizer: &fakeAZ{dec: &module.Decision{Allow: true}},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	dec, _, err := e.Evaluate(context.Background(), &module.Request{
		Method: "GET", Host: "api", Path: "/x", TenantID: "acme",
	})
	if err != nil || !dec.Allow {
		t.Fatalf("Evaluate: dec=%+v err=%v", dec, err)
	}

	// Audit
	if len(got) != 1 {
		t.Fatalf("audit events = %d, want 1", len(got))
	}
	ev := got[0]
	if ev.Decision != "allow" || ev.Subject != "alice" || ev.Tenant != "acme" {
		t.Errorf("event = %+v", ev)
	}
	if ev.Authorizer != "az" {
		t.Errorf("Authorizer = %q, want az", ev.Authorizer)
	}
	if ev.LatencyMs < 0 {
		// Allow zero: on Windows the system clock has ~15.6 ms
		// resolution so a sub-tick Evaluate call can legitimately
		// produce time.Since(start) == 0. Anything negative would be a
		// real bug.
		t.Errorf("LatencyMs = %v, want >= 0", ev.LatencyMs)
	}

	// Metrics — scrape and assert at least the decision counter is
	// present with the right labels.
	body := scrapeMetrics(t, rec)
	wants := []string{
		`lwauth_decisions_total{authorizer="az",outcome="allow",tenant="acme"} 1`,
		`lwauth_identifier_total{identifier="jwt",outcome="match"} 1`,
	}
	for _, w := range wants {
		if !strings.Contains(body, w) {
			t.Errorf("missing %q in metrics:\n%s", w, body)
		}
	}
}

func TestEvaluate_DenyEmitsErrorOutcome(t *testing.T) {
	rec := metrics.New()
	prevMetrics := metrics.Default()
	metrics.SetDefault(rec)
	t.Cleanup(func() { metrics.SetDefault(prevMetrics) })

	e, _ := New(Options{
		Identifiers: []module.Identifier{&fakeID{name: "jwt", err: module.ErrNoMatch}},
		Authorizer:  &fakeAZ{dec: &module.Decision{Allow: true}},
	})
	dec, _, _ := e.Evaluate(context.Background(), &module.Request{TenantID: "acme"})
	if dec.Allow {
		t.Fatal("expected deny on no-match identifier")
	}
	body := scrapeMetrics(t, rec)
	if !strings.Contains(body, `outcome="error"`) {
		t.Errorf("expected error outcome metric, got:\n%s", body)
	}
}

func scrapeMetrics(t *testing.T, r *metrics.Recorder) string {
	t.Helper()
	srv := httptest.NewServer(r.Handler())
	t.Cleanup(srv.Close)
	resp, err := srv.Client().Get(srv.URL)
	if err != nil {
		t.Fatalf("scrape: %v", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return string(b)
}
