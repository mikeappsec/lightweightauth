package metrics

import (
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestRecorder_DecisionAndIdentifier(t *testing.T) {
	t.Parallel()
	r := New()
	r.ObserveDecision("allow", "rbac", "acme", 12*time.Millisecond)
	r.ObserveDecision("deny", "rbac", "acme", 5*time.Millisecond)
	r.ObserveIdentifier("jwt", "match")
	r.ObserveIdentifier("jwt", "no_match")

	body := scrape(t, r)
	for _, want := range []string{
		`lwauth_decisions_total{authorizer="rbac",outcome="allow",tenant="acme"} 1`,
		`lwauth_decisions_total{authorizer="rbac",outcome="deny",tenant="acme"} 1`,
		`lwauth_identifier_total{identifier="jwt",outcome="match"} 1`,
		`lwauth_identifier_total{identifier="jwt",outcome="no_match"} 1`,
		`lwauth_decision_latency_seconds_bucket`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q in scrape output:\n%s", want, body)
		}
	}
}

func TestRecorder_RegisterCacheStats(t *testing.T) {
	t.Parallel()
	r := New()
	var hits, misses, evictions atomic.Uint64
	hits.Store(7)
	misses.Store(3)
	evictions.Store(1)
	r.RegisterCacheStats("decision",
		hits.Load, misses.Load, evictions.Load)

	body := scrape(t, r)
	for _, want := range []string{
		`lwauth_cache_hits_total{cache="decision"} 7`,
		`lwauth_cache_misses_total{cache="decision"} 3`,
		`lwauth_cache_evictions_total{cache="decision"} 1`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q in scrape output:\n%s", want, body)
		}
	}

	// Live update — increment and re-scrape; CounterFunc reads the
	// closure each time so no manual refresh is needed.
	hits.Add(5)
	body = scrape(t, r)
	if !strings.Contains(body, `lwauth_cache_hits_total{cache="decision"} 12`) {
		t.Errorf("CounterFunc did not pick up live increment:\n%s", body)
	}
}

func TestDefaultIsLazy(t *testing.T) {
	t.Parallel()
	SetDefault(nil)
	if Default() == nil {
		t.Fatal("Default() must not return nil")
	}
}

func TestNilRecorderTolerated(t *testing.T) {
	t.Parallel()
	var r *Recorder
	r.ObserveDecision("allow", "rbac", "", time.Millisecond)
	r.ObserveIdentifier("jwt", "match")
	r.RegisterCacheStats("x", func() uint64 { return 0 }, func() uint64 { return 0 }, func() uint64 { return 0 })
}

func scrape(t *testing.T, r *Recorder) string {
	t.Helper()
	srv := httptest.NewServer(r.Handler())
	t.Cleanup(srv.Close)
	resp, err := srv.Client().Get(srv.URL)
	if err != nil {
		t.Fatalf("scrape: %v", err)
	}
	defer resp.Body.Close()
	buf := make([]byte, 64*1024)
	n, _ := resp.Body.Read(buf)
	return string(buf[:n])
}
