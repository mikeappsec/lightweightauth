// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package metrics

import (
	"strings"
	"testing"
)

// promFixture is a realistic slice of /metrics output matching the
// metric families registered in pkg/observability/metrics/metrics.go.
// It exercises the same Prometheus text format the aggregator parses at
// scrape time.
const promFixture = `# HELP lwauth_decisions_total Authorization decisions made by the pipeline.
# TYPE lwauth_decisions_total counter
lwauth_decisions_total{authorizer="rbac-allow",outcome="allow",tenant="acme"} 5
lwauth_decisions_total{authorizer="rbac-allow",outcome="deny",tenant="acme"} 2
lwauth_decisions_total{authorizer="rbac-allow",outcome="error",tenant="acme"} 1
lwauth_decisions_total{authorizer="opa",outcome="deny",tenant="acme"} 1
lwauth_decisions_total{authorizer="opa",outcome="error",tenant="acme"} 1
# HELP lwauth_decision_latency_seconds End-to-end latency of pipeline.Evaluate from request entry to decision.
# TYPE lwauth_decision_latency_seconds histogram
lwauth_decision_latency_seconds_bucket{authorizer="rbac-allow",le="0.0001",outcome="allow",tenant="acme"} 2
lwauth_decision_latency_seconds_bucket{authorizer="rbac-allow",le="0.0002",outcome="allow",tenant="acme"} 4
lwauth_decision_latency_seconds_bucket{authorizer="rbac-allow",le="0.0004",outcome="allow",tenant="acme"} 5
lwauth_decision_latency_seconds_bucket{authorizer="rbac-allow",le="+Inf",outcome="allow",tenant="acme"} 5
lwauth_decision_latency_seconds_sum{authorizer="rbac-allow",outcome="allow",tenant="acme"} 0.0021
lwauth_decision_latency_seconds_count{authorizer="rbac-allow",outcome="allow",tenant="acme"} 5
lwauth_decision_latency_seconds_bucket{authorizer="opa",le="0.0001",outcome="deny",tenant="acme"} 1
lwauth_decision_latency_seconds_bucket{authorizer="opa",le="0.0002",outcome="deny",tenant="acme"} 2
lwauth_decision_latency_seconds_bucket{authorizer="opa",le="0.0004",outcome="deny",tenant="acme"} 2
lwauth_decision_latency_seconds_bucket{authorizer="opa",le="+Inf",outcome="deny",tenant="acme"} 2
lwauth_decision_latency_seconds_sum{authorizer="opa",outcome="deny",tenant="acme"} 0.0003
lwauth_decision_latency_seconds_count{authorizer="opa",outcome="deny",tenant="acme"} 2
# HELP lwauth_cache_hits_total Cache hits by named cache.
# TYPE lwauth_cache_hits_total counter
lwauth_cache_hits_total{cache="decision"} 8
lwauth_cache_hits_total{cache="revocation"} 3
# HELP lwauth_cache_misses_total Cache misses by named cache.
# TYPE lwauth_cache_misses_total counter
lwauth_cache_misses_total{cache="decision"} 2
lwauth_cache_misses_total{cache="revocation"} 1
# HELP lwauth_cache_evictions_total Cache evictions by named cache.
# TYPE lwauth_cache_evictions_total counter
lwauth_cache_evictions_total{cache="decision"} 0
`

func TestParsePrometheusCounters_Outcomes(t *testing.T) {
	t.Parallel()
	c := parsePrometheusCounters(promFixture)
	if c.decisions != 10 {
		t.Errorf("decisions = %v, want 10 (5 allow + 2 deny + 1 error + 1 deny + 1 error)", c.decisions)
	}
	if c.denies != 3 {
		t.Errorf("denies = %v, want 3 (2 from rbac + 1 from opa)", c.denies)
	}
	if c.errors != 2 {
		t.Errorf("errors = %v, want 2 (1 from rbac + 1 from opa)", c.errors)
	}
}

func TestParsePrometheusCounters_CacheTotals(t *testing.T) {
	t.Parallel()
	c := parsePrometheusCounters(promFixture)
	if c.cacheHits != 11 {
		t.Errorf("cacheHits = %v, want 11 (8 decision + 3 revocation)", c.cacheHits)
	}
	if c.cacheTotal != 14 {
		t.Errorf("cacheTotal = %v, want 14 (sum hits+misses = 11 + 3)", c.cacheTotal)
	}
}

func TestParsePrometheusCounters_HistogramBucketsUnknown(t *testing.T) {
	t.Parallel()
	// Body with no decision metrics must yield zeroed counters rather
	// than panicking or returning bogus values.
	c := parsePrometheusCounters("# empty scrape\n")
	if c.decisions != 0 || c.denies != 0 || c.errors != 0 ||
		c.cacheHits != 0 || c.cacheTotal != 0 {
		t.Errorf("expected zeroed counters, got %+v", c)
	}
}

func TestParseHistogramQuantile(t *testing.T) {
	t.Parallel()
	// Fixture has two outcomes' buckets:
	//   rbac-allow (5 samples): le 0.0001 -> 2, le 0.0002 -> 4, le 0.0004 -> 5
	//   opa        (2 samples): le 0.0001 -> 1, le 0.0002 -> 2, le 0.0004 -> 2
	// Aggregated across labels:
	//   le 0.0001 -> 3, le 0.0002 -> 6, le 0.0004 -> 7, le +Inf -> 7
	// P50 of 7 = sample index ceil(0.5 * 7) = 4 -> falls in 0.0002 bucket
	// (cumulative after 0.0001 = 3 < 4; after 0.0002 = 6 >= 4).
	// P99 of 7 = sample index ceil(0.99 * 7) = 7 -> falls in 0.0004 bucket.
	p50 := parseHistogramQuantile(promFixture, "lwauth_decision_latency_seconds", 0.5)
	if p50 != 0.0002 {
		t.Errorf("P50 = %v, want 0.0002", p50)
	}
	p99 := parseHistogramQuantile(promFixture, "lwauth_decision_latency_seconds", 0.99)
	if p99 != 0.0004 {
		t.Errorf("P99 = %v, want 0.0004", p99)
	}
}

func TestParseHistogramQuantile_NoSamples(t *testing.T) {
	t.Parallel()
	if got := parseHistogramQuantile("# empty\n", "lwauth_decision_latency_seconds", 0.5); got != 0 {
		t.Errorf("expected 0 when no samples, got %v", got)
	}
}

func TestExtractLabel(t *testing.T) {
	t.Parallel()
	cases := []struct {
		line, name, want string
	}{
		{`lwauth_decisions_total{authorizer="rbac",outcome="deny",tenant="acme"} 3`, "outcome", "deny"},
		{`lwauth_decisions_total{authorizer="rbac",outcome="deny",tenant="acme"} 3`, "tenant", "acme"},
		{`lwauth_decisions_total{authorizer="rbac",outcome="deny",tenant="acme"} 3`, "authorizer", "rbac"},
		{`lwauth_cache_hits_total{cache="decision"} 1`, "cache", "decision"},
		{`lwauth_decisions_total 5`, "outcome", ""},
		{`lwauth_decisions_total{outcome="allow"} 1`, "missing", ""},
	}
	for i, c := range cases {
		if got := extractLabel(c.line, c.name); got != c.want {
			t.Errorf("case %d: extractLabel(%q,%q) = %q, want %q", i, c.line, c.name, got, c.want)
		}
	}
}

func TestParseHistogramQuantile_SkipsSumCount(t *testing.T) {
	t.Parallel()
	// `_sum` and `_count` series share the histogram prefix but must
	// not be confused with the cumulative bucket counters.
	body := strings.Join([]string{
		`lwauth_decision_latency_seconds_bucket{le="0.0001"} 1`,
		`lwauth_decision_latency_seconds_bucket{le="+Inf"} 1`,
		`lwauth_decision_latency_seconds_count 1`,
		`lwauth_decision_latency_seconds_sum 0.00005`,
		`lwauth_decision_latency_seconds_bucket_sum 0`,
	}, "\n")
	if got := parseHistogramQuantile(body, "lwauth_decision_latency_seconds", 0.99); got != 0.0001 {
		t.Errorf("P99 = %v, want 0.0001", got)
	}
}