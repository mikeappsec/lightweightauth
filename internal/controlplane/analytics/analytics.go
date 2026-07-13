// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

// Package analytics implements thin query proxies that the control-
// plane REST API uses to serve the Decision Inspector and Policy
// Analytics pages. It queries Prometheus + Loki (the same clients
// the alerting engine uses) and normalises the results into JSON
// shapes the frontend chart components can consume directly.
//
// The package does NOT store anything — it is a read-only proxy.
// Durability is the operator's Loki/Prometheus deployment.
package analytics

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"time"

	"github.com/mikeappsec/lightweightauth/internal/controlplane/alerting"
)

// Service is the analytics query proxy. It shares the alerting
// engine's Prom + Loki clients so there is one HTTP connection pool
// per backend and one degraded-state truth source.
type Service struct {
	Prom   *alerting.PromClient
	Loki   *alerting.LokiClient
	Cluster string
}

// NewService constructs an analytics service. prom and loki may be
// nil/degraded — the methods return ErrDegraded and the API endpoints
// surface a 503 with a "backend not configured" message.
func NewService(prom *alerting.PromClient, loki *alerting.LokiClient, cluster string) *Service {
	return &Service{Prom: prom, Loki: loki, Cluster: cluster}
}

// IsDegraded reports whether one or both backends are unconfigured.
func (s *Service) IsDegraded() (prom, loki bool) {
	return s.Prom.Empty(), s.Loki.Empty()
}

// --- response types ---

// TimeSeriesPoint is one [timestamp_ms, value] pair for the frontend
// ECharts time-series chart. Timestamp is Unix milliseconds (ECharts
// native format).
type TimeSeriesPoint struct {
	Timestamp int64   `json:"timestamp"`
	Value     float64 `json:"value"`
}

// TimeSeriesResponse is the normalised chart payload.
type TimeSeriesResponse struct {
	Series []TimeSeriesRow `json:"series"`
}

// TimeSeriesRow is one named series (e.g. "allow", "deny", "error").
type TimeSeriesRow struct {
	Name  string            `json:"name"`
	Label map[string]string `json:"label,omitempty"` // e.g. {"tenant":"acme"}
	Color string            `json:"color,omitempty"`
	Data  []TimeSeriesPoint `json:"data"`
}

// HistogramResponse is the latency-distribution payload.
type HistogramResponse struct {
	Buckets []HistogramBucket `json:"buckets"`
	Count   int               `json:"count"`
}

// HistogramBucket is one cumulative bucket from the Prometheus
// histogram.
type HistogramBucket struct {
	Le    string  `json:"le"`    // human-readable upper bound (e.g. "100ms")
	Count float64 `json:"count"`
}

// PolicyBreakdownResponse is the per-policy-version analytics payload.
type PolicyBreakdownResponse struct {
	Versions []PolicyVersionStats `json:"versions"`
}

// PolicyVersionStats holds the aggregate decision counts and
// disagreement rates for one policy_version.
type PolicyVersionStats struct {
	Version           string  `json:"policy_version"`
	AllowCount        float64 `json:"allow_count"`
	DenyCount         float64 `json:"deny_count"`
	ErrorCount        float64 `json:"error_count"`
	TotalCount        float64 `json:"total_count"`
	DenyRate          float64 `json:"deny_rate"`            // 0..1
	ErrorRate         float64 `json:"error_rate"`           // 0..1
	ShadowDisagree    float64 `json:"shadow_disagreement"`  // 0..1
	CanaryDisagree    float64 `json:"canary_disagreement"`  // 0..1
}

// TopDimensionResponse is the top-N leaderboard payload.
type TopDimensionResponse struct {
	Dimension string         `json:"dimension"`
	Items     []TopDimension `json:"items"`
}

// TopDimension is one entry in a top-N leaderboard.
type TopDimension struct {
	Label string  `json:"label"`
	Count float64 `json:"count"`
	Share float64 `json:"share,omitempty"` // 0..1 relative to total
}

// --- query methods ---

// DecisionTimeSeries returns a time-series of decision counts broken
// down by outcome (allow/deny/error) over the given window. Uses
// Prometheus rate() queries with the supplied step interval.
func (s *Service) DecisionTimeSeries(ctx context.Context, window time.Duration, step time.Duration, groupBy string) (*TimeSeriesResponse, error) {
	if s.Prom.Empty() {
		return nil, alerting.ErrDegraded
	}
	// Build a sum by (groupBy) rate query for each outcome.
	outcomes := []struct {
		name  string
		color string
	}{
		{"allow", "#22c55e"},
		{"deny", "#ef4444"},
		{"error", "#f97316"},
	}
	end := time.Now()
	start := end.Add(-window)

	var rows []TimeSeriesRow
	for _, o := range outcomes {
		query := fmt.Sprintf(`sum by (%s) (rate(lwauth_decisions_total{outcome="%s"}[%s]))`,
			groupBy, o.name, durationToProm(window))
		matrix, err := s.Prom.QueryRange(ctx, query, start, end, step)
		if err != nil {
			continue // degraded per-outcome — don't fail the whole response
		}
		for _, m := range matrix {
			points := make([]TimeSeriesPoint, 0, len(m.Values))
			for _, v := range m.Values {
				ts, val := parseRangeSample(v)
				if ts > 0 {
					points = append(points, TimeSeriesPoint{Timestamp: ts, Value: val})
				}
			}
			if len(points) == 0 {
				continue
			}
			rows = append(rows, TimeSeriesRow{
				Name:  o.name,
				Label: m.Metric,
				Color: o.color,
				Data:  points,
			})
		}
	}
	return &TimeSeriesResponse{Series: rows}, nil
}

// LatencyHistogram returns the cumulative bucket counts for the
// decision-latency histogram, suitable for the ECharts bar chart.
// Uses Prometheus's native _bucket series.
func (s *Service) LatencyHistogram(ctx context.Context, window time.Duration) (*HistogramResponse, error) {
	if s.Prom.Empty() {
		return nil, alerting.ErrDegraded
	}
	query := fmt.Sprintf(`sum by (le) (rate(lwauth_decision_latency_seconds_bucket[%s]))`, durationToProm(window))
	end := time.Now()
	start := end.Add(-window)
	// Single instant query is enough — we want the current distribution.
	matrix, err := s.Prom.QueryRange(ctx, query, start, end, 5*time.Minute)
	if err != nil {
		return nil, err
	}
	if len(matrix) == 0 {
		return &HistogramResponse{Buckets: []HistogramBucket{}}, nil
	}
	// Take the last sample from each bucket-le series.
	buckets := make([]HistogramBucket, 0, len(matrix))
	total := 0.0
	for _, m := range matrix {
		le := m.Metric["le"]
		if le == "" || le == "+Inf" {
			continue
		}
		if len(m.Values) == 0 {
			continue
		}
		_, count := parseRangeSample(m.Values[len(m.Values)-1])
		leSecs, _ := strconv.ParseFloat(le, 64)
		label := fmt.Sprintf("%.0fms", leSecs*1000)
		buckets = append(buckets, HistogramBucket{Le: label, Count: count})
		total += count
	}
	sort.Slice(buckets, func(i, j int) bool {
		return buckets[i].Le < buckets[j].Le
	})
	return &HistogramResponse{Buckets: buckets, Count: int(total)}, nil
}

// LatencyQuantiles returns P50/P90/P99 as a time-series for the
// latency-trend chart on the Policy Analytics page.
func (s *Service) LatencyQuantiles(ctx context.Context, window time.Duration, step time.Duration) (*TimeSeriesResponse, error) {
	if s.Prom.Empty() {
		return nil, alerting.ErrDegraded
	}
	quantiles := []struct {
		name  string
		q     float64
		color string
	}{
		{"P50", 0.5, "#3b82f6"},
		{"P90", 0.9, "#f59e0b"},
		{"P99", 0.99, "#dc2626"},
	}
	end := time.Now()
	start := end.Add(-window)

	var rows []TimeSeriesRow
	for _, q := range quantiles {
		query := fmt.Sprintf(`histogram_quantile(%f, sum by (le) (rate(lwauth_decision_latency_seconds_bucket[%s])))`,
			q.q, durationToProm(window))
		matrix, err := s.Prom.QueryRange(ctx, query, start, end, step)
		if err != nil {
			continue
		}
		for _, m := range matrix {
			points := make([]TimeSeriesPoint, 0, len(m.Values))
			for _, v := range m.Values {
				ts, val := parseRangeSample(v)
				if ts > 0 {
					// Convert seconds → milliseconds for the UI.
					points = append(points, TimeSeriesPoint{Timestamp: ts, Value: val * 1000})
				}
			}
			if len(points) == 0 {
				continue
			}
			rows = append(rows, TimeSeriesRow{
				Name:  q.name,
				Color: q.color,
				Data:  points,
			})
		}
	}
	return &TimeSeriesResponse{Series: rows}, nil
}

// PolicyBreakdown returns per-policy-version decision counts and
// disagreement rates. Uses instant Prometheus queries (not range)
// since the breakdown is a current-state summary, not a time-series.
func (s *Service) PolicyBreakdown(ctx context.Context, window time.Duration) (*PolicyBreakdownResponse, error) {
	if s.Prom.Empty() {
		return nil, alerting.ErrDegraded
	}
	// Query all decisions grouped by policy_version + outcome.
	query := fmt.Sprintf(`sum by (policy_version, outcome) (increase(lwauth_decisions_total[%s]))`, durationToProm(window))
	rows, err := s.Prom.Query(ctx, query)
	if err != nil {
		return nil, err
	}

	// Aggregate by policy_version.
	byVersion := map[string]*PolicyVersionStats{}
	for _, row := range rows {
		pv := row.Metric["policy_version"]
		if pv == "" {
			continue
		}
		val, _ := row.Float()
		stats, ok := byVersion[pv]
		if !ok {
			stats = &PolicyVersionStats{Version: pv}
			byVersion[pv] = stats
		}
		stats.TotalCount += val
		switch row.Metric["outcome"] {
		case "allow":
			stats.AllowCount += val
		case "deny":
			stats.DenyCount += val
		case "error":
			stats.ErrorCount += val
		}
	}

	// Query shadow disagreements per policy_version.
	shadowQuery := fmt.Sprintf(`sum by (policy_version) (increase(lwauth_shadow_disagreement_total[%s]))`, durationToProm(window))
	shadowRows, _ := s.Prom.Query(ctx, shadowQuery)
	for _, row := range shadowRows {
		pv := row.Metric["policy_version"]
		if pv == "" {
			continue
		}
		val, _ := row.Float()
		if stats, ok := byVersion[pv]; ok {
			stats.ShadowDisagree = val
		}
	}

	// Query canary disagreements per policy_version.
	canaryQuery := fmt.Sprintf(`sum by (policy_version) (increase(lwauth_canary_agreement_total{agreement="prod_allow_canary_deny"}[%s]) + increase(lwauth_canary_agreement_total{agreement="prod_deny_canary_allow"}[%s]))`,
		durationToProm(window), durationToProm(window))
	canaryRows, _ := s.Prom.Query(ctx, canaryQuery)
	for _, row := range canaryRows {
		pv := row.Metric["policy_version"]
		if pv == "" {
			continue
		}
		val, _ := row.Float()
		if stats, ok := byVersion[pv]; ok {
			stats.CanaryDisagree = val
		}
	}

	// Compute rates + sort by total descending.
	versions := make([]PolicyVersionStats, 0, len(byVersion))
	for _, stats := range byVersion {
		if stats.TotalCount > 0 {
			stats.DenyRate = stats.DenyCount / stats.TotalCount
			stats.ErrorRate = stats.ErrorCount / stats.TotalCount
		}
		versions = append(versions, *stats)
	}
	sort.Slice(versions, func(i, j int) bool {
		return versions[i].TotalCount > versions[j].TotalCount
	})

	return &PolicyBreakdownResponse{Versions: versions}, nil
}

// TopDimension returns the top-N entries for a given dimension
// (subject, tenant, path, authorizer, identifier) over the window.
// Uses Prometheus increase() grouped by the dimension label.
func (s *Service) TopDimension(ctx context.Context, dimension string, window time.Duration, limit int) (*TopDimensionResponse, error) {
	if s.Prom.Empty() {
		return nil, alerting.ErrDegraded
	}
	if limit <= 0 || limit > 50 {
		limit = 10
	}
	// Map UI dimension names to the metric label name.
	labelMap := map[string]string{
		"tenant":     "tenant",
		"authorizer": "authorizer",
		"identifier": "identifier",
	}
	label, ok := labelMap[dimension]
	if !ok {
		return nil, fmt.Errorf("unsupported dimension %q", dimension)
	}
	query := fmt.Sprintf(`topk(%d, sum by (%s) (increase(lwauth_decisions_total[%s])))`, limit, label, durationToProm(window))
	rows, err := s.Prom.Query(ctx, query)
	if err != nil {
		return nil, err
	}

	items := make([]TopDimension, 0, len(rows))
	total := 0.0
	for _, row := range rows {
		val, _ := row.Float()
		l := row.Metric[label]
		if l == "" {
			continue
		}
		items = append(items, TopDimension{Label: l, Count: val})
		total += val
	}
	for i := range items {
		if total > 0 {
			items[i].Share = items[i].Count / total
		}
	}
	sort.Slice(items, func(i, j int) bool {
		return items[i].Count > items[j].Count
	})

	return &TopDimensionResponse{Dimension: dimension, Items: items}, nil
}

// --- helpers ---

// durationToProm converts a Go time.Duration to a PromQL duration
// string (e.g. "5m", "1h", "24h").
func durationToProm(d time.Duration) string {
	seconds := int64(d.Seconds())
	if seconds%3600 == 0 {
		return fmt.Sprintf("%dh", seconds/3600)
	}
	if seconds%60 == 0 {
		return fmt.Sprintf("%dm", seconds/60)
	}
	return fmt.Sprintf("%ds", seconds)
}

// parseRangeSample extracts [timestamp_ms, float_value] from a
// Prometheus range-vector sample (a [2]any array where [0] is a
// Unix timestamp as float64 or string, and [1] is the value as
// string or float64).
func parseRangeSample(v [2]any) (int64, float64) {
	var ts int64
	switch t := v[0].(type) {
	case float64:
		ts = int64(t * 1000)
	case string:
		f, _ := strconv.ParseFloat(t, 64)
		ts = int64(f * 1000)
	}
	var val float64
	switch s := v[1].(type) {
	case string:
		val, _ = strconv.ParseFloat(s, 64)
	case float64:
		val = s
	}
	return ts, val
}