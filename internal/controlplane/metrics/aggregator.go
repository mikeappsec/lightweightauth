// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

// Package metrics implements a lightweight metrics aggregator that scrapes
// /metrics from discovered instances, computing per-cluster and global rollups
// without requiring a Prometheus server.
package metrics

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/mikeappsec/lightweightauth/internal/controlplane/discovery"
)

// InstanceMetrics holds scraped metrics for a single instance.
type InstanceMetrics struct {
	Instance      string    `json:"instance"`
	Cluster       string    `json:"cluster"`
	DecisionRate  float64   `json:"decisionRate"`  // decisions/sec
	DenyRate      float64   `json:"denyRate"`      // denies/sec
	CacheHitRatio float64   `json:"cacheHitRatio"` // 0-1
	ErrorRate     float64   `json:"errorRate"`     // errors/sec
	LatencyP50Ms  float64   `json:"latencyP50Ms"`
	LatencyP99Ms  float64   `json:"latencyP99Ms"`
	LastScrape    time.Time `json:"lastScrape"`
	Stale         bool      `json:"stale"`
}

// ClusterRollup aggregates metrics across instances in a cluster.
type ClusterRollup struct {
	Cluster        string  `json:"cluster"`
	TotalDecisions float64 `json:"totalDecisions"` // total decisions/sec
	TotalDenies    float64 `json:"totalDenies"`
	AvgCacheHit    float64 `json:"avgCacheHit"`
	InstanceCount  int     `json:"instanceCount"`
}

// GlobalRollup aggregates metrics across all clusters.
type GlobalRollup struct {
	TotalDecisionRate float64         `json:"totalDecisionRate"`
	TotalDenyRate     float64         `json:"totalDenyRate"`
	AvgCacheHitRatio  float64         `json:"avgCacheHitRatio"`
	TotalErrorRate    float64         `json:"totalErrorRate"`
	Clusters          []ClusterRollup `json:"clusters"`
}

// Aggregator periodically scrapes instance metrics and computes rollups.
type Aggregator struct {
	Registry *discovery.Registry
	Client   *http.Client
	Interval time.Duration

	mu     sync.RWMutex
	byInst map[string]*InstanceMetrics // key: cluster/name
	// Previous scrape counters for rate computation.
	prevCounters map[string]*counters
	prevTime     map[string]time.Time
}

type counters struct {
	decisions  float64
	denies     float64
	errors     float64
	cacheHits  float64
	cacheTotal float64
}

// NewAggregator creates a metrics aggregator.
func NewAggregator(registry *discovery.Registry) *Aggregator {
	return &Aggregator{
		Registry: registry,
		Client: &http.Client{
			Timeout: 5 * time.Second,
		},
		Interval:     10 * time.Second,
		byInst:       make(map[string]*InstanceMetrics),
		prevCounters: make(map[string]*counters),
		prevTime:     make(map[string]time.Time),
	}
}

// Run starts the periodic scrape loop. Blocks until ctx is cancelled.
func (a *Aggregator) Run(ctx context.Context) {
	logger := log.FromContext(ctx).WithName("metrics-aggregator")
	ticker := time.NewTicker(a.Interval)
	defer ticker.Stop()

	logger.Info("starting metrics aggregator", "interval", a.Interval)
	a.scrapeAll(ctx)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			a.scrapeAll(ctx)
		}
	}
}

// GetInstanceMetrics returns metrics for a specific instance.
func (a *Aggregator) GetInstanceMetrics(cluster, name string) (*InstanceMetrics, bool) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	m, ok := a.byInst[cluster+"/"+name]
	return m, ok
}

// ListInstanceMetrics returns all instance metrics.
func (a *Aggregator) ListInstanceMetrics() []*InstanceMetrics {
	a.mu.RLock()
	defer a.mu.RUnlock()
	result := make([]*InstanceMetrics, 0, len(a.byInst))
	for _, m := range a.byInst {
		result = append(result, m)
	}
	return result
}

// GlobalRollup computes aggregated metrics across all instances.
func (a *Aggregator) GetGlobalRollup() GlobalRollup {
	a.mu.RLock()
	defer a.mu.RUnlock()

	clusters := make(map[string]*ClusterRollup)
	var global GlobalRollup

	for _, m := range a.byInst {
		if m.Stale {
			continue
		}
		cr, ok := clusters[m.Cluster]
		if !ok {
			cr = &ClusterRollup{Cluster: m.Cluster}
			clusters[m.Cluster] = cr
		}
		cr.TotalDecisions += m.DecisionRate
		cr.TotalDenies += m.DenyRate
		cr.AvgCacheHit += m.CacheHitRatio
		cr.InstanceCount++

		global.TotalDecisionRate += m.DecisionRate
		global.TotalDenyRate += m.DenyRate
		global.TotalErrorRate += m.ErrorRate
		global.AvgCacheHitRatio += m.CacheHitRatio
	}

	total := 0
	for _, cr := range clusters {
		if cr.InstanceCount > 0 {
			cr.AvgCacheHit /= float64(cr.InstanceCount)
		}
		global.Clusters = append(global.Clusters, *cr)
		total += cr.InstanceCount
	}
	if total > 0 {
		global.AvgCacheHitRatio /= float64(total)
	}

	return global
}

func (a *Aggregator) scrapeAll(ctx context.Context) {
	logger := log.FromContext(ctx).WithName("metrics-aggregator")
	instances := a.Registry.List("")

	// Mark instances that are no longer registered as stale.
	a.mu.Lock()
	activeKeys := make(map[string]bool, len(instances))
	for _, inst := range instances {
		activeKeys[inst.Cluster+"/"+inst.Name] = true
	}
	for k, m := range a.byInst {
		if !activeKeys[k] {
			m.Stale = true
		}
	}
	a.mu.Unlock()

	for _, inst := range instances {
		if err := a.scrapeInstance(ctx, inst); err != nil {
			logger.V(1).Info("scrape failed", "instance", inst.Name, "cluster", inst.Cluster, "error", err)
		}
	}
}

func (a *Aggregator) scrapeInstance(ctx context.Context, inst *discovery.Instance) error {
	url := inst.AdminURL + "/metrics"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}

	resp, err := a.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1MB limit
	if err != nil {
		return err
	}

	cur := parsePrometheusCounters(string(body))
	key := inst.Cluster + "/" + inst.Name
	now := time.Now()

	a.mu.Lock()
	defer a.mu.Unlock()

	prev, hasPrev := a.prevCounters[key]
	prevT, hasPrevT := a.prevTime[key]

	m := &InstanceMetrics{
		Instance:   inst.Name,
		Cluster:    inst.Cluster,
		LastScrape: now,
		Stale:      false,
	}

	if hasPrev && hasPrevT {
		dt := now.Sub(prevT).Seconds()
		if dt > 0 {
			m.DecisionRate = (cur.decisions - prev.decisions) / dt
			m.DenyRate = (cur.denies - prev.denies) / dt
			m.ErrorRate = (cur.errors - prev.errors) / dt
		}
	}

	// Cache hit ratio from current counters.
	if cur.cacheTotal > 0 {
		m.CacheHitRatio = cur.cacheHits / cur.cacheTotal
	}

	// lwauth_decision_latency_seconds is a HistogramVec — it exposes
	// `_bucket{le="..."}` cumulative series rather than summary
	// `{quantile="..."}` lines, so compute P50/P99 from the bucket
	// counts aggregated across all label combinations.
	m.LatencyP50Ms = parseHistogramQuantile(string(body), "lwauth_decision_latency_seconds", 0.5) * 1000
	m.LatencyP99Ms = parseHistogramQuantile(string(body), "lwauth_decision_latency_seconds", 0.99) * 1000

	a.byInst[key] = m
	a.prevCounters[key] = cur
	a.prevTime[key] = now

	return nil
}

// parsePrometheusCounters extracts counter values from Prometheus text
// format. lwauth_decisions_total{outcome,authorizer,tenant} is a
// CounterVec so each label combination appears as its own line — the
// totals are the sum across every series. Cache hits/misses are likewise
// summed across every registered cache name.
func parsePrometheusCounters(body string) *counters {
	c := &counters{}
	for _, line := range strings.Split(body, "\n") {
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		switch {
		case strings.HasPrefix(line, "lwauth_decisions_total"):
			// lwauth_decisions_total appears once per outcome+authorizer+tenant
			// label combination; all of them must be summed.
			c.decisions += parseMetricValue(line)
			switch extractLabel(line, "outcome") {
			case "deny":
				c.denies += parseMetricValue(line)
			case "error":
				c.errors += parseMetricValue(line)
			}
		case strings.HasPrefix(line, "lwauth_cache_hits_total"):
			c.cacheHits += parseMetricValue(line)
		case strings.HasPrefix(line, "lwauth_cache_misses_total"):
			c.cacheTotal += parseMetricValue(line)
		}
	}
	// There is no `lwauth_cache_requests_total` metric; total = hits +
	// misses models the full-request denominator.
	c.cacheTotal += c.cacheHits
	return c
}

// extractLabel reads the value of a single Prometheus label from a metric
// line, e.g. `lwauth_decisions_total{outcome="deny",tenant="acme"} 3`
// with `outcome` returns "deny". Returns "" if the label is absent.
func extractLabel(line, name string) string {
	marker := name + "=\""
	i := strings.Index(line, marker)
	if i < 0 {
		return ""
	}
	start := i + len(marker)
	j := strings.IndexByte(line[start:], '"')
	if j < 0 {
		return ""
	}
	return line[start : start+j]
}

func parseMetricValue(line string) float64 {
	parts := strings.Fields(line)
	if len(parts) < 2 {
		return 0
	}
	v, _ := strconv.ParseFloat(parts[len(parts)-1], 64)
	return v
}

// parseHistogramQuantile computes a per-instance aggregate quantile (0..1)
// from a Prometheus HistogramVec scrape body by summing the cumulative
// `_bucket{le="..."}` counts across every label combination, then
// finding the smallest bucket boundary whose cumulative count crosses the
// requested quantile of the total. Returns 0 if there are no samples.
//
// `+Inf` buckets are skipped as bucket candidates (they hold the total
// but are not a usable upper-bound value); the total count is taken from
// them. When the quantile falls above the highest finite bucket boundary,
// the highest finite boundary is returned — consistent with Prometheus'
// histogram_quantile behavior on histograms with finite +Inf only.
func parseHistogramQuantile(body, metric string, q float64) float64 {
	bucketPrefix := metric + "_bucket"
	leCounts := map[float64]float64{}
	infCount := 0.0
	for _, line := range strings.Split(body, "\n") {
		if !strings.HasPrefix(line, bucketPrefix) || strings.HasPrefix(line, bucketPrefix+"_") {
			continue
		}
		// Only finite `le` boundaries accumulate into leCounts; +Inf
		// holds the total count and is used as the denominator.
		le := extractLabel(line, "le")
		v := parseMetricValue(line)
		if le == "+Inf" {
			infCount += v
			continue
		}
		f, err := strconv.ParseFloat(le, 64)
		if err != nil {
			continue
		}
		leCounts[f] += v
	}
	total := infCount
	if total <= 0 {
		return 0
	}
	// Histogram `_bucket{le="..."}` counters are cumulative, so summing
	// them across label combinations yields the aggregated cumulative
	// count at each boundary — no extra accumulation is needed during
	// the boundary walk.
	boundaries := make([]float64, 0, len(leCounts))
	for le := range leCounts {
		boundaries = append(boundaries, le)
	}
	sort.Float64s(boundaries)
	var last float64
	for _, le := range boundaries {
		last = le
		if leCounts[le] >= q*total {
			return le
		}
	}
	return last
}
