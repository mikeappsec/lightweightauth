// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package alerting

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/mikeappsec/lightweightauth/pkg/observability/audit"
)

// Enricher attaches ReasonPayload to a freshly-opened or re-opened
// alert so the triage UI answers "why are requests not responding"
// at a glance without the operator leaving the panel.
//
// Sources:
//   - the data-plane audit.RecentRing (via the DecisionCollector's
//     recent-scrape cache on the control-plane aggregator). The
//     ring's events are already subject-hashed, so no raw PII ever
//     crosses the enrichment boundary — the "metadata only" redaction
//     contract is enforced at the data plane, not here.
//   - the open-alerts registry on this engine (siblings in the same
//     scope fire the correlated hint).
//
// The Enricher is read-only against every input path; it never
// mutates the Alert in place (the engine copies alert value before
// invoking the enricher so the snapshot passed to sinks/WS already
// carries the Reason).
type Enricher struct {
	// RingSnapshot returns recent redacted audit events for the
	// given scope dimension filters. The engine wires this against
	// the in-memory DecisionCollector cache, optionally filtering on
	// tenant/verdict. limit <= 0 returns every match.
	RingSnapshot func(scope Scope, limit int) []audit.Event

	// Headlines lets the engine per-rule template a readable sentence.
	// Not in the lock scope but lightweight and rolls back the
	// "metadata only" triage answer at the panel level.
}

// NewEnricher constructs an enricher against a ring-snapshot callback.
// A nil callback degrades to no-op enrichment (the alert still fires,
// the Reason payload is left empty so the UI is honest about the
// missing context).
func NewEnricher(ringSnapshot func(scope Scope, limit int) []audit.Event) *Enricher {
	return &Enricher{RingSnapshot: ringSnapshot}
}

// BuildReason constructs the ReasonPayload for one alert. The engine
// passes the full alert (scope + rule + severity) and the snapshot
// of open siblings so correlated alerts surface in the panel.
func (en *Enricher) BuildReason(alert Alert, siblings []Alert) *ReasonPayload {
	// Correlated hint is always available — it reads from the
	// engine's in-memory open-alerts registry, not the ring.
	corr := correlated(alert, siblings)
	if en == nil || en.RingSnapshot == nil {
		return &ReasonPayload{
			Headline:   fallbackHeadline(alert),
			Correlated: corr,
		}
	}
	// Pull up to 32 recent events so the top-contributors aggregation
	// has enough signal; the recentFailures preview is capped at 5.
	events := en.RingSnapshot(alert.Scope, 32)
	if len(events) == 0 {
		return &ReasonPayload{
			Headline:   fallbackHeadline(alert),
			Correlated: corr,
		}
	}

	return &ReasonPayload{
		Headline:        headlineFor(alert, events),
		TopContributors: topContributors(events),
		RecentFailures:  recentFailures(events, 5),
		Correlated:      corr,
	}
}

// fallbackHeadline names the alert readable-verbatim; used when the
// recent-decisions ring is unavailable (degraded-UI fallback).
func fallbackHeadline(alert Alert) string {
	return fmt.Sprintf("Alert %q firing (severity=%s); recent-decisions ring unavailable — UI shows rule-scope metadata only.",
		alert.Rule, alert.Severity)
}

// headlineFor produces a one-line human sentence that reads "what
// specifically broke". The shape per rule is templated because
// operators use the rule name as a canonical identifier: each name
// maps to one phrasing pattern.
func headlineFor(a Alert, events []audit.Event) string {
	// Count outcomes against the message body: honours the metadata
	// only contract — no raw subject/path are leaked even if the
	// events happen to round-trip through bound loggers.
	deny := 0
	err := 0
	for _, e := range events {
		switch e.Decision {
		case "deny":
			deny++
		case "error":
			err++
		}
	}
	cluster := a.Scope["cluster"]
	tenant := a.Scope["tenant"]
	identifier := a.Scope["identifier"]
	authorizer := a.Scope["authorizer"]
	policy := a.Scope["policy_version"]

	var b strings.Builder
	switch a.Rule {
	case "identifier_upstream_error":
		fmt.Fprintf(&b, "Identifier %q is returning upstream errors at %.1f%% — top failing host: ", identifier, a.Metric.Value*100)
	case "authorizer_error":
		fmt.Fprintf(&b, "Authorizer %q is returning errors at %.1f%% — top failing host: ", authorizer, a.Metric.Value*100)
	case "pipeline_p99_latency":
		fmt.Fprintf(&b, "Pipeline P99 latency at %.0fms (cluster %s) — top slow paths: ", a.Metric.Value*1000, cluster)
	case "pipeline_error_rate":
		fmt.Fprintf(&b, "Pipeline returning errors at %.1f%% — looks like an upstream outage or misconfig", a.Metric.Value*100)
	case "deny_rate_spike":
		fmt.Fprintf(&b, "Deny volume spiking for tenant %q (cluster %s): %d denials in last ring window", tenant, cluster, deny)
	case "rate_limit_denial":
		fmt.Fprintf(&b, "Tenant %q being rate-limited at %.0f/s — likely a runaway client or a misconfigured budget", tenant, a.Metric.Value)
	case "revocation_spike":
		fmt.Fprintf(&b, "Revocation churn: %.1f revocations/s in cluster %s (possible mass logout)", a.Metric.Value, cluster)
	case "cache_stale_served":
		fmt.Fprintf(&b, "Data plane serving stale cache decisions in cluster %s — backend outage", cluster)
	case "shadow_disagreement":
		fmt.Fprintf(&b, "Shadow policy %q disagrees with production at %.1f%% — do not promote", policy, a.Metric.Value*100)
	case "canary_disagreement":
		fmt.Fprintf(&b, "Canary policy %q diverging from production at %.1f%% — do not promote", policy, a.Metric.Value*100)
	default:
		fmt.Fprintf(&b, "Alert %q firing in cluster %s (value=%.2f, threshold=%.2f)", a.Rule, cluster, a.Metric.Value, a.Metric.Threshold)
	}
	return b.String()
}

// topContributors aggregates the recent-event set by the dimension
// canonically relevant to the alert's rule (e.g. identifier rule
// buckets by `identity_source`; authorizer rule by `authorizer`).
// Returns up to 3 contributors ordered by share descending.
func topContributors(events []audit.Event) []ReasonContributor {
	counts := map[string]map[string]int{}
	dimensionFor := func(e audit.Event) (string, string) {
		switch {
		case e.IdentitySource != "":
			return "identity_source", e.IdentitySource
		case e.Authorizer != "":
			return "authorizer", e.Authorizer
		case e.Tenant != "":
			return "tenant", e.Tenant
		case e.Path != "":
			return "path", e.Path
		}
		return "", ""
	}
	for _, e := range events {
		dim, val := dimensionFor(e)
		if dim == "" {
			continue
		}
		if counts[dim] == nil {
			counts[dim] = map[string]int{}
		}
		counts[dim][val]++
	}
	// Flatten to one dimension-consistent list (identity_source is
	// the most useful triage dimension, then authorizer, then tenant)
	// ranked by per-value counts.
	var out []ReasonContributor
	for _, dim := range []string{"identity_source", "authorizer", "tenant", "path"} {
		buckets := counts[dim]
		if len(buckets) == 0 {
			continue
		}
		type kv struct {
			k string
			v int
		}
		var pairs []kv
		for k, v := range buckets {
			pairs = append(pairs, kv{k, v})
		}
		sort.Slice(pairs, func(i, j int) bool { return pairs[i].v > pairs[j].v })
		total := 0
		for _, p := range pairs {
			total += p.v
		}
		for i, p := range pairs {
			if i >= 3 {
				break
			}
			out = append(out, ReasonContributor{
				Dimension: dim,
				Value:     p.k,
				Share:     float64(p.v) / float64(total),
			})
		}
		// First dimension with data is sufficient for the panel —
		// avoids cluttering the reason with low-signal buckets.
		if len(out) > 0 {
			break
		}
	}
	return out
}

// recentFailures returns up to limit recent-denial rows ordered
// newest-first. Subjects are already hashed by the data plane ring,
// so the row carries a field literally named "subject_hash" — per the
// locked metadata-only exposure contract.
func recentFailures(events []audit.Event, limit int) []ReasonFailure {
	if limit <= 0 {
		return nil
	}
	// Copy + sort newest first.
	copied := make([]audit.Event, 0, len(events))
	for _, e := range events {
		if e.Decision == "deny" || e.Decision == "error" {
			copied = append(copied, e)
		}
	}
	sort.Slice(copied, func(i, j int) bool { return copied[i].Timestamp.After(copied[j].Timestamp) })
	out := make([]ReasonFailure, 0, limit)
	for i, e := range copied {
		if i >= limit {
			break
		}
		out = append(out, ReasonFailure{
			Timestamp:   e.Timestamp,
			Method:      e.Method,
			Path:        e.Path,
			SubjectHash: e.Subject,
			Reason:      e.DenyReason,
			Tenant:      e.Tenant,
		})
	}
	return out
}

// correlated surfaces sibling open alerts on the same scope. Useful
// for chains like identifier_upstream_error present-symptom-matching
// pipeline_p99_latency (the operator can see both at once).
func correlated(a Alert, siblings []Alert) []ReasonCorrelated {
	var out []ReasonCorrelated
	seen := map[string]bool{a.Rule: true}
	for _, sib := range siblings {
		if sib.Rule == a.Rule {
			continue
		}
		if seen[sib.Rule] {
			continue
		}
		// Same scope cluster is enough — sibling rule still matches
		// if cluster + policy_version align even when tenant differs.
		if sib.Scope["cluster"] != a.Scope["cluster"] {
			continue
		}
		seen[sib.Rule] = true
		note := ""
		if sib.Severity == SeverityCritical {
			note = "presenting symptom"
		}
		val := ""
		if sib.Metric != nil {
			val = fmt.Sprintf("%.2f", sib.Metric.Value)
		}
		out = append(out, ReasonCorrelated{Rule: sib.Rule, Value: val, Note: note})
		if len(out) >= 5 {
			break
		}
	}
	return out
}

// ListSiblings returns the open-alerts on the same cluster scope as
// the input alert so the enricher can identify correlated signals.
// Unique to enrich.go to keep engine.go's surface minimal.
func (e *Engine) ListSiblings(target Alert) []Alert {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]Alert, 0, len(e.opens))
	for _, a := range e.opens {
		if a.ID == target.ID {
			continue
		}
		// Same cluster OR same tenant pair is enough; exact-scope
		// would erase the cross-tenant identifier error overlap (two
		// tenants whose identifier is the same IdP).
		if a.Scope["cluster"] == target.Scope["cluster"] {
			out = append(out, *a)
		}
	}
	return out
}

// _ is a compile-time guard against unused imports dropping during
// refactor passes. context/time are imported because they're needed
// for the public Reach interface contract in future increments even
// though the v1 implementation doesn't need ctx plumbing for the
// ring pull (the ring snapshot is sync).
var _ = context.Background
var _ = time.Second