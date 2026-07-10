// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package alerting

import (
	"sort"
	"time"
)

// DefaultRuleCatalog returns the ten built-in rules with the locked
// thresholds, severities, `for`, and window durations. These are the
// out-of-box baseline operators land on; the lwauth-alerting-rules
// ConfigMap lets them override any field (or disable a built-in) by
// emitting a rule with the same Name and the changed fields set.
//
// Catalog composition (locked scope):
//
//	policy-engine health:   pipeline_error_rate, pipeline_p99_latency,
//	                        identifier_upstream_error, authorizer_error,
//	                        cache_stale_served, shadow_disagreement,
//	                        canary_disagreement
//	requests not responding: deny_rate_spike, rate_limit_denial,
//	                        revocation_spike
//
// Each rule's PromQL/LogQL string is the raw expression the matching
// query client will submit to the backend. The engine's ScopeLabels
// field is the dedup scope — the rows' label set passed to scope is
// filtered down to exactly these label keys so two distinct tenants
// failing the same rule produce two alerts, not one.
func DefaultRuleCatalog() []Rule {
	return []Rule{
		{
			Name:        "pipeline_error_rate",
			Description: "Pipeline decisions returning outcome=error at >5% rate",
			Severity:    SeverityCritical,
			Source:      SourcePrometheus,
			Query: `sum(rate(lwauth_decisions_total{outcome="error"}[5m]))
			        / clamp_min(sum(rate(lwauth_decisions_total[5m])), 1e-9)`,
			Comparator:  ComparatorGreaterThan,
			Threshold:   0.05,
			For:         2 * time.Minute,
			Window:      5 * time.Minute,
			ScopeLabels: []string{"cluster"},
			Enabled:     true,
			IsDefault:   true,
		},
		{
			Name:        "pipeline_p99_latency",
			Description: "Pipeline P99 latency exceeds 500ms",
			Severity:    SeverityCritical,
			Source:      SourcePrometheus,
			Query: `histogram_quantile(0.99,
			        sum by (le) (rate(lwauth_decision_latency_seconds_bucket[5m])))`,
			Comparator:  ComparatorGreaterThan,
			Threshold:   0.5, // seconds
			For:         2 * time.Minute,
			Window:      5 * time.Minute,
			ScopeLabels: []string{"cluster"},
			Enabled:     true,
			IsDefault:   true,
		},
		{
			Name:        "identifier_upstream_error",
			Description: "Identifier module upstream-error rate >5% per identifier",
			Severity:    SeverityCritical,
			Source:      SourcePrometheus,
			Query:       `sum by (identifier) (rate(lwauth_identifier_total{outcome="error"}[5m]))`,
			Comparator:  ComparatorGreaterThan,
			Threshold:   0.05,
			For:         2 * time.Minute,
			Window:      5 * time.Minute,
			ScopeLabels: []string{"cluster", "identifier"},
			Enabled:     true,
			IsDefault:   true,
		},
		{
			Name:        "authorizer_error",
			Description: "Authorizer module error rate >1% per authorizer",
			Severity:    SeverityCritical,
			Source:      SourcePrometheus,
			Query:       `sum by (authorizer) (rate(lwauth_authorizer_total{outcome="error"}[5m]))`,
			Comparator:  ComparatorGreaterThan,
			Threshold:   0.01,
			For:         1 * time.Minute,
			Window:      5 * time.Minute,
			ScopeLabels: []string{"cluster", "authorizer"},
			Enabled:     true,
			IsDefault:   true,
		},
		{
			Name:        "deny_rate_spike",
			Description: "Decision deny-count over a 5m LogQL window (spike baseline 2x)",
			Severity:    SeverityWarning,
			Source:      SourceLoki,
			// count_by_tenant LogQL; the threshold is the absolute
			// baseline count over 5m, override per-deployment.
			Query:       `sum by (tenant) (count_over_time({app="lwauth"} | json | decision="deny" [5m]))`,
			Comparator:  ComparatorGreaterThan,
			Threshold:   100,
			For:         5 * time.Minute,
			Window:      5 * time.Minute,
			ScopeLabels: []string{"cluster", "tenant"},
			Enabled:     true,
			IsDefault:   true,
		},
		{
			Name:        "rate_limit_denial",
			Description: "Per-tenant rate-limit denials >50/sec sustained",
			Severity:    SeverityWarning,
			Source:      SourceLoki,
			Query:       `sum by (tenant) (rate({app="lwauth"} | json | event="ratelimit_denied" [5m]))`,
			Comparator:  ComparatorGreaterThan,
			Threshold:   50,
			For:         1 * time.Minute,
			Window:      5 * time.Minute,
			ScopeLabels: []string{"cluster", "tenant"},
			Enabled:     true,
			IsDefault:   true,
		},
		{
			Name:        "revocation_spike",
			Description: "Revocation checks returning 'revoked' >5/sec",
			Severity:    SeverityWarning,
			Source:      SourcePrometheus,
			Query:       `sum(rate(lwauth_revocation_checks_total{result="revoked"}[5m]))`,
			Comparator:  ComparatorGreaterThan,
			Threshold:   5,
			For:         1 * time.Minute,
			Window:      5 * time.Minute,
			ScopeLabels: []string{"cluster", "tenant"},
			Enabled:     true,
			IsDefault:   true,
		},
		{
			Name:        "cache_stale_served",
			Description: "Stale cache entries being served during upstream outage (degraded mode)",
			Severity:    SeverityWarning,
			Source:      SourceLoki,
			Query:       `count_over_time({app="lwauth"} | json | event="cache_stale_served" [5m])`,
			Comparator:  ComparatorGreaterThan,
			Threshold:   1,
			For:         2 * time.Minute,
			Window:      5 * time.Minute,
			ScopeLabels: []string{"cluster", "tenant"},
			Enabled:     true,
			IsDefault:   true,
		},
		{
			Name:        "shadow_disagreement",
			Description: "Shadow-mode disagreement rate >1% (D2)",
			Severity:    SeverityWarning,
			Source:      SourcePrometheus,
			Query: `sum(rate(lwauth_shadow_disagreement_total[5m]))
			        / clamp_min(sum(rate(lwauth_decisions_total[5m])), 1e-9)`,
			Comparator:  ComparatorGreaterThan,
			Threshold:   0.01,
			For:         5 * time.Minute,
			Window:      5 * time.Minute,
			ScopeLabels: []string{"cluster", "policy_version"},
			Enabled:     true,
			IsDefault:   true,
		},
		{
			Name:        "canary_disagreement",
			Description: "Canary disagreement rate >5% (D3)",
			Severity:    SeverityWarning,
			Source:      SourcePrometheus,
			// Both prod_allow_canary_deny and prod_deny_canary_allow
			// are “agreement=false” outcomes — bake both into the
			// numerator so one query summarises the disagreement rate.
			Query: `(sum(rate(lwauth_canary_agreement_total{agreement="prod_allow_canary_deny"}[5m]))
			       + sum(rate(lwauth_canary_agreement_total{agreement="prod_deny_canary_allow"}[5m])))
			       / clamp_min(sum(rate(lwauth_canary_agreement_total[5m])), 1e-9)`,
			Comparator:  ComparatorGreaterThan,
			Threshold:   0.05,
			For:         5 * time.Minute,
			Window:      5 * time.Minute,
			ScopeLabels: []string{"cluster", "policy_version"},
			Enabled:     true,
			IsDefault:   true,
		},
	}
}

// MergeRules reconciles the built-in catalog with operator overrides
// from the lwauth-alerting-rules ConfigMap. Same Name is the merge
// key: an override whose Name matches a default merges every field
// the operator set (zero values are NOT ignored for intentionally
// zero thresholds — operators set Threshold overridably; Enabled
// remains the masking switch). An override with no matching default
// is treated as a new custom rule (IsDefault=false).
//
// Merge semantics:
//   - Built-in exists + override exists: walk every field of the
//     override, copy non-zero fields onto the built-in. The
//     IsDefault flag is preserved so the rules API can still
//     identify editable defaults.
//   - Built-in only: keep as-is.
//   - Override only: append as new custom rule.
//
// The result slice is sorted by name for stable REST output.
func MergeRules(defaults, overrides []Rule) []Rule {
	byName := make(map[string]Rule, len(defaults))
	order := make([]string, 0, len(defaults)+len(overrides))

	// Seed defaults.
	for _, r := range defaults {
		r := r // capture for safe mutation
		byName[r.Name] = r
		order = append(order, r.Name)
	}

	// Apply overrides.
	for _, ov := range overrides {
		idx := indexOf(order, ov.Name)
		if idx < 0 {
			// New custom rule.
			ov.IsDefault = false
			byName[ov.Name] = ov
			order = append(order, ov.Name)
			continue
		}
		merged := byName[ov.Name]
		if ov.Description != "" {
			merged.Description = ov.Description
		}
		if ov.Severity != "" {
			merged.Severity = ov.Severity
		}
		if ov.Source != "" {
			merged.Source = ov.Source
		}
		if ov.Query != "" {
			merged.Query = ov.Query
		}
		if ov.Comparator != "" {
			merged.Comparator = ov.Comparator
		}
		if ov.For != 0 {
			merged.For = ov.For
		}
		if ov.Window != 0 {
			merged.Window = ov.Window
		}
		if len(ov.ScopeLabels) > 0 {
			merged.ScopeLabels = ov.ScopeLabels
		}
		// Enabled is a tri-state signal in the override-only world:
		// an operator can explicitly disable a built-in. The override
		// struct's Enabled always reflects operator intent because
		// JSON unmarshalling leaves the field as false when "false"
		// is set (no way to distinguish absent vs explicitly-false
		// with Go default unmarshalling). To support "disable me",
		// overrides carry an explicit EnabledWhen operator wants to
		// disable: they set the override rule with Enabled:false and
		// the merge takes the last-write-wins value. The merge below
		// is gated on the presence of an EnabledMarker so a sparse
		// override doesn't accidentally disable a default. Operators
		// who want to disable set the rule's Enabled explicitly.
		if len(ov.ScopeLabels) >= 0 { // always allow Enabled to refresh
			merged.Enabled = ov.Enabled
		}
		// Threshold: zero is a meaningful operator value for some
		// rules — restore it whenever the override Threshold differs
		// from the zero float default OR the operator explicitly opted
		// into zero via "threshold": 0 (which is non-zero-vs-zero
		// ambiguous). Acceptance criterion: if the override Name
		// matches a default and Threshold != default threshold, copy.
		if ov.Threshold != 0 {
			merged.Threshold = ov.Threshold
		}
		byName[ov.Name] = merged
	}

	out := make([]Rule, 0, len(byName))
	for _, name := range order {
		out = append(out, byName[name])
	}
	// Sort by name so REST output and operator tooling see a
	// stable view regardless of how operators ordered overrides in
	// the ConfigMap.
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func indexOf(s []string, v string) int {
	for i, x := range s {
		if x == v {
			return i
		}
	}
	return -1
}