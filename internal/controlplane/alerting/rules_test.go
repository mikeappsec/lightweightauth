// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package alerting

import (
	"testing"
	"time"
)

func TestDefaultRuleCatalog_HasTenRules(t *testing.T) {
	t.Parallel()
	rules := DefaultRuleCatalog()
	if len(rules) != 10 {
		t.Fatalf("DefaultRuleCatalog returned %d rules, want 10", len(rules))
	}
	seen := map[string]bool{}
	for _, r := range rules {
		if seen[r.Name] {
			t.Errorf("duplicate rule %q", r.Name)
		}
		seen[r.Name] = true
		if !r.Enabled {
			t.Errorf("default rule %q must ship enabled", r.Name)
		}
		if !r.IsDefault {
			t.Errorf("default rule %q must set IsDefault", r.Name)
		}
		if r.For <= 0 {
			t.Errorf("rule %q missing for duration", r.Name)
		}
		if r.Window <= 0 {
			t.Errorf("rule %q missing window duration", r.Name)
		}
		if r.Severity != SeverityCritical && r.Severity != SeverityWarning && r.Severity != SeverityInfo {
			t.Errorf("rule %q has invalid severity %q", r.Name, r.Severity)
		}
	}
}

func TestDefaultRuleCatalog_SeverityAllocation(t *testing.T) {
	t.Parallel()
	for _, r := range DefaultRuleCatalog() {
		switch r.Name {
		case "pipeline_error_rate", "pipeline_p99_latency",
			"identifier_upstream_error", "authorizer_error":
			if r.Severity != SeverityCritical {
				t.Errorf("rule %q expected critical, got %s", r.Name, r.Severity)
			}
		case "deny_rate_spike", "rate_limit_denial", "revocation_spike",
			"cache_stale_served", "shadow_disagreement", "canary_disagreement":
			if r.Severity != SeverityWarning {
				t.Errorf("rule %q expected warning, got %s", r.Name, r.Severity)
			}
		default:
			t.Errorf("unrecognized default rule %q — update the test catalog", r.Name)
		}
	}
}

func TestRule_Breached(t *testing.T) {
	t.Parallel()
	r := Rule{Comparator: ComparatorGreaterThan, Threshold: 0.05}
	if !r.Breached(0.06) {
		t.Errorf("0.06 > 0.05 should breach")
	}
	if r.Breached(0.05) {
		t.Errorf("0.05 > 0.05 should NOT breach (strict)")
	}
	if r.Breached(0.04) {
		t.Errorf("0.04 > 0.05 should not breach")
	}

	rEQ := Rule{Comparator: ComparatorGreaterThanEqual, Threshold: 0.05}
	if !rEQ.Breached(0.05) {
		t.Errorf("0.05 >= 0.05 should breach")
	}

	rLT := Rule{Comparator: ComparatorLessThan, Threshold: 0.05}
	if !rLT.Breached(0.04) {
		t.Errorf("0.04 < 0.05 should breach")
	}
	if rLT.Breached(0.05) {
		t.Errorf("0.05 < 0.05 should not breach")
	}

	rLE := Rule{Comparator: ComparatorLessThanEqual, Threshold: 0.05}
	if !rLE.Breached(0.05) {
		t.Errorf("0.05 <= 0.05 should breach")
	}
}

func TestMergeRules_OverrideUpdates(t *testing.T) {
	t.Parallel()
	defaults := []Rule{{Name: "r1", Severity: SeverityWarning, Threshold: 0.05, Enabled: true, IsDefault: true}}
	overrides := []Rule{{Name: "r1", Severity: SeverityCritical, Threshold: 0.1, Enabled: true}}
	merged := MergeRules(defaults, overrides)
	if len(merged) != 1 {
		t.Fatalf("merge returned %d rules, want 1", len(merged))
	}
	if merged[0].Severity != SeverityCritical {
		t.Errorf("override severity not applied: %+v", merged[0])
	}
	if merged[0].Threshold != 0.1 {
		t.Errorf("override threshold not applied: %+v", merged[0])
	}
	if !merged[0].IsDefault {
		t.Errorf("IsDefault should be preserved on override merge")
	}
}

func TestMergeRules_DisableDefault(t *testing.T) {
	t.Parallel()
	defaults := []Rule{{Name: "can", Severity: SeverityWarning, Threshold: 1, Enabled: true, IsDefault: true}}
	overrides := []Rule{{Name: "can", Enabled: false}}
	merged := MergeRules(defaults, overrides)
	if len(merged) != 1 {
		t.Fatalf("merge returned %d rules, want 1", len(merged))
	}
	if merged[0].Enabled {
		t.Errorf("override should disable default")
	}
}

func TestMergeRules_NewCustomRule(t *testing.T) {
	t.Parallel()
	defaults := []Rule{{Name: "r1", Severity: SeverityWarning, Threshold: 1, Enabled: true, IsDefault: true}}
	overrides := []Rule{{
		Name: "custom", Severity: SeverityInfo, Source: SourceLoki,
		Query: "rate({}[5m])", Comparator: ComparatorGreaterThan,
		Threshold: 100, For: time.Minute, Window: 5 * time.Minute,
		Enabled: true,
	}}
	merged := MergeRules(defaults, overrides)
	if len(merged) != 2 {
		t.Fatalf("merge returned %d rules, want 2", len(merged))
	}
	var custom *Rule
	for i := range merged {
		if merged[i].Name == "custom" {
			custom = &merged[i]
		}
	}
	if custom == nil {
		t.Fatal("custom rule not merged")
	}
	if custom.IsDefault {
		t.Errorf("custom rule should not be marked IsDefault")
	}
}

func TestMergeRules_SortStable(t *testing.T) {
	t.Parallel()
	defaults := []Rule{{Name: "zeta", Enabled: true, IsDefault: true}, {Name: "alpha", Enabled: true, IsDefault: true}}
	overrides := []Rule{{Name: "mid", Enabled: true}}
	merged := MergeRules(defaults, overrides)
	if len(merged) != 3 {
		t.Fatalf("expected 3 rules, got %d", len(merged))
	}
	for i := 1; i < len(merged); i++ {
		if merged[i-1].Name > merged[i].Name {
			t.Errorf("rules not sorted by name: %q before %q", merged[i-1].Name, merged[i].Name)
		}
	}
}