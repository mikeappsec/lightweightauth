// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"testing"

	"github.com/mikeappsec/lightweightauth/internal/config"
	"github.com/mikeappsec/lightweightauth/pkg/ratelimit"
)

func TestCompliance_SOC2_FullyConfigured(t *testing.T) {
	prev := complianceRuntimeVerified
	complianceRuntimeVerified = false
	t.Cleanup(func() { complianceRuntimeVerified = prev })

	ac := &config.AuthConfig{
		Version: "v1.0.0",
		Identifiers: []config.ModuleSpec{
			{Name: "jwt", Type: "jwt", Config: map[string]any{"jwksRefreshInterval": "1h"}},
			{Name: "mtls", Type: "mtls"},
		},
		Authorizers: []config.ModuleSpec{
			{Name: "rbac", Type: "rbac"},
		},
		RateLimit:  &ratelimit.Spec{},
		Revocation: &config.RevocationSpec{Enabled: true, Backend: "valkey"},
		Secrets: &config.SecretsSpec{
			Backends: map[string]map[string]any{"vault": {"addr": "https://vault:8200"}},
		},
		Audit: &config.AuditSpec{
			Redaction: &config.RedactionSpec{
				Fields: []config.RedactionField{
					{Name: "subject", Action: config.RedactHash},
				},
			},
			DataResidency: &config.DataResidencySpec{Region: "eu"},
		},
	}

	report := evaluate(ac, soc2Framework, "test.yaml")

	if report.Framework != "SOC 2 Type II" {
		t.Fatalf("expected SOC 2 Type II, got %s", report.Framework)
	}
	if report.Summary.Fail != 0 {
		t.Fatalf("expected 0 failures, got %d", report.Summary.Fail)
		for _, c := range report.Controls {
			if c.Status == "fail" {
				t.Logf("  FAIL: %s %s — %s", c.ID, c.Title, c.Evidence)
			}
		}
	}
	if report.Summary.Pass == 0 {
		t.Fatal("expected at least some passes")
	}
}

func TestCompliance_SOC2_Minimal_HasFailures(t *testing.T) {
	prev := complianceRuntimeVerified
	complianceRuntimeVerified = false
	t.Cleanup(func() { complianceRuntimeVerified = prev })

	ac := &config.AuthConfig{} // empty config

	report := evaluate(ac, soc2Framework, "empty.yaml")

	if report.Summary.Fail == 0 {
		t.Fatal("expected failures for empty config")
	}
	// Specifically: no identifiers, no authorizers should fail.
	failIDs := map[string]bool{}
	for _, c := range report.Controls {
		if c.Status == "fail" {
			failIDs[c.ID] = true
		}
	}
	for _, id := range []string{"CC6.1", "CC6.2", "CC6.3"} {
		if !failIDs[id] {
			t.Errorf("expected %s to fail for empty config", id)
		}
	}
}

func TestCompliance_AllFrameworks(t *testing.T) {
	prev := complianceRuntimeVerified
	complianceRuntimeVerified = false
	t.Cleanup(func() { complianceRuntimeVerified = prev })

	ac := &config.AuthConfig{
		Identifiers: []config.ModuleSpec{{Name: "jwt", Type: "jwt"}},
		Authorizers: []config.ModuleSpec{{Name: "rbac", Type: "rbac"}},
	}

	for name, fw := range frameworks {
		t.Run(name, func(t *testing.T) {
			report := evaluate(ac, fw, "test.yaml")
			if report.Summary.Total == 0 {
				t.Fatal("expected at least one control")
			}
			if report.Summary.Total != report.Summary.Pass+report.Summary.Fail+report.Summary.Warn+report.Summary.Skip {
				t.Fatal("summary counts don't add up")
			}
		})
	}
}

func TestCompliance_JSONMarshal(t *testing.T) {
	prev := complianceRuntimeVerified
	complianceRuntimeVerified = false
	t.Cleanup(func() { complianceRuntimeVerified = prev })

	ac := &config.AuthConfig{
		Version:     "v2.0",
		Identifiers: []config.ModuleSpec{{Name: "apikey", Type: "apikey"}},
		Authorizers: []config.ModuleSpec{{Name: "opa", Type: "opa"}},
	}

	report := evaluate(ac, soc2Framework, "config.yaml")

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var parsed ComplianceReport
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if parsed.Framework != "SOC 2 Type II" {
		t.Fatalf("roundtrip: expected SOC 2 Type II, got %s", parsed.Framework)
	}
	if len(parsed.Controls) != len(report.Controls) {
		t.Fatalf("roundtrip: expected %d controls, got %d", len(report.Controls), len(parsed.Controls))
	}
}

func TestCompliance_DefaultAllow_Fails(t *testing.T) {
	prev := complianceRuntimeVerified
	complianceRuntimeVerified = false
	t.Cleanup(func() { complianceRuntimeVerified = prev })

	ac := &config.AuthConfig{
		Identifiers: []config.ModuleSpec{{Name: "jwt", Type: "jwt"}},
		Authorizers: []config.ModuleSpec{
			{Name: "permissive", Type: "rbac", Config: map[string]any{"defaultAllow": true}},
		},
	}

	report := evaluate(ac, soc2Framework, "test.yaml")

	// CC6.3 (Least privilege) should fail.
	for _, c := range report.Controls {
		if c.ID == "CC6.3" {
			if c.Status != "fail" {
				t.Fatalf("CC6.3 should fail when defaultAllow: true, got %s", c.Status)
			}
			return
		}
	}
	t.Fatal("CC6.3 not found in controls")
}

func TestCompliance_PIIRedaction_WarnWithoutRuntimeEvidence(t *testing.T) {
	prev := complianceRuntimeVerified
	complianceRuntimeVerified = false
	t.Cleanup(func() { complianceRuntimeVerified = prev })

	ac := &config.AuthConfig{
		Identifiers: []config.ModuleSpec{{Name: "jwt", Type: "jwt"}},
		Authorizers: []config.ModuleSpec{{Name: "rbac", Type: "rbac"}},
		Audit: &config.AuditSpec{
			Redaction: &config.RedactionSpec{
				Fields: []config.RedactionField{
					{Name: "subject", Action: config.RedactHash},
					{Name: "path", Action: config.RedactDrop},
				},
			},
		},
	}

	report := evaluate(ac, soc2Framework, "test.yaml")

	for _, c := range report.Controls {
		if c.ID == "CC9.1" {
			if c.Status != "warn" {
				t.Fatalf("CC9.1 should warn without runtime evidence, got %s: %s", c.Status, c.Evidence)
			}
			return
		}
	}
	t.Fatal("CC9.1 not found")
}

func TestCompliance_PIIRedaction_PassWithRuntimeEvidence(t *testing.T) {
	prev := complianceRuntimeVerified
	complianceRuntimeVerified = true
	t.Cleanup(func() { complianceRuntimeVerified = prev })

	ac := &config.AuthConfig{
		Identifiers: []config.ModuleSpec{{Name: "jwt", Type: "jwt"}},
		Authorizers: []config.ModuleSpec{{Name: "rbac", Type: "rbac"}},
		Audit: &config.AuditSpec{
			Redaction: &config.RedactionSpec{
				Fields: []config.RedactionField{
					{Name: "subject", Action: config.RedactHash},
					{Name: "path", Action: config.RedactDrop},
				},
			},
		},
	}

	report := evaluate(ac, soc2Framework, "test.yaml")

	for _, c := range report.Controls {
		if c.ID == "CC9.1" {
			if c.Status != "pass" {
				t.Fatalf("CC9.1 should pass with runtime evidence, got %s: %s", c.Status, c.Evidence)
			}
			return
		}
	}
	t.Fatal("CC9.1 not found")
}

func TestCompliance_RevocationEnabled_Pass(t *testing.T) {
	prev := complianceRuntimeVerified
	complianceRuntimeVerified = false
	t.Cleanup(func() { complianceRuntimeVerified = prev })

	ac := &config.AuthConfig{
		Identifiers: []config.ModuleSpec{{Name: "jwt", Type: "jwt"}},
		Authorizers: []config.ModuleSpec{{Name: "rbac", Type: "rbac"}},
		Revocation:  &config.RevocationSpec{Enabled: true, Backend: "memory"},
	}

	report := evaluate(ac, soc2Framework, "test.yaml")

	for _, c := range report.Controls {
		if c.ID == "CC6.8" {
			if c.Status != "pass" {
				t.Fatalf("CC6.8 should pass with revocation, got %s", c.Status)
			}
			return
		}
	}
	t.Fatal("CC6.8 not found")
}
