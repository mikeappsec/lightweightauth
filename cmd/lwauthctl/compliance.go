// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/mikeappsec/lightweightauth/internal/config"
)

var complianceRuntimeVerified bool

// compliance implements `lwauthctl compliance --config FILE --framework NAME`.
// It inspects an AuthConfig YAML offline and emits a JSON compliance
// evidence report against a well-known framework control catalogue.
func compliance(args []string) {
	fs := flag.NewFlagSet("compliance", flag.ExitOnError)
	cfgPath := fs.String("config", "", "path to AuthConfig YAML")
	framework := fs.String("framework", "", "compliance framework: soc2, iso27001, pci-dss, hipaa, fedramp")
	outPath := fs.String("out", "", "output file (default: stdout)")
	runtimeVerified := fs.Bool("runtime-verified", false, "assert runtime verification evidence exists for audit/privacy controls")
	_ = fs.Parse(args)

	if *cfgPath == "" || *framework == "" {
		fmt.Fprintln(os.Stderr, "usage: lwauthctl compliance --config FILE --framework {soc2|iso27001|pci-dss|hipaa|fedramp}")
		os.Exit(2)
	}

	fw, ok := frameworks[strings.ToLower(*framework)]
	if !ok {
		fmt.Fprintf(os.Stderr, "unknown framework %q; supported: soc2, iso27001, pci-dss, hipaa, fedramp\n", *framework)
		os.Exit(2)
	}

	ac, err := config.LoadFile(*cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "load:", err)
		os.Exit(1)
	}

	complianceRuntimeVerified = *runtimeVerified

	report := evaluate(ac, fw, *cfgPath)

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		fmt.Fprintln(os.Stderr, "marshal:", err)
		os.Exit(1)
	}

	if *outPath != "" {
		if err := validateOutPath(*outPath); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		if err := os.WriteFile(*outPath, data, 0o644); err != nil {
			fmt.Fprintln(os.Stderr, "write:", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "wrote %s report to %s\n", report.Framework, *outPath)
	} else {
		fmt.Println(string(data))
	}

	if report.Summary.Fail > 0 {
		os.Exit(1)
	}
}

// --- Report types ----------------------------------------------------------

// ComplianceReport is the top-level JSON output of the compliance command.
type ComplianceReport struct {
	// GeneratedAt is the RFC 3339 timestamp of report generation.
	GeneratedAt string `json:"generated_at"`
	// Framework is the compliance framework name.
	Framework string `json:"framework"`
	// FrameworkVersion is the edition/year of the framework.
	FrameworkVersion string `json:"framework_version"`
	// ConfigFile is the path to the AuthConfig that was evaluated.
	ConfigFile string `json:"config_file"`
	// PolicyVersion is the operator-set spec.version tag (if any).
	PolicyVersion string `json:"policy_version,omitempty"`
	// Summary counts pass/fail/warn/skip.
	Summary ReportSummary `json:"summary"`
	// Controls lists every evaluated control with evidence.
	Controls []ControlResult `json:"controls"`
}

// ReportSummary aggregates control outcomes.
type ReportSummary struct {
	Total int `json:"total"`
	Pass  int `json:"pass"`
	Fail  int `json:"fail"`
	Warn  int `json:"warn"`
	Skip  int `json:"skip"`
}

// ControlResult is one evaluated control.
type ControlResult struct {
	// ID is the framework-specific control identifier (e.g. "CC6.1").
	ID string `json:"id"`
	// Title is a short human description.
	Title string `json:"title"`
	// Status is "pass", "fail", "warn", or "skip".
	Status string `json:"status"`
	// Evidence describes what was found in the config.
	Evidence string `json:"evidence"`
}

// --- Frameworks & controls ------------------------------------------------

// controlCheck is a function that inspects an AuthConfig and returns
// a status and evidence string.
type controlCheck func(ac *config.AuthConfig) (status, evidence string)

// frameworkDef describes a compliance framework and its control checks.
type frameworkDef struct {
	Name     string
	Version  string
	Controls []controlDef
}

type controlDef struct {
	ID    string
	Title string
	Check controlCheck
}

var frameworks = map[string]frameworkDef{
	"soc2":     soc2Framework,
	"iso27001": iso27001Framework,
	"pci-dss":  pciDSSFramework,
	"hipaa":    hipaaFramework,
	"fedramp":  fedrampFramework,
}

// --- SOC 2 ----------------------------------------------------------------

var soc2Framework = frameworkDef{
	Name:    "SOC 2 Type II",
	Version: "2017",
	Controls: []controlDef{
		{"CC6.1", "Logical access controls", checkIdentifiersExist},
		{"CC6.2", "Access provisioning per policy", checkAuthorizersExist},
		{"CC6.3", "Least privilege enforcement", checkAuthorizerNotDefaultAllow},
		{"CC6.6", "Boundary protection", checkRateLimitEnabled},
		{"CC6.7", "Encryption in transit", checkTLSOrMTLS},
		{"CC6.8", "Credential revocation", checkRevocationEnabled},
		{"CC7.1", "Security monitoring", checkAuditConfigured},
		{"CC7.2", "Anomaly detection (audit trail)", checkAuditRetention},
		{"CC8.1", "Change management (versioned policy)", checkPolicyVersionSet},
		{"CC9.1", "Risk mitigation (PII redaction)", checkPIIRedaction},
	},
}

// --- ISO 27001 ------------------------------------------------------------

var iso27001Framework = frameworkDef{
	Name:    "ISO/IEC 27001",
	Version: "2022",
	Controls: []controlDef{
		{"A.5.15", "Access control", checkIdentifiersExist},
		{"A.5.16", "Identity management", checkMultipleIdentifiers},
		{"A.5.17", "Authentication information", checkSecretRefUsed},
		{"A.5.18", "Access rights (authorization)", checkAuthorizersExist},
		{"A.5.23", "Cloud services access", checkRateLimitEnabled},
		{"A.5.33", "Protection of records", checkAuditConfigured},
		{"A.8.2", "Privileged access rights", checkAuthorizerNotDefaultAllow},
		{"A.8.3", "Information access restriction", checkCacheEnabled},
		{"A.8.5", "Secure authentication", checkTLSOrMTLS},
		{"A.8.24", "Cryptography (key rotation)", checkKeyRotation},
	},
}

// --- PCI DSS 4.0 ----------------------------------------------------------

var pciDSSFramework = frameworkDef{
	Name:    "PCI DSS",
	Version: "4.0",
	Controls: []controlDef{
		{"7.2.1", "Access control system", checkIdentifiersExist},
		{"7.2.2", "Assignment of access per job function", checkAuthorizersExist},
		{"7.2.4", "Review of user accounts", checkPolicyVersionSet},
		{"7.2.5", "Least privilege for application accounts", checkAuthorizerNotDefaultAllow},
		{"8.3.1", "Strong authentication for users", checkTLSOrMTLS},
		{"8.3.6", "Password/credential rotation", checkKeyRotation},
		{"8.6.1", "Credential revocation processes", checkRevocationEnabled},
		{"10.2.1", "Audit logs capture access events", checkAuditConfigured},
		{"10.3.1", "Audit log integrity", checkAuditRetention},
		{"11.5.1", "Intrusion detection (rate limiting)", checkRateLimitEnabled},
	},
}

// --- HIPAA ----------------------------------------------------------------

var hipaaFramework = frameworkDef{
	Name:    "HIPAA Security Rule",
	Version: "45 CFR 164",
	Controls: []controlDef{
		{"164.312(a)(1)", "Access control", checkIdentifiersExist},
		{"164.312(a)(2)(i)", "Unique user identification", checkMultipleIdentifiers},
		{"164.312(a)(2)(iv)", "Encryption (data in transit)", checkTLSOrMTLS},
		{"164.312(b)", "Audit controls", checkAuditConfigured},
		{"164.312(c)(1)", "Integrity controls", checkPolicyVersionSet},
		{"164.312(d)", "Person/entity authentication", checkAuthorizersExist},
		{"164.312(e)(1)", "Transmission security", checkSecretRefUsed},
		{"164.308(a)(4)", "Information access management", checkAuthorizerNotDefaultAllow},
		{"164.308(a)(5)", "Security awareness (PII)", checkPIIRedaction},
		{"164.316(b)(1)", "Documentation & record retention", checkAuditRetention},
	},
}

// --- FedRAMP --------------------------------------------------------------

var fedrampFramework = frameworkDef{
	Name:    "FedRAMP",
	Version: "Rev 5 (NIST 800-53)",
	Controls: []controlDef{
		{"AC-2", "Account management", checkIdentifiersExist},
		{"AC-3", "Access enforcement", checkAuthorizersExist},
		{"AC-6", "Least privilege", checkAuthorizerNotDefaultAllow},
		{"AU-2", "Audit events", checkAuditConfigured},
		{"AU-9", "Protection of audit information", checkPIIRedaction},
		{"AU-11", "Audit retention", checkAuditRetention},
		{"IA-2", "Identification and authentication", checkTLSOrMTLS},
		{"IA-5", "Authenticator management (rotation)", checkKeyRotation},
		{"SC-7", "Boundary protection (rate limiting)", checkRateLimitEnabled},
		{"SC-8", "Transmission confidentiality (secrets)", checkSecretRefUsed},
	},
}

// --- Control check functions -----------------------------------------------

func checkIdentifiersExist(ac *config.AuthConfig) (string, string) {
	if len(ac.Identifiers) == 0 {
		return "fail", "no identifiers configured — unauthenticated access"
	}
	names := make([]string, len(ac.Identifiers))
	for i, id := range ac.Identifiers {
		names[i] = id.Name + " (" + id.Type + ")"
	}
	return "pass", fmt.Sprintf("%d identifier(s): %s", len(ac.Identifiers), strings.Join(names, ", "))
}

func checkMultipleIdentifiers(ac *config.AuthConfig) (string, string) {
	if len(ac.Identifiers) < 2 {
		return "warn", fmt.Sprintf("only %d identifier(s) — consider multiple identity sources for defense in depth", len(ac.Identifiers))
	}
	return "pass", fmt.Sprintf("%d identifier(s) configured", len(ac.Identifiers))
}

func checkAuthorizersExist(ac *config.AuthConfig) (string, string) {
	if len(ac.Authorizers) == 0 {
		return "fail", "no authorizers configured — all authenticated requests are implicitly allowed"
	}
	names := make([]string, len(ac.Authorizers))
	for i, az := range ac.Authorizers {
		names[i] = az.Name + " (" + az.Type + ")"
	}
	return "pass", fmt.Sprintf("%d authorizer(s): %s", len(ac.Authorizers), strings.Join(names, ", "))
}

func checkAuthorizerNotDefaultAllow(ac *config.AuthConfig) (string, string) {
	for _, az := range ac.Authorizers {
		if az.Config != nil {
			if v, ok := az.Config["defaultAllow"]; ok {
				if b, isBool := v.(bool); isBool && b {
					return "fail", fmt.Sprintf("authorizer %q has defaultAllow: true — violates least privilege", az.Name)
				}
			}
		}
	}
	if len(ac.Authorizers) == 0 {
		return "fail", "no authorizers — implicit allow-all"
	}
	return "pass", "no authorizer uses defaultAllow: true"
}

func checkRateLimitEnabled(ac *config.AuthConfig) (string, string) {
	if ac.RateLimit == nil {
		return "warn", "rate limiting not configured — no abuse protection"
	}
	return "pass", "rate limiting enabled"
}

func checkTLSOrMTLS(ac *config.AuthConfig) (string, string) {
	for _, id := range ac.Identifiers {
		if id.Type == "mtls" {
			return "pass", fmt.Sprintf("mTLS identifier %q provides mutual authentication", id.Name)
		}
	}
	// Cannot verify TLS from config alone (TLS is at the transport level,
	// not in AuthConfig), but mTLS is explicit.
	return "warn", "no mTLS identifier found — ensure TLS is enforced at the ingress/transport layer"
}

func checkRevocationEnabled(ac *config.AuthConfig) (string, string) {
	if ac.Revocation == nil || !ac.Revocation.Enabled {
		return "warn", "credential revocation not enabled — compromised tokens cannot be revoked in real-time"
	}
	return "pass", fmt.Sprintf("revocation enabled (backend: %s)", ac.Revocation.Backend)
}

func checkAuditConfigured(ac *config.AuthConfig) (string, string) {
	if ac.Audit == nil {
		return "warn", "no explicit audit policy configured (redaction/data residency); runtime sink wiring must be verified"
	}
	if !complianceRuntimeVerified {
		if ac.Audit.Redaction != nil && len(ac.Audit.Redaction.Fields) > 0 {
			return "warn", "audit policy is statically configured; runtime verification evidence not provided (use --runtime-verified only after live verification)"
		}
		if ac.Audit.DataResidency != nil && strings.TrimSpace(ac.Audit.DataResidency.Region) != "" {
			return "warn", "data residency is statically configured; runtime verification evidence not provided (use --runtime-verified only after live verification)"
		}
	}
	if ac.Audit.Redaction != nil && len(ac.Audit.Redaction.Fields) > 0 {
		return "pass", fmt.Sprintf("audit policy includes %d redaction field(s)", len(ac.Audit.Redaction.Fields))
	}
	if ac.Audit.DataResidency != nil && strings.TrimSpace(ac.Audit.DataResidency.Region) != "" {
		return "pass", fmt.Sprintf("audit policy includes data residency region %q", ac.Audit.DataResidency.Region)
	}
	return "warn", "audit policy present but missing explicit redaction/data residency controls"
}

func checkAuditRetention(ac *config.AuthConfig) (string, string) {
	// Audit retention is primarily an operator-side concern (sink
	// configuration, storage retention policies). We only surface static
	// policy indicators from AuthConfig.
	if ac.Audit != nil && ac.Audit.DataResidency != nil {
		if strings.TrimSpace(ac.Audit.DataResidency.Region) == "" {
			return "warn", "data residency block present but region is empty — retention routing cannot be validated"
		}
		if !complianceRuntimeVerified {
			return "warn", "data residency region configured; runtime retention verification evidence not provided (use --runtime-verified only after live verification)"
		}
		return "pass", "data residency region configured; verify sink/storage retention controls out-of-band"
	}
	return "warn", "no data-residency policy in config — verify audit retention at the sink/storage layer"
}

func checkPolicyVersionSet(ac *config.AuthConfig) (string, string) {
	if ac.Version == "" {
		return "warn", "spec.version not set — no change-tracking tag for this policy revision"
	}
	return "pass", fmt.Sprintf("policy version: %q", ac.Version)
}

func checkPIIRedaction(ac *config.AuthConfig) (string, string) {
	if ac.Audit == nil || ac.Audit.Redaction == nil || len(ac.Audit.Redaction.Fields) == 0 {
		return "warn", "no PII redaction configured — audit events may contain personal data"
	}
	valid := make([]string, 0, len(ac.Audit.Redaction.Fields))
	for _, f := range ac.Audit.Redaction.Fields {
		name := strings.TrimSpace(f.Name)
		if !isKnownRedactionField(name) {
			return "fail", fmt.Sprintf("unknown redaction field %q", f.Name)
		}
		switch f.Action {
		case config.RedactHash, config.RedactDrop:
			valid = append(valid, name+"="+string(f.Action))
		default:
			return "fail", fmt.Sprintf("unsupported redaction action %q for field %q", f.Action, f.Name)
		}
	}
	if len(valid) == 0 {
		return "warn", "PII redaction policy is present but has no effective fields"
	}
	if !complianceRuntimeVerified {
		return "warn", fmt.Sprintf("PII redaction policy present (%s), but runtime verification evidence not provided (use --runtime-verified only after live verification)", strings.Join(valid, ", "))
	}
	return "pass", fmt.Sprintf("PII redaction policy: %s", strings.Join(valid, ", "))
}

func checkSecretRefUsed(ac *config.AuthConfig) (string, string) {
	if ac.Secrets == nil {
		return "warn", "no external secret backend — credentials may be stored as plaintext in manifests"
	}
	backends := make([]string, 0, len(ac.Secrets.Backends))
	for k := range ac.Secrets.Backends {
		backends = append(backends, k)
	}
	return "pass", fmt.Sprintf("external secrets enabled (backends: %s)", strings.Join(backends, ", "))
}

func checkKeyRotation(ac *config.AuthConfig) (string, string) {
	// Key rotation is configured per-identifier, not globally. Check if
	// any identifier mentions rotation-related config keys.
	for _, id := range ac.Identifiers {
		if id.Config != nil {
			for _, key := range []string{"rotationInterval", "rotation_interval", "jwksRefreshInterval", "jwks_refresh_interval"} {
				if _, ok := id.Config[key]; ok {
					return "pass", fmt.Sprintf("identifier %q has key rotation configured (%s)", id.Name, key)
				}
			}
		}
	}
	return "warn", "no key rotation configuration found in identifiers"
}

func checkCacheEnabled(ac *config.AuthConfig) (string, string) {
	if ac.Cache == nil {
		return "warn", "decision cache not configured — every request evaluates the full authorization pipeline"
	}
	return "pass", fmt.Sprintf("decision cache enabled (backend: %s, TTL: %s)", ac.Cache.Backend, ac.Cache.TTL)
}

func isKnownRedactionField(name string) bool {
	switch name {
	case "subject", "path", "host", "deny_reason", "identity_source", "trace_id":
		return true
	default:
		return false
	}
}

// --- Evaluation engine ----------------------------------------------------

func evaluate(ac *config.AuthConfig, fw frameworkDef, cfgPath string) ComplianceReport {
	report := ComplianceReport{
		GeneratedAt:      time.Now().UTC().Format(time.RFC3339),
		Framework:        fw.Name,
		FrameworkVersion: fw.Version,
		ConfigFile:       cfgPath,
		PolicyVersion:    ac.Version,
		Controls:         make([]ControlResult, 0, len(fw.Controls)),
	}
	for _, c := range fw.Controls {
		status, evidence := c.Check(ac)
		report.Controls = append(report.Controls, ControlResult{
			ID:       c.ID,
			Title:    c.Title,
			Status:   status,
			Evidence: evidence,
		})
		switch status {
		case "pass":
			report.Summary.Pass++
		case "fail":
			report.Summary.Fail++
		case "warn":
			report.Summary.Warn++
		default:
			report.Summary.Skip++
		}
		report.Summary.Total++
	}
	return report
}
