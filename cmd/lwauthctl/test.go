// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/mikeappsec/lightweightauth/internal/config"
	"github.com/mikeappsec/lightweightauth/pkg/module"
)

// testCmd implements `lwauthctl test` — run YAML test fixtures against an
// AuthConfig, reporting pass/fail per case (G8 — POL-TEST-1).
func testCmd(args []string) {
	fs := flag.NewFlagSet("test", flag.ExitOnError)
	cfgPath := fs.String("config", "", "path to AuthConfig YAML")
	fixtureGlob := fs.String("fixtures", "", "glob pattern for fixture YAML files (e.g. tests/*.yaml)")
	verbose := fs.Bool("v", false, "verbose output (print each test case)")
	outputFmt := fs.String("output", "text", "output format: text | tap")
	_ = fs.Parse(args)

	if *cfgPath == "" || *fixtureGlob == "" {
		fmt.Fprintln(os.Stderr, "usage: lwauthctl test --config FILE --fixtures GLOB")
		fmt.Fprintln(os.Stderr, "  --config    path to AuthConfig YAML")
		fmt.Fprintln(os.Stderr, "  --fixtures  glob for test fixture YAML files")
		fmt.Fprintln(os.Stderr, "  --v         verbose per-case output")
		fmt.Fprintln(os.Stderr, "  --output    text | tap")
		os.Exit(2)
	}

	// Compile the policy.
	ac, err := config.LoadFile(*cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "load config:", err)
		os.Exit(1)
	}
	engine, err := config.Compile(ac)
	if err != nil {
		fmt.Fprintln(os.Stderr, "compile config:", err)
		os.Exit(1)
	}
	defer engine.Close()

	// Find fixture files.
	matches, err := filepath.Glob(*fixtureGlob)
	if err != nil {
		fmt.Fprintln(os.Stderr, "glob:", err)
		os.Exit(1)
	}
	if len(matches) == 0 {
		fmt.Fprintln(os.Stderr, "no fixture files match:", *fixtureGlob)
		os.Exit(2)
	}

	// Load and run all fixtures.
	var results []TestResult
	for _, path := range matches {
		suite, err := loadFixtureFile(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "load %s: %v\n", path, err)
			os.Exit(1)
		}
		for _, tc := range suite.Tests {
			result := runTestCase(engine, suite.Defaults, tc, path)
			results = append(results, result)
		}
	}

	// Report.
	pass, fail := 0, 0
	for _, r := range results {
		if r.Pass {
			pass++
		} else {
			fail++
		}
	}

	switch *outputFmt {
	case "tap":
		printTAP(results)
	default:
		printTestText(results, *verbose)
	}

	fmt.Printf("\n%d passed, %d failed, %d total\n", pass, fail, len(results))
	if fail > 0 {
		os.Exit(1)
	}
}

// --- Fixture YAML schema ---------------------------------------------------

// TestFixtureSuite is the top-level structure of a fixture YAML file.
type TestFixtureSuite struct {
	// Description is a human-readable label for the file.
	Description string `yaml:"description,omitempty"`
	// Defaults are merged into every test case's request (overridden per-case).
	Defaults *TestRequestDefaults `yaml:"defaults,omitempty"`
	// Tests is the ordered list of test cases.
	Tests []TestCase `yaml:"tests"`
}

// TestRequestDefaults provides default values merged into each test request.
type TestRequestDefaults struct {
	Method   string              `yaml:"method,omitempty"`
	Host     string              `yaml:"host,omitempty"`
	TenantID string              `yaml:"tenant_id,omitempty"`
	Headers  map[string][]string `yaml:"headers,omitempty"`
}

// TestCase is a single request → expected decision assertion.
type TestCase struct {
	// Name is a unique identifier for the test case.
	Name string `yaml:"name"`
	// Description is optional human-readable context.
	Description string `yaml:"description,omitempty"`
	// Request defines the synthetic request.
	Request TestRequest `yaml:"request"`
	// Expect defines the expected outcome.
	Expect TestExpect `yaml:"expect"`
}

// TestRequest is the request portion of a fixture.
type TestRequest struct {
	Method   string              `yaml:"method,omitempty"`
	Host     string              `yaml:"host,omitempty"`
	Path     string              `yaml:"path"`
	Headers  map[string][]string `yaml:"headers,omitempty"`
	TenantID string              `yaml:"tenant_id,omitempty"`
}

// TestExpect defines the expected decision outcome.
type TestExpect struct {
	// Decision: "allow" or "deny".
	Decision string `yaml:"decision"`
	// Status is the expected HTTP status (optional, checked only if set).
	Status int `yaml:"status,omitempty"`
	// Reason is a substring that must appear in the deny reason (optional).
	Reason string `yaml:"reason,omitempty"`
}

// --- Test result -----------------------------------------------------------

// TestResult captures the outcome of running a single test case.
type TestResult struct {
	File   string
	Name   string
	Pass   bool
	Detail string // empty on pass; explains mismatch on fail
}

// --- Execution -------------------------------------------------------------

// policyTester is the interface the test runner needs (matches *pipeline.Engine).
type policyTester interface {
	SimEvaluate(ctx context.Context, r *module.Request) (allow bool, reason string)
}

func runTestCase(engine policyTester, defaults *TestRequestDefaults, tc TestCase, file string) TestResult {
	req := buildTestRequest(defaults, tc.Request)

	allow, reason := engine.SimEvaluate(context.Background(), req)

	result := TestResult{File: file, Name: tc.Name, Pass: true}

	// Check decision.
	wantAllow := tc.Expect.Decision == "allow"
	if allow != wantAllow {
		got := "allow"
		if !allow {
			got = "deny"
		}
		result.Pass = false
		result.Detail = fmt.Sprintf("decision: got %s, want %s", got, tc.Expect.Decision)
		if reason != "" {
			result.Detail += " (reason: " + reason + ")"
		}
		return result
	}

	// Check reason substring (only on deny).
	if tc.Expect.Reason != "" && !allow {
		if !strings.Contains(reason, tc.Expect.Reason) {
			result.Pass = false
			result.Detail = fmt.Sprintf("reason: got %q, want substring %q", reason, tc.Expect.Reason)
			return result
		}
	}

	return result
}

func buildTestRequest(defaults *TestRequestDefaults, tr TestRequest) *module.Request {
	method := tr.Method
	host := tr.Host
	tenantID := tr.TenantID
	headers := tr.Headers

	if defaults != nil {
		if method == "" {
			method = defaults.Method
		}
		if host == "" {
			host = defaults.Host
		}
		if tenantID == "" {
			tenantID = defaults.TenantID
		}
		if headers == nil && defaults.Headers != nil {
			headers = defaults.Headers
		}
	}

	if method == "" {
		method = "GET"
	}

	// Normalize header keys to lowercase.
	normalized := make(map[string][]string, len(headers))
	for k, vs := range headers {
		normalized[strings.ToLower(k)] = vs
	}

	return &module.Request{
		Method:   strings.ToUpper(method),
		Host:     host,
		Path:     tr.Path,
		TenantID: tenantID,
		Headers:  normalized,
		Context:  map[string]any{},
	}
}

// --- File loading ----------------------------------------------------------

func loadFixtureFile(path string) (*TestFixtureSuite, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var suite TestFixtureSuite
	if err := yaml.Unmarshal(data, &suite); err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}
	if len(suite.Tests) == 0 {
		return nil, fmt.Errorf("no tests defined")
	}
	for i, tc := range suite.Tests {
		if tc.Name == "" {
			return nil, fmt.Errorf("test[%d]: name is required", i)
		}
		if tc.Request.Path == "" {
			return nil, fmt.Errorf("test %q: request.path is required", tc.Name)
		}
		if tc.Expect.Decision == "" {
			return nil, fmt.Errorf("test %q: expect.decision is required", tc.Name)
		}
		if tc.Expect.Decision != "allow" && tc.Expect.Decision != "deny" {
			return nil, fmt.Errorf("test %q: expect.decision must be 'allow' or 'deny'", tc.Name)
		}
	}
	return &suite, nil
}

// --- Output formatters -----------------------------------------------------

func printTestText(results []TestResult, verbose bool) {
	for _, r := range results {
		if r.Pass {
			if verbose {
				fmt.Printf("  ✓ %s\n", r.Name)
			}
		} else {
			fmt.Printf("  ✗ %s: %s\n", r.Name, r.Detail)
		}
	}
}

func printTAP(results []TestResult) {
	fmt.Printf("TAP version 13\n1..%d\n", len(results))
	for i, r := range results {
		if r.Pass {
			fmt.Printf("ok %d - %s\n", i+1, r.Name)
		} else {
			fmt.Printf("not ok %d - %s\n", i+1, r.Name)
			fmt.Printf("  ---\n  message: %s\n  file: %s\n  ...\n", r.Detail, r.File)
		}
	}
}
