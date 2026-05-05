// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

// Package policytest provides a Go testing harness for running LightweightAuth
// policy test fixtures from standard Go tests (G8 — POL-TEST-1).
//
// Usage in a _test.go file:
//
//	func TestPolicy(t *testing.T) {
//	    policytest.Run(t, policytest.Options{
//	        ConfigPath:  "../../deploy/authconfig.yaml",
//	        FixtureGlob: "testdata/*.yaml",
//	    })
//	}
//
// Each YAML fixture file contains test cases with request definitions and
// expected decisions. See cmd/lwauthctl documentation for the fixture schema.
package policytest

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/mikeappsec/lightweightauth/internal/config"
	"github.com/mikeappsec/lightweightauth/internal/pipeline"
	"github.com/mikeappsec/lightweightauth/pkg/module"
)

// Options configures the policy test harness.
type Options struct {
	// ConfigPath is the path to the AuthConfig YAML to test.
	ConfigPath string
	// FixtureGlob is a glob pattern matching fixture YAML files.
	FixtureGlob string
}

// Run loads the config, compiles the pipeline, and runs all fixture test
// cases as Go sub-tests. Each test case becomes a t.Run sub-test, so
// failures are individually identifiable and Go's -run flag works.
func Run(t *testing.T, opts Options) {
	t.Helper()

	if opts.ConfigPath == "" {
		t.Fatal("policytest: ConfigPath is required")
	}
	if opts.FixtureGlob == "" {
		t.Fatal("policytest: FixtureGlob is required")
	}

	ac, err := config.LoadFile(opts.ConfigPath)
	if err != nil {
		t.Fatalf("policytest: load config: %v", err)
	}
	engine, err := config.Compile(ac)
	if err != nil {
		t.Fatalf("policytest: compile config: %v", err)
	}
	t.Cleanup(engine.Close)

	matches, err := filepath.Glob(opts.FixtureGlob)
	if err != nil {
		t.Fatalf("policytest: glob: %v", err)
	}
	if len(matches) == 0 {
		t.Fatalf("policytest: no fixture files match: %s", opts.FixtureGlob)
	}

	for _, path := range matches {
		suite, err := LoadFixtureFile(path)
		if err != nil {
			t.Fatalf("policytest: load %s: %v", path, err)
		}
		base := filepath.Base(path)
		for _, tc := range suite.Tests {
			tc := tc // capture
			name := base + "/" + tc.Name
			t.Run(name, func(t *testing.T) {
				t.Parallel()
				runCase(t, engine, suite.Defaults, tc)
			})
		}
	}
}

// RunSuite runs a single pre-loaded fixture suite against the given engine.
// Useful when the caller wants more control over engine construction.
func RunSuite(t *testing.T, engine *pipeline.Engine, suite *FixtureSuite) {
	t.Helper()
	for _, tc := range suite.Tests {
		tc := tc
		t.Run(tc.Name, func(t *testing.T) {
			t.Parallel()
			runCase(t, engine, suite.Defaults, tc)
		})
	}
}

func runCase(t *testing.T, engine *pipeline.Engine, defaults *RequestDefaults, tc TestCase) {
	t.Helper()
	req := buildRequest(defaults, tc.Request)
	allow, reason := engine.SimEvaluate(context.Background(), req)

	wantAllow := tc.Expect.Decision == "allow"
	if allow != wantAllow {
		got := "allow"
		if !allow {
			got = "deny"
		}
		msg := fmt.Sprintf("decision: got %s, want %s", got, tc.Expect.Decision)
		if reason != "" {
			msg += " (reason: " + reason + ")"
		}
		t.Error(msg)
		return
	}

	if tc.Expect.Reason != "" && !allow {
		if !strings.Contains(reason, tc.Expect.Reason) {
			t.Errorf("reason: got %q, want substring %q", reason, tc.Expect.Reason)
		}
	}
}

func buildRequest(defaults *RequestDefaults, tr TestRequest) *module.Request {
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

// --- Fixture YAML schema (exported for reuse) ------------------------------

// FixtureSuite is the top-level structure of a fixture YAML file.
type FixtureSuite struct {
	Description string           `yaml:"description,omitempty"`
	Defaults    *RequestDefaults `yaml:"defaults,omitempty"`
	Tests       []TestCase       `yaml:"tests"`
}

// RequestDefaults provides default values merged into each test request.
type RequestDefaults struct {
	Method   string              `yaml:"method,omitempty"`
	Host     string              `yaml:"host,omitempty"`
	TenantID string              `yaml:"tenant_id,omitempty"`
	Headers  map[string][]string `yaml:"headers,omitempty"`
}

// TestCase is a single request → expected decision assertion.
type TestCase struct {
	Name        string      `yaml:"name"`
	Description string      `yaml:"description,omitempty"`
	Request     TestRequest `yaml:"request"`
	Expect      TestExpect  `yaml:"expect"`
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
	Decision string `yaml:"decision"`
	Status   int    `yaml:"status,omitempty"`
	Reason   string `yaml:"reason,omitempty"`
}

// LoadFixtureFile parses a YAML fixture file and validates it.
func LoadFixtureFile(path string) (*FixtureSuite, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var suite FixtureSuite
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
