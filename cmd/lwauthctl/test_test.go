// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"os"
	"testing"

	"github.com/mikeappsec/lightweightauth/pkg/module"
)

// fakePolicyEngine implements policyTester for unit testing the test runner.
type fakePolicyEngine struct {
	// allowPaths is the set of paths that are allowed; everything else is denied.
	allowPaths map[string]bool
	denyReason string
}

func (f *fakePolicyEngine) SimEvaluate(_ context.Context, r *module.Request) (bool, string) {
	if f.allowPaths[r.Path] {
		return true, ""
	}
	reason := f.denyReason
	if reason == "" {
		reason = "denied by policy"
	}
	return false, reason
}

func TestRunTestCase_Pass_Allow(t *testing.T) {
	t.Parallel()
	engine := &fakePolicyEngine{allowPaths: map[string]bool{"/api": true}}
	tc := TestCase{
		Name:    "allow-api",
		Request: TestRequest{Path: "/api", Method: "GET"},
		Expect:  TestExpect{Decision: "allow"},
	}
	result := runTestCase(engine, nil, tc, "test.yaml")
	if !result.Pass {
		t.Fatalf("expected pass, got fail: %s", result.Detail)
	}
}

func TestRunTestCase_Pass_Deny(t *testing.T) {
	t.Parallel()
	engine := &fakePolicyEngine{allowPaths: map[string]bool{}, denyReason: "forbidden"}
	tc := TestCase{
		Name:    "deny-admin",
		Request: TestRequest{Path: "/admin", Method: "DELETE"},
		Expect:  TestExpect{Decision: "deny"},
	}
	result := runTestCase(engine, nil, tc, "test.yaml")
	if !result.Pass {
		t.Fatalf("expected pass, got fail: %s", result.Detail)
	}
}

func TestRunTestCase_Fail_ExpectedAllowGotDeny(t *testing.T) {
	t.Parallel()
	engine := &fakePolicyEngine{allowPaths: map[string]bool{}, denyReason: "no access"}
	tc := TestCase{
		Name:    "should-allow",
		Request: TestRequest{Path: "/api", Method: "GET"},
		Expect:  TestExpect{Decision: "allow"},
	}
	result := runTestCase(engine, nil, tc, "test.yaml")
	if result.Pass {
		t.Fatal("expected fail")
	}
	if result.Detail == "" {
		t.Error("expected non-empty detail")
	}
}

func TestRunTestCase_Fail_ExpectedDenyGotAllow(t *testing.T) {
	t.Parallel()
	engine := &fakePolicyEngine{allowPaths: map[string]bool{"/secret": true}}
	tc := TestCase{
		Name:    "should-deny",
		Request: TestRequest{Path: "/secret", Method: "GET"},
		Expect:  TestExpect{Decision: "deny"},
	}
	result := runTestCase(engine, nil, tc, "test.yaml")
	if result.Pass {
		t.Fatal("expected fail")
	}
}

func TestRunTestCase_ReasonSubstring(t *testing.T) {
	t.Parallel()
	engine := &fakePolicyEngine{allowPaths: map[string]bool{}, denyReason: "not in admin group"}
	tc := TestCase{
		Name:    "deny-reason",
		Request: TestRequest{Path: "/admin", Method: "GET"},
		Expect:  TestExpect{Decision: "deny", Reason: "admin group"},
	}
	result := runTestCase(engine, nil, tc, "test.yaml")
	if !result.Pass {
		t.Fatalf("expected pass, got: %s", result.Detail)
	}
}

func TestRunTestCase_ReasonMismatch(t *testing.T) {
	t.Parallel()
	engine := &fakePolicyEngine{allowPaths: map[string]bool{}, denyReason: "rate limited"}
	tc := TestCase{
		Name:    "wrong-reason",
		Request: TestRequest{Path: "/api", Method: "GET"},
		Expect:  TestExpect{Decision: "deny", Reason: "admin group"},
	}
	result := runTestCase(engine, nil, tc, "test.yaml")
	if result.Pass {
		t.Fatal("expected fail due to reason mismatch")
	}
	if result.Detail == "" {
		t.Error("expected non-empty detail")
	}
}

func TestRunTestCase_Defaults(t *testing.T) {
	t.Parallel()
	engine := &fakePolicyEngine{allowPaths: map[string]bool{"/api": true}}
	defaults := &TestRequestDefaults{
		Method:   "POST",
		Host:     "example.com",
		TenantID: "acme",
	}
	tc := TestCase{
		Name:    "uses-defaults",
		Request: TestRequest{Path: "/api"},
		Expect:  TestExpect{Decision: "allow"},
	}
	result := runTestCase(engine, defaults, tc, "test.yaml")
	if !result.Pass {
		t.Fatalf("expected pass: %s", result.Detail)
	}
}

func TestRunTestCase_RequestOverridesDefaults(t *testing.T) {
	t.Parallel()
	engine := &fakePolicyEngine{allowPaths: map[string]bool{"/api": true}}
	defaults := &TestRequestDefaults{
		Method: "POST",
		Host:   "default.com",
	}
	tc := TestCase{
		Name:    "override-host",
		Request: TestRequest{Path: "/api", Method: "GET", Host: "custom.com"},
		Expect:  TestExpect{Decision: "allow"},
	}
	result := runTestCase(engine, defaults, tc, "test.yaml")
	if !result.Pass {
		t.Fatalf("expected pass: %s", result.Detail)
	}
}

func TestLoadFixtureFile_Valid(t *testing.T) {
	t.Parallel()
	content := `
description: basic tests
defaults:
  method: GET
  host: example.com
tests:
  - name: allow-public
    request:
      path: /public
    expect:
      decision: allow
  - name: deny-admin
    request:
      path: /admin
      method: DELETE
    expect:
      decision: deny
      reason: forbidden
`
	path := t.TempDir() + "/fixture.yaml"
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	suite, err := loadFixtureFile(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(suite.Tests) != 2 {
		t.Fatalf("len(Tests) = %d, want 2", len(suite.Tests))
	}
	if suite.Tests[0].Name != "allow-public" {
		t.Errorf("name = %q", suite.Tests[0].Name)
	}
	if suite.Defaults.Host != "example.com" {
		t.Errorf("defaults.host = %q", suite.Defaults.Host)
	}
}

func TestLoadFixtureFile_MissingName(t *testing.T) {
	t.Parallel()
	content := `
tests:
  - request:
      path: /foo
    expect:
      decision: allow
`
	path := t.TempDir() + "/bad.yaml"
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	_, err := loadFixtureFile(path)
	if err == nil {
		t.Fatal("expected error for missing name")
	}
}

func TestLoadFixtureFile_InvalidDecision(t *testing.T) {
	t.Parallel()
	content := `
tests:
  - name: bad
    request:
      path: /foo
    expect:
      decision: maybe
`
	path := t.TempDir() + "/bad.yaml"
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	_, err := loadFixtureFile(path)
	if err == nil {
		t.Fatal("expected error for invalid decision")
	}
}

func TestLoadFixtureFile_NoTests(t *testing.T) {
	t.Parallel()
	content := `
description: empty
tests: []
`
	path := t.TempDir() + "/empty.yaml"
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	_, err := loadFixtureFile(path)
	if err == nil {
		t.Fatal("expected error for empty tests")
	}
}

func TestBuildTestRequest_NormalizesHeaders(t *testing.T) {
	t.Parallel()
	tr := TestRequest{
		Path: "/test",
		Headers: map[string][]string{
			"Authorization": {"Bearer abc"},
			"X-Custom":      {"value"},
		},
	}
	req := buildTestRequest(nil, tr)
	if req.Headers["authorization"] == nil {
		t.Error("expected lowercase authorization header")
	}
	if req.Headers["x-custom"] == nil {
		t.Error("expected lowercase x-custom header")
	}
	if req.Method != "GET" {
		t.Errorf("default method = %q, want GET", req.Method)
	}
}
