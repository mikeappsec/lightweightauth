// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package policytest

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadFixtureFile_RoundTrip(t *testing.T) {
	t.Parallel()
	content := `
description: example suite
defaults:
  method: GET
  host: api.example.com
  tenant_id: acme
tests:
  - name: public-read
    request:
      path: /public/data
    expect:
      decision: allow
  - name: admin-write-denied
    request:
      path: /admin
      method: DELETE
    expect:
      decision: deny
      reason: forbidden
  - name: health-check
    request:
      path: /healthz
      method: GET
    expect:
      decision: allow
`
	dir := t.TempDir()
	path := filepath.Join(dir, "fixtures.yaml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	suite, err := LoadFixtureFile(path)
	if err != nil {
		t.Fatalf("LoadFixtureFile: %v", err)
	}
	if suite.Description != "example suite" {
		t.Errorf("Description = %q", suite.Description)
	}
	if suite.Defaults == nil {
		t.Fatal("expected defaults")
	}
	if suite.Defaults.TenantID != "acme" {
		t.Errorf("Defaults.TenantID = %q", suite.Defaults.TenantID)
	}
	if len(suite.Tests) != 3 {
		t.Fatalf("len(Tests) = %d, want 3", len(suite.Tests))
	}
	if suite.Tests[1].Expect.Reason != "forbidden" {
		t.Errorf("test[1].Expect.Reason = %q", suite.Tests[1].Expect.Reason)
	}
}

func TestLoadFixtureFile_Errors(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		content string
	}{
		{"no tests", `tests: []`},
		{"missing name", "tests:\n  - request:\n      path: /x\n    expect:\n      decision: allow\n"},
		{"missing path", "tests:\n  - name: x\n    request:\n      method: GET\n    expect:\n      decision: allow\n"},
		{"missing decision", "tests:\n  - name: x\n    request:\n      path: /x\n    expect:\n      status: 200\n"},
		{"bad decision", "tests:\n  - name: x\n    request:\n      path: /x\n    expect:\n      decision: maybe\n"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			path := filepath.Join(dir, "bad.yaml")
			if err := os.WriteFile(path, []byte(tc.content), 0644); err != nil {
				t.Fatal(err)
			}
			_, err := LoadFixtureFile(path)
			if err == nil {
				t.Fatal("expected error")
			}
		})
	}
}
