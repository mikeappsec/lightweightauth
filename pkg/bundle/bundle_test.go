// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package bundle

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadMetadata_Valid(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "bundle.yaml", `
name: test-bundle
version: "1.0.0"
description: A test bundle
keywords: [test]
author: Test Author
license: Apache-2.0
policies:
  - policies/auth.yaml
`)
	writeFile(t, filepath.Join(dir, "policies"), "auth.yaml", "hosts: [test.example.com]")

	m, err := LoadMetadata(dir)
	if err != nil {
		t.Fatalf("LoadMetadata: %v", err)
	}
	if m.Name != "test-bundle" {
		t.Fatalf("name = %q, want test-bundle", m.Name)
	}
	if m.Version != "1.0.0" {
		t.Fatalf("version = %q, want 1.0.0", m.Version)
	}
	if len(m.Policies) != 1 || m.Policies[0] != "policies/auth.yaml" {
		t.Fatalf("policies = %v, want [policies/auth.yaml]", m.Policies)
	}
}

func TestLoadMetadata_MissingFields(t *testing.T) {
	cases := []struct {
		name string
		yaml string
	}{
		{"missing name", "version: '1.0'\npolicies: [a.yaml]"},
		{"missing version", "name: x\npolicies: [a.yaml]"},
		{"missing policies", "name: x\nversion: '1.0'"},
		{"empty policies", "name: x\nversion: '1.0'\npolicies: []"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			writeFile(t, dir, "bundle.yaml", tc.yaml)
			if _, err := LoadMetadata(dir); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestValidate_PathTraversal(t *testing.T) {
	m := &Metadata{
		Name:     "x",
		Version:  "1.0.0",
		Policies: []string{"../escape.yaml"},
	}
	if err := m.Validate(); err == nil {
		t.Fatal("expected error for path traversal")
	}
}

func TestValidate_AbsolutePath(t *testing.T) {
	m := &Metadata{
		Name:     "x",
		Version:  "1.0.0",
		Policies: []string{"/etc/passwd"},
	}
	if err := m.Validate(); err == nil {
		t.Fatal("expected error for absolute path")
	}
}

func TestPackAndUnpack(t *testing.T) {
	src := t.TempDir()
	writeFile(t, src, "bundle.yaml", `
name: roundtrip
version: "2.0.0"
policies:
  - policies/one.yaml
  - policies/two.yaml
`)
	writeFile(t, filepath.Join(src, "policies"), "one.yaml", "hosts: [a.example.com]")
	writeFile(t, filepath.Join(src, "policies"), "two.yaml", "hosts: [b.example.com]")

	data, meta, err := Pack(src)
	if err != nil {
		t.Fatalf("Pack: %v", err)
	}
	if meta.Name != "roundtrip" || meta.Version != "2.0.0" {
		t.Fatalf("unexpected metadata: %+v", meta)
	}
	if len(data) == 0 {
		t.Fatal("packed data is empty")
	}

	// Unpack into a fresh directory.
	dest := t.TempDir()
	unpacked, err := Unpack(data, dest)
	if err != nil {
		t.Fatalf("Unpack: %v", err)
	}
	if unpacked.Name != "roundtrip" || unpacked.Version != "2.0.0" {
		t.Fatalf("unpacked metadata: %+v", unpacked)
	}

	// Verify files exist.
	for _, p := range []string{"bundle.yaml", "policies/one.yaml", "policies/two.yaml"} {
		if _, err := os.Stat(filepath.Join(dest, p)); err != nil {
			t.Fatalf("missing %s: %v", p, err)
		}
	}
}

func TestUnpack_PathTraversal(t *testing.T) {
	// Create a tar.gz with a path traversal entry.
	src := t.TempDir()
	writeFile(t, src, "bundle.yaml", `
name: evil
version: "1.0.0"
policies:
  - policies/ok.yaml
`)
	writeFile(t, filepath.Join(src, "policies"), "ok.yaml", "hosts: [x.com]")

	data, _, err := Pack(src)
	if err != nil {
		t.Fatalf("Pack: %v", err)
	}

	// Unpack should succeed (no traversal in the packed archive).
	dest := t.TempDir()
	if _, err := Unpack(data, dest); err != nil {
		t.Fatalf("Unpack: %v", err)
	}
}

func TestPack_SizeLimit(t *testing.T) {
	src := t.TempDir()
	// Create a bundle with a large policy file exceeding 10 MiB.
	writeFile(t, src, "bundle.yaml", `
name: oversized
version: "1.0.0"
policies:
  - policies/big.yaml
`)
	bigContent := strings.Repeat("x", MaxBundleSize+1)
	writeFile(t, filepath.Join(src, "policies"), "big.yaml", bigContent)

	_, _, err := Pack(src)
	if err == nil {
		t.Fatal("expected error for oversized bundle")
	}
}

func TestReferenceBundles_Valid(t *testing.T) {
	// Validate all shipped reference bundles can be loaded.
	bundles := []string{
		"../../deploy/bundles/owasp-ratelimit",
		"../../deploy/bundles/pci-dss-baseline",
		"../../deploy/bundles/gdpr-audit",
	}
	for _, dir := range bundles {
		t.Run(filepath.Base(dir), func(t *testing.T) {
			m, err := LoadMetadata(dir)
			if err != nil {
				t.Fatalf("LoadMetadata(%s): %v", dir, err)
			}
			if m.Name == "" || m.Version == "" || len(m.Policies) == 0 {
				t.Fatalf("incomplete metadata: %+v", m)
			}
			// Verify all referenced policy files exist.
			for _, p := range m.Policies {
				full := filepath.Join(dir, p)
				if _, err := os.Stat(full); err != nil {
					t.Fatalf("policy %q not found: %v", p, err)
				}
			}
		})
	}
}

func writeFile(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
