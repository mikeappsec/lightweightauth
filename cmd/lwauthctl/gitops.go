// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/mikeappsec/lightweightauth/internal/config"
)

// k8sNameRe validates Kubernetes resource names (RFC 1123 DNS subdomain).
var k8sNameRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9.\-]*[a-z0-9])?$`)

// validateK8sName checks that s is a valid Kubernetes resource name.
func validateK8sName(s string) error {
	if len(s) == 0 || len(s) > 253 {
		return fmt.Errorf("invalid resource name: length %d (must be 1-253)", len(s))
	}
	if !k8sNameRe.MatchString(s) {
		return fmt.Errorf("invalid resource name %q: must match [a-z0-9][a-z0-9.-]*[a-z0-9]", s)
	}
	return nil
}

// validateOutPath refuses output paths containing traversal sequences.
func validateOutPath(p string) error {
	cleaned := filepath.Clean(p)
	if strings.Contains(cleaned, "..") {
		return fmt.Errorf("refusing output path %q: contains path traversal", p)
	}
	return nil
}

// canonicalJSON marshals v with sorted map keys for deterministic output.
// This ensures the same logical config always produces the same digest
// regardless of Go map iteration order.
func canonicalJSON(v any) ([]byte, error) {
	// json.Marshal already sorts map keys in Go 1.12+, but config
	// contains map[string]any from YAML decode where nested maps may
	// be map[any]any. We normalize via a round-trip through sorted
	// encoding.
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	// Re-decode into interface{} and re-encode to normalize.
	var raw any
	if err := json.Unmarshal(b, &raw); err != nil {
		return b, nil // fallback to original
	}
	normalized := sortKeys(raw)
	return json.Marshal(normalized)
}

// sortKeys recursively sorts map keys for deterministic serialization.
func sortKeys(v any) any {
	switch val := v.(type) {
	case map[string]any:
		sorted := make(map[string]any, len(val))
		for k, v2 := range val {
			sorted[k] = sortKeys(v2)
		}
		return sorted
	case []any:
		for i, item := range val {
			val[i] = sortKeys(item)
		}
		return val
	default:
		return v
	}
}

// promote validates the config, optionally stamps spec.version, computes
// the spec digest, and emits the GitOps-ready YAML to stdout (or to a
// file). Designed for CI pipelines that validate-then-push to Git.
//
// Usage:
//
//	lwauthctl promote --config authconfig.yaml --version "2026-05-01"
//	lwauthctl promote --config authconfig.yaml --auto-version
func promote(args []string) {
	fs := flag.NewFlagSet("promote", flag.ExitOnError)
	cfgPath := fs.String("config", "", "path to AuthConfig YAML")
	version := fs.String("version", "", "explicit version string to stamp into spec.version")
	autoVer := fs.Bool("auto-version", false, "auto-generate a version string (date-based)")
	outPath := fs.String("out", "", "write promoted YAML to this file (default: stdout)")
	_ = fs.Parse(args)

	if *cfgPath == "" {
		fmt.Fprintln(os.Stderr, "--config required")
		os.Exit(2)
	}
	ac, err := config.LoadFile(*cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "load:", err)
		os.Exit(1)
	}
	if _, err := config.Compile(ac); err != nil {
		fmt.Fprintln(os.Stderr, "compile:", err)
		os.Exit(1)
	}

	// Stamp version.
	switch {
	case *version != "":
		ac.Version = *version
	case *autoVer:
		ac.Version = time.Now().UTC().Format("2006-01-02T150405Z")
	}

	// Compute digest with canonical (sorted-key) JSON.
	specJSON, _ := canonicalJSON(ac)
	digest := sha256.Sum256(specJSON)

	fmt.Fprintf(os.Stderr, "✓ validated: identifiers=%d authorizers=%d\n",
		len(ac.Identifiers), len(ac.Authorizers))
	fmt.Fprintf(os.Stderr, "  version:  %s\n", ac.Version)
	fmt.Fprintf(os.Stderr, "  digest:   sha256:%x\n", digest)

	// Emit the promoted YAML.
	out := os.Stdout
	if *outPath != "" {
		if err := validateOutPath(*outPath); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		f, err := os.Create(*outPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, "create:", err)
			os.Exit(1)
		}
		defer f.Close()
		out = f
	}

	// We emit JSON because the config is loaded from YAML but we want
	// a canonical representation. Operators pipe through yq for YAML.
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	if err := enc.Encode(ac); err != nil {
		fmt.Fprintln(os.Stderr, "encode:", err)
		os.Exit(1)
	}
}

// rollback rewrites spec.version in the given config to a target version
// and re-validates. This is a local operation — it does not talk to the
// cluster. Pair with `kubectl apply` or a GitOps commit.
//
// Usage:
//
//	lwauthctl rollback --config authconfig.yaml --to-version "2026-04-30"
func rollback(args []string) {
	fs := flag.NewFlagSet("rollback", flag.ExitOnError)
	cfgPath := fs.String("config", "", "path to AuthConfig YAML")
	toVersion := fs.String("to-version", "", "version string to roll back to")
	outPath := fs.String("out", "", "write result to file (default: stdout)")
	_ = fs.Parse(args)

	if *cfgPath == "" || *toVersion == "" {
		fmt.Fprintln(os.Stderr, "--config and --to-version required")
		os.Exit(2)
	}
	ac, err := config.LoadFile(*cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "load:", err)
		os.Exit(1)
	}

	oldVersion := ac.Version
	ac.Version = *toVersion

	if _, err := config.Compile(ac); err != nil {
		fmt.Fprintln(os.Stderr, "compile after rollback:", err)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "✓ rollback: %s → %s\n", oldVersion, *toVersion)

	out := os.Stdout
	if *outPath != "" {
		f, err := os.Create(*outPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, "create:", err)
			os.Exit(1)
		}
		defer f.Close()
		out = f
	}

	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	if err := enc.Encode(ac); err != nil {
		fmt.Fprintln(os.Stderr, "encode:", err)
		os.Exit(1)
	}
}

// drift compares the local config file against the live AuthConfig's
// status in the cluster. It checks:
//   - spec.version vs status.appliedVersion
//   - computed digest vs status.appliedDigest
//
// Non-zero exit means drift was detected.
//
// Usage:
//
//	lwauthctl drift --config authconfig.yaml --namespace payments --name payments
func drift(args []string) {
	fs := flag.NewFlagSet("drift", flag.ExitOnError)
	cfgPath := fs.String("config", "", "path to desired AuthConfig YAML")
	namespace := fs.String("namespace", "default", "Kubernetes namespace")
	name := fs.String("name", "", "AuthConfig resource name (default: derived from filename)")
	_ = fs.Parse(args)

	if *cfgPath == "" {
		fmt.Fprintln(os.Stderr, "--config required")
		os.Exit(2)
	}
	ac, err := config.LoadFile(*cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "load:", err)
		os.Exit(1)
	}
	if _, err := config.Compile(ac); err != nil {
		fmt.Fprintln(os.Stderr, "compile:", err)
		os.Exit(1)
	}

	// Compute local digest.
	// TC10: canonical JSON for deterministic digest.
	specJSON, _ := canonicalJSON(ac)
	localDigest := fmt.Sprintf("sha256:%x", sha256.Sum256(specJSON))

	// Fetch live status from cluster via kubectl.
	if *name == "" {
		// Derive from filename: "payments.yaml" -> "payments"
		base := *cfgPath
		if idx := strings.LastIndex(base, "/"); idx >= 0 {
			base = base[idx+1:]
		}
		if idx := strings.LastIndex(base, "\\"); idx >= 0 {
			base = base[idx+1:]
		}
		base = strings.TrimSuffix(base, ".yaml")
		base = strings.TrimSuffix(base, ".yml")
		*name = strings.ToLower(base)
	}
	// TC1: validate derived name is a legal K8s resource name.
	if err := validateK8sName(*name); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	// kubectl get authconfig <name> -n <ns> -o jsonpath
	liveVersion, err := kubectlJSONPath(*namespace, *name, "{.status.appliedVersion}")
	if err != nil {
		fmt.Fprintf(os.Stderr, "⚠ cannot read live status: %v\n", err)
		fmt.Fprintln(os.Stderr, "  (is the cluster reachable? is the AuthConfig applied?)")
		os.Exit(2)
	}
	liveDigest, _ := kubectlJSONPath(*namespace, *name, "{.status.appliedDigest}")

	drifted := false

	// Compare version.
	if ac.Version != "" && liveVersion != ac.Version {
		fmt.Printf("DRIFT  version: local=%q  live=%q\n", ac.Version, liveVersion)
		drifted = true
	} else if ac.Version != "" {
		fmt.Printf("OK     version: %q\n", ac.Version)
	}

	// Compare digest.
	if liveDigest != "" && liveDigest != localDigest {
		fmt.Printf("DRIFT  digest:  local=%s  live=%s\n", localDigest, liveDigest)
		drifted = true
	} else if liveDigest != "" {
		fmt.Printf("OK     digest:  %s\n", localDigest)
	}

	if !drifted {
		fmt.Println("\n✓ no drift detected")
	} else {
		fmt.Println("\n✗ drift detected — run `lwauthctl promote` + `kubectl apply` to reconcile")
		os.Exit(1)
	}
}

// kubectlJSONPath runs kubectl get authconfig and extracts a jsonpath field.
// The "--" separator prevents the resource name from being interpreted as
// a kubectl flag (TC1 fix).
func kubectlJSONPath(namespace, name, jsonpath string) (string, error) {
	cmd := exec.Command("kubectl", "-n", namespace, "get",
		"authconfig.lightweightauth.io",
		"-o", fmt.Sprintf("jsonpath=%s", jsonpath),
		"--", name)
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}
