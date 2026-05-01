package main

import (
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/mikeappsec/lightweightauth/internal/config"
)

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

	// Compute digest.
	specJSON, _ := json.Marshal(ac)
	digest := sha256.Sum256(specJSON)

	fmt.Fprintf(os.Stderr, "✓ validated: identifiers=%d authorizers=%d\n",
		len(ac.Identifiers), len(ac.Authorizers))
	fmt.Fprintf(os.Stderr, "  version:  %s\n", ac.Version)
	fmt.Fprintf(os.Stderr, "  digest:   sha256:%x\n", digest)

	// Emit the promoted YAML.
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
	specJSON, _ := json.Marshal(ac)
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
		*name = base
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
func kubectlJSONPath(namespace, name, jsonpath string) (string, error) {
	cmd := exec.Command("kubectl", "-n", namespace, "get", "authconfig.lightweightauth.io", name,
		"-o", fmt.Sprintf("jsonpath=%s", jsonpath))
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}
