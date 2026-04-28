// Package helmchart hosts golden-style render tests for the
// lightweightauth Helm chart.
//
// These tests shell out to `helm template` and assert on the rendered
// YAML. They are skipped when `helm` is not on PATH so they don't
// break developers who haven't installed the Helm CLI; CI is expected
// to run with helm available.
package helmchart

import (
	"os/exec"
	"strings"
	"testing"
)

// helmTemplate renders the chart with the given --set overrides and
// returns the combined manifest. Skips the test when the helm CLI is
// missing.
func helmTemplate(t *testing.T, sets ...string) string {
	t.Helper()
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skipf("helm not on PATH: %v", err)
	}
	args := []string{"template", "lwtest", "."}
	for _, s := range sets {
		args = append(args, "--set", s)
	}
	out, err := exec.Command("helm", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("helm template failed: %v\n%s", err, out)
	}
	return string(out)
}

// extractNetworkPolicy isolates the rendered NetworkPolicy document so
// assertions don't accidentally match strings inside Deployments etc.
func extractNetworkPolicy(t *testing.T, manifest string) string {
	t.Helper()
	const marker = "kind: NetworkPolicy"
	idx := strings.Index(manifest, marker)
	if idx < 0 {
		return ""
	}
	rest := manifest[idx:]
	if end := strings.Index(rest, "\n---"); end >= 0 {
		return rest[:end]
	}
	return rest
}

// TestNetworkPolicy_DefaultDenyAll verifies the regression fix for the
// previous default which rendered an empty `from:` list. Kubernetes
// treats an ingress rule with no `from` peers as matching ALL sources,
// so the chart must instead render `ingress: []` (deny-all) when no
// allowedFrom selectors are configured.
func TestNetworkPolicy_DefaultDenyAll(t *testing.T) {
	manifest := helmTemplate(t)
	np := extractNetworkPolicy(t, manifest)
	if np == "" {
		t.Fatal("default render produced no NetworkPolicy (expected deny-all)")
	}
	if !strings.Contains(np, "ingress: []") {
		t.Fatalf("default NetworkPolicy must render ingress: [] (deny-all); got:\n%s", np)
	}
	// Belt-and-braces: make sure we never emit an ingress rule body
	// that ports-only matches all sources.
	if strings.Contains(np, "- from:") && !strings.Contains(np, "namespaceSelector") && !strings.Contains(np, "podSelector") {
		t.Fatalf("rendered an ingress rule with no peers; this matches ALL sources:\n%s", np)
	}
}

// TestNetworkPolicy_PopulatedRendersFromPeers verifies that selectors
// passed on the command line still produce a real allow-list rule.
func TestNetworkPolicy_PopulatedRendersFromPeers(t *testing.T) {
	manifest := helmTemplate(t, "networkPolicy.allowedFrom.namespaceSelectors[0].name=istio-system")
	np := extractNetworkPolicy(t, manifest)
	if np == "" {
		t.Fatal("populated render produced no NetworkPolicy")
	}
	for _, want := range []string{"- from:", "namespaceSelector", "name: istio-system", "port: 8080", "port: 9001"} {
		if !strings.Contains(np, want) {
			t.Fatalf("rendered NetworkPolicy missing %q:\n%s", want, np)
		}
	}
	if strings.Contains(np, "ingress: []") {
		t.Fatalf("populated render should not collapse to deny-all:\n%s", np)
	}
}

// TestNetworkPolicy_DisabledRendersNothing confirms operators can
// still opt out entirely.
func TestNetworkPolicy_DisabledRendersNothing(t *testing.T) {
	manifest := helmTemplate(t, "networkPolicy.enabled=false")
	if extractNetworkPolicy(t, manifest) != "" {
		t.Fatal("networkPolicy.enabled=false should not emit a NetworkPolicy document")
	}
}
