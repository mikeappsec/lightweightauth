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

// TestRBAC_NamespaceScopeStillEmitsClusterRoleForIdentityProvider
// pins the regression fix for the chart bug where the default
// (`controllerRBAC.preferNamespaceScope=true` + `controller.watchNamespace`
// set) emitted only a namespace-scoped Role covering authconfigs,
// authpolicies AND identityproviders. Because IdentityProvider is
// cluster-scoped, the namespace Role couldn't actually grant
// list/watch on it and the controller's informer cache failed to
// sync, leaving readiness at 503 forever.
func TestRBAC_NamespaceScopeStillEmitsClusterRoleForIdentityProvider(t *testing.T) {
	manifest := helmTemplate(t,
		"controller.enabled=true",
		"controller.watchNamespace=lwauth-demo",
	)

	// Must contain a ClusterRole that covers identityproviders…
	idpClusterRole := strings.Contains(manifest, "kind: ClusterRole") &&
		strings.Contains(manifest, "name: lwtest-idp") &&
		strings.Contains(manifest, "identityproviders")
	if !idpClusterRole {
		t.Fatalf("expected a ClusterRole covering identityproviders; got:\n%s", manifest)
	}

	// …AND a namespace-scoped Role for the rest, which must NOT
	// list identityproviders any more.
	// Normalise CRLF so the test passes on Windows where helm.exe
	// emits \r\n line endings.
	normalised := strings.ReplaceAll(manifest, "\r\n", "\n")
	roleIdx := strings.Index(normalised, "kind: Role\n")
	if roleIdx < 0 {
		t.Fatalf("expected a namespace-scoped Role; got:\n%s", normalised)
	}
	role := normalised[roleIdx:]
	if next := strings.Index(role, "\n---"); next >= 0 {
		role = role[:next]
	}
	if strings.Contains(role, "identityproviders") {
		t.Fatalf("namespace-scoped Role must not reference cluster-scoped identityproviders:\n%s", role)
	}
	for _, want := range []string{"authconfigs", "authpolicies"} {
		if !strings.Contains(role, want) {
			t.Fatalf("namespace-scoped Role must still cover %q; got:\n%s", want, role)
		}
	}
}

// TestRBAC_OptOutOfIdentityProviderClusterRole lets advanced operators
// bind the IdP permission themselves (e.g. via a centrally-managed
// ClusterRoleBinding). The chart must respect the opt-out and emit
// no ClusterRole/ClusterRoleBinding for identityproviders.
func TestRBAC_OptOutOfIdentityProviderClusterRole(t *testing.T) {
	manifest := helmTemplate(t,
		"controller.enabled=true",
		"controller.watchNamespace=lwauth-demo",
		"controllerRBAC.identityProviderClusterRole.enabled=false",
	)
	if strings.Contains(manifest, "name: lwtest-idp") {
		t.Fatalf("opt-out flag should suppress the lwtest-idp ClusterRole:\n%s", manifest)
	}
}

// TestGateway_DisabledByDefault asserts the chart stays a single-pod
// install when gateway.enabled is left at its default. We don't want
// the gateway sneaking in just because someone forgot to read the
// values reference.
func TestGateway_DisabledByDefault(t *testing.T) {
	manifest := helmTemplate(t)
	for _, want := range []string{"-gateway", "component: gateway", "envoyproxy/envoy"} {
		if strings.Contains(manifest, want) {
			t.Fatalf("default render must not include gateway artifacts; found %q in:\n%s", want, manifest)
		}
	}
}

// TestGateway_RequiresUpstreamService is the chart-side guardrail
// against the most likely misconfig: enabling the gateway without
// telling it where to forward. Helm should fail render rather than
// produce a Deployment that endlessly NXDOMAINs.
func TestGateway_RequiresUpstreamService(t *testing.T) {
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skipf("helm not on PATH: %v", err)
	}
	out, err := exec.Command("helm", "template", "lwtest", ".",
		"--set", "gateway.enabled=true").CombinedOutput()
	if err == nil {
		t.Fatalf("expected render failure when gateway.upstream.service is empty; got:\n%s", out)
	}
	if !strings.Contains(string(out), "gateway.upstream.service") {
		t.Fatalf("error message should mention gateway.upstream.service; got:\n%s", out)
	}
}

// TestGateway_EnabledRendersFullStack pins the happy-path render: a
// ConfigMap, Deployment, and Service are emitted with the standard
// gateway labels, and the rendered envoy.yaml wires both clusters
// (upstream + lwauth) using the release-derived addresses. We assert
// on textual fragments rather than parsing YAML so the test stays
// readable; the things asserted here are the things we'd notice if
// someone broke them in a future template refactor.
func TestGateway_EnabledRendersFullStack(t *testing.T) {
	manifest := helmTemplate(t,
		"gateway.enabled=true",
		"gateway.upstream.service=backend",
	)
	for _, want := range []string{
		// Rendered Kinds.
		"name: lwtest-gateway",
		"app.kubernetes.io/component: gateway",
		"image: \"envoyproxy/envoy:",
		// Generated envoy.yaml clusters.
		"address: backend.default.svc.cluster.local",
		"address: lwtest.default.svc.cluster.local",
		// HTTP/2 to lwauth — the most important non-default knob.
		"http2_protocol_options: {}",
		// Failure-mode default must stay closed.
		"failure_mode_allow: false",
	} {
		if !strings.Contains(manifest, want) {
			t.Fatalf("rendered gateway missing %q in:\n%s", want, manifest)
		}
	}
}

// TestGateway_AutoAdmitsItselfInLwauthNetworkPolicy proves the chart
// closes the loop: when gateway.enabled is true, the lwauth
// NetworkPolicy gets a podSelector matching the gateway Pod's labels
// without the operator having to repeat them under
// `networkPolicy.allowedFrom.podSelectors`. This was a recurring
// foot-gun before the chart owned the gateway.
func TestGateway_AutoAdmitsItselfInLwauthNetworkPolicy(t *testing.T) {
	manifest := helmTemplate(t,
		"gateway.enabled=true",
		"gateway.upstream.service=backend",
	)
	normalised := strings.ReplaceAll(manifest, "\r\n", "\n")
	npIdx := strings.Index(normalised, "kind: NetworkPolicy")
	if npIdx < 0 {
		t.Fatalf("expected a NetworkPolicy in the render; got:\n%s", normalised)
	}
	np := normalised[npIdx:]
	if end := strings.Index(np, "\n---"); end >= 0 {
		np = np[:end]
	}
	for _, want := range []string{
		"- from:",
		"app.kubernetes.io/component: gateway",
		"app.kubernetes.io/instance: lwtest",
	} {
		if !strings.Contains(np, want) {
			t.Fatalf("lwauth NetworkPolicy must auto-admit the gateway (%q missing):\n%s", want, np)
		}
	}
	if strings.Contains(np, "ingress: []") {
		t.Fatalf("gateway.enabled should override the deny-all default:\n%s", np)
	}
}
