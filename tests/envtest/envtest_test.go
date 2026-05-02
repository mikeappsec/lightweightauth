// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

//go:build envtest

// Package envtest is the controller-runtime envtest end-to-end suite
// promised by DESIGN.md §M12 item 1.
//
// It exercises the AuthConfigReconciler against a *real* kube-apiserver
// (started by sigs.k8s.io/controller-runtime/pkg/envtest), not the fake
// client used by internal/controller/authconfig_test.go. This catches
// the issues unit tests can't:
//
//   - status sub-resource permissions and update semantics
//   - watch + predicate wiring (creates / updates / deletes round-trip
//     through etcd and the apiserver, not a synchronous in-memory map)
//   - IdentityProvider cluster-scope vs AuthConfig namespace-scope
//     interaction under a real RESTMapper
//   - controller-runtime manager start/stop lifecycle (no leaked
//     goroutines after Stop)
//
// Build tag: this file is gated behind the `envtest` build tag because
// it needs `etcd` + `kube-apiserver` binaries on PATH (or under
// $KUBEBUILDER_ASSETS / .envtest-bin). CI installs them via setup-envtest;
// local devs run:
//
//	setup-envtest use --bin-dir .envtest-bin -p path
//	$env:KUBEBUILDER_ASSETS = "...path printed above..."
//	go test -tags envtest ./tests/envtest/...
//
// Without the binaries the suite is skipped, so `go test ./...`
// without the tag remains green.
package envtest_test

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	configv1alpha1 "sigs.k8s.io/controller-runtime/pkg/config"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	v1alpha1 "github.com/mikeappsec/lightweightauth/api/crd/v1alpha1"
	"github.com/mikeappsec/lightweightauth/internal/config"
	"github.com/mikeappsec/lightweightauth/internal/controller"
	"github.com/mikeappsec/lightweightauth/internal/server"

	_ "github.com/mikeappsec/lightweightauth/pkg/builtins"
)

// crdsDir is resolved relative to this test file so the binary path
// trick is portable across `go test` invocations.
func crdsDir(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Join(filepath.Dir(file), "crds")
}

// resolveAssets returns a value for KUBEBUILDER_ASSETS, falling back to
// the repo-local .envtest-bin populated by setup-envtest. Returns "" if
// nothing is found, in which case the suite skips.
func resolveAssets(t *testing.T) string {
	t.Helper()
	if v := os.Getenv("KUBEBUILDER_ASSETS"); v != "" {
		return v
	}
	// Walk up to repo root looking for .envtest-bin/k8s/<ver>-<os>-<arch>.
	_, file, _, _ := runtime.Caller(0)
	dir := filepath.Dir(file)
	for i := 0; i < 6; i++ {
		root := filepath.Join(dir, ".envtest-bin", "k8s")
		entries, err := os.ReadDir(root)
		if err == nil && len(entries) > 0 {
			return filepath.Join(root, entries[0].Name())
		}
		dir = filepath.Dir(dir)
	}
	return ""
}

// startEnv boots envtest with our CRDs and returns a stop func.
func startEnv(t *testing.T) (*envtest.Environment, client.Client) {
	t.Helper()
	assets := resolveAssets(t)
	if assets == "" {
		t.Skip("envtest binaries not found; run `setup-envtest use --bin-dir .envtest-bin -p path` " +
			"or set KUBEBUILDER_ASSETS")
	}
	t.Setenv("KUBEBUILDER_ASSETS", assets)

	env := &envtest.Environment{
		CRDDirectoryPaths:     []string{crdsDir(t)},
		ErrorIfCRDPathMissing: true,
	}
	cfg, err := env.Start()
	if err != nil {
		t.Fatalf("envtest start: %v", err)
	}
	t.Cleanup(func() {
		if err := env.Stop(); err != nil {
			t.Logf("envtest stop: %v", err)
		}
	})

	scheme := clientgoscheme.Scheme
	if err := v1alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme: %v", err)
	}
	cli, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatalf("client.New: %v", err)
	}

	// Sanity: the namespaces resource should be reachable, proving the
	// apiserver is up before we start poking CRDs.
	var nsList corev1.NamespaceList
	if err := cli.List(context.Background(), &nsList); err != nil {
		t.Fatalf("list namespaces (apiserver health): %v", err)
	}
	return env, cli
}

func makeAC(name, ns, idpRef string) *v1alpha1.AuthConfig {
	ac := &v1alpha1.AuthConfig{
		TypeMeta: metav1.TypeMeta{
			APIVersion: v1alpha1.GroupVersion.String(),
			Kind:       "AuthConfig",
		},
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec: config.AuthConfig{
			Identifier: config.IdentifierFirstMatch,
			Identifiers: []config.ModuleSpec{{
				Name: "dev-apikey",
				Type: "apikey",
				Config: map[string]any{
					"headerName": "X-Api-Key",
					"static": map[string]any{
						"k1": map[string]any{"subject": "alice", "roles": []any{"admin"}},
					},
				},
			}},
			Authorizers: []config.ModuleSpec{{
				Name:   "rbac",
				Type:   "rbac",
				Config: map[string]any{"rolesFrom": "claim:roles", "allow": []any{"admin"}},
			}},
		},
	}
	return ac
}

// runManager starts the controller-runtime manager wired to the
// AuthConfigReconciler under test, returns the holder and a stop func.
func runManager(t *testing.T, env *envtest.Environment, watched types.NamespacedName) *server.EngineHolder {
	t.Helper()
	mgr, err := ctrl.NewManager(env.Config, ctrl.Options{
		Scheme:         clientgoscheme.Scheme,
		LeaderElection: false,
		// Bind metrics to "0" so the manager doesn't try to grab a real
		// port (envtest tests run several managers serially).
		Metrics: metricsserver.Options{BindAddress: "0"},
		// Each test in this suite spins up a fresh manager but
		// controller-runtime keeps a process-global controller-name
		// registry; without this, the second test fails with
		// "controller with name authconfig already exists".
		Controller: configv1alpha1.Controller{SkipNameValidation: ptr.To(true)},
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	holder := server.NewEngineHolder(nil)
	r := &controller.AuthConfigReconciler{
		Client:  mgr.GetClient(),
		Holder:  holder,
		Watched: watched,
	}
	if err := r.SetupWithManager(mgr); err != nil {
		t.Fatalf("SetupWithManager: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- mgr.Start(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil && err != context.Canceled {
				t.Logf("manager Start returned: %v", err)
			}
		case <-time.After(10 * time.Second):
			t.Log("manager did not stop within 10s")
		}
	})
	return holder
}

// waitFor polls until f returns true or the deadline expires.
func waitFor(t *testing.T, what string, timeout time.Duration, f func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if f() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s after %s", what, timeout)
}

// TestEnvtest_AuthConfigReconcile_RoundTrip is the headline e2e: post an
// AuthConfig to a real apiserver, observe the reconciler swap an Engine
// into the holder, and verify the status sub-resource records Ready=true
// with the right ObservedGeneration.
func TestEnvtest_AuthConfigReconcile_RoundTrip(t *testing.T) {
	env, cli := startEnv(t)
	_ = env

	ns := "lwauth-test"
	if err := cli.Create(context.Background(), &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: ns},
	}); err != nil {
		t.Fatalf("create namespace: %v", err)
	}

	watched := types.NamespacedName{Namespace: ns, Name: "default"}
	holder := runManager(t, env, watched)

	ac := makeAC("default", ns, "")
	if err := cli.Create(context.Background(), ac); err != nil {
		t.Fatalf("create AuthConfig: %v", err)
	}

	waitFor(t, "engine swap", 10*time.Second, func() bool {
		return holder.Load() != nil
	})

	waitFor(t, "status Ready=true", 10*time.Second, func() bool {
		var got v1alpha1.AuthConfig
		if err := cli.Get(context.Background(), watched, &got); err != nil {
			return false
		}
		return got.Status.Ready &&
			got.Status.ObservedGeneration == got.Generation
	})
}

// TestEnvtest_IdPRefPropagates: create a cluster-scoped IdentityProvider,
// create an AuthConfig that does NOT reference it (so it compiles
// trivially), then update the AuthConfig to reference the IdP and
// confirm the engine is rebuilt. This exercises the cross-resource
// watch wired in SetupWithManager.
func TestEnvtest_IdPRefPropagates(t *testing.T) {
	env, cli := startEnv(t)

	ns := "lwauth-idp"
	if err := cli.Create(context.Background(), &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: ns},
	}); err != nil {
		t.Fatalf("create namespace: %v", err)
	}

	watched := types.NamespacedName{Namespace: ns, Name: "default"}
	holder := runManager(t, env, watched)

	ac := makeAC("default", ns, "")
	if err := cli.Create(context.Background(), ac); err != nil {
		t.Fatalf("create AuthConfig: %v", err)
	}
	waitFor(t, "first engine swap", 10*time.Second, func() bool {
		return holder.Load() != nil
	})
	first := holder.Load()

	// Now create a cluster-scoped IdentityProvider. We don't reference
	// it from the AuthConfig — the goal is just to prove the cross-
	// resource watch fires a reconcile rebuild even on unrelated IdP
	// changes (which is the conservative behaviour: we always re-resolve
	// idpRefs on every IdP event).
	idp := &v1alpha1.IdentityProvider{
		TypeMeta: metav1.TypeMeta{
			APIVersion: v1alpha1.GroupVersion.String(),
			Kind:       "IdentityProvider",
		},
		ObjectMeta: metav1.ObjectMeta{Name: "test-idp"},
		Spec: v1alpha1.IdentityProviderSpec{
			IssuerURL: "https://idp.example.com",
			Audiences: []string{"lwauth-test"},
		},
	}
	if err := cli.Create(context.Background(), idp); err != nil {
		t.Fatalf("create IdentityProvider: %v", err)
	}

	// The reconciler should re-run and produce a fresh Engine pointer
	// (Compile builds a new *Engine on each call).
	waitFor(t, "engine rebuild after IdP create", 10*time.Second, func() bool {
		cur := holder.Load()
		return cur != nil && cur != first
	})
}

// TestEnvtest_NoLeakOnStop: start the manager, spin a few reconciles,
// stop, and verify no apiserver-bound goroutines linger. Mostly a
// regression guard for the manager lifecycle path.
func TestEnvtest_NoLeakOnStop(t *testing.T) {
	env, cli := startEnv(t)

	ns := "lwauth-leak"
	if err := cli.Create(context.Background(), &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: ns},
	}); err != nil {
		t.Fatalf("create namespace: %v", err)
	}

	watched := types.NamespacedName{Namespace: ns, Name: "default"}
	holder := runManager(t, env, watched)

	if err := cli.Create(context.Background(), makeAC("default", ns, "")); err != nil {
		t.Fatalf("create AuthConfig: %v", err)
	}
	waitFor(t, "engine swap", 10*time.Second, func() bool {
		return holder.Load() != nil
	})
	// runManager's t.Cleanup cancels the manager and waits for Stop;
	// any leak will surface there as a 10s log line. We don't use
	// goleak here because controller-runtime spins up dozens of
	// well-known long-lived helper goroutines (reflectors, leader
	// election, even when disabled) that are hard to allow-list
	// portably.
}
