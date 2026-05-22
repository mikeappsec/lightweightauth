// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

//go:build envtest

// Package envtest_test contains the control-plane envtest suite.
// It verifies the full create → reconcile → discover → health → delete
// lifecycle for LwauthInstance resources.
//
// Run:
//
//	setup-envtest use --bin-dir .envtest-bin -p path
//	$env:KUBEBUILDER_ASSETS = "...path printed above..."
//	go test -tags envtest ./tests/envtest/ -run TestControlPlane
package envtest_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	v1alpha1 "github.com/mikeappsec/lightweightauth/api/crd/v1alpha1"
	"github.com/mikeappsec/lightweightauth/internal/controlplane"
	cpapi "github.com/mikeappsec/lightweightauth/internal/controlplane/api"
	"github.com/mikeappsec/lightweightauth/internal/controlplane/discovery"
)

// TestControlPlane_InstanceLifecycle exercises the full lifecycle:
// create LwauthInstance → reconciler creates Deployment+Service+PDB →
// manual register → health check → deregister → delete instance.
func TestControlPlane_InstanceLifecycle(t *testing.T) {
	env, k8sClient := startEnv(t)
	_ = env

	// Register additional schemes.
	scheme := clientgoscheme.Scheme
	if err := appsv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := policyv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Create test namespace.
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "cp-test"}}
	if err := k8sClient.Create(ctx, ns); err != nil {
		t.Fatalf("create namespace: %v", err)
	}

	// Start manager with InstanceReconciler.
	mgr, err := ctrl.NewManager(env.Config, ctrl.Options{
		Scheme: scheme,
		Metrics: metricsserver.Options{
			BindAddress: "0", // disable
		},
	})
	if err != nil {
		t.Fatalf("create manager: %v", err)
	}

	reconciler := &controlplane.InstanceReconciler{
		Client:       mgr.GetClient(),
		Scheme:       mgr.GetScheme(),
		DefaultImage: "ghcr.io/mikeappsec/lightweightauth:test",
	}
	if err := reconciler.SetupWithManager(mgr); err != nil {
		t.Fatalf("setup reconciler: %v", err)
	}

	mgrCtx, mgrCancel := context.WithCancel(ctx)
	defer mgrCancel()
	go func() {
		if err := mgr.Start(mgrCtx); err != nil {
			t.Logf("manager stopped: %v", err)
		}
	}()

	// Wait for cache sync.
	if !mgr.GetCache().WaitForCacheSync(ctx) {
		t.Fatal("cache sync failed")
	}

	// --- Step 1: Create LwauthInstance ---
	instance := &v1alpha1.LwauthInstance{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-instance",
			Namespace: "cp-test",
		},
		Spec: v1alpha1.LwauthInstanceSpec{
			Replicas: int32Ptr(2),
			Version:  "v1.0.0",
		},
	}
	if err := k8sClient.Create(ctx, instance); err != nil {
		t.Fatalf("create LwauthInstance: %v", err)
	}

	// Wait for Deployment to appear.
	deploy := &appsv1.Deployment{}
	if err := waitForObject(ctx, k8sClient, types.NamespacedName{
		Name: "test-instance", Namespace: "cp-test",
	}, deploy, 10*time.Second); err != nil {
		t.Fatalf("waiting for Deployment: %v", err)
	}

	if *deploy.Spec.Replicas != 2 {
		t.Errorf("expected 2 replicas, got %d", *deploy.Spec.Replicas)
	}

	// Verify Service created.
	svc := &corev1.Service{}
	if err := waitForObject(ctx, k8sClient, types.NamespacedName{
		Name: "test-instance", Namespace: "cp-test",
	}, svc, 5*time.Second); err != nil {
		t.Fatalf("waiting for Service: %v", err)
	}

	// Verify PDB created.
	pdb := &policyv1.PodDisruptionBudget{}
	if err := waitForObject(ctx, k8sClient, types.NamespacedName{
		Name: "test-instance", Namespace: "cp-test",
	}, pdb, 5*time.Second); err != nil {
		t.Fatalf("waiting for PDB: %v", err)
	}

	// --- Step 2: Manual registration + API ---
	registry := discovery.NewRegistry()
	apiServer := cpapi.NewServer(registry)

	// Start a fake admin endpoint to simulate a live lwauth instance.
	fakeAdmin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"healthy","version":"v1.0.0"}`))
	}))
	defer fakeAdmin.Close()

	// Register via API.
	regBody := fmt.Sprintf(`{"name":"test-instance","cluster":"local","adminUrl":"%s"}`, fakeAdmin.URL)
	req := httptest.NewRequest(http.MethodPost, "/v1/controlplane/instances/register", jsonBody(regBody))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	apiServer.Mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("register: expected 201, got %d: %s", rec.Code, rec.Body.String())
	}

	// --- Step 3: Verify instance appears in list ---
	req = httptest.NewRequest(http.MethodGet, "/v1/controlplane/instances", nil)
	rec = httptest.NewRecorder()
	apiServer.Mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("list: expected 200, got %d", rec.Code)
	}

	var instances []map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &instances); err != nil {
		t.Fatalf("unmarshal list: %v", err)
	}
	if len(instances) != 1 {
		t.Fatalf("expected 1 instance, got %d", len(instances))
	}

	// --- Step 4: Health check ---
	healthChecker := discovery.NewHealthChecker(registry)
	healthCtx, healthCancel := context.WithCancel(ctx)
	go healthChecker.Run(healthCtx)

	// Give health checker time to probe.
	time.Sleep(3 * time.Second)
	healthCancel()

	// Verify instance is now healthy.
	inst := registry.Get("local", "test-instance")
	if inst == nil {
		t.Fatal("instance not found in registry after health check")
	}
	if inst.Status.Healthy != true {
		t.Errorf("expected healthy=true, got %v", inst.Status.Healthy)
	}

	// --- Step 5: Get single instance ---
	req = httptest.NewRequest(http.MethodGet, "/v1/controlplane/instances/local/test-instance", nil)
	rec = httptest.NewRecorder()
	apiServer.Mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("get instance: expected 200, got %d", rec.Code)
	}

	// --- Step 6: Delete (deregister) instance ---
	req = httptest.NewRequest(http.MethodDelete, "/v1/controlplane/instances/local/test-instance", nil)
	rec = httptest.NewRecorder()
	apiServer.Mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete: expected 204, got %d: %s", rec.Code, rec.Body.String())
	}

	// Confirm gone.
	req = httptest.NewRequest(http.MethodGet, "/v1/controlplane/instances/local/test-instance", nil)
	rec = httptest.NewRecorder()
	apiServer.Mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("after delete: expected 404, got %d", rec.Code)
	}

	// --- Step 7: Delete the CRD resource ---
	if err := k8sClient.Delete(ctx, instance); err != nil {
		t.Fatalf("delete LwauthInstance: %v", err)
	}

	// Verify Deployment is eventually deleted by the reconciler (ownerRef GC).
	// In envtest, GC doesn't run, so we just verify the delete call succeeds.
	t.Log("control-plane lifecycle test passed")
}

// TestControlPlane_APIValidation tests input validation on the registration endpoint.
func TestControlPlane_APIValidation(t *testing.T) {
	registry := discovery.NewRegistry()
	apiServer := cpapi.NewServer(registry)

	tests := []struct {
		name   string
		body   string
		expect int
	}{
		{"empty body", `{}`, http.StatusBadRequest},
		{"missing name", `{"cluster":"c","adminUrl":"http://x"}`, http.StatusBadRequest},
		{"missing cluster", `{"name":"n","adminUrl":"http://x"}`, http.StatusBadRequest},
		{"missing adminUrl", `{"name":"n","cluster":"c"}`, http.StatusBadRequest},
		{"invalid url scheme", `{"name":"n","cluster":"c","adminUrl":"ftp://x"}`, http.StatusBadRequest},
		{"valid", `{"name":"n","cluster":"c","adminUrl":"http://localhost:8081"}`, http.StatusCreated},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/v1/controlplane/instances/register", jsonBody(tt.body))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			apiServer.Mux.ServeHTTP(rec, req)
			if rec.Code != tt.expect {
				t.Errorf("expected %d, got %d: %s", tt.expect, rec.Code, rec.Body.String())
			}
		})
	}
}

// TestControlPlane_HealthEndpoint verifies the /health endpoint.
func TestControlPlane_HealthEndpoint(t *testing.T) {
	registry := discovery.NewRegistry()
	apiServer := cpapi.NewServer(registry)

	req := httptest.NewRequest(http.MethodGet, "/v1/controlplane/health", nil)
	rec := httptest.NewRecorder()
	apiServer.Mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
}

// --- Helpers ---

func int32Ptr(i int32) *int32 { return &i }

func jsonBody(s string) *jsonReader {
	return &jsonReader{data: []byte(s)}
}

type jsonReader struct {
	data []byte
	pos  int
}

func (r *jsonReader) Read(p []byte) (int, error) {
	if r.pos >= len(r.data) {
		return 0, fmt.Errorf("EOF")
	}
	n := copy(p, r.data[r.pos:])
	r.pos += n
	if r.pos >= len(r.data) {
		return n, fmt.Errorf("EOF")
	}
	return n, nil
}

func waitForObject(ctx context.Context, c client.Client, key types.NamespacedName, obj client.Object, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if err := c.Get(ctx, key, obj); err == nil {
			return nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	return fmt.Errorf("timed out waiting for %s/%s", key.Namespace, key.Name)
}

// freePort returns an available TCP port on localhost.
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	return port
}
