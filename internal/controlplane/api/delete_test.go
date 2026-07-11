// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package api_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/mikeappsec/lightweightauth/internal/controlplane/api"
	"github.com/mikeappsec/lightweightauth/internal/controlplane/configmgmt"
	"github.com/mikeappsec/lightweightauth/internal/controlplane/discovery"
	"github.com/mikeappsec/lightweightauth/internal/controlplane/metrics"
	"github.com/mikeappsec/lightweightauth/internal/controlplane/multicluster"
	"github.com/mikeappsec/lightweightauth/internal/controlplane/routes"
	"github.com/mikeappsec/lightweightauth/internal/controlplane/streaming"
)

func cpLabels(name string) map[string]string {
	return map[string]string{
		"app.kubernetes.io/name":       "lwauth",
		"app.kubernetes.io/instance":   name,
		"app.kubernetes.io/managed-by": "lwauth-controlplane",
	}
}

func newServerWithClient(kc client.Client) *api.Server {
	registry := discovery.NewRegistry()
	aggregator := metrics.NewAggregator(registry)
	clusterMgr := multicluster.NewManager(registry)
	configStore := configmgmt.NewStore()
	routeStore := routes.NewStore(registry)
	hub := streaming.NewHub(registry, aggregator)
	return api.NewServer(registry, clusterMgr, configStore, routeStore, aggregator, hub, kc, "")
}

func TestHandleDeleteInstance_FullTeardown(t *testing.T) {
	name, ns := "payments-auth", "lwauth-system"
	labels := cpLabels(name)

	seed := []client.Object{
		&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns, Labels: labels}},
		&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns, Labels: labels}},
		&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: name + "-config", Namespace: ns, Labels: labels}},
		// A CP-owned secret (labelled) should be removed.
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: name + "-tls", Namespace: ns, Labels: labels}},
		// An externally-managed secret (no CP labels) must be preserved.
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "shared-wildcard-tls", Namespace: ns}},
	}
	kc := fake.NewClientBuilder().WithObjects(seed...).Build()
	s := newServerWithClient(kc)

	// Register as an auto-discovered instance so teardown runs.
	s.Registry.Register(&discovery.Instance{
		Name: name, Cluster: "local", Namespace: ns,
		Source: discovery.SourceAutoDiscovery,
	})

	req := httptest.NewRequest(http.MethodDelete, "/v1/controlplane/instances/local/"+name, nil)
	rr := httptest.NewRecorder()
	s.Mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", rr.Code, rr.Body.String())
	}

	ctx := context.Background()
	assertGone := func(obj client.Object, key string) {
		err := kc.Get(ctx, client.ObjectKeyFromObject(obj), obj)
		if !apierrors.IsNotFound(err) {
			t.Errorf("expected %s to be deleted, err=%v", key, err)
		}
	}
	assertGone(&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns}}, "deployment")
	assertGone(&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns}}, "service")
	assertGone(&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: name + "-config", Namespace: ns}}, "configmap")
	assertGone(&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: name + "-tls", Namespace: ns}}, "cp-secret")

	// Shared secret must survive.
	shared := &corev1.Secret{}
	if err := kc.Get(ctx, client.ObjectKey{Name: "shared-wildcard-tls", Namespace: ns}, shared); err != nil {
		t.Errorf("externally-managed secret must be preserved, got err=%v", err)
	}

	// Instance must be removed from the registry.
	if _, ok := s.Registry.Get("local", name); ok {
		t.Error("instance should be deregistered after delete")
	}
}

func TestHandleDeleteInstance_ManualLeavesClusterAlone(t *testing.T) {
	name, ns := "external-node", "demo"
	kc := fake.NewClientBuilder().WithObjects(
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: name + "-tls", Namespace: ns, Labels: cpLabels(name)}},
	).Build()
	s := newServerWithClient(kc)

	s.Registry.Register(&discovery.Instance{
		Name: name, Cluster: "local", Namespace: ns,
		Source: discovery.SourceManual,
	})

	req := httptest.NewRequest(http.MethodDelete, "/v1/controlplane/instances/local/"+name, nil)
	rr := httptest.NewRecorder()
	s.Mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", rr.Code)
	}
	// Manual instances own no cluster resources; the labelled secret is left intact.
	sec := &corev1.Secret{}
	if err := kc.Get(context.Background(), client.ObjectKey{Name: name + "-tls", Namespace: ns}, sec); err != nil {
		t.Errorf("manual delete must not touch cluster resources, err=%v", err)
	}
}

func TestHandleDeleteInstance_NotFound(t *testing.T) {
	kc := fake.NewClientBuilder().Build()
	s := newServerWithClient(kc)
	req := httptest.NewRequest(http.MethodDelete, "/v1/controlplane/instances/local/ghost", nil)
	rr := httptest.NewRecorder()
	s.Mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rr.Code)
	}
}
