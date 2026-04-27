package controller_test

import (
	"context"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	v1alpha1 "github.com/mikeappsec/lightweightauth/api/crd/v1alpha1"
	"github.com/mikeappsec/lightweightauth/internal/config"
	"github.com/mikeappsec/lightweightauth/internal/controller"
	"github.com/mikeappsec/lightweightauth/internal/server"

	_ "github.com/mikeappsec/lightweightauth/pkg/builtins"
)

// makeAuthConfig returns a minimal but valid AuthConfig that uses
// in-memory apikey + rbac so no external services are needed.
func makeAuthConfig(name, ns string) *v1alpha1.AuthConfig {
	return &v1alpha1.AuthConfig{
		TypeMeta: metav1.TypeMeta{
			APIVersion: v1alpha1.GroupVersion.String(),
			Kind:       "AuthConfig",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:       name,
			Namespace:  ns,
			Generation: 7,
		},
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
				Name: "rbac",
				Type: "rbac",
				Config: map[string]any{
					"rolesFrom": "claim:roles",
					"allow":     []any{"admin"},
				},
			}},
		},
	}
}

func newScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	if err := v1alpha1.AddToScheme(s); err != nil {
		t.Fatalf("AddToScheme: %v", err)
	}
	return s
}

// TestReconcile_HappyPath: creating a watched AuthConfig leads to the
// engine being installed and status going Ready=true.
func TestReconcile_HappyPath(t *testing.T) {
	t.Parallel()
	s := newScheme(t)
	ac := makeAuthConfig("default", "lwauth")

	cli := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(ac).
		WithStatusSubresource(&v1alpha1.AuthConfig{}).
		Build()

	holder := server.NewEngineHolder(nil)
	r := &controller.AuthConfigReconciler{
		Client:  cli,
		Holder:  holder,
		Watched: types.NamespacedName{Namespace: "lwauth", Name: "default"},
	}

	res, err := r.Reconcile(context.Background(), reconcile.Request{
		NamespacedName: r.Watched,
	})
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if res.Requeue || res.RequeueAfter != 0 {
		t.Errorf("expected no requeue, got %+v", res)
	}
	if holder.Load() == nil {
		t.Fatal("engine was not installed in holder")
	}

	// Status round-trip: status sub-resource should reflect Ready=true.
	var got v1alpha1.AuthConfig
	if err := cli.Get(context.Background(), r.Watched, &got); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !got.Status.Ready || got.Status.ObservedGeneration != 7 {
		t.Errorf("status = %+v, want Ready=true ObservedGeneration=7", got.Status)
	}
}

// TestReconcile_CompileError: a malformed spec must NOT install an
// engine, MUST surface the error on .status, and MUST NOT crash.
func TestReconcile_CompileError(t *testing.T) {
	t.Parallel()
	s := newScheme(t)
	bad := makeAuthConfig("default", "lwauth")
	// Invalid: unknown identifier type.
	bad.Spec.Identifiers[0].Type = "no-such-identifier"

	cli := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(bad).
		WithStatusSubresource(&v1alpha1.AuthConfig{}).
		Build()

	holder := server.NewEngineHolder(nil)
	r := &controller.AuthConfigReconciler{
		Client:  cli,
		Holder:  holder,
		Watched: types.NamespacedName{Namespace: "lwauth", Name: "default"},
	}

	if _, err := r.Reconcile(context.Background(), reconcile.Request{
		NamespacedName: r.Watched,
	}); err != nil {
		t.Fatalf("Reconcile (compile-error path) returned error: %v", err)
	}
	if holder.Load() != nil {
		t.Errorf("engine should NOT be installed on compile error")
	}
	var got v1alpha1.AuthConfig
	if err := cli.Get(context.Background(), r.Watched, &got); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Status.Ready {
		t.Errorf("Ready should be false; status=%+v", got.Status)
	}
	if got.Status.Message == "" {
		t.Errorf("Message should carry the compile error")
	}
}

// TestReconcile_DeletePreservesEngine: deleting the watched CR keeps
// the last good engine running. Operators recover by re-creating.
func TestReconcile_DeletePreservesEngine(t *testing.T) {
	t.Parallel()
	s := newScheme(t)
	ac := makeAuthConfig("default", "lwauth")

	cli := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(ac).
		WithStatusSubresource(&v1alpha1.AuthConfig{}).
		Build()

	holder := server.NewEngineHolder(nil)
	r := &controller.AuthConfigReconciler{
		Client:  cli,
		Holder:  holder,
		Watched: types.NamespacedName{Namespace: "lwauth", Name: "default"},
	}

	// First reconcile -> engine installed.
	if _, err := r.Reconcile(context.Background(), reconcile.Request{
		NamespacedName: r.Watched,
	}); err != nil {
		t.Fatalf("Reconcile #1: %v", err)
	}
	first := holder.Load()
	if first == nil {
		t.Fatal("engine missing after first reconcile")
	}

	// Delete the CR.
	if err := cli.Delete(context.Background(), ac); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	// Second reconcile (NotFound) -> engine retained.
	if _, err := r.Reconcile(context.Background(), reconcile.Request{
		NamespacedName: r.Watched,
	}); err != nil {
		t.Fatalf("Reconcile #2: %v", err)
	}
	if holder.Load() != first {
		t.Errorf("engine pointer changed after delete; want previous engine retained")
	}
}
