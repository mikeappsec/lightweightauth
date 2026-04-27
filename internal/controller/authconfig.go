// Package controller hosts the controller-runtime Reconcilers that turn
// LightweightAuth CRDs into a live *pipeline.Engine. The package is
// internal/ so external embedders go through pkg/lwauthd, which decides
// when (and whether) to start the manager.
//
// Today's reconciler is intentionally narrow: it watches *one* AuthConfig
// — selected by namespace+name on the command line — and atomically
// swaps the resulting Engine into the running EngineHolder. Aggregating
// many AuthConfigs by host/path is M11 work.
package controller

import (
	"context"
	"fmt"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	v1alpha1 "github.com/yourorg/lightweightauth/api/crd/v1alpha1"
	"github.com/yourorg/lightweightauth/internal/config"
	"github.com/yourorg/lightweightauth/internal/server"
)

// AuthConfigReconciler watches a single AuthConfig and swaps the
// resulting Engine into the holder. Other AuthConfigs in the same
// namespace are ignored.
//
// Reconciler nomenclature recap:
//   - The Reconciler is invoked for any change to the watched CR.
//   - On success, returning ctrl.Result{} (no Requeue) tells the manager
//     "I'm done, call me when something else changes."
//   - On error, controller-runtime requeues with backoff.
type AuthConfigReconciler struct {
	Client client.Client
	Holder *server.EngineHolder

	// Watched is the (namespace, name) of the single AuthConfig we
	// care about. Other AuthConfigs are filtered out at the predicate
	// stage so we never even see them.
	Watched types.NamespacedName
}

// Reconcile compiles the watched AuthConfig's .spec into a
// pipeline.Engine and swaps it in. Deletion of the watched CR
// preserves the previous Engine in memory — operators can recover by
// re-creating the CR.
func (r *AuthConfigReconciler) Reconcile(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
	logger := log.FromContext(ctx).WithValues("authconfig", req.NamespacedName.String())

	if req.NamespacedName != r.Watched {
		// Predicate already filters; this is defense-in-depth.
		return reconcile.Result{}, nil
	}

	var ac v1alpha1.AuthConfig
	if err := r.Client.Get(ctx, req.NamespacedName, &ac); err != nil {
		if apierrors.IsNotFound(err) {
			// CR was deleted. Keep the last good engine running.
			logger.Info("watched AuthConfig deleted; keeping last good engine")
			return reconcile.Result{}, nil
		}
		return reconcile.Result{}, fmt.Errorf("get AuthConfig: %w", err)
	}

	eng, err := config.Compile(&ac.Spec)
	if err != nil {
		// Surface compile errors on the CR's status so kubectl describe
		// shows them, but don't crash the manager.
		logger.Error(err, "compile failed; previous engine kept running")
		ac.Status = v1alpha1.AuthConfigStatus{
			Ready:              false,
			ObservedGeneration: ac.Generation,
			Message:            err.Error(),
		}
		_ = r.Client.Status().Update(ctx, &ac)
		return reconcile.Result{}, nil //nolint:nilerr // we recorded it on status
	}

	r.Holder.Swap(eng)

	ac.Status = v1alpha1.AuthConfigStatus{
		Ready:              true,
		ObservedGeneration: ac.Generation,
		Message:            "compiled and swapped",
	}
	if err := r.Client.Status().Update(ctx, &ac); err != nil {
		// Status updates are best-effort; the engine swap already happened.
		logger.Error(err, "status update failed")
	}
	return reconcile.Result{}, nil
}

// SetupWithManager registers the reconciler. The watch predicate filters
// down to just the named AuthConfig so we don't waste reconcile budget
// on siblings in the same namespace.
func (r *AuthConfigReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.AuthConfig{}).
		WithEventFilter(matchesNamePredicate{Watched: r.Watched}).
		Named("authconfig").
		Complete(r)
}

// AddToScheme installs every CRD this package reconciles into the given
// runtime.Scheme. lwauthd calls this once before starting the manager.
func AddToScheme(s *runtime.Scheme) error {
	return v1alpha1.AddToScheme(s)
}
