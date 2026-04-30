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
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	v1alpha1 "github.com/mikeappsec/lightweightauth/api/crd/v1alpha1"
	"github.com/mikeappsec/lightweightauth/internal/config"
	"github.com/mikeappsec/lightweightauth/internal/server"
	"github.com/mikeappsec/lightweightauth/pkg/configstream"
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

	// Broker, if non-nil, receives a Publish() call after every
	// successful Compile-and-Swap. Remote lwauth pods subscribed via
	// the configstream gRPC server pick the snapshot up from there.
	// In single-process embedders (cmd/lwauth) this stays nil; the
	// in-process Holder.Swap is enough.
	Broker *configstream.Broker
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

	// Resolve cluster-scoped IdentityProvider references before compile,
	// so the jwt identifier (and any future bearer-style identifier) sees
	// a fully materialized config. Tenant-set fields override the IdP's
	// defaults; see ResolveIdPRefs for the merge rules.
	var idps v1alpha1.IdentityProviderList
	if err := r.Client.List(ctx, &idps); err != nil {
		return reconcile.Result{}, fmt.Errorf("list IdentityProviders: %w", err)
	}
	if err := ResolveIdPRefs(&ac.Spec, idps.Items); err != nil {
		logger.Error(err, "idpRef resolution failed; previous engine kept running")
		setReady(&ac, metav1.ConditionFalse, v1alpha1.ReasonIdPRefError, err.Error())
		_ = r.Client.Status().Update(ctx, &ac)
		return reconcile.Result{}, nil //nolint:nilerr // surfaced on status
	}

	eng, err := config.Compile(&ac.Spec)
	if err != nil {
		// Surface compile errors on the CR's status so kubectl describe
		// shows them, but don't crash the manager.
		logger.Error(err, "compile failed; previous engine kept running")
		setReady(&ac, metav1.ConditionFalse, v1alpha1.ReasonCompileError, err.Error())
		_ = r.Client.Status().Update(ctx, &ac)
		return reconcile.Result{}, nil //nolint:nilerr // we recorded it on status
	}

	r.Holder.Swap(eng)
	if r.Broker != nil {
		// Publish a deep-copied spec so subscribers can't see
		// further mutations. The CR object's spec is shared with
		// the local cache; copying via the existing DeepCopy keeps
		// us honest.
		specCopy := ac.DeepCopy().Spec
		r.Broker.Publish(&specCopy)
	}

	setReady(&ac, metav1.ConditionTrue, v1alpha1.ReasonCompiled, "compiled and swapped")
	if err := r.Client.Status().Update(ctx, &ac); err != nil {
		// Status updates are best-effort; the engine swap already happened.
		logger.Error(err, "status update failed")
	}
	return reconcile.Result{}, nil
}

// setReady writes a single Ready condition into ac.Status.Conditions
// and mirrors it onto the deprecated flat fields. Centralising the
// status mutation here means callers can never forget to keep the
// flat bool, the conditions[] entry, and ObservedGeneration in sync.
func setReady(ac *v1alpha1.AuthConfig, status metav1.ConditionStatus, reason, message string) {
	cond := metav1.Condition{
		Type:               v1alpha1.ConditionTypeReady,
		Status:             status,
		Reason:             reason,
		Message:            message,
		ObservedGeneration: ac.Generation,
	}
	meta.SetStatusCondition(&ac.Status.Conditions, cond)
	ac.Status.Ready = status == metav1.ConditionTrue
	ac.Status.ObservedGeneration = ac.Generation
	ac.Status.Message = message
}

// SetupWithManager registers the reconciler. The watch predicate filters
// down to just the named AuthConfig so we don't waste reconcile budget
// on siblings in the same namespace.
func (r *AuthConfigReconciler) SetupWithManager(mgr ctrl.Manager) error {
	// Any IdentityProvider change enqueues the single watched AuthConfig
	// so its compiled engine picks up the new key material. We don't
	// need a fan-out here because the reconciler only owns one config;
	// in a future multi-AuthConfig world this becomes a List+filter.
	enqueueWatched := handler.EnqueueRequestsFromMapFunc(
		func(_ context.Context, _ client.Object) []reconcile.Request {
			return []reconcile.Request{{NamespacedName: r.Watched}}
		},
	)
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.AuthConfig{}, builder.WithPredicates(matchesNamePredicate{Watched: r.Watched})).
		Watches(&v1alpha1.IdentityProvider{}, enqueueWatched).
		Named("authconfig").
		Complete(r)
}

// AddToScheme installs every CRD this package reconciles into the given
// runtime.Scheme. lwauthd calls this once before starting the manager.
func AddToScheme(s *runtime.Scheme) error {
	return v1alpha1.AddToScheme(s)
}
