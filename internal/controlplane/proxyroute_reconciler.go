// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package controlplane

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	v1alpha1 "github.com/mikeappsec/lightweightauth/api/crd/v1alpha1"
	"github.com/mikeappsec/lightweightauth/internal/controlplane/discovery"
)

const (
	proxyRouteFinalizer   = "lightweightauth.io/proxyroute-cleanup"
	conditionTypeReady    = "Ready"
	conditionTypeHealthy  = "Healthy"
	reasonReconciled      = "Reconciled"
	reasonSourceNotFound  = "SourceNotFound"
	reasonTargetNotFound  = "TargetNotFound"
	reasonNotAllowed      = "NotAllowed"
	reasonTargetUnhealthy = "TargetUnhealthy"
	reasonProbeSucceeded  = "ProbeSucceeded"
	reasonProbeFailed     = "ProbeFailed"
)

// ProxyRouteReconciler reconciles ProxyRoute CRDs.
type ProxyRouteReconciler struct {
	Client   client.Client
	Scheme   *runtime.Scheme
	Registry *discovery.Registry
}

// SetupWithManager registers the reconciler.
func (r *ProxyRouteReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.ProxyRoute{}).
		Complete(r)
}

// Reconcile ensures the ProxyRoute is valid and the target is reachable.
func (r *ProxyRouteReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx).WithValues("proxyroute", req.NamespacedName)

	var route v1alpha1.ProxyRoute
	if err := r.Client.Get(ctx, req.NamespacedName, &route); err != nil {
		if client.IgnoreNotFound(err) == nil {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	// Handle deletion.
	if !route.DeletionTimestamp.IsZero() {
		if controllerutil.ContainsFinalizer(&route, proxyRouteFinalizer) {
			controllerutil.RemoveFinalizer(&route, proxyRouteFinalizer)
			if err := r.Client.Update(ctx, &route); err != nil {
				return ctrl.Result{}, err
			}
		}
		return ctrl.Result{}, nil
	}

	// Ensure finalizer.
	if !controllerutil.ContainsFinalizer(&route, proxyRouteFinalizer) {
		controllerutil.AddFinalizer(&route, proxyRouteFinalizer)
		if err := r.Client.Update(ctx, &route); err != nil {
			return ctrl.Result{}, err
		}
	}

	// Resolve source instance.
	sourceCluster := route.Spec.Source.Cluster
	if sourceCluster == "" {
		sourceCluster = "local"
	}
	sourceInst, ok := r.Registry.Get(sourceCluster, route.Spec.Source.InstanceRef)
	if !ok {
		logger.Info("source instance not found", "instance", route.Spec.Source.InstanceRef)
		r.setCondition(&route, conditionTypeReady, metav1.ConditionFalse, reasonSourceNotFound,
			fmt.Sprintf("source instance %q not found in cluster %q", route.Spec.Source.InstanceRef, sourceCluster))
		_ = r.Client.Status().Update(ctx, &route)
		return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
	}

	// Resolve target instance.
	targetCluster := route.Spec.Target.Cluster
	if targetCluster == "" {
		targetCluster = "local"
	}
	targetInst, ok := r.Registry.Get(targetCluster, route.Spec.Target.InstanceRef)
	if !ok {
		logger.Info("target instance not found", "instance", route.Spec.Target.InstanceRef)
		r.setCondition(&route, conditionTypeReady, metav1.ConditionFalse, reasonTargetNotFound,
			fmt.Sprintf("target instance %q not found in cluster %q", route.Spec.Target.InstanceRef, targetCluster))
		_ = r.Client.Status().Update(ctx, &route)
		return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
	}

	// Allowlist enforcement (3.6).
	if len(route.Spec.Target.AllowSources) > 0 {
		allowed := false
		for _, src := range route.Spec.Target.AllowSources {
			if src == route.Spec.Source.InstanceRef {
				allowed = true
				break
			}
		}
		if !allowed {
			logger.Info("source not in target allowSources", "source", route.Spec.Source.InstanceRef)
			r.setCondition(&route, conditionTypeReady, metav1.ConditionFalse, reasonNotAllowed,
				fmt.Sprintf("source %q not in target's allowSources", route.Spec.Source.InstanceRef))
			route.Status.Healthy = false
			_ = r.Client.Status().Update(ctx, &route)
			return ctrl.Result{}, nil
		}
	}

	// Probe target health (3.7).
	healthy := r.probeTarget(ctx, targetInst, route.Spec.Source.PathPrefix)
	now := metav1.Now()
	route.Status.LastProbe = &now
	route.Status.Healthy = healthy

	if healthy {
		r.setCondition(&route, conditionTypeHealthy, metav1.ConditionTrue, reasonProbeSucceeded, "target responds to health probe")
		r.setCondition(&route, conditionTypeReady, metav1.ConditionTrue, reasonReconciled,
			fmt.Sprintf("route %s → %s active", sourceInst.Name, targetInst.Name))
	} else {
		r.setCondition(&route, conditionTypeHealthy, metav1.ConditionFalse, reasonProbeFailed, "target unreachable or unhealthy")
		r.setCondition(&route, conditionTypeReady, metav1.ConditionFalse, reasonTargetUnhealthy, "target probe failed")
	}

	if err := r.Client.Status().Update(ctx, &route); err != nil {
		return ctrl.Result{}, err
	}

	// Re-probe periodically.
	return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
}

// probeTarget verifies the target instance is reachable.
func (r *ProxyRouteReconciler) probeTarget(ctx context.Context, target *discovery.Instance, pathPrefix string) bool {
	if target.AdminURL == "" {
		return false
	}

	url := target.AdminURL + "/v1/admin/status"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false
	}

	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

func (r *ProxyRouteReconciler) setCondition(route *v1alpha1.ProxyRoute, condType string, status metav1.ConditionStatus, reason, message string) {
	meta.SetStatusCondition(&route.Status.Conditions, metav1.Condition{
		Type:               condType,
		Status:             status,
		ObservedGeneration: route.Generation,
		LastTransitionTime: metav1.Now(),
		Reason:             reason,
		Message:            message,
	})
}
