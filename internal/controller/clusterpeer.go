// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"fmt"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	v1alpha1 "github.com/mikeappsec/lightweightauth/api/crd/v1alpha1"
	"github.com/mikeappsec/lightweightauth/pkg/federation"
)

// ClusterPeerReconciler watches ClusterPeer CRDs and manages federation
// connections to remote clusters.
type ClusterPeerReconciler struct {
	client.Client
	FedServer *federation.Server
	PeerSet   *federation.PeerSet
}

// Reconcile handles a ClusterPeer create/update/delete.
func (r *ClusterPeerReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	var peer v1alpha1.ClusterPeer
	if err := r.Get(ctx, req.NamespacedName, &peer); err != nil {
		if apierrors.IsNotFound(err) {
			logger.Info("ClusterPeer deleted, cleaning up", "name", req.Name)
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	// Skip paused peers.
	if peer.Spec.Paused {
		logger.Info("ClusterPeer paused, skipping", "peer", peer.Spec.ClusterID)
		r.setCondition(&peer, "Ready", metav1.ConditionFalse, "Paused", "Federation paused by operator")
		if err := r.Status().Update(ctx, &peer); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	// Validate.
	cid := federation.ClusterID(peer.Spec.ClusterID)
	if err := cid.Validate(); err != nil {
		r.setCondition(&peer, "Ready", metav1.ConditionFalse, "InvalidConfig", err.Error())
		if err := r.Status().Update(ctx, &peer); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}
	if peer.Spec.Endpoint == "" {
		r.setCondition(&peer, "Ready", metav1.ConditionFalse, "InvalidConfig", "endpoint is required")
		if err := r.Status().Update(ctx, &peer); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	// Check peer health.
	p, exists := r.PeerSet.Get(cid)
	if !exists {
		r.setCondition(&peer, "Ready", metav1.ConditionFalse, "NotRegistered",
			fmt.Sprintf("peer %q not in federation config", cid))
		if err := r.Status().Update(ctx, &peer); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
	}

	// Update status from peer state.
	peer.Status.Connected = p.IsHealthy()
	if !p.LastSeen().IsZero() {
		t := metav1.NewTime(p.LastSeen())
		peer.Status.LastSyncTime = &t
	}
	peer.Status.LastSyncVersion = p.Version()

	if p.IsHealthy() {
		r.setCondition(&peer, "Ready", metav1.ConditionTrue, "Connected", "Federation stream active")
		peer.Status.LastError = ""
	} else {
		r.setCondition(&peer, "Ready", metav1.ConditionFalse, "Disconnected", "Peer not reachable")
	}

	if err := r.Status().Update(ctx, &peer); err != nil {
		return ctrl.Result{}, err
	}

	// Requeue to periodically refresh status.
	return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
}

func (r *ClusterPeerReconciler) setCondition(peer *v1alpha1.ClusterPeer, condType string, status metav1.ConditionStatus, reason, message string) {
	meta.SetStatusCondition(&peer.Status.Conditions, metav1.Condition{
		Type:               condType,
		Status:             status,
		Reason:             reason,
		Message:            message,
		LastTransitionTime: metav1.Now(),
	})
}

// SetupWithManager registers the ClusterPeer reconciler.
func (r *ClusterPeerReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.ClusterPeer{}).
		Complete(r)
}
