// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"sync"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	v1alpha1 "github.com/mikeappsec/lightweightauth/api/crd/v1alpha1"
)

// PeerDialer is implemented by the node's peer mesh to connect to or
// disconnect from a peer. The MembershipWatcher calls these when the
// ClusterMembership CR changes.
//
// Implementations must be goroutine-safe. Dial is expected to be
// non-blocking: it enqueues the connection attempt and returns immediately.
// The actual mTLS handshake happens in a background goroutine with
// exponential backoff.
type PeerDialer interface {
	// Dial initiates an mTLS connection to the peer. No-op if already connected.
	Dial(peer v1alpha1.ClusterMember)

	// Hangup closes the connection to the peer and removes it from the
	// local peer table. No-op if not connected.
	Hangup(name, namespace string)
}

// MembershipWatcher is a controller-runtime Reconciler that runs on each
// lwauth data-plane node. It watches the ClusterMembership CR for this
// node's AppCluster and keeps the local peer table in sync.
//
// Wiring:
//
//	mgr.Add / SetupWithManager registers the watcher.
//	PeerDialer is satisfied by the node's intra-cluster peer mesh.
//
// The watcher is NOT part of the control-plane process. It runs inside
// the lwauth node process (cmd/lwauth), so it talks directly to the
// k8s API server via the node's ServiceAccount — no control-plane
// involvement at runtime.
type MembershipWatcher struct {
	// Client reads ClusterMembership from the k8s API (etcd).
	Client client.Client

	// Watched is the (namespace, name) of the ClusterMembership CR
	// for this node's AppCluster. Set at startup from config.
	Watched types.NamespacedName

	// SelfName is the name of this node's LwauthInstance — used to
	// skip the self-entry when building the peer table.
	SelfName string

	// SelfNamespace is the namespace this node's Pod runs in.
	SelfNamespace string

	// Dialer connects/disconnects peers as membership changes.
	Dialer PeerDialer

	mu      sync.Mutex
	current map[string]v1alpha1.ClusterMember // key: "<namespace>/<name>"
}

// SetupWithManager registers the MembershipWatcher with a controller-runtime
// manager. The manager's informer cache handles the watch stream; no polling.
func (w *MembershipWatcher) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.ClusterMembership{}).
		Complete(w)
}

// Reconcile is called whenever the ClusterMembership CR changes. It diffs
// the new spec.members list against the locally tracked peer table and
// calls Dialer.Dial / Dialer.Hangup for any additions or removals.
//
// This is idempotent: running it twice with the same membership produces
// the same outcome.
func (w *MembershipWatcher) Reconcile(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
	if req.NamespacedName != w.Watched {
		return reconcile.Result{}, nil // not our membership CR
	}

	logger := log.FromContext(ctx).WithName("membership-watcher").
		WithValues("membership", req.NamespacedName)

	var membership v1alpha1.ClusterMembership
	if err := w.Client.Get(ctx, req.NamespacedName, &membership); err != nil {
		return reconcile.Result{}, client.IgnoreNotFound(err)
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	desired := make(map[string]v1alpha1.ClusterMember, len(membership.Spec.Members))
	for _, m := range membership.Spec.Members {
		if m.Name == w.SelfName && m.Namespace == w.SelfNamespace {
			continue // never connect to ourselves
		}
		key := m.Namespace + "/" + m.Name
		desired[key] = m
	}

	// Connect any new peers not yet in the local table.
	for key, member := range desired {
		if _, known := w.current[key]; !known {
			logger.Info("new peer discovered, initiating dial",
				"peer", key, "endpoint", member.Endpoint, "spiffeID", member.SPIFFEID)
			w.Dialer.Dial(member)
		}
	}

	// Disconnect peers that were removed from spec.members.
	for key, member := range w.current {
		if _, stillPresent := desired[key]; !stillPresent {
			logger.Info("peer removed from membership, hanging up",
				"peer", key)
			w.Dialer.Hangup(member.Name, member.Namespace)
		}
	}

	w.current = desired

	// Update status.memberCount and status.healthyCount (best-effort).
	w.updateStatus(ctx, &membership)

	return reconcile.Result{}, nil
}

// updateStatus writes this node's observed healthy count back to the
// ClusterMembership status subresource. Uses a status-only update so it
// does not conflict with spec writes from the instance_reconciler.
func (w *MembershipWatcher) updateStatus(ctx context.Context, membership *v1alpha1.ClusterMembership) {
	membership.Status.MemberCount = len(membership.Spec.Members)

	// Mark this node's own status entry as healthy.
	found := false
	for i, s := range membership.Status.MemberStatuses {
		if s.Name == w.SelfName && s.Namespace == w.SelfNamespace {
			now := metav1.Now()
			membership.Status.MemberStatuses[i].Healthy = true
			membership.Status.MemberStatuses[i].LastSeen = &now
			found = true
			break
		}
	}
	if !found {
		now := metav1.Now()
		membership.Status.MemberStatuses = append(membership.Status.MemberStatuses, v1alpha1.ClusterMemberStatus{
			Name:      w.SelfName,
			Namespace: w.SelfNamespace,
			Healthy:   true,
			LastSeen:  &now,
		})
	}

	meta.SetStatusCondition(&membership.Status.Conditions, metav1.Condition{
		Type:               "WatcherReady",
		Status:             metav1.ConditionTrue,
		Reason:             "Synced",
		Message:            "Membership synced by node " + w.SelfName,
		LastTransitionTime: metav1.Now(),
	})

	// Ignore errors — status update is best-effort; the node will retry
	// on the next reconcile cycle triggered by any membership change.
	_ = w.Client.Status().Update(ctx, membership)
}
