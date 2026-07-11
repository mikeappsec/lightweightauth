// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// =====================================================================
// ClusterMembership — the durable peer registry for an AppCluster.
//
// There is exactly one ClusterMembership per AppCluster, scoped to the
// same namespace. It holds the authoritative list of nodes that belong
// to the AppCluster. Nodes watch this CR (via controller-runtime
// informers) to build and maintain their in-memory peer tables.
//
// Write authority:
//   - Helm chart creates the initial CR with bootstrap nodes.
//   - instance_reconciler upserts/removes entries on LwauthInstance
//     create/delete.
//   - lwauthctl can manually add external (VM/bare-metal) nodes.
//   - Nodes themselves NEVER write spec.members — only status.
//
// =====================================================================

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="AppCluster",type="string",JSONPath=".spec.appClusterID"
// +kubebuilder:printcolumn:name="Members",type="integer",JSONPath=".status.memberCount"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// ClusterMembership is the authoritative peer registry for one AppCluster.
// Nodes watch this CR to discover and authenticate peers.
type ClusterMembership struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              ClusterMembershipSpec   `json:"spec"`
	Status            ClusterMembershipStatus `json:"status,omitempty"`
}

// ClusterMembershipSpec is the desired membership list.
type ClusterMembershipSpec struct {
	// AppClusterID scopes this membership list to one AppCluster.
	// Must match the AppCluster CR's spec.id in the same namespace.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MaxLength=63
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`
	AppClusterID string `json:"appClusterID"`

	// Members is the authoritative list of nodes in this AppCluster.
	// The instance_reconciler upserts entries here; nodes read them.
	// +listType=map
	// +listMapKey=name
	Members []ClusterMember `json:"members,omitempty"`
}

// ClusterMember describes one node registered in the AppCluster.
type ClusterMember struct {
	// Name is the node's LwauthInstance name (and k8s object name).
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MaxLength=253
	Name string `json:"name"`

	// Namespace is the k8s namespace the node's Pod runs in.
	// +kubebuilder:validation:Required
	Namespace string `json:"namespace"`

	// Endpoint is the gRPC address (host:port) for intra-cluster peer
	// connections. Derived from the node's Service DNS name.
	// Format: "<service-name>.<namespace>.svc:<port>"
	// +kubebuilder:validation:Required
	Endpoint string `json:"endpoint"`

	// SPIFFEID is the expected SPIFFE X.509 URI SAN for this node's cert.
	// Derived at provisioning time: spiffe://<appClusterID>.lwauth/<namespace>/<name>
	// Nodes verify the peer's cert contains exactly this SAN during handshake.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Pattern=`^spiffe://`
	SPIFFEID string `json:"spiffeID"`

	// JoinedAt is when this member was first registered.
	JoinedAt metav1.Time `json:"joinedAt"`

	// Labels carry optional metadata for topology-aware routing
	// (e.g. zone, tier, region). Not used for auth decisions.
	// +optional
	Labels map[string]string `json:"labels,omitempty"`
}

// ClusterMembershipStatus is the observed state of the membership.
// Written by nodes (status subresource only).
type ClusterMembershipStatus struct {
	// MemberCount is the number of entries in spec.members.
	MemberCount int `json:"memberCount,omitempty"`

	// HealthyCount is the number of members currently reachable,
	// as reported by at least one peer node.
	HealthyCount int `json:"healthyCount,omitempty"`

	// MemberStatuses holds per-node observed health, written by nodes
	// updating only their own entry (identified by name+namespace).
	// +optional
	MemberStatuses []ClusterMemberStatus `json:"memberStatuses,omitempty"`

	// Conditions describe the overall membership state.
	// +optional
	// +patchMergeKey=type
	// +patchStrategy=merge
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty" patchStrategy:"merge" patchMergeKey:"type"`
}

// ClusterMemberStatus is one node's observed health, written by the node itself.
type ClusterMemberStatus struct {
	// Name matches ClusterMember.Name.
	Name string `json:"name"`

	// Namespace matches ClusterMember.Namespace.
	Namespace string `json:"namespace"`

	// Healthy is true if this node's mTLS connection to the peer is up.
	Healthy bool `json:"healthy"`

	// LastSeen is the last time a successful message was received from this peer.
	// +optional
	LastSeen *metav1.Time `json:"lastSeen,omitempty"`
}

// +kubebuilder:object:root=true

// ClusterMembershipList is the list type for ClusterMembership.
type ClusterMembershipList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ClusterMembership `json:"items"`
}

// DeepCopyObject implements runtime.Object.
func (in *ClusterMembership) DeepCopyObject() runtime.Object { return in.DeepCopy() }

// DeepCopy clones the receiver.
func (in *ClusterMembership) DeepCopy() *ClusterMembership {
	if in == nil {
		return nil
	}
	out := &ClusterMembership{}
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
	return out
}

// DeepCopyInto copies spec fields into out.
func (in *ClusterMembershipSpec) DeepCopyInto(out *ClusterMembershipSpec) {
	*out = *in
	if in.Members != nil {
		out.Members = make([]ClusterMember, len(in.Members))
		for i := range in.Members {
			in.Members[i].DeepCopyInto(&out.Members[i])
		}
	}
}

// DeepCopyInto copies member fields into out.
func (in *ClusterMember) DeepCopyInto(out *ClusterMember) {
	*out = *in
	out.JoinedAt = *in.JoinedAt.DeepCopy()
	if in.Labels != nil {
		out.Labels = make(map[string]string, len(in.Labels))
		for k, v := range in.Labels {
			out.Labels[k] = v
		}
	}
}

// DeepCopyInto copies status fields into out.
func (in *ClusterMembershipStatus) DeepCopyInto(out *ClusterMembershipStatus) {
	*out = *in
	if in.MemberStatuses != nil {
		out.MemberStatuses = make([]ClusterMemberStatus, len(in.MemberStatuses))
		for i := range in.MemberStatuses {
			in.MemberStatuses[i].DeepCopyInto(&out.MemberStatuses[i])
		}
	}
	if in.Conditions != nil {
		out.Conditions = make([]metav1.Condition, len(in.Conditions))
		for i := range in.Conditions {
			in.Conditions[i].DeepCopyInto(&out.Conditions[i])
		}
	}
}

// DeepCopyInto copies member status fields into out.
func (in *ClusterMemberStatus) DeepCopyInto(out *ClusterMemberStatus) {
	*out = *in
	if in.LastSeen != nil {
		out.LastSeen = in.LastSeen.DeepCopy()
	}
}

// DeepCopyObject implements runtime.Object.
func (in *ClusterMembershipList) DeepCopyObject() runtime.Object { return in.DeepCopy() }

// DeepCopy clones the list.
func (in *ClusterMembershipList) DeepCopy() *ClusterMembershipList {
	if in == nil {
		return nil
	}
	out := &ClusterMembershipList{TypeMeta: in.TypeMeta}
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	out.Items = make([]ClusterMembership, len(in.Items))
	for i := range in.Items {
		out.Items[i] = *in.Items[i].DeepCopy()
	}
	return out
}
