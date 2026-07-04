// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// =====================================================================
// AppCluster — defines an application-level group of lwauth nodes that
// share the same CA, SPIFFE trust domain, and peer mesh.
//
// One Kubernetes cluster can host many AppClusters in separate
// namespaces (payments, analytics, etc.). Each AppCluster is fully
// isolated: different CA, different SPIFFE trust domain, NetworkPolicy
// enforced at the namespace boundary.
//
// Relationship to other CRDs:
//   AppCluster (1) ─── (1) ClusterMembership
//   AppCluster (1) ─── (N) LwauthInstance
//
// =====================================================================

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="ID",type="string",JSONPath=".spec.id"
// +kubebuilder:printcolumn:name="Description",type="string",JSONPath=".spec.description"
// +kubebuilder:printcolumn:name="Ready",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// AppCluster defines an application-level isolation boundary for lwauth nodes.
// Each AppCluster has its own CA, SPIFFE trust domain, and ClusterMembership.
type AppCluster struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              AppClusterSpec   `json:"spec"`
	Status            AppClusterStatus `json:"status,omitempty"`
}

// AppClusterSpec defines the desired state of an AppCluster.
type AppClusterSpec struct {
	// ID is the globally unique identifier for this AppCluster.
	// Used as the SPIFFE trust domain component:
	//   spiffe://<ID>.lwauth/<namespace>/<node-name>
	// Must be DNS-label safe: lowercase alphanumeric and hyphens,
	// max 63 characters, must start and end with alphanumeric.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MaxLength=63
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`
	ID string `json:"id"`

	// Description is a human-readable label shown in the UI.
	// +optional
	Description string `json:"description,omitempty"`

	// CASecretRef references the cluster CA Secret in this namespace.
	// The Secret must be of type kubernetes.io/tls and contain a CA
	// cert+key pair. cert-manager uses this as the Issuer source.
	// The CA key MUST NOT be mounted into node pods.
	// +kubebuilder:validation:Required
	CASecretRef corev1.LocalObjectReference `json:"caSecretRef"`

	// AllowedNamespaces lists additional namespaces (beyond the
	// AppCluster's own namespace) that may host LwauthInstance nodes
	// for this AppCluster. Empty means only the AppCluster's namespace.
	// +optional
	AllowedNamespaces []string `json:"allowedNamespaces,omitempty"`

	// CrossClusterRoutes lists AppCluster IDs that nodes in this
	// AppCluster are permitted to proxy auth decisions to via
	// ProxyRoute. This is an explicit allowlist — cross-AppCluster
	// traffic is denied by default at both the network and TLS layers.
	// +optional
	CrossClusterRoutes []string `json:"crossClusterRoutes,omitempty"`
}

// AppClusterStatus is the observed state of an AppCluster.
type AppClusterStatus struct {
	// NodeCount is the number of LwauthInstance nodes currently
	// registered in the ClusterMembership for this AppCluster.
	NodeCount int `json:"nodeCount,omitempty"`

	// CAExpiry is the expiry time of the cluster CA certificate.
	// Used to surface upcoming CA rotation needs in the UI.
	// +optional
	CAExpiry *metav1.Time `json:"caExpiry,omitempty"`

	// Conditions describe the AppCluster's reconciliation state.
	// +optional
	// +patchMergeKey=type
	// +patchStrategy=merge
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty" patchStrategy:"merge" patchMergeKey:"type"`
}

// AppCluster condition types.
const (
	AppClusterConditionReady = "Ready"

	AppClusterReasonCAMissing       = "CASecretMissing"
	AppClusterReasonCAInvalid       = "CASecretInvalid"
	AppClusterReasonMembershipReady = "MembershipReady"
)

// +kubebuilder:object:root=true

// AppClusterList is the list type for AppCluster.
type AppClusterList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []AppCluster `json:"items"`
}

// DeepCopyObject implements runtime.Object.
func (in *AppCluster) DeepCopyObject() runtime.Object { return in.DeepCopy() }

// DeepCopy clones the receiver.
func (in *AppCluster) DeepCopy() *AppCluster {
	if in == nil {
		return nil
	}
	out := &AppCluster{}
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
	return out
}

// DeepCopyInto copies spec fields into out.
func (in *AppClusterSpec) DeepCopyInto(out *AppClusterSpec) {
	*out = *in
	out.CASecretRef = in.CASecretRef
	if in.AllowedNamespaces != nil {
		out.AllowedNamespaces = append([]string(nil), in.AllowedNamespaces...)
	}
	if in.CrossClusterRoutes != nil {
		out.CrossClusterRoutes = append([]string(nil), in.CrossClusterRoutes...)
	}
}

// DeepCopyInto copies status fields into out.
func (in *AppClusterStatus) DeepCopyInto(out *AppClusterStatus) {
	*out = *in
	if in.CAExpiry != nil {
		out.CAExpiry = in.CAExpiry.DeepCopy()
	}
	if in.Conditions != nil {
		out.Conditions = make([]metav1.Condition, len(in.Conditions))
		for i := range in.Conditions {
			in.Conditions[i].DeepCopyInto(&out.Conditions[i])
		}
	}
}

// DeepCopyObject implements runtime.Object.
func (in *AppClusterList) DeepCopyObject() runtime.Object { return in.DeepCopy() }

// DeepCopy clones the list.
func (in *AppClusterList) DeepCopy() *AppClusterList {
	if in == nil {
		return nil
	}
	out := &AppClusterList{TypeMeta: in.TypeMeta}
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	out.Items = make([]AppCluster, len(in.Items))
	for i := range in.Items {
		out.Items[i] = *in.Items[i].DeepCopy()
	}
	return out
}
