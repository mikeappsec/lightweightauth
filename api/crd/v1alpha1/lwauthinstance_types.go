// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// =====================================================================
// LwauthInstance — declares a desired lwauth data-plane instance.
// The control-plane controller reconciles this into a Deployment,
// Service, AuthConfig, NetworkPolicy, PDB, and ServiceAccount.
// =====================================================================

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Ready",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="Replicas",type="string",JSONPath=".status.replicas"
// +kubebuilder:printcolumn:name="Version",type="string",JSONPath=".spec.version"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// LwauthInstance declares a desired lwauth data-plane deployment.
type LwauthInstance struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              LwauthInstanceSpec   `json:"spec"`
	Status            LwauthInstanceStatus `json:"status,omitempty"`
}

// LwauthInstanceSpec defines the desired state of a lwauth instance.
type LwauthInstanceSpec struct {
	// AppClusterID identifies the AppCluster this instance belongs to.
	// Must match an AppCluster CR's spec.id in the same namespace.
	// Determines the SPIFFE trust domain and ClusterMembership the
	// instance_reconciler will register this node into.
	// If empty, defaults to the namespace name.
	// +optional
	AppClusterID string `json:"appClusterID,omitempty"`

	// TargetNamespace is where the lwauth Deployment + Service land.
	// Defaults to the LwauthInstance's own namespace if empty.
	TargetNamespace string `json:"targetNamespace,omitempty"`

	// Replicas is the desired number of lwauth pods. Defaults to 2.
	// +kubebuilder:default=2
	// +kubebuilder:validation:Minimum=1
	Replicas *int32 `json:"replicas,omitempty"`

	// Version is the lwauth container image tag to deploy.
	// Empty means "latest stable" as determined by the control plane.
	Version string `json:"version,omitempty"`

	// Image overrides the full container image (registry/repo:tag).
	// If set, Version is ignored.
	Image string `json:"image,omitempty"`

	// Config references the AuthConfig for this instance.
	Config LwauthInstanceConfig `json:"config,omitempty"`

	// Resources defines CPU/memory requests and limits for each Pod.
	Resources corev1.ResourceRequirements `json:"resources,omitempty"`

	// TLS configures TLS for the instance's serving endpoints.
	TLS *LwauthInstanceTLS `json:"tls,omitempty"`

	// NetworkPolicy controls whether a restrictive NetworkPolicy is
	// created for this instance. Defaults to true.
	// +kubebuilder:default=true
	NetworkPolicy *bool `json:"networkPolicy,omitempty"`

	// PodDisruptionBudget configures the PDB. Defaults to minAvailable=1.
	PodDisruptionBudget *PDBSpec `json:"podDisruptionBudget,omitempty"`

	// Autoscaling configures optional HPA. Disabled by default.
	Autoscaling *AutoscalingSpec `json:"autoscaling,omitempty"`

	// AllowInboundProxy opts this instance in to receiving proxied
	// auth decisions from other instances via ProxyRoute. Default false.
	AllowInboundProxy bool `json:"allowInboundProxy,omitempty"`
}

// LwauthInstanceConfig references or inlines the AuthConfig.
type LwauthInstanceConfig struct {
	// AuthConfigRef references an existing AuthConfig CR by name.
	// The CR must be in the same namespace as targetNamespace.
	AuthConfigRef *AuthConfigReference `json:"authConfigRef,omitempty"`

	// Inline allows specifying the AuthConfig spec directly.
	// Mutually exclusive with AuthConfigRef.
	Inline *InlineAuthConfig `json:"inline,omitempty"`
}

// AuthConfigReference is a reference to a named AuthConfig CR.
type AuthConfigReference struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace,omitempty"`
}

// InlineAuthConfig holds a raw JSON/YAML spec that will be written
// as an AuthConfig CR by the controller.
type InlineAuthConfig struct {
	// Spec is the AuthConfig spec content. Stored as raw JSON to
	// avoid importing internal/config into the API types.
	// +kubebuilder:pruning:PreserveUnknownFields
	Spec runtime.RawExtension `json:"spec"`
}

// LwauthInstanceTLS configures TLS.
type LwauthInstanceTLS struct {
	// Enabled controls whether TLS is configured.
	Enabled bool `json:"enabled,omitempty"`

	// CertManager configures cert-manager integration for auto TLS.
	CertManager *CertManagerConfig `json:"certManager,omitempty"`

	// SecretRef references a pre-existing TLS Secret (tls.crt + tls.key).
	SecretRef string `json:"secretRef,omitempty"`
}

// CertManagerConfig references a cert-manager Issuer or ClusterIssuer.
type CertManagerConfig struct {
	IssuerRef IssuerReference `json:"issuerRef"`
}

// IssuerReference identifies a cert-manager issuer.
type IssuerReference struct {
	Name string `json:"name"`
	Kind string `json:"kind"` // Issuer or ClusterIssuer
}

// PDBSpec configures PodDisruptionBudget.
type PDBSpec struct {
	// MinAvailable is the minimum number of pods that must remain available.
	// +kubebuilder:default=1
	MinAvailable *int32 `json:"minAvailable,omitempty"`
}

// AutoscalingSpec configures optional HPA.
type AutoscalingSpec struct {
	Enabled     bool   `json:"enabled,omitempty"`
	MinReplicas *int32 `json:"minReplicas,omitempty"`
	MaxReplicas *int32 `json:"maxReplicas,omitempty"`
	// TargetCPUPercent is the target CPU utilization percentage.
	TargetCPUPercent *int32 `json:"targetCPUPercent,omitempty"`
}

// LwauthInstanceStatus is the observed state of a lwauth instance.
type LwauthInstanceStatus struct {
	// Conditions describe the resource's reconciliation state.
	// +optional
	// +patchMergeKey=type
	// +patchStrategy=merge
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty" patchStrategy:"merge" patchMergeKey:"type"`

	// Ready indicates the instance is fully reconciled and healthy.
	Ready bool `json:"ready,omitempty"`

	// Replicas is a "ready/desired" string like "2/2".
	Replicas string `json:"replicas,omitempty"`

	// ConfigVersion is the SHA-256 of the applied AuthConfig spec.
	ConfigVersion string `json:"configVersion,omitempty"`

	// LastReconcile is the timestamp of the last successful reconciliation.
	LastReconcile *metav1.Time `json:"lastReconcile,omitempty"`

	// ExternalUrl is the externally-reachable admin URL for this instance.
	// Used for cross-cluster proxy routes and manual registration.
	ExternalURL string `json:"externalUrl,omitempty"`

	// ObservedGeneration tracks the latest generation reconciled.
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
}

// LwauthInstance condition types.
const (
	InstanceConditionReady       = "Ready"
	InstanceConditionProgressing = "Progressing"
	InstanceConditionDegraded    = "Degraded"

	InstanceReasonReconciled   = "Reconciled"
	InstanceReasonProgressing  = "Progressing"
	InstanceReasonCreateFailed = "CreateFailed"
	InstanceReasonHealthy      = "Healthy"
	InstanceReasonUnhealthy    = "Unhealthy"
)

// +kubebuilder:object:root=true

// LwauthInstanceList is the list type for LwauthInstance.
type LwauthInstanceList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []LwauthInstance `json:"items"`
}

// DeepCopyObject implements runtime.Object.
func (in *LwauthInstance) DeepCopyObject() runtime.Object { return in.DeepCopy() }

// DeepCopy clones the receiver.
func (in *LwauthInstance) DeepCopy() *LwauthInstance {
	if in == nil {
		return nil
	}
	out := &LwauthInstance{}
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
	return out
}

// DeepCopyInto copies spec fields.
func (in *LwauthInstanceSpec) DeepCopyInto(out *LwauthInstanceSpec) {
	*out = *in
	if in.Replicas != nil {
		out.Replicas = new(int32)
		*out.Replicas = *in.Replicas
	}
	in.Resources.DeepCopyInto(&out.Resources)
	if in.TLS != nil {
		out.TLS = &LwauthInstanceTLS{}
		*out.TLS = *in.TLS
	}
	if in.NetworkPolicy != nil {
		out.NetworkPolicy = new(bool)
		*out.NetworkPolicy = *in.NetworkPolicy
	}
	if in.PodDisruptionBudget != nil {
		out.PodDisruptionBudget = &PDBSpec{}
		*out.PodDisruptionBudget = *in.PodDisruptionBudget
	}
	if in.Autoscaling != nil {
		out.Autoscaling = &AutoscalingSpec{}
		*out.Autoscaling = *in.Autoscaling
	}
	// Config: shallow copy is fine for reference; inline needs deep.
	out.Config = in.Config
	if in.Config.Inline != nil {
		out.Config.Inline = &InlineAuthConfig{
			Spec: runtime.RawExtension{Raw: append([]byte(nil), in.Config.Inline.Spec.Raw...)},
		}
	}
	if in.Config.AuthConfigRef != nil {
		out.Config.AuthConfigRef = &AuthConfigReference{}
		*out.Config.AuthConfigRef = *in.Config.AuthConfigRef
	}
}

// DeepCopyInto copies status fields.
func (in *LwauthInstanceStatus) DeepCopyInto(out *LwauthInstanceStatus) {
	*out = *in
	if in.Conditions != nil {
		out.Conditions = make([]metav1.Condition, len(in.Conditions))
		for i := range in.Conditions {
			in.Conditions[i].DeepCopyInto(&out.Conditions[i])
		}
	}
	if in.LastReconcile != nil {
		out.LastReconcile = in.LastReconcile.DeepCopy()
	}
}

// DeepCopyObject implements runtime.Object.
func (in *LwauthInstanceList) DeepCopyObject() runtime.Object { return in.DeepCopy() }

// DeepCopy clones the list.
func (in *LwauthInstanceList) DeepCopy() *LwauthInstanceList {
	if in == nil {
		return nil
	}
	out := &LwauthInstanceList{TypeMeta: in.TypeMeta}
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	out.Items = make([]LwauthInstance, len(in.Items))
	for i := range in.Items {
		out.Items[i] = *in.Items[i].DeepCopy()
	}
	return out
}
