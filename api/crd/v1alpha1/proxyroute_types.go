// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// =====================================================================
// ProxyRoute — declares cross-tenant/cross-cluster auth decision
// federation. The control-plane controller patches the source
// instance's AuthConfig to inject a pipeline rule that calls the
// target's /v1/authorize.
// =====================================================================

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Source",type="string",JSONPath=".spec.source.instanceRef"
// +kubebuilder:printcolumn:name="Target",type="string",JSONPath=".spec.target.instanceRef"
// +kubebuilder:printcolumn:name="Healthy",type="boolean",JSONPath=".status.healthy"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// ProxyRoute declares cross-tenant auth decision proxy between instances.
type ProxyRoute struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              ProxyRouteSpec   `json:"spec"`
	Status            ProxyRouteStatus `json:"status,omitempty"`
}

// ProxyRouteSpec defines the desired proxy configuration.
type ProxyRouteSpec struct {
	// Source is the lwauth instance that receives the original request.
	Source ProxyRouteSource `json:"source"`

	// Target is the lwauth instance that owns the target policy.
	Target ProxyRouteTarget `json:"target"`

	// ForwardBody controls whether the request body is forwarded.
	// Default false (auth decisions rarely need it).
	ForwardBody bool `json:"forwardBody,omitempty"`

	// Timeout for the cross-instance call. Default "2s".
	Timeout string `json:"timeout,omitempty"`

	// FailureMode determines behaviour when target is unreachable.
	// "deny" (default) or "allow".
	// +kubebuilder:default="deny"
	// +kubebuilder:validation:Enum=deny;allow
	FailureMode string `json:"failureMode,omitempty"`
}

// ProxyRouteSource identifies the source instance and path prefix.
type ProxyRouteSource struct {
	// InstanceRef is the name of the source LwauthInstance.
	InstanceRef string `json:"instanceRef"`

	// Cluster is the cluster where the source instance lives.
	// Empty means same cluster as the ProxyRoute.
	Cluster string `json:"cluster,omitempty"`

	// PathPrefix is the URL path prefix to match for proxying.
	PathPrefix string `json:"pathPrefix"`
}

// ProxyRouteTarget identifies the target instance.
type ProxyRouteTarget struct {
	// InstanceRef is the name of the target LwauthInstance.
	InstanceRef string `json:"instanceRef"`

	// Cluster is the cluster where the target instance lives.
	// Empty means same cluster as the ProxyRoute.
	Cluster string `json:"cluster,omitempty"`

	// Transport is the protocol for the cross-instance call.
	// "http" (default) or "grpc".
	// +kubebuilder:default="http"
	// +kubebuilder:validation:Enum=http;grpc
	Transport string `json:"transport,omitempty"`

	// MTLS enables mutual TLS between source and target.
	// Default true when mesh certs are available.
	// +kubebuilder:default=true
	MTLS *bool `json:"mtls,omitempty"`

	// AllowSources restricts which source instances may proxy to
	// this target. Empty means all sources are allowed (subject to
	// the target's AllowInboundProxy flag).
	AllowSources []string `json:"allowSources,omitempty"`
}

// ProxyRouteStatus is the observed state of a ProxyRoute.
type ProxyRouteStatus struct {
	// Healthy indicates the route is functional.
	Healthy bool `json:"healthy,omitempty"`

	// LastProbe is the timestamp of the last health probe.
	LastProbe *metav1.Time `json:"lastProbe,omitempty"`

	// LatencyP99 is the observed p99 latency of the proxy call.
	LatencyP99 string `json:"latencyP99,omitempty"`

	// Conditions describe the route's reconciliation state.
	// +optional
	// +patchMergeKey=type
	// +patchStrategy=merge
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty" patchStrategy:"merge" patchMergeKey:"type"`
}

// +kubebuilder:object:root=true

// ProxyRouteList is the list type for ProxyRoute.
type ProxyRouteList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ProxyRoute `json:"items"`
}

// DeepCopyObject implements runtime.Object.
func (in *ProxyRoute) DeepCopyObject() runtime.Object { return in.DeepCopy() }

// DeepCopy clones the receiver.
func (in *ProxyRoute) DeepCopy() *ProxyRoute {
	if in == nil {
		return nil
	}
	out := &ProxyRoute{}
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
	return out
}

// DeepCopyInto copies spec fields.
func (in *ProxyRouteSpec) DeepCopyInto(out *ProxyRouteSpec) {
	*out = *in
	in.Target.DeepCopyInto(&out.Target)
}

// DeepCopyInto copies target fields.
func (in *ProxyRouteTarget) DeepCopyInto(out *ProxyRouteTarget) {
	*out = *in
	if in.MTLS != nil {
		out.MTLS = new(bool)
		*out.MTLS = *in.MTLS
	}
	if in.AllowSources != nil {
		out.AllowSources = append([]string(nil), in.AllowSources...)
	}
}

// DeepCopyInto copies status fields.
func (in *ProxyRouteStatus) DeepCopyInto(out *ProxyRouteStatus) {
	*out = *in
	if in.LastProbe != nil {
		out.LastProbe = in.LastProbe.DeepCopy()
	}
	if in.Conditions != nil {
		out.Conditions = make([]metav1.Condition, len(in.Conditions))
		for i := range in.Conditions {
			in.Conditions[i].DeepCopyInto(&out.Conditions[i])
		}
	}
}

// DeepCopyObject implements runtime.Object.
func (in *ProxyRouteList) DeepCopyObject() runtime.Object { return in.DeepCopy() }

// DeepCopy clones the list.
func (in *ProxyRouteList) DeepCopy() *ProxyRouteList {
	if in == nil {
		return nil
	}
	out := &ProxyRouteList{TypeMeta: in.TypeMeta}
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	out.Items = make([]ProxyRoute, len(in.Items))
	for i := range in.Items {
		out.Items[i] = *in.Items[i].DeepCopy()
	}
	return out
}
