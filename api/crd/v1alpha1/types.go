// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

// Package v1alpha1 contains the Kubernetes CRD types for LightweightAuth:
// AuthConfig, AuthPolicy, IdentityProvider. See docs/DESIGN.md §3.
//
// In M4 these became real Kubernetes types: metav1.TypeMeta /
// metav1.ObjectMeta, scheme registration, runtime.Object implementations,
// and List types so controller-runtime can watch them.
//
// We hand-write the DeepCopy methods rather than generate them. The
// payload is small (config.AuthConfig is JSON-roundtrippable) and the
// generator chain (controller-gen) would add a build-time dependency for
// little gain. If the surface grows, switching to generated code is a
// drop-in.
//
// +kubebuilder:object:generate=true
// +groupName=lightweightauth.io
package v1alpha1

import (
	"encoding/json"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/mikeappsec/lightweightauth/internal/config"
)

// GroupVersion is the canonical (group, version) for our CRDs.
var GroupVersion = schema.GroupVersion{Group: "lightweightauth.io", Version: "v1alpha1"}

// SchemeBuilder is consumed by AddToScheme.
var SchemeBuilder = runtime.NewSchemeBuilder(addKnownTypes)

// AddToScheme registers our types with a runtime.Scheme. The controller
// manager calls this in main().
var AddToScheme = SchemeBuilder.AddToScheme

func addKnownTypes(scheme *runtime.Scheme) error {
	scheme.AddKnownTypes(GroupVersion,
		&AuthConfig{}, &AuthConfigList{},
		&AuthPolicy{}, &AuthPolicyList{},
		&IdentityProvider{}, &IdentityProviderList{},
	)
	metav1.AddToGroupVersion(scheme, GroupVersion)
	return nil
}

// =====================================================================
// AuthConfig — the main resource. Wraps internal/config.AuthConfig in
// the .spec field so the on-disk YAML and the K8s CR share one source
// of truth.
// =====================================================================

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// AuthConfig is the main namespaced resource a tenant authors.
type AuthConfig struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              config.AuthConfig `json:"spec"`
	Status            AuthConfigStatus  `json:"status,omitempty"`
}

// AuthConfigStatus is the typical K8s status sub-resource shape.
//
// Conditions follows the standard metav1.Condition pattern so generic
// tooling (kubectl wait --for=condition=Ready, Argo health checks,
// kstatus) can read the resource without special knowledge. The flat
// Ready bool is preserved as a deprecated mirror of the Ready
// condition's status; new code should read Conditions instead.
type AuthConfigStatus struct {
	// Conditions describe the resource's progress through its
	// reconciliation lifecycle. The Ready condition is set to True
	// when the engine has been compiled and swapped in successfully.
	// +optional
	// +patchMergeKey=type
	// +patchStrategy=merge
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty" patchStrategy:"merge" patchMergeKey:"type"`

	// Ready mirrors the Ready condition's status as a flat bool.
	// Deprecated: read Conditions instead. Retained for one release
	// for backwards compatibility with existing monitoring queries.
	Ready              bool   `json:"ready,omitempty"`
	ObservedGeneration int64  `json:"observedGeneration,omitempty"`
	Message            string `json:"message,omitempty"`

	// AppliedVersion is the spec.version that was last successfully
	// compiled and swapped in. Empty if spec.version is unset.
	// OPS-GITOPS-1: enables lwauthctl drift to compare live vs desired.
	AppliedVersion string `json:"appliedVersion,omitempty"`

	// AppliedDigest is the SHA-256 digest of the canonical JSON
	// encoding of the spec at the time of the last successful compile.
	// OPS-GITOPS-1: enables lwauthctl drift to detect config drift
	// even when spec.version is not used.
	AppliedDigest string `json:"appliedDigest,omitempty"`
}

// ConditionTypeReady is the canonical Ready condition type. Reasons
// are short, machine-readable strings — Compiled, CompileError,
// IdPRefError — kept in one place so callers don't typo-drift.
const (
	ConditionTypeReady = "Ready"

	ReasonCompiled     = "Compiled"
	ReasonCompileError = "CompileError"
	ReasonIdPRefError  = "IdPRefError"
)

// +kubebuilder:object:root=true

// AuthConfigList is required by controller-runtime for list/watch.
type AuthConfigList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []AuthConfig `json:"items"`
}

// DeepCopyObject implements runtime.Object.
func (in *AuthConfig) DeepCopyObject() runtime.Object { return in.DeepCopy() }

// DeepCopy clones the receiver. JSON round-trip keeps the implementation
// short — config.AuthConfig is by definition JSON-encodable.
func (in *AuthConfig) DeepCopy() *AuthConfig {
	if in == nil {
		return nil
	}
	out := &AuthConfig{}
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	out.Status = in.Status
	if b, err := json.Marshal(in.Spec); err == nil {
		_ = json.Unmarshal(b, &out.Spec)
	}
	return out
}

// DeepCopyObject implements runtime.Object.
func (in *AuthConfigList) DeepCopyObject() runtime.Object { return in.DeepCopy() }

// DeepCopy clones the list and every item.
func (in *AuthConfigList) DeepCopy() *AuthConfigList {
	if in == nil {
		return nil
	}
	out := &AuthConfigList{TypeMeta: in.TypeMeta}
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	out.Items = make([]AuthConfig, len(in.Items))
	for i := range in.Items {
		out.Items[i] = *in.Items[i].DeepCopy()
	}
	return out
}

// =====================================================================
// AuthPolicy — binds an AuthConfig to host/path patterns. Concrete
// matcher shape is intentionally minimal in v1alpha1; richer matching
// (CEL on attributes, header conditions) is a v1beta1 concern.
// =====================================================================

// +kubebuilder:object:root=true

// AuthPolicy binds an AuthConfig to one or more hosts/path patterns.
type AuthPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              AuthPolicySpec `json:"spec"`
}

// AuthPolicySpec selects which inbound requests an AuthConfig applies to.
type AuthPolicySpec struct {
	AuthConfigRef string   `json:"authConfigRef"`
	Hosts         []string `json:"hosts,omitempty"`
	PathPatterns  []string `json:"pathPatterns,omitempty"`
}

// +kubebuilder:object:root=true

// AuthPolicyList is the list type for AuthPolicy.
type AuthPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []AuthPolicy `json:"items"`
}

// DeepCopyObject implements runtime.Object.
func (in *AuthPolicy) DeepCopyObject() runtime.Object { return in.DeepCopy() }

// DeepCopy clones the receiver.
func (in *AuthPolicy) DeepCopy() *AuthPolicy {
	if in == nil {
		return nil
	}
	out := &AuthPolicy{TypeMeta: in.TypeMeta}
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	out.Spec.AuthConfigRef = in.Spec.AuthConfigRef
	out.Spec.Hosts = append([]string(nil), in.Spec.Hosts...)
	out.Spec.PathPatterns = append([]string(nil), in.Spec.PathPatterns...)
	return out
}

// DeepCopyObject implements runtime.Object.
func (in *AuthPolicyList) DeepCopyObject() runtime.Object { return in.DeepCopy() }

// DeepCopy clones the list and every item.
func (in *AuthPolicyList) DeepCopy() *AuthPolicyList {
	if in == nil {
		return nil
	}
	out := &AuthPolicyList{TypeMeta: in.TypeMeta}
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	out.Items = make([]AuthPolicy, len(in.Items))
	for i := range in.Items {
		out.Items[i] = *in.Items[i].DeepCopy()
	}
	return out
}

// =====================================================================
// IdentityProvider — cluster-scoped, reusable IdP definitions. Tenant
// AuthConfigs reference these by name.
// =====================================================================

// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Cluster

// IdentityProvider is cluster-scoped so multiple tenants can share
// one IdP definition without duplicating it in every namespace.
type IdentityProvider struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              IdentityProviderSpec `json:"spec"`
}

// IdentityProviderSpec captures the bits an Identifier needs to verify
// tokens; full IdP shape (OAuth2 client creds, JWKS pinning, ...)
// arrives with the M5/M6 modules.
// IdentityProviderSpec captures the bits an Identifier needs to verify
// tokens. Cluster-scoped so multiple tenants can share one IdP
// definition without duplicating it in every namespace; tenant
// AuthConfigs reference it via `idpRef: <name>` on a `jwt` identifier
// and may override individual fields (extra audience, custom header).
//
// In M11 we extended this beyond the original (issuer / jwks /
// audiences) triple to cover everything pkg/identity/jwt accepts, so an
// operator can fully define an IdP once and have tenants point at it
// with one line.
type IdentityProviderSpec struct {
	IssuerURL string   `json:"issuerUrl"`
	JWKSURL   string   `json:"jwksUrl,omitempty"`
	Audiences []string `json:"audiences,omitempty"`

	// Header / Scheme name the request header tenants should expect
	// the bearer token in. Defaults inherited from the identifier
	// factory (Authorization / Bearer).
	Header string `json:"header,omitempty"`
	Scheme string `json:"scheme,omitempty"`

	// MinRefreshInterval bounds how often the underlying jwx cache
	// re-fetches the JWKS on kid misses. Empty = identifier default.
	MinRefreshInterval string `json:"minRefreshInterval,omitempty"`
}

// +kubebuilder:object:root=true

// IdentityProviderList is the list type for IdentityProvider.
type IdentityProviderList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []IdentityProvider `json:"items"`
}

// DeepCopyObject implements runtime.Object.
func (in *IdentityProvider) DeepCopyObject() runtime.Object { return in.DeepCopy() }

// DeepCopy clones the receiver.
func (in *IdentityProvider) DeepCopy() *IdentityProvider {
	if in == nil {
		return nil
	}
	out := &IdentityProvider{TypeMeta: in.TypeMeta}
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	out.Spec.IssuerURL = in.Spec.IssuerURL
	out.Spec.JWKSURL = in.Spec.JWKSURL
	out.Spec.Audiences = append([]string(nil), in.Spec.Audiences...)
	out.Spec.Header = in.Spec.Header
	out.Spec.Scheme = in.Spec.Scheme
	out.Spec.MinRefreshInterval = in.Spec.MinRefreshInterval
	return out
}

// DeepCopyObject implements runtime.Object.
func (in *IdentityProviderList) DeepCopyObject() runtime.Object { return in.DeepCopy() }

// DeepCopy clones the list and every item.
func (in *IdentityProviderList) DeepCopy() *IdentityProviderList {
	if in == nil {
		return nil
	}
	out := &IdentityProviderList{TypeMeta: in.TypeMeta}
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	out.Items = make([]IdentityProvider, len(in.Items))
	for i := range in.Items {
		out.Items[i] = *in.Items[i].DeepCopy()
	}
	return out
}
