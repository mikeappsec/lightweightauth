// Package v1alpha1 contains the Kubernetes CRD types for LightweightAuth:
// AuthConfig, AuthPolicy, IdentityProvider. See docs/DESIGN.md §3.
//
// M0 ships only the type *shapes*; deepcopy generation, the controller,
// and admission validation arrive in M4. Importing this package outside
// of the controller is fine for typed YAML decoding.
//
// +groupName=lightweightauth.io
package v1alpha1

import (
	"github.com/yourorg/lightweightauth/internal/config"
)

// AuthConfig is the K8s CRD wrapping config.AuthConfig.
type AuthConfig struct {
	TypeMeta   `json:",inline"`
	ObjectMeta `json:"metadata,omitempty"`
	Spec       config.AuthConfig `json:"spec"`
	Status     AuthConfigStatus  `json:"status,omitempty"`
}

// AuthConfigStatus is the typical K8s status sub-resource shape.
type AuthConfigStatus struct {
	Ready              bool   `json:"ready,omitempty"`
	ObservedGeneration int64  `json:"observedGeneration,omitempty"`
	Message            string `json:"message,omitempty"`
}

// AuthPolicy binds an AuthConfig to one or more hosts/path patterns. The
// detailed selector shape lands in M4; this is a placeholder so the API
// surface is committed.
type AuthPolicy struct {
	TypeMeta   `json:",inline"`
	ObjectMeta `json:"metadata,omitempty"`
	Spec       AuthPolicySpec `json:"spec"`
}

type AuthPolicySpec struct {
	AuthConfigRef string   `json:"authConfigRef"`
	Hosts         []string `json:"hosts,omitempty"`
	PathPatterns  []string `json:"pathPatterns,omitempty"`
}

// IdentityProvider is cluster-scoped and reusable across namespaces /
// tenants. Concrete fields land in M4.
type IdentityProvider struct {
	TypeMeta   `json:",inline"`
	ObjectMeta `json:"metadata,omitempty"`
	Spec       IdentityProviderSpec `json:"spec"`
}

type IdentityProviderSpec struct {
	IssuerURL string   `json:"issuerUrl"`
	Audiences []string `json:"audiences,omitempty"`
}

// Stand-ins for k8s.io/apimachinery types so this package can compile in
// M0 without pulling in the K8s deps; replaced with real metav1.TypeMeta /
// metav1.ObjectMeta in M4.
type (
	TypeMeta struct {
		Kind       string `json:"kind,omitempty"`
		APIVersion string `json:"apiVersion,omitempty"`
	}
	ObjectMeta struct {
		Name      string `json:"name,omitempty"`
		Namespace string `json:"namespace,omitempty"`
	}
)
