// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// =====================================================================
// MCPServer — registers a deployed MCP server with LightweightAuth so
// lwauth can act as its Resource Authorization Server, implementing the
// MCP Enterprise-Managed Authorization spec (ID-JAG, RFC 7523 / 9728 /
// 8414). See docs/design/mcp-enterprise-auth.md.
//
// One MCPServer per deployed MCP server. A single lwauth deployment can
// serve many MCPServer registrations, each under its own /mcp/<name>/
// path prefix with its own signing key.
// =====================================================================

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Resource",type="string",JSONPath=".spec.resourceIdentifier"
// +kubebuilder:printcolumn:name="Mode",type="string",JSONPath=".spec.tokenValidation.mode"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// MCPServer registers an MCP server as an OAuth 2.0 Protected Resource
// for which LightweightAuth issues and validates access tokens.
type MCPServer struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              MCPServerSpec   `json:"spec"`
	Status            MCPServerStatus `json:"status,omitempty"`
}

// MCPServerSpec defines the desired registration of an MCP server.
type MCPServerSpec struct {
	// ResourceIdentifier is the canonical URL of the MCP server. Must
	// match the `resource` claim the IdP places in ID-JAG tokens, and
	// becomes the `aud` of the issued access token.
	// Example: "https://github-mcp.internal.example.com/"
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Pattern=`^https://`
	ResourceIdentifier string `json:"resourceIdentifier"`

	// IdentityProviderRef names the IdentityProvider CR whose JWKS is
	// used to verify incoming ID-JAG token signatures.
	// +kubebuilder:validation:Required
	IdentityProviderRef string `json:"identityProviderRef"`

	// ScopeBindings maps OAuth scopes granted by the IdP to roles that
	// LightweightAuth embeds in the issued access token. Scopes present
	// in the ID-JAG but absent here are dropped.
	// +kubebuilder:validation:MinItems=1
	ScopeBindings []MCPScopeBinding `json:"scopeBindings"`

	// TokenTTL is how long issued access tokens remain valid.
	// +kubebuilder:default="1h"
	TokenTTL string `json:"tokenTTL,omitempty"`

	// AllowedClients optionally restricts which client_id values are
	// accepted. Empty means any client_id in a valid ID-JAG is accepted.
	// +optional
	AllowedClients []string `json:"allowedClients,omitempty"`

	// TokenValidation configures how the MCP server validates the tokens
	// LightweightAuth issues for it.
	TokenValidation MCPTokenValidation `json:"tokenValidation"`
}

// MCPScopeBinding maps an OAuth scope to a role claim.
type MCPScopeBinding struct {
	// Scope is the OAuth scope string (e.g. "mcp:read").
	// +kubebuilder:validation:Required
	Scope string `json:"scope"`

	// Role is embedded as the `role` claim in the issued access token.
	// The MCP server reads it to enforce tool-level authorization.
	// +kubebuilder:validation:Required
	Role string `json:"role"`

	// Rank orders overlapping scopes. When a token grants multiple
	// scopes, the binding with the highest Rank wins. Defaults to the
	// position in the list if unset.
	// +optional
	Rank int `json:"rank,omitempty"`
}

// MCPTokenValidation describes how the MCP server validates issued tokens.
type MCPTokenValidation struct {
	// Mode is "extauthz" (MCP server behind Envoy + lwauth ext_authz) or
	// "jwks" (MCP server validates tokens itself against lwauth's JWKS).
	// +kubebuilder:validation:Enum=extauthz;jwks
	// +kubebuilder:default="extauthz"
	Mode string `json:"mode"`

	// AuthConfigRef names the AuthConfig used for extauthz validation.
	// If empty, the reconciler auto-generates one from this spec.
	// +optional
	AuthConfigRef string `json:"authConfigRef,omitempty"`
}

// MCPServerStatus is the observed state of an MCPServer registration.
type MCPServerStatus struct {
	// DiscoveryURL is the RFC 9728 Protected Resource Metadata URL.
	DiscoveryURL string `json:"discoveryURL,omitempty"`

	// TokenEndpointURL is the OAuth 2.0 token endpoint for this server.
	TokenEndpointURL string `json:"tokenEndpointURL,omitempty"`

	// JWKSEndpointURL is the JWKS endpoint for jwks-mode validation.
	JWKSEndpointURL string `json:"jwksEndpointURL,omitempty"`

	// SigningKeyExpiry is the expiry of the current RS256 signing key.
	// +optional
	SigningKeyExpiry *metav1.Time `json:"signingKeyExpiry,omitempty"`

	// ObservedGeneration tracks the latest generation reconciled.
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// Conditions follow the standard k8s condition pattern.
	// +optional
	// +patchMergeKey=type
	// +patchStrategy=merge
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty" patchStrategy:"merge" patchMergeKey:"type"`
}

// MCPServer condition types.
const (
	MCPServerConditionReady = "Ready"

	MCPServerReasonReconciled  = "Reconciled"
	MCPServerReasonIdPRefError = "IdentityProviderRefError"
	MCPServerReasonKeyError    = "SigningKeyError"
)

// +kubebuilder:object:root=true

// MCPServerList is the list type for MCPServer.
type MCPServerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []MCPServer `json:"items"`
}

// DeepCopyObject implements runtime.Object.
func (in *MCPServer) DeepCopyObject() runtime.Object { return in.DeepCopy() }

// DeepCopy clones the receiver.
func (in *MCPServer) DeepCopy() *MCPServer {
	if in == nil {
		return nil
	}
	out := &MCPServer{}
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
	return out
}

// DeepCopyInto copies spec fields into out.
func (in *MCPServerSpec) DeepCopyInto(out *MCPServerSpec) {
	*out = *in
	out.TokenValidation = in.TokenValidation
	if in.ScopeBindings != nil {
		out.ScopeBindings = make([]MCPScopeBinding, len(in.ScopeBindings))
		copy(out.ScopeBindings, in.ScopeBindings)
	}
	if in.AllowedClients != nil {
		out.AllowedClients = append([]string(nil), in.AllowedClients...)
	}
}

// DeepCopyInto copies status fields into out.
func (in *MCPServerStatus) DeepCopyInto(out *MCPServerStatus) {
	*out = *in
	if in.SigningKeyExpiry != nil {
		out.SigningKeyExpiry = in.SigningKeyExpiry.DeepCopy()
	}
	if in.Conditions != nil {
		out.Conditions = make([]metav1.Condition, len(in.Conditions))
		for i := range in.Conditions {
			in.Conditions[i].DeepCopyInto(&out.Conditions[i])
		}
	}
}

// DeepCopyObject implements runtime.Object.
func (in *MCPServerList) DeepCopyObject() runtime.Object { return in.DeepCopy() }

// DeepCopy clones the list.
func (in *MCPServerList) DeepCopy() *MCPServerList {
	if in == nil {
		return nil
	}
	out := &MCPServerList{TypeMeta: in.TypeMeta}
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	out.Items = make([]MCPServer, len(in.Items))
	for i := range in.Items {
		out.Items[i] = *in.Items[i].DeepCopy()
	}
	return out
}
