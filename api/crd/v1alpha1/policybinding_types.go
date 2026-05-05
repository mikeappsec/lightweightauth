// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// =====================================================================
// PolicyBinding — namespaced RBAC policy for the admin plane.
// Declares which subjects can perform which verbs on AuthConfig
// resources within the binding's namespace.
// =====================================================================

// +kubebuilder:object:root=true

// PolicyBinding defines per-namespace admin RBAC rules for AuthConfig
// resources. Each binding declares a set of subjects (users, groups,
// service accounts) and the verbs they are allowed to perform on
// AuthConfig resources in this namespace.
//
// When the lwauth validating webhook is active, any CREATE/UPDATE/DELETE
// on an AuthConfig is checked against all PolicyBindings in the same
// namespace. If no PolicyBinding grants the requesting user the
// required verb, the request is denied.
//
// This implements G2 (ADMIN-RBAC-1) — separation-of-duties for the
// auth control plane.
type PolicyBinding struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              PolicyBindingSpec `json:"spec"`
}

// PolicyBindingSpec defines who can do what to AuthConfig resources.
type PolicyBindingSpec struct {
	// Subjects lists the identities this binding applies to.
	Subjects []PolicySubject `json:"subjects"`

	// Verbs lists the operations allowed. Valid values:
	// "create", "update", "delete", "*" (all).
	Verbs []PolicyVerb `json:"verbs"`

	// ResourceNames optionally restricts the binding to specific
	// AuthConfig names. If empty, the binding applies to all
	// AuthConfigs in the namespace.
	ResourceNames []string `json:"resourceNames,omitempty"`
}

// PolicySubject identifies a requestor.
type PolicySubject struct {
	// Kind is one of: "User", "Group", "ServiceAccount".
	Kind SubjectKind `json:"kind"`
	// Name is the subject's identifier.
	// For User: the Kubernetes username (e.g. "alice@example.com").
	// For Group: the group name (e.g. "platform-team").
	// For ServiceAccount: the SA name (namespace is inferred from the
	// PolicyBinding's namespace, or explicitly set via Namespace field).
	Name string `json:"name"`
	// Namespace is only relevant for ServiceAccount subjects. If empty,
	// the PolicyBinding's own namespace is used.
	Namespace string `json:"namespace,omitempty"`
}

// SubjectKind enumerates valid subject types.
type SubjectKind string

const (
	SubjectKindUser           SubjectKind = "User"
	SubjectKindGroup          SubjectKind = "Group"
	SubjectKindServiceAccount SubjectKind = "ServiceAccount"
)

// PolicyVerb enumerates valid verbs for policy bindings.
type PolicyVerb string

const (
	PolicyVerbCreate PolicyVerb = "create"
	PolicyVerbUpdate PolicyVerb = "update"
	PolicyVerbDelete PolicyVerb = "delete"
	PolicyVerbAll    PolicyVerb = "*"
)

// +kubebuilder:object:root=true

// PolicyBindingList is the list type for PolicyBinding.
type PolicyBindingList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []PolicyBinding `json:"items"`
}

// DeepCopyObject implements runtime.Object.
func (in *PolicyBinding) DeepCopyObject() runtime.Object { return in.DeepCopy() }

// DeepCopy clones the receiver.
func (in *PolicyBinding) DeepCopy() *PolicyBinding {
	if in == nil {
		return nil
	}
	out := &PolicyBinding{TypeMeta: in.TypeMeta}
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	out.Spec.Verbs = append([]PolicyVerb(nil), in.Spec.Verbs...)
	out.Spec.ResourceNames = append([]string(nil), in.Spec.ResourceNames...)
	out.Spec.Subjects = make([]PolicySubject, len(in.Spec.Subjects))
	copy(out.Spec.Subjects, in.Spec.Subjects)
	return out
}

// DeepCopyObject implements runtime.Object.
func (in *PolicyBindingList) DeepCopyObject() runtime.Object { return in.DeepCopy() }

// DeepCopy clones the list and every item.
func (in *PolicyBindingList) DeepCopy() *PolicyBindingList {
	if in == nil {
		return nil
	}
	out := &PolicyBindingList{TypeMeta: in.TypeMeta}
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	out.Items = make([]PolicyBinding, len(in.Items))
	for i := range in.Items {
		out.Items[i] = *in.Items[i].DeepCopy()
	}
	return out
}
