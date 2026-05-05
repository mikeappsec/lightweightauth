// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

// Package webhook implements the Kubernetes validating admission webhook
// for LightweightAuth admin-plane RBAC (G2: ADMIN-RBAC-1).
//
// The webhook intercepts CREATE/UPDATE/DELETE operations on AuthConfig
// resources and validates that the requesting user is authorized by a
// PolicyBinding in the target namespace. This enforces separation of
// duties — one team cannot edit another team's auth policy even if they
// have Kubernetes RBAC `edit` on the namespace.
//
// The webhook is intentionally fail-open (failurePolicy: Ignore) so that
// a webhook outage does not block all AuthConfig changes cluster-wide.
// This trade-off is documented in DESIGN.md §G2.
package webhook

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"

	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	crdv1alpha1 "github.com/mikeappsec/lightweightauth/api/crd/v1alpha1"
)

// PolicyResolver looks up PolicyBindings for a given namespace.
// In production this is backed by an informer cache; tests inject a
// static implementation.
type PolicyResolver interface {
	// ListBindings returns all PolicyBindings in the given namespace.
	ListBindings(ctx context.Context, namespace string) ([]crdv1alpha1.PolicyBinding, error)
}

// Handler is the admission webhook HTTP handler.
type Handler struct {
	resolver PolicyResolver
	log      *slog.Logger
}

// NewHandler creates a validating admission webhook handler.
func NewHandler(resolver PolicyResolver, log *slog.Logger) *Handler {
	if log == nil {
		log = slog.Default()
	}
	return &Handler{resolver: resolver, log: log}
}

// ServeHTTP handles admission review requests.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20)) // 1 MiB max
	if err != nil {
		http.Error(w, "failed to read body", http.StatusBadRequest)
		return
	}

	var review admissionv1.AdmissionReview
	if err := json.Unmarshal(body, &review); err != nil {
		http.Error(w, "invalid admission review", http.StatusBadRequest)
		return
	}

	if review.Request == nil {
		http.Error(w, "missing request in admission review", http.StatusBadRequest)
		return
	}

	response := h.validate(r.Context(), review.Request)
	review.Response = response
	review.Response.UID = review.Request.UID

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(review); err != nil {
		h.log.Error("failed to encode admission response", "error", err)
	}
}

// validate checks the admission request against PolicyBindings.
func (h *Handler) validate(ctx context.Context, req *admissionv1.AdmissionRequest) *admissionv1.AdmissionResponse {
	// Only validate AuthConfig resources.
	if req.Resource.Group != crdv1alpha1.GroupVersion.Group ||
		req.Resource.Resource != "authconfigs" {
		return allowed("not an AuthConfig resource")
	}

	// Map the K8s operation to our policy verb.
	verb, ok := operationToVerb(req.Operation)
	if !ok {
		return allowed("operation not gated")
	}

	// Look up PolicyBindings in the target namespace.
	bindings, err := h.resolver.ListBindings(ctx, req.Namespace)
	if err != nil {
		h.log.Error("failed to list policy bindings",
			"namespace", req.Namespace,
			"error", err,
		)
		// Fail-open: allow if we can't resolve bindings.
		return allowed("policy resolver error (fail-open)")
	}

	// If no bindings exist in the namespace, allow (no policy = open).
	if len(bindings) == 0 {
		return allowed("no PolicyBindings in namespace")
	}

	// Check if any binding authorizes this user.
	userInfo := UserInfo{
		Username: req.UserInfo.Username,
		Groups:   req.UserInfo.Groups,
	}

	resourceName := ""
	if req.Name != "" {
		resourceName = req.Name
	}

	for i := range bindings {
		if bindingAuthorizes(&bindings[i], userInfo, verb, resourceName) {
			h.log.Info("admin RBAC: allowed",
				"user", userInfo.Username,
				"verb", verb,
				"resource", resourceName,
				"namespace", req.Namespace,
				"binding", bindings[i].Name,
			)
			return allowed(fmt.Sprintf("authorized by PolicyBinding %q", bindings[i].Name))
		}
	}

	// Denied: no binding matched.
	reason := fmt.Sprintf(
		"user %q is not authorized to %s AuthConfig %q in namespace %q (no matching PolicyBinding)",
		userInfo.Username, verb, resourceName, req.Namespace,
	)
	h.log.Warn("admin RBAC: denied",
		"user", userInfo.Username,
		"verb", verb,
		"resource", resourceName,
		"namespace", req.Namespace,
	)
	return denied(reason)
}

// UserInfo is the extracted user information from an admission request.
type UserInfo struct {
	Username string
	Groups   []string
}

// bindingAuthorizes checks if a PolicyBinding grants the given user
// the given verb on the given resource.
func bindingAuthorizes(binding *crdv1alpha1.PolicyBinding, user UserInfo, verb crdv1alpha1.PolicyVerb, resourceName string) bool {
	// Check verb match.
	if !verbMatches(binding.Spec.Verbs, verb) {
		return false
	}

	// Check resource name restriction.
	if len(binding.Spec.ResourceNames) > 0 && resourceName != "" {
		if !stringInSlice(resourceName, binding.Spec.ResourceNames) {
			return false
		}
	}

	// Check subject match.
	for _, subject := range binding.Spec.Subjects {
		if subjectMatches(subject, user, binding.Namespace) {
			return true
		}
	}
	return false
}

// subjectMatches checks if a PolicySubject matches the given user.
func subjectMatches(subject crdv1alpha1.PolicySubject, user UserInfo, bindingNamespace string) bool {
	switch subject.Kind {
	case crdv1alpha1.SubjectKindUser:
		return subject.Name == user.Username
	case crdv1alpha1.SubjectKindGroup:
		return stringInSlice(subject.Name, user.Groups)
	case crdv1alpha1.SubjectKindServiceAccount:
		// Kubernetes represents service accounts as
		// "system:serviceaccount:<namespace>:<name>"
		ns := subject.Namespace
		if ns == "" {
			ns = bindingNamespace
		}
		expected := "system:serviceaccount:" + ns + ":" + subject.Name
		return user.Username == expected
	default:
		return false
	}
}

// verbMatches checks if the verb list includes the target verb.
func verbMatches(verbs []crdv1alpha1.PolicyVerb, target crdv1alpha1.PolicyVerb) bool {
	for _, v := range verbs {
		if v == target || v == crdv1alpha1.PolicyVerbAll {
			return true
		}
	}
	return false
}

// operationToVerb maps Kubernetes admission operations to policy verbs.
func operationToVerb(op admissionv1.Operation) (crdv1alpha1.PolicyVerb, bool) {
	switch op {
	case admissionv1.Create:
		return crdv1alpha1.PolicyVerbCreate, true
	case admissionv1.Update:
		return crdv1alpha1.PolicyVerbUpdate, true
	case admissionv1.Delete:
		return crdv1alpha1.PolicyVerbDelete, true
	default:
		return "", false
	}
}

func stringInSlice(s string, slice []string) bool {
	for _, item := range slice {
		if item == s {
			return true
		}
	}
	return false
}

func allowed(reason string) *admissionv1.AdmissionResponse {
	return &admissionv1.AdmissionResponse{
		Allowed: true,
		Result: &metav1.Status{
			Message: reason,
		},
	}
}

func denied(reason string) *admissionv1.AdmissionResponse {
	return &admissionv1.AdmissionResponse{
		Allowed: false,
		Result: &metav1.Status{
			Status:  "Failure",
			Message: reason,
			Reason:  metav1.StatusReasonForbidden,
			Code:    403,
		},
	}
}
