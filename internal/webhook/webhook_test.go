// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package webhook

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	admissionv1 "k8s.io/api/admission/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"

	crdv1alpha1 "github.com/mikeappsec/lightweightauth/api/crd/v1alpha1"
)

func makeReview(op admissionv1.Operation, user string, groups []string, resource, name, ns string) admissionv1.AdmissionReview {
	return admissionv1.AdmissionReview{
		TypeMeta: metav1.TypeMeta{APIVersion: "admission.k8s.io/v1", Kind: "AdmissionReview"},
		Request: &admissionv1.AdmissionRequest{
			UID:       types.UID("test-uid"),
			Operation: op,
			UserInfo:  authenticationv1.UserInfo{Username: user, Groups: groups},
			Resource:  metav1.GroupVersionResource{Group: "lightweightauth.io", Version: "v1alpha1", Resource: resource},
			Name:      name,
			Namespace: ns,
		},
	}
}

func postReview(t *testing.T, handler http.Handler, review admissionv1.AdmissionReview) admissionv1.AdmissionReview {
	t.Helper()
	body, err := json.Marshal(review)
	if err != nil {
		t.Fatalf("marshal review: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/validate-authconfig", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp admissionv1.AdmissionReview
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	return resp
}

func binding(name, ns string, subjects []crdv1alpha1.PolicySubject, verbs []crdv1alpha1.PolicyVerb, resourceNames []string) crdv1alpha1.PolicyBinding {
	return crdv1alpha1.PolicyBinding{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec: crdv1alpha1.PolicyBindingSpec{
			Subjects:      subjects,
			Verbs:         verbs,
			ResourceNames: resourceNames,
		},
	}
}

func TestWebhook_DeniesWhenNoBindings(t *testing.T) {
	resolver := NewStaticResolver(nil)
	handler := NewHandler(resolver, nil)

	review := makeReview(admissionv1.Create, "alice", nil, "authconfigs", "my-config", "team-a")
	resp := postReview(t, handler, review)

	if resp.Response.Allowed {
		t.Fatalf("expected denied when namespace has no PolicyBindings")
	}
}

func TestWebhook_AllowsAuthorizedUser(t *testing.T) {
	resolver := NewStaticResolver(map[string][]crdv1alpha1.PolicyBinding{
		"team-a": {
			binding("editors", "team-a",
				[]crdv1alpha1.PolicySubject{{Kind: crdv1alpha1.SubjectKindUser, Name: "alice"}},
				[]crdv1alpha1.PolicyVerb{crdv1alpha1.PolicyVerbCreate, crdv1alpha1.PolicyVerbUpdate},
				nil,
			),
		},
	})
	handler := NewHandler(resolver, nil)

	review := makeReview(admissionv1.Create, "alice", nil, "authconfigs", "my-config", "team-a")
	resp := postReview(t, handler, review)

	if !resp.Response.Allowed {
		t.Fatalf("expected allowed, got denied: %s", resp.Response.Result.Message)
	}
}

func TestWebhook_DeniesUnauthorizedUser(t *testing.T) {
	resolver := NewStaticResolver(map[string][]crdv1alpha1.PolicyBinding{
		"team-a": {
			binding("editors", "team-a",
				[]crdv1alpha1.PolicySubject{{Kind: crdv1alpha1.SubjectKindUser, Name: "alice"}},
				[]crdv1alpha1.PolicyVerb{crdv1alpha1.PolicyVerbCreate},
				nil,
			),
		},
	})
	handler := NewHandler(resolver, nil)

	// "bob" is not in the binding.
	review := makeReview(admissionv1.Create, "bob", nil, "authconfigs", "my-config", "team-a")
	resp := postReview(t, handler, review)

	if resp.Response.Allowed {
		t.Fatal("expected denied, got allowed")
	}
	if resp.Response.Result.Code != 403 {
		t.Fatalf("expected 403, got %d", resp.Response.Result.Code)
	}
}

func TestWebhook_AllowsGroupMatch(t *testing.T) {
	resolver := NewStaticResolver(map[string][]crdv1alpha1.PolicyBinding{
		"team-b": {
			binding("platform-team", "team-b",
				[]crdv1alpha1.PolicySubject{{Kind: crdv1alpha1.SubjectKindGroup, Name: "platform-admins"}},
				[]crdv1alpha1.PolicyVerb{crdv1alpha1.PolicyVerbAll},
				nil,
			),
		},
	})
	handler := NewHandler(resolver, nil)

	review := makeReview(admissionv1.Delete, "charlie", []string{"platform-admins", "devs"}, "authconfigs", "x", "team-b")
	resp := postReview(t, handler, review)

	if !resp.Response.Allowed {
		t.Fatalf("expected allowed via group, got denied: %s", resp.Response.Result.Message)
	}
}

func TestWebhook_AllowsServiceAccountMatch(t *testing.T) {
	resolver := NewStaticResolver(map[string][]crdv1alpha1.PolicyBinding{
		"infra": {
			binding("ci-deploy", "infra",
				[]crdv1alpha1.PolicySubject{{Kind: crdv1alpha1.SubjectKindServiceAccount, Name: "deploy-bot"}},
				[]crdv1alpha1.PolicyVerb{crdv1alpha1.PolicyVerbCreate, crdv1alpha1.PolicyVerbUpdate},
				nil,
			),
		},
	})
	handler := NewHandler(resolver, nil)

	// K8s represents SAs as "system:serviceaccount:<ns>:<name>"
	review := makeReview(admissionv1.Update, "system:serviceaccount:infra:deploy-bot", nil, "authconfigs", "svc-config", "infra")
	resp := postReview(t, handler, review)

	if !resp.Response.Allowed {
		t.Fatalf("expected allowed via SA, got denied: %s", resp.Response.Result.Message)
	}
}

func TestWebhook_DeniesWrongVerb(t *testing.T) {
	resolver := NewStaticResolver(map[string][]crdv1alpha1.PolicyBinding{
		"ns1": {
			binding("readers", "ns1",
				[]crdv1alpha1.PolicySubject{{Kind: crdv1alpha1.SubjectKindUser, Name: "alice"}},
				[]crdv1alpha1.PolicyVerb{crdv1alpha1.PolicyVerbCreate},
				nil,
			),
		},
	})
	handler := NewHandler(resolver, nil)

	// alice can create but NOT delete.
	review := makeReview(admissionv1.Delete, "alice", nil, "authconfigs", "cfg", "ns1")
	resp := postReview(t, handler, review)

	if resp.Response.Allowed {
		t.Fatal("expected denied for wrong verb, got allowed")
	}
}

func TestWebhook_ResourceNameRestriction(t *testing.T) {
	resolver := NewStaticResolver(map[string][]crdv1alpha1.PolicyBinding{
		"ns1": {
			binding("scoped", "ns1",
				[]crdv1alpha1.PolicySubject{{Kind: crdv1alpha1.SubjectKindUser, Name: "alice"}},
				[]crdv1alpha1.PolicyVerb{crdv1alpha1.PolicyVerbAll},
				[]string{"allowed-config"},
			),
		},
	})
	handler := NewHandler(resolver, nil)

	// Allowed: resource name matches.
	review := makeReview(admissionv1.Update, "alice", nil, "authconfigs", "allowed-config", "ns1")
	resp := postReview(t, handler, review)
	if !resp.Response.Allowed {
		t.Fatalf("expected allowed for matching resource name, got denied")
	}

	// Denied: resource name doesn't match.
	review2 := makeReview(admissionv1.Update, "alice", nil, "authconfigs", "other-config", "ns1")
	resp2 := postReview(t, handler, review2)
	if resp2.Response.Allowed {
		t.Fatal("expected denied for non-matching resource name, got allowed")
	}

	// CREATE with empty req.Name must still enforce resourceNames by using metadata.name.
	review3 := makeReview(admissionv1.Create, "alice", nil, "authconfigs", "", "ns1")
	objAllowed := map[string]any{"metadata": map[string]any{"name": "allowed-config"}}
	rawAllowed, err := json.Marshal(objAllowed)
	if err != nil {
		t.Fatalf("marshal object: %v", err)
	}
	review3.Request.Object = runtime.RawExtension{Raw: rawAllowed}
	resp3 := postReview(t, handler, review3)
	if !resp3.Response.Allowed {
		t.Fatalf("expected CREATE allowed for metadata.name matching resourceNames")
	}

	review4 := makeReview(admissionv1.Create, "alice", nil, "authconfigs", "", "ns1")
	objDenied := map[string]any{"metadata": map[string]any{"name": "other-config"}}
	rawDenied, err := json.Marshal(objDenied)
	if err != nil {
		t.Fatalf("marshal object: %v", err)
	}
	review4.Request.Object = runtime.RawExtension{Raw: rawDenied}
	resp4 := postReview(t, handler, review4)
	if resp4.Response.Allowed {
		t.Fatalf("expected CREATE denied for metadata.name not in resourceNames")
	}
}

func TestWebhook_NonAuthConfigAllowed(t *testing.T) {
	resolver := NewStaticResolver(map[string][]crdv1alpha1.PolicyBinding{
		"ns1": {
			binding("strict", "ns1",
				[]crdv1alpha1.PolicySubject{{Kind: crdv1alpha1.SubjectKindUser, Name: "alice"}},
				[]crdv1alpha1.PolicyVerb{crdv1alpha1.PolicyVerbCreate},
				nil,
			),
		},
	})
	handler := NewHandler(resolver, nil)

	// A different resource type — should be allowed without checking bindings.
	review := makeReview(admissionv1.Create, "bob", nil, "authpolicies", "some-policy", "ns1")
	resp := postReview(t, handler, review)

	if !resp.Response.Allowed {
		t.Fatalf("expected allowed for non-AuthConfig resource, got denied")
	}
}

func TestWebhook_FailClosedOnResolverError(t *testing.T) {
	resolver := &errorResolver{}
	handler := NewHandler(resolver, nil)

	review := makeReview(admissionv1.Create, "bob", nil, "authconfigs", "cfg", "ns1")
	resp := postReview(t, handler, review)

	if resp.Response.Allowed {
		t.Fatalf("expected fail-closed on resolver error, got allowed")
	}
}

func TestWebhook_DeniesUnknownOperation(t *testing.T) {
	resolver := NewStaticResolver(map[string][]crdv1alpha1.PolicyBinding{
		"ns1": {
			binding("admins", "ns1",
				[]crdv1alpha1.PolicySubject{{Kind: crdv1alpha1.SubjectKindUser, Name: "alice"}},
				[]crdv1alpha1.PolicyVerb{crdv1alpha1.PolicyVerbAll},
				nil,
			),
		},
	})
	handler := NewHandler(resolver, nil)

	// CONNECT is not a supported AuthConfig mutation operation.
	review := makeReview(admissionv1.Operation("CONNECT"), "alice", nil, "authconfigs", "cfg", "ns1")
	resp := postReview(t, handler, review)
	if resp.Response.Allowed {
		t.Fatalf("expected denied for unknown operation")
	}
}

// errorResolver always returns an error.
type errorResolver struct{}

func (r *errorResolver) ListBindings(_ context.Context, _ string) ([]crdv1alpha1.PolicyBinding, error) {
	return nil, context.DeadlineExceeded
}

func TestWebhook_MethodNotAllowed(t *testing.T) {
	handler := NewHandler(NewStaticResolver(nil), nil)
	req := httptest.NewRequest(http.MethodGet, "/validate-authconfig", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", rec.Code)
	}
}

func TestWebhook_WildcardVerb(t *testing.T) {
	resolver := NewStaticResolver(map[string][]crdv1alpha1.PolicyBinding{
		"ns1": {
			binding("super", "ns1",
				[]crdv1alpha1.PolicySubject{{Kind: crdv1alpha1.SubjectKindUser, Name: "admin"}},
				[]crdv1alpha1.PolicyVerb{crdv1alpha1.PolicyVerbAll},
				nil,
			),
		},
	})
	handler := NewHandler(resolver, nil)

	for _, op := range []admissionv1.Operation{admissionv1.Create, admissionv1.Update, admissionv1.Delete} {
		review := makeReview(op, "admin", nil, "authconfigs", "any", "ns1")
		resp := postReview(t, handler, review)
		if !resp.Response.Allowed {
			t.Fatalf("expected wildcard to allow %s, got denied", op)
		}
	}
}
