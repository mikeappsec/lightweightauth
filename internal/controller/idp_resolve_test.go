package controller

import (
	"reflect"
	"sort"
	"testing"

	v1alpha1 "github.com/mikeappsec/lightweightauth/api/crd/v1alpha1"
	"github.com/mikeappsec/lightweightauth/internal/config"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func makeIdP(name string, spec v1alpha1.IdentityProviderSpec) v1alpha1.IdentityProvider {
	return v1alpha1.IdentityProvider{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec:       spec,
	}
}

func TestResolveIdPRefs_NoRefIsNoOp(t *testing.T) {
	ac := &config.AuthConfig{
		Identifiers: []config.ModuleSpec{
			{Name: "j", Type: "jwt", Config: map[string]any{
				"jwksUrl": "https://example/jwks",
			}},
		},
	}
	if err := ResolveIdPRefs(ac, nil); err != nil {
		t.Fatalf("ResolveIdPRefs: %v", err)
	}
	if got := ac.Identifiers[0].Config["jwksUrl"]; got != "https://example/jwks" {
		t.Fatalf("config mutated unexpectedly: %v", ac.Identifiers[0].Config)
	}
}

func TestResolveIdPRefs_FillsFromIdP(t *testing.T) {
	ac := &config.AuthConfig{
		Identifiers: []config.ModuleSpec{
			{Name: "j", Type: "jwt", Config: map[string]any{"idpRef": "corp"}},
		},
	}
	idps := []v1alpha1.IdentityProvider{
		makeIdP("corp", v1alpha1.IdentityProviderSpec{
			IssuerURL: "https://idp.corp",
			JWKSURL:   "https://idp.corp/jwks",
			Audiences: []string{"api.corp", "ops.corp"},
			Header:    "Authorization",
			Scheme:    "Bearer",
		}),
	}
	if err := ResolveIdPRefs(ac, idps); err != nil {
		t.Fatalf("ResolveIdPRefs: %v", err)
	}
	cfg := ac.Identifiers[0].Config
	if _, present := cfg["idpRef"]; present {
		t.Fatalf("idpRef marker not stripped: %v", cfg)
	}
	if cfg["issuerUrl"] != "https://idp.corp" || cfg["jwksUrl"] != "https://idp.corp/jwks" {
		t.Fatalf("issuer/jwks not merged: %v", cfg)
	}
	auds := stringSlice(cfg["audiences"])
	sort.Strings(auds)
	if !reflect.DeepEqual(auds, []string{"api.corp", "ops.corp"}) {
		t.Fatalf("audiences = %v", auds)
	}
}

func TestResolveIdPRefs_TenantOverrideWins(t *testing.T) {
	ac := &config.AuthConfig{
		Identifiers: []config.ModuleSpec{
			{Name: "j", Type: "jwt", Config: map[string]any{
				"idpRef":    "corp",
				"header":    "X-Tenant-Token", // override
				"audiences": []any{"tenant-only"},
			}},
		},
	}
	idps := []v1alpha1.IdentityProvider{
		makeIdP("corp", v1alpha1.IdentityProviderSpec{
			IssuerURL: "https://idp.corp",
			JWKSURL:   "https://idp.corp/jwks",
			Audiences: []string{"api.corp"},
			Header:    "Authorization",
		}),
	}
	if err := ResolveIdPRefs(ac, idps); err != nil {
		t.Fatalf("ResolveIdPRefs: %v", err)
	}
	cfg := ac.Identifiers[0].Config

	// Tenant-set header wins.
	if cfg["header"] != "X-Tenant-Token" {
		t.Fatalf("header override lost: %v", cfg["header"])
	}
	// Audience set-union (tenant + cluster).
	auds := stringSlice(cfg["audiences"])
	sort.Strings(auds)
	want := []string{"api.corp", "tenant-only"}
	if !reflect.DeepEqual(auds, want) {
		t.Fatalf("audiences = %v, want %v", auds, want)
	}
	// IdP-only fields fill in.
	if cfg["issuerUrl"] != "https://idp.corp" || cfg["jwksUrl"] != "https://idp.corp/jwks" {
		t.Fatalf("idp fields missing: %v", cfg)
	}
}

func TestResolveIdPRefs_UnknownRefIsError(t *testing.T) {
	ac := &config.AuthConfig{
		Identifiers: []config.ModuleSpec{
			{Name: "j", Type: "jwt", Config: map[string]any{"idpRef": "ghost"}},
		},
	}
	err := ResolveIdPRefs(ac, []v1alpha1.IdentityProvider{
		makeIdP("corp", v1alpha1.IdentityProviderSpec{IssuerURL: "x"}),
	})
	if err == nil {
		t.Fatal("expected error for unknown idpRef")
	}
}

func TestResolveIdPRefs_AudienceDeduplicates(t *testing.T) {
	ac := &config.AuthConfig{
		Identifiers: []config.ModuleSpec{
			{Name: "j", Type: "jwt", Config: map[string]any{
				"idpRef":    "corp",
				"audiences": []any{"shared", "tenant"},
			}},
		},
	}
	idps := []v1alpha1.IdentityProvider{
		makeIdP("corp", v1alpha1.IdentityProviderSpec{
			IssuerURL: "x",
			Audiences: []string{"shared", "cluster"},
		}),
	}
	if err := ResolveIdPRefs(ac, idps); err != nil {
		t.Fatalf("ResolveIdPRefs: %v", err)
	}
	auds := stringSlice(ac.Identifiers[0].Config["audiences"])
	sort.Strings(auds)
	want := []string{"cluster", "shared", "tenant"}
	if !reflect.DeepEqual(auds, want) {
		t.Fatalf("audiences = %v, want %v (de-duped)", auds, want)
	}
}
