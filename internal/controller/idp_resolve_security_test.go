package controller

// Security regressions for IdP-ref trust-material handling.
//
// issuerUrl and jwksUrl are TRUST anchors: when an identifier sets
// idpRef, the cluster IdP's values must overwrite any tenant-supplied
// ones. Otherwise a tenant with AuthConfig write access could
// reference an approved IdentityProvider while still pointing the
// identifier at an attacker-controlled issuer/JWKS, defeating the
// reference. Reviewers / admission policies that treat `idpRef` as
// proof of centralised trust would be silently bypassed.

import (
	"testing"

	v1alpha1 "github.com/mikeappsec/lightweightauth/api/crd/v1alpha1"
	"github.com/mikeappsec/lightweightauth/internal/config"
)

func TestResolveIdPRefs_TenantCannotOverrideTrustMaterial(t *testing.T) {
	t.Parallel()
	ac := &config.AuthConfig{
		Identifiers: []config.ModuleSpec{
			{Name: "j", Type: "jwt", Config: map[string]any{
				"idpRef":    "corp",
				"issuerUrl": "https://attacker.example.com",
				"jwksUrl":   "https://attacker.example.com/jwks",
			}},
		},
	}
	idps := []v1alpha1.IdentityProvider{
		makeIdP("corp", v1alpha1.IdentityProviderSpec{
			IssuerURL: "https://idp.corp",
			JWKSURL:   "https://idp.corp/jwks",
		}),
	}
	if err := ResolveIdPRefs(ac, idps); err != nil {
		t.Fatalf("ResolveIdPRefs: %v", err)
	}
	cfg := ac.Identifiers[0].Config

	if got := cfg["issuerUrl"]; got != "https://idp.corp" {
		t.Errorf("issuerUrl = %q, want https://idp.corp (tenant override must lose)", got)
	}
	if got := cfg["jwksUrl"]; got != "https://idp.corp/jwks" {
		t.Errorf("jwksUrl = %q, want https://idp.corp/jwks (tenant override must lose)", got)
	}
}

// TestResolveIdPRefs_OperationalDefaultsRemainOverridable asserts the
// fix is precisely scoped: header / scheme / minRefreshInterval /
// audiences are NOT trust material and remain tenant-overridable.
// (This duplicates part of TestResolveIdPRefs_TenantOverrideWins as a
// positive control adjacent to the security fence.)
func TestResolveIdPRefs_OperationalDefaultsRemainOverridable(t *testing.T) {
	t.Parallel()
	ac := &config.AuthConfig{
		Identifiers: []config.ModuleSpec{
			{Name: "j", Type: "jwt", Config: map[string]any{
				"idpRef": "corp",
				"header": "X-Tenant-Token",
				"scheme": "Custom",
			}},
		},
	}
	idps := []v1alpha1.IdentityProvider{
		makeIdP("corp", v1alpha1.IdentityProviderSpec{
			IssuerURL: "https://idp.corp",
			JWKSURL:   "https://idp.corp/jwks",
			Header:    "Authorization",
			Scheme:    "Bearer",
		}),
	}
	if err := ResolveIdPRefs(ac, idps); err != nil {
		t.Fatalf("ResolveIdPRefs: %v", err)
	}
	cfg := ac.Identifiers[0].Config
	if cfg["header"] != "X-Tenant-Token" {
		t.Errorf("header = %q, want tenant value (operational override must win)", cfg["header"])
	}
	if cfg["scheme"] != "Custom" {
		t.Errorf("scheme = %q, want tenant value (operational override must win)", cfg["scheme"])
	}
}
