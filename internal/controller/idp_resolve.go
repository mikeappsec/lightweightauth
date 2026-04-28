package controller

import (
	"fmt"

	v1alpha1 "github.com/mikeappsec/lightweightauth/api/crd/v1alpha1"
	"github.com/mikeappsec/lightweightauth/internal/config"
)

// ResolveIdPRefs expands every identifier in `ac` whose Config carries
// an `idpRef: <name>` key by looking the name up in `idps` (the list of
// cluster-scoped IdentityProvider CRs the controller cached) and
// merging the IdP's spec into the identifier's Config.
//
// Merge rules (M11 multi-tenancy hardening, DESIGN.md §8):
//
//   - The IdP defines the canonical key material: issuerUrl, jwksUrl,
//     audiences, header, scheme, minRefreshInterval.
//   - Tenant-set fields on the identifier WIN. So a tenant can extend
//     `audiences` (set-union) or override `header` for a special route
//     without forking the IdP definition cluster-wide.
//   - Unknown / typo'd `idpRef` is a hard config error — the
//     reconciler surfaces it on AuthConfig.status.
//
// Today we resolve refs for `jwt` identifiers; the same hook applies
// trivially to future bearer-style identifiers because they all read
// the same five-or-six keys.
//
// ResolveIdPRefs mutates the AuthConfig in place (the controller has
// already deep-copied the CR before calling it). Returns an error on
// the first unresolved reference.
func ResolveIdPRefs(ac *config.AuthConfig, idps []v1alpha1.IdentityProvider) error {
	if ac == nil || len(ac.Identifiers) == 0 {
		return nil
	}
	idx := make(map[string]v1alpha1.IdentityProvider, len(idps))
	for _, p := range idps {
		idx[p.Name] = p
	}
	for i := range ac.Identifiers {
		spec := &ac.Identifiers[i]
		ref, ok := spec.Config["idpRef"].(string)
		if !ok || ref == "" {
			continue
		}
		idp, found := idx[ref]
		if !found {
			return fmt.Errorf("identifier %q: idpRef %q not found among cluster-scoped IdentityProviders", spec.Name, ref)
		}
		if spec.Config == nil {
			spec.Config = map[string]any{}
		}
		mergeIdPInto(spec.Config, idp.Spec)
		// Drop the marker so factories don't see an unknown key.
		delete(spec.Config, "idpRef")
	}
	return nil
}

// mergeIdPInto copies fields from idp into cfg, leaving any
// tenant-set value alone. For audiences the merge is a set-union
// because an "API gateway shared by two services" idiom genuinely
// wants the cluster-defined list AND the tenant's extra audience.
func mergeIdPInto(cfg map[string]any, idp v1alpha1.IdentityProviderSpec) {
	setIfMissing(cfg, "issuerUrl", idp.IssuerURL)
	setIfMissing(cfg, "jwksUrl", idp.JWKSURL)
	setIfMissing(cfg, "header", idp.Header)
	setIfMissing(cfg, "scheme", idp.Scheme)
	setIfMissing(cfg, "minRefreshInterval", idp.MinRefreshInterval)

	if len(idp.Audiences) > 0 {
		existing := stringSlice(cfg["audiences"])
		seen := make(map[string]struct{}, len(existing)+len(idp.Audiences))
		merged := make([]any, 0, len(existing)+len(idp.Audiences))
		for _, a := range existing {
			if _, dup := seen[a]; dup {
				continue
			}
			seen[a] = struct{}{}
			merged = append(merged, a)
		}
		for _, a := range idp.Audiences {
			if _, dup := seen[a]; dup {
				continue
			}
			seen[a] = struct{}{}
			merged = append(merged, a)
		}
		cfg["audiences"] = merged
	}
}

func setIfMissing(cfg map[string]any, key, value string) {
	if value == "" {
		return
	}
	if v, ok := cfg[key].(string); ok && v != "" {
		return // tenant override wins
	}
	cfg[key] = value
}

// stringSlice normalizes the various decoded shapes audiences can take
// (yaml/json decoders give us []any, but a hand-built config can be
// []string).
func stringSlice(v any) []string {
	switch t := v.(type) {
	case []string:
		return t
	case []any:
		out := make([]string, 0, len(t))
		for _, x := range t {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}
