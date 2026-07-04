// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"encoding/json"
	"net/http"
	"sort"

	"github.com/mikeappsec/lightweightauth/internal/controlplane/provisioner"
	"github.com/mikeappsec/lightweightauth/pkg/module"
)

// ModuleInfo describes a registered module type for the UI catalogue.
type ModuleInfo struct {
	Type        string        `json:"type"`
	DisplayName string        `json:"displayName"`
	Description string        `json:"description"`
	BuiltIn     bool          `json:"builtIn"`
	Fields      []ModuleField `json:"fields"`
}

// ModuleField describes a single configurable field for a module type.
type ModuleField struct {
	Name        string   `json:"name"`
	Type        string   `json:"type"` // "string", "number", "boolean", "stringArray", "object", "select"
	Required    bool     `json:"required"`
	Default     any      `json:"default,omitempty"`
	Placeholder string   `json:"placeholder,omitempty"`
	Description string   `json:"description,omitempty"`
	Options     []string `json:"options,omitempty"` // For "select" type.
}

// ModuleCatalogue is the response for GET /v1/controlplane/modules.
type ModuleCatalogue struct {
	Identifiers        []ModuleInfo `json:"identifiers"`
	Authorizers        []ModuleInfo `json:"authorizers"`
	Mutators           []ModuleInfo `json:"mutators"`
	CacheBackends      []string     `json:"cacheBackends"`
	RevocationBackends []string     `json:"revocationBackends"`
}

// handleListModules returns the module catalogue for the create-node wizard.
func (s *Server) handleListModules(w http.ResponseWriter, r *http.Request) {
	identifierTypes := module.RegisteredTypes(module.KindIdentifier)
	authorizerTypes := module.RegisteredTypes(module.KindAuthorizer)
	mutatorTypes := module.RegisteredTypes(module.KindMutator)

	catalogue := ModuleCatalogue{
		Identifiers:        buildModuleInfoList(identifierTypes, identifierMeta),
		Authorizers:        buildModuleInfoList(authorizerTypes, authorizerMeta),
		Mutators:           buildModuleInfoList(mutatorTypes, mutatorMeta),
		CacheBackends:      []string{"memory", "valkey", "tiered"},
		RevocationBackends: []string{"memory", "valkey"},
	}

	writeJSON(w, http.StatusOK, catalogue)
}

func buildModuleInfoList(types []string, meta map[string]moduleMetadata) []ModuleInfo {
	sort.Strings(types)
	out := make([]ModuleInfo, 0, len(types))
	for _, t := range types {
		m, ok := meta[t]
		if !ok {
			m = moduleMetadata{
				displayName: t,
				description: "Module: " + t,
			}
		}
		out = append(out, ModuleInfo{
			Type:        t,
			DisplayName: m.displayName,
			Description: m.description,
			BuiltIn:     true,
			Fields:      m.fields,
		})
	}
	return out
}

// moduleMetadata holds the human-readable metadata and field schema for each
// built-in module type. This drives the UI form generation.
type moduleMetadata struct {
	displayName string
	description string
	fields      []ModuleField
}

// ── Identifier metadata ─────────────────────────────────────────────────

var identifierMeta = map[string]moduleMetadata{
	"jwt": {
		displayName: "JWT (OIDC / JWKS)",
		description: "Verify JWTs against a JWKS endpoint with issuer and audience validation",
		fields: []ModuleField{
			{Name: "jwksUrl", Type: "string", Required: true, Placeholder: "https://auth.example.com/.well-known/jwks.json", Description: "URL of the JWKS endpoint"},
			{Name: "issuer", Type: "string", Required: true, Placeholder: "https://auth.example.com", Description: "Expected token issuer (iss claim)"},
			{Name: "audiences", Type: "stringArray", Required: false, Placeholder: "api.example.com", Description: "Expected token audiences (aud claim)"},
			{Name: "clockSkew", Type: "string", Required: false, Default: "30s", Description: "Allowed clock skew for token validation"},
			{Name: "requiredClaims", Type: "object", Required: false, Description: "Additional claims that must be present"},
		},
	},
	"apikey": {
		displayName: "API Key",
		description: "Authenticate requests using API keys from headers or query parameters",
		fields: []ModuleField{
			{Name: "backend", Type: "select", Required: true, Default: "entries", Options: []string{"entries", "file", "kubernetes-secret"}, Description: "Key storage backend"},
			{Name: "header", Type: "string", Required: false, Default: "X-API-Key", Description: "Header name containing the API key"},
			{Name: "query", Type: "string", Required: false, Description: "Query parameter name (alternative to header)"},
			{Name: "secret", Type: "string", Required: false, Placeholder: "lwauth-api-keys", Description: "Kubernetes Secret name (for kubernetes-secret backend)"},
			{Name: "entries", Type: "object", Required: false, Description: "Inline key entries (for entries backend)"},
		},
	},
	"mtls": {
		displayName: "Mutual TLS (mTLS)",
		description: "Authenticate using client certificates with SPIFFE URI-SAN support",
		fields: []ModuleField{
			{Name: "trustedCAs", Type: "string", Required: false, Description: "Path to trusted CA bundle or Kubernetes Secret reference"},
			{Name: "subjectFrom", Type: "select", Required: false, Default: "spiffe", Options: []string{"spiffe", "cn", "dns-san"}, Description: "Extract subject identity from"},
			{Name: "allowedSpiffeIds", Type: "stringArray", Required: false, Description: "Allowed SPIFFE IDs (if subjectFrom=spiffe)"},
		},
	},
	"hmac": {
		displayName: "HMAC Signature",
		description: "Verify HMAC-signed requests with constant-time comparison",
		fields: []ModuleField{
			{Name: "clockSkew", Type: "string", Required: false, Default: "5m", Description: "Allowed clock skew"},
			{Name: "keys", Type: "object", Required: true, Description: "Named signing keys with subject and role mappings"},
		},
	},
	"oauth2": {
		displayName: "OAuth2 Auth Code",
		description: "Browser-based OAuth2 authorization code flow with PKCE",
		fields: []ModuleField{
			{Name: "issuer", Type: "string", Required: true, Placeholder: "https://auth.example.com", Description: "OAuth2 issuer URL"},
			{Name: "clientId", Type: "string", Required: true, Description: "OAuth2 client ID"},
			{Name: "clientSecret", Type: "string", Required: false, Description: "OAuth2 client secret (use vault:// reference)"},
			{Name: "redirectUrl", Type: "string", Required: true, Description: "OAuth2 redirect URL"},
			{Name: "scopes", Type: "stringArray", Required: false, Default: []string{"openid", "profile"}, Description: "OAuth2 scopes to request"},
		},
	},
	"oauth2-introspection": {
		displayName: "OAuth2 Token Introspection",
		description: "Validate opaque tokens via RFC 7662 introspection endpoint",
		fields: []ModuleField{
			{Name: "introspectionUrl", Type: "string", Required: true, Placeholder: "https://auth.example.com/oauth2/introspect", Description: "Token introspection endpoint URL"},
			{Name: "clientId", Type: "string", Required: true, Description: "Client ID for introspection"},
			{Name: "clientSecret", Type: "string", Required: false, Description: "Client secret (use vault:// reference)"},
			{Name: "cacheTtl", Type: "string", Required: false, Default: "60s", Description: "Cache TTL for introspection results"},
		},
	},
	"dpop": {
		displayName: "DPoP (RFC 9449)",
		description: "Sender-constrained token binding via Demonstrating Proof-of-Possession",
		fields: []ModuleField{
			{Name: "maxClockSkew", Type: "string", Required: false, Default: "30s", Description: "Maximum clock skew for DPoP proof"},
			{Name: "requiredCnf", Type: "boolean", Required: false, Default: true, Description: "Require cnf claim in access token"},
		},
	},
}

// ── Authorizer metadata ─────────────────────────────────────────────────

var authorizerMeta = map[string]moduleMetadata{
	"rbac": {
		displayName: "RBAC (Role-Based)",
		description: "Built-in role-based access control with subject-to-role-to-permission mapping",
		fields: []ModuleField{
			{Name: "roles", Type: "object", Required: true, Description: "Role definitions with permissions"},
			{Name: "rolesClaim", Type: "string", Required: false, Default: "roles", Description: "JWT claim containing user roles"},
		},
	},
	"opa": {
		displayName: "OPA / Rego",
		description: "Open Policy Agent embedded Rego policy evaluation",
		fields: []ModuleField{
			{Name: "policy", Type: "string", Required: true, Description: "Rego policy source (inline or file path)"},
			{Name: "query", Type: "string", Required: false, Default: "data.authz.allow", Description: "Rego query to evaluate"},
		},
	},
	"cel": {
		displayName: "CEL (Common Expression Language)",
		description: "Lightweight attribute-based policies using Google CEL expressions",
		fields: []ModuleField{
			{Name: "expression", Type: "string", Required: true, Placeholder: "request.method == 'GET' || identity.roles.exists(r, r == 'admin')", Description: "CEL expression returning a boolean"},
		},
	},
	"openfga": {
		displayName: "OpenFGA (Zanzibar ReBAC)",
		description: "Relationship-based access control via OpenFGA check API",
		fields: []ModuleField{
			{Name: "apiUrl", Type: "string", Required: true, Placeholder: "http://openfga:8080", Description: "OpenFGA API URL"},
			{Name: "storeId", Type: "string", Required: true, Description: "OpenFGA store ID"},
			{Name: "modelId", Type: "string", Required: false, Description: "Authorization model ID (latest if empty)"},
		},
	},
	"spicedb": {
		displayName: "SpiceDB (Zanzibar)",
		description: "Google Zanzibar-style permissions via SpiceDB CheckPermission API",
		fields: []ModuleField{
			{Name: "endpoint", Type: "string", Required: true, Placeholder: "spicedb:50051", Description: "SpiceDB gRPC endpoint"},
			{Name: "token", Type: "string", Required: false, Description: "Pre-shared token (use vault:// reference)"},
			{Name: "objectType", Type: "string", Required: true, Description: "Object type for permission checks"},
			{Name: "relation", Type: "string", Required: true, Description: "Relation / permission to check"},
		},
	},
	"composite": {
		displayName: "Composite (anyOf / allOf)",
		description: "Combine multiple authorizers with anyOf or allOf logic",
		fields: []ModuleField{
			{Name: "mode", Type: "select", Required: true, Default: "anyOf", Options: []string{"anyOf", "allOf"}, Description: "Composition mode"},
			{Name: "authorizers", Type: "object", Required: true, Description: "List of nested authorizer specs"},
		},
	},
}

// ── Mutator metadata ────────────────────────────────────────────────────

var mutatorMeta = map[string]moduleMetadata{
	"header-add": {
		displayName: "Header Add",
		description: "Inject identity attributes as upstream request headers",
		fields: []ModuleField{
			{Name: "subjectHeader", Type: "string", Required: false, Default: "X-Auth-Subject", Description: "Header for subject identity"},
			{Name: "rolesHeader", Type: "string", Required: false, Description: "Header for user roles"},
			{Name: "claimsHeaders", Type: "object", Required: false, Description: "Map of claim name to header name"},
		},
	},
	"header-remove": {
		displayName: "Header Remove",
		description: "Strip specified headers from the upstream request",
		fields: []ModuleField{
			{Name: "headers", Type: "stringArray", Required: true, Description: "List of header names to remove"},
		},
	},
	"header-passthrough": {
		displayName: "Header Passthrough",
		description: "Forward specific request headers to the upstream unchanged",
		fields: []ModuleField{
			{Name: "headers", Type: "stringArray", Required: true, Description: "List of header names to pass through"},
		},
	},
	"jwt-issue": {
		displayName: "JWT Issue",
		description: "Mint a new signed JWT and inject it as an upstream header",
		fields: []ModuleField{
			{Name: "signingKey", Type: "string", Required: true, Description: "Signing key (use vault:// reference)"},
			{Name: "algorithm", Type: "select", Required: false, Default: "RS256", Options: []string{"RS256", "ES256", "EdDSA", "HS256"}, Description: "JWT signing algorithm"},
			{Name: "ttl", Type: "string", Required: false, Default: "5m", Description: "Token time-to-live"},
			{Name: "claims", Type: "object", Required: false, Description: "Additional claims to include"},
			{Name: "header", Type: "string", Required: false, Default: "X-Auth-Token", Description: "Header to inject the JWT into"},
		},
	},
}

// handleListPresets returns the available configuration presets.
func (s *Server) handleListPresets(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, provisioner.BuiltInPresets())
}

// handlePreviewCreate generates the auth config YAML and Helm values from
// the structured form submission without actually creating anything.
func (s *Server) handlePreviewCreate(w http.ResponseWriter, r *http.Request) {
	var req provisioner.CreateNodeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}

	// Apply preset if specified and no identifiers provided.
	if req.Preset != "" && len(req.Identifiers) == 0 {
		if !provisioner.ApplyPreset(&req, req.Preset) {
			writeError(w, http.StatusUnprocessableEntity, "unknown preset: "+req.Preset)
			return
		}
	}

	authConfig, err := req.GenerateAuthConfig()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to generate config: "+err.Error())
		return
	}

	helmValues, err := req.GenerateHelmValues()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to generate helm values: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"authConfig": authConfig,
		"helmValues": helmValues,
	})
}

// handleValidateCreate validates the structured form submission without
// creating anything, returning field-level errors.
func (s *Server) handleValidateCreate(w http.ResponseWriter, r *http.Request) {
	var req provisioner.CreateNodeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}

	// Apply preset if specified.
	if req.Preset != "" && len(req.Identifiers) == 0 {
		provisioner.ApplyPreset(&req, req.Preset)
	}

	result := req.Validate()
	writeJSON(w, http.StatusOK, result)
}
