// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package provisioner

// Preset is a named template that pre-fills the create-node form with a
// common configuration pattern. The UI shows these as one-click options.
type Preset struct {
	Name           string            `json:"name"`
	DisplayName    string            `json:"displayName"`
	Description    string            `json:"description"`
	Identifiers    []ModuleEntry     `json:"identifiers"`
	Authorizers    []ModuleEntry     `json:"authorizers"`
	Mutators       []ModuleEntry     `json:"mutators"`
	Infrastructure InfrastructureReq `json:"infrastructure"`
}

// BuiltInPresets returns the default presets available in the UI.
func BuiltInPresets() []Preset {
	return []Preset{
		{
			Name:        "api-gateway",
			DisplayName: "API Gateway",
			Description: "Protect REST APIs behind Envoy with JWT authentication and RBAC authorization",
			Identifiers: []ModuleEntry{
				{
					Name: "jwt-verifier",
					Type: "jwt",
					Config: map[string]any{
						"jwksUrl":   "https://auth.example.com/.well-known/jwks.json",
						"issuer":    "https://auth.example.com",
						"audiences": []any{"api.example.com"},
						"clockSkew": "30s",
					},
				},
			},
			Authorizers: []ModuleEntry{
				{
					Name: "rbac-main",
					Type: "rbac",
					Config: map[string]any{
						"allow": []any{"admin", "viewer"},
					},
				},
			},
			Mutators: []ModuleEntry{
				{
					Name: "forward-identity",
					Type: "header-add",
					Config: map[string]any{
						"subjectHeader": "X-Auth-Subject",
						"rolesHeader":   "X-Auth-Roles",
					},
				},
			},
			Infrastructure: InfrastructureReq{
				CacheBackend:  "memory",
				NetworkPolicy: true,
			},
		},
		{
			Name:        "service-mesh",
			DisplayName: "Service Mesh",
			Description: "Zero-trust service-to-service authentication using mTLS with CEL policies",
			Identifiers: []ModuleEntry{
				{
					Name: "mtls-svc",
					Type: "mtls",
					Config: map[string]any{
						"subjectFrom": "spiffe",
					},
				},
			},
			Authorizers: []ModuleEntry{
				{
					Name: "cel-policy",
					Type: "cel",
					Config: map[string]any{
						"expression": "identity.subject.startsWith('spiffe://cluster.local/')",
					},
				},
			},
			Mutators: []ModuleEntry{
				{
					Name: "passthrough-headers",
					Type: "header-passthrough",
					Config: map[string]any{
						"headers": []any{"X-Request-Id", "X-Trace-Id"},
					},
				},
			},
			Infrastructure: InfrastructureReq{
				CacheBackend:  "memory",
				NetworkPolicy: true,
			},
		},
		{
			Name:        "internal-tools",
			DisplayName: "Internal Tools",
			Description: "Protect internal dashboards and CLI tools with API key authentication",
			Identifiers: []ModuleEntry{
				{
					Name: "apikey-auth",
					Type: "apikey",
					Config: map[string]any{
						"header": "X-API-Key",
						"entries": map[string]any{
							"replace-me": map[string]any{"subject": "tool-user"},
						},
					},
				},
			},
			Authorizers: []ModuleEntry{
				{
					Name: "rbac-internal",
					Type: "rbac",
					Config: map[string]any{
						"allow": []any{"admin", "user"},
					},
				},
			},
			Mutators: []ModuleEntry{
				{
					Name: "forward-identity",
					Type: "header-add",
					Config: map[string]any{
						"subjectHeader": "X-Auth-Subject",
					},
				},
			},
			Infrastructure: InfrastructureReq{
				CacheBackend:  "memory",
				NetworkPolicy: true,
			},
		},
		{
			Name:        "oauth2-app",
			DisplayName: "OAuth2 Web App",
			Description: "Browser-based SPA with OAuth2 authorization code flow and OPA policies",
			Identifiers: []ModuleEntry{
				{
					Name: "oauth2-login",
					Type: "oauth2",
					Config: map[string]any{
						"issuer":      "https://auth.example.com",
						"clientId":    "my-app",
						"redirectUrl": "https://app.example.com/callback",
						"scopes":      []any{"openid", "profile", "email"},
					},
				},
			},
			Authorizers: []ModuleEntry{
				{
					Name: "opa-policy",
					Type: "opa",
					Config: map[string]any{
						"policy": "package authz\ndefault allow = false\nallow { input.identity.email_verified == true }",
						"query":  "data.authz.allow",
					},
				},
			},
			Mutators: []ModuleEntry{
				{
					Name: "issue-token",
					Type: "jwt-issue",
					Config: map[string]any{
						"algorithm": "RS256",
						"ttl":       "5m",
						"header":    "X-Auth-Token",
					},
				},
			},
			Infrastructure: InfrastructureReq{
				CacheBackend:  "memory",
				NetworkPolicy: true,
			},
		},
		{
			Name:        "machine-to-machine",
			DisplayName: "Machine-to-Machine",
			Description: "HMAC-signed webhooks, cron jobs, and IoT device authentication",
			Identifiers: []ModuleEntry{
				{
					Name: "hmac-svc",
					Type: "hmac",
					Config: map[string]any{
						"clockSkew": "5m",
						"keys": map[string]any{
							"service-a": map[string]any{
								"subject": "service-a",
								"roles":   []any{"machine"},
							},
						},
					},
				},
			},
			Authorizers: []ModuleEntry{
				{
					Name: "cel-allow-machines",
					Type: "cel",
					Config: map[string]any{
						"expression": "identity.roles.exists(r, r == 'machine')",
					},
				},
			},
			Mutators: []ModuleEntry{
				{
					Name: "forward-identity",
					Type: "header-add",
					Config: map[string]any{
						"subjectHeader": "X-Auth-Subject",
					},
				},
			},
			Infrastructure: InfrastructureReq{
				CacheBackend:  "memory",
				NetworkPolicy: true,
			},
		},
	}
}

// ApplyPreset fills a CreateNodeRequest with the matching preset's modules,
// preserving any fields already set (name, namespace, cluster, replicas, etc.).
func ApplyPreset(req *CreateNodeRequest, presetName string) bool {
	for _, p := range BuiltInPresets() {
		if p.Name == presetName {
			req.Identifiers = p.Identifiers
			req.Authorizers = p.Authorizers
			req.Mutators = p.Mutators
			req.Infrastructure = p.Infrastructure
			return true
		}
	}
	return false
}
