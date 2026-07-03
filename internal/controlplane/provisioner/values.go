// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

// Package provisioner converts structured create-instance requests into
// Helm values and lwauth AuthConfig YAML.
package provisioner

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// CreateNodeRequest is the structured body for the module-aware create
// endpoint. The UI wizard submits this; the provisioner converts it to
// valid config YAML and Helm values.
type CreateNodeRequest struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace,omitempty"`
	Cluster   string `json:"cluster,omitempty"`
	Replicas  *int32 `json:"replicas,omitempty"`
	ImageTag  string `json:"imageTag,omitempty"`
	Preset    string `json:"preset,omitempty"`

	Identifiers    []ModuleEntry     `json:"identifiers,omitempty"`
	Authorizers    []ModuleEntry     `json:"authorizers,omitempty"`
	Mutators       []ModuleEntry     `json:"mutators,omitempty"`
	Infrastructure InfrastructureReq `json:"infrastructure"`
}

// ModuleEntry represents a single pipeline module selection from the form.
type ModuleEntry struct {
	Name   string         `json:"name"`
	Type   string         `json:"type"`
	Config map[string]any `json:"config,omitempty"`
}

// InfrastructureReq captures the infrastructure tab selections.
type InfrastructureReq struct {
	CacheBackend  string         `json:"cacheBackend,omitempty"`
	CacheAddr     string         `json:"cacheAddr,omitempty"`
	RateLimiting  *RateLimitReq  `json:"rateLimiting,omitempty"`
	Revocation    *RevocationReq `json:"revocation,omitempty"`
	Gateway       *GatewayReq    `json:"gateway,omitempty"`
	TLS           *TLSReq        `json:"tls,omitempty"`
	NetworkPolicy bool           `json:"networkPolicy"`
}

// RateLimitReq is the rate-limiting form section.
type RateLimitReq struct {
	Enabled bool `json:"enabled"`
	RPS     int  `json:"rps,omitempty"`
	Burst   int  `json:"burst,omitempty"`
}

// RevocationReq is the revocation form section.
type RevocationReq struct {
	Enabled bool   `json:"enabled"`
	Backend string `json:"backend,omitempty"`
}

// GatewayReq is the Envoy sidecar gateway form section.
type GatewayReq struct {
	Enabled      bool   `json:"enabled"`
	UpstreamHost string `json:"upstreamHost,omitempty"`
	UpstreamPort int    `json:"upstreamPort,omitempty"`
}

// TLSReq enables HTTPS on the data-plane node.
type TLSReq struct {
	// Enabled turns on TLS for the HTTP listener.
	Enabled bool `json:"enabled"`
	// SecretName is the name of a Kubernetes TLS Secret (tls.crt + tls.key)
	// in the node's namespace. Required when Enabled is true.
	SecretName string `json:"secretName,omitempty"`
}

// ValidationError is a structured error pointing to a specific form field.
type ValidationError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

// ValidationResult holds multiple field-level errors.
type ValidationResult struct {
	Valid  bool              `json:"valid"`
	Errors []ValidationError `json:"errors,omitempty"`
}

// Validate checks the request for required fields and structural correctness.
func (req *CreateNodeRequest) Validate() ValidationResult {
	var errs []ValidationError

	if req.Name == "" {
		errs = append(errs, ValidationError{Field: "name", Message: "name is required"})
	} else if !isValidK8sName(req.Name) {
		errs = append(errs, ValidationError{Field: "name", Message: "must be a valid Kubernetes name (lowercase alphanumeric and hyphens)"})
	}

	if req.Replicas != nil && (*req.Replicas < 1 || *req.Replicas > 10) {
		errs = append(errs, ValidationError{Field: "replicas", Message: "replicas must be between 1 and 10"})
	}

	if len(req.Identifiers) == 0 {
		errs = append(errs, ValidationError{Field: "identifiers", Message: "at least one identity module is required"})
	}

	for i, id := range req.Identifiers {
		if id.Name == "" {
			errs = append(errs, ValidationError{
				Field:   fmt.Sprintf("identifiers[%d].name", i),
				Message: "identifier name is required",
			})
		}
		if id.Type == "" {
			errs = append(errs, ValidationError{
				Field:   fmt.Sprintf("identifiers[%d].type", i),
				Message: "identifier type is required",
			})
		}
	}

	if len(req.Authorizers) == 0 {
		errs = append(errs, ValidationError{Field: "authorizers", Message: "at least one authorizer is required"})
	}

	for i, az := range req.Authorizers {
		if az.Name == "" {
			errs = append(errs, ValidationError{
				Field:   fmt.Sprintf("authorizers[%d].name", i),
				Message: "authorizer name is required",
			})
		}
		if az.Type == "" {
			errs = append(errs, ValidationError{
				Field:   fmt.Sprintf("authorizers[%d].type", i),
				Message: "authorizer type is required",
			})
		}
	}

	return ValidationResult{Valid: len(errs) == 0, Errors: errs}
}

// GenerateAuthConfig renders the inline auth config YAML from the form
// submission. This is the value that goes into config.inline in the Helm
// chart values.
func (req *CreateNodeRequest) GenerateAuthConfig() (string, error) {
	var buf bytes.Buffer

	// Identifiers.
	buf.WriteString("identifiers:\n")
	for _, id := range req.Identifiers {
		buf.WriteString(fmt.Sprintf("  - name: %s\n", id.Name))
		buf.WriteString(fmt.Sprintf("    type: %s\n", id.Type))
		if len(id.Config) > 0 {
			buf.WriteString("    config:\n")
			writeIdentifierConfig(&buf, id.Type, id.Config, 6)
		}
	}

	// Authorizers.
	buf.WriteString("\nauthorizers:\n")
	for _, az := range req.Authorizers {
		buf.WriteString(fmt.Sprintf("  - name: %s\n", az.Name))
		buf.WriteString(fmt.Sprintf("    type: %s\n", az.Type))
		if len(az.Config) > 0 {
			buf.WriteString("    config:\n")
			writeAuthorizerConfig(&buf, az.Type, az.Config, 6)
		}
	}

	// Response mutators.
	if len(req.Mutators) > 0 {
		buf.WriteString("\nresponse:\n")
		for _, m := range req.Mutators {
			buf.WriteString(fmt.Sprintf("  - name: %s\n", m.Name))
			buf.WriteString(fmt.Sprintf("    type: %s\n", m.Type))
			if len(m.Config) > 0 {
				buf.WriteString("    config:\n")
				writeConfigMap(&buf, m.Config, 6)
			}
		}
	}

	return buf.String(), nil
}

// GenerateHelmValues renders the full Helm values.yaml from the form
// submission.
func (req *CreateNodeRequest) GenerateHelmValues() (string, error) {
	authConfig, err := req.GenerateAuthConfig()
	if err != nil {
		return "", fmt.Errorf("generating auth config: %w", err)
	}

	// Default to a single replica. Nodes are stateless and Kubernetes restarts
	// them on failure; a second replica doubles memory, which is significant on
	// small clusters (e.g. the 12 GB OCI Always Free tier). Callers that need
	// HA set Replicas explicitly.
	replicas := int32(1)
	if req.Replicas != nil {
		replicas = *req.Replicas
	}

	imageTag := "latest"
	if req.ImageTag != "" {
		imageTag = req.ImageTag
	}

	var buf bytes.Buffer
	buf.WriteString("# Auto-generated by lwauth control plane\n")
	buf.WriteString(fmt.Sprintf("# Instance: %s | Cluster: %s | Namespace: %s\n", req.Name, req.effectiveCluster(), req.effectiveNamespace()))
	buf.WriteString(fmt.Sprintf("replicaCount: %d\n\n", replicas))

	buf.WriteString("image:\n")
	buf.WriteString(fmt.Sprintf("  tag: \"%s\"\n\n", imageTag))

	// Inline config.
	buf.WriteString("config:\n")
	buf.WriteString("  inline: |\n")
	for _, line := range strings.Split(authConfig, "\n") {
		if line == "" {
			buf.WriteString("\n")
		} else {
			buf.WriteString("    " + line + "\n")
		}
	}

	// Cache.
	backend := "memory"
	if req.Infrastructure.CacheBackend != "" {
		backend = req.Infrastructure.CacheBackend
	}
	buf.WriteString(fmt.Sprintf("\ncache:\n  backend: %s\n", backend))
	if req.Infrastructure.CacheAddr != "" {
		buf.WriteString(fmt.Sprintf("  addr: \"%s\"\n", req.Infrastructure.CacheAddr))
	}

	// Rate limiting.
	if req.Infrastructure.RateLimiting != nil && req.Infrastructure.RateLimiting.Enabled {
		buf.WriteString(fmt.Sprintf("\nrateLimit:\n  perTenant:\n    rps: %d\n    burst: %d\n",
			req.Infrastructure.RateLimiting.RPS, req.Infrastructure.RateLimiting.Burst))
	}

	// Revocation.
	if req.Infrastructure.Revocation != nil && req.Infrastructure.Revocation.Enabled {
		revBackend := "memory"
		if req.Infrastructure.Revocation.Backend != "" {
			revBackend = req.Infrastructure.Revocation.Backend
		}
		buf.WriteString(fmt.Sprintf("\nrevocation:\n  backend: %s\n", revBackend))
	}

	// Gateway.
	if req.Infrastructure.Gateway != nil && req.Infrastructure.Gateway.Enabled {
		buf.WriteString("\ngateway:\n  enabled: true\n")
		if req.Infrastructure.Gateway.UpstreamHost != "" {
			buf.WriteString(fmt.Sprintf("  upstream:\n    service: \"%s\"\n", req.Infrastructure.Gateway.UpstreamHost))
			if req.Infrastructure.Gateway.UpstreamPort > 0 {
				buf.WriteString(fmt.Sprintf("    port: %d\n", req.Infrastructure.Gateway.UpstreamPort))
			}
		}
	}

	// Network policy.
	buf.WriteString(fmt.Sprintf("\nnetworkPolicy:\n  enabled: %t\n", req.Infrastructure.NetworkPolicy))

	return buf.String(), nil
}

func (req *CreateNodeRequest) effectiveNamespace() string {
	if req.Namespace != "" {
		return req.Namespace
	}
	return "lwauth-system"
}

func (req *CreateNodeRequest) effectiveCluster() string {
	if req.Cluster != "" {
		return req.Cluster
	}
	return "local"
}

func isValidK8sName(name string) bool {
	if len(name) > 63 {
		return false
	}
	for _, c := range name {
		if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-') {
			return false
		}
	}
	return len(name) > 0 && name[0] != '-' && name[len(name)-1] != '-'
}

// writeIdentifierConfig dispatches to a type-specific renderer for identifier
// modules that have a schema that differs from a generic map passthrough.
func writeIdentifierConfig(buf *bytes.Buffer, moduleType string, cfg map[string]any, indent int) {
	switch moduleType {
	case "apikey":
		writeAPIKeyConfig(buf, cfg, indent)
	default:
		writeConfigMap(buf, cfg, indent)
	}
}

// writeAuthorizerConfig dispatches to a type-specific renderer for authorizer
// modules whose schema differs from a generic map passthrough.
func writeAuthorizerConfig(buf *bytes.Buffer, moduleType string, cfg map[string]any, indent int) {
	switch moduleType {
	case "rbac":
		writeRBACConfig(buf, cfg, indent)
	default:
		writeConfigMap(buf, cfg, indent)
	}
}

// writeAPIKeyConfig renders an apikey identifier config. The form wizard may
// send inline keys under an "entries" key; the apikey module expects "static".
func writeAPIKeyConfig(buf *bytes.Buffer, cfg map[string]any, indent int) {
	prefix := strings.Repeat(" ", indent)
	for k, v := range cfg {
		effectiveKey := k
		if k == "entries" {
			// Rename: the apikey module uses "static" for plaintext inline keys.
			effectiveKey = "static"
		}
		if m, ok := v.(map[string]any); ok {
			buf.WriteString(fmt.Sprintf("%s%s:\n", prefix, effectiveKey))
			writeConfigMap(buf, m, indent+2)
		} else {
			writeConfigMap(buf, map[string]any{effectiveKey: v}, indent)
		}
	}
}

// writeRBACConfig renders an rbac authorizer config. The form wizard may send
// a "roles" map with permission objects; the rbac module expects a flat
// "allow" list of role names.
func writeRBACConfig(buf *bytes.Buffer, cfg map[string]any, indent int) {
	prefix := strings.Repeat(" ", indent)

	// rolesFrom (optional; module default is "claim:roles").
	if v, ok := cfg["rolesFrom"].(string); ok && v != "" {
		buf.WriteString(fmt.Sprintf("%srolesFrom: \"%s\"\n", prefix, v))
	}

	// allow: accept either the correct []string form or the form's roles map.
	if roles, ok := cfg["roles"].(map[string]any); ok && len(roles) > 0 {
		// Extract role names from the wizard's { roleName: { permissions } } shape.
		names := make([]string, 0, len(roles))
		for k := range roles {
			names = append(names, k)
		}
		sort.Strings(names)
		buf.WriteString(fmt.Sprintf("%sallow:\n", prefix))
		for _, name := range names {
			buf.WriteString(fmt.Sprintf("%s  - %s\n", prefix, name))
		}
	} else if allow, ok := cfg["allow"].([]any); ok {
		// Already in the correct format.
		buf.WriteString(fmt.Sprintf("%sallow:\n", prefix))
		for _, v := range allow {
			if s, ok := v.(string); ok {
				buf.WriteString(fmt.Sprintf("%s  - %s\n", prefix, s))
			}
		}
	}

	// Pass through any other rbac fields (e.g. future extensions).
	for k, v := range cfg {
		if k == "roles" || k == "allow" || k == "rolesFrom" {
			continue
		}
		writeConfigMap(buf, map[string]any{k: v}, indent)
	}
}

// writeConfigMap renders a map[string]any as indented YAML lines.
func writeConfigMap(buf *bytes.Buffer, m map[string]any, indent int) {
	prefix := strings.Repeat(" ", indent)
	for k, v := range m {
		switch val := v.(type) {
		case string:
			buf.WriteString(fmt.Sprintf("%s%s: \"%s\"\n", prefix, k, val))
		case bool:
			buf.WriteString(fmt.Sprintf("%s%s: %t\n", prefix, k, val))
		case float64:
			if val == float64(int(val)) {
				buf.WriteString(fmt.Sprintf("%s%s: %d\n", prefix, k, int(val)))
			} else {
				buf.WriteString(fmt.Sprintf("%s%s: %g\n", prefix, k, val))
			}
		case json.Number:
			buf.WriteString(fmt.Sprintf("%s%s: %s\n", prefix, k, val.String()))
		case []any:
			buf.WriteString(fmt.Sprintf("%s%s:\n", prefix, k))
			for _, item := range val {
				switch sv := item.(type) {
				case string:
					buf.WriteString(fmt.Sprintf("%s  - \"%s\"\n", prefix, sv))
				case map[string]any:
					buf.WriteString(fmt.Sprintf("%s  -\n", prefix))
					writeConfigMap(buf, sv, indent+4)
				default:
					buf.WriteString(fmt.Sprintf("%s  - %v\n", prefix, item))
				}
			}
		case map[string]any:
			buf.WriteString(fmt.Sprintf("%s%s:\n", prefix, k))
			writeConfigMap(buf, val, indent+2)
		default:
			buf.WriteString(fmt.Sprintf("%s%s: %v\n", prefix, k, v))
		}
	}
}
