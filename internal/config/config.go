// Package config defines the on-disk YAML / CRD-derived shape of an
// AuthConfig and provides the Compiler that turns it into a *pipeline.Engine.
//
// The same Go struct backs both the local YAML loader and the Kubernetes
// CRD types in api/crd/v1alpha1, decoded via sigs.k8s.io/yaml. See
// docs/DESIGN.md §6.
package config

// AuthConfig is the top-level configuration unit. One YAML file or one
// AuthConfig CRD instance maps to exactly one AuthConfig value, which the
// Compiler turns into a pipeline.Engine.
type AuthConfig struct {
	// Hosts limits this config to specific virtual hosts. Empty = match all.
	Hosts []string `json:"hosts,omitempty" yaml:"hosts,omitempty"`

	// TenantID is stamped into every Request.TenantID handled by the
	// resulting Engine. Optional; the controller fills it from the CRD's
	// namespace when running in K8s.
	TenantID string `json:"tenantId,omitempty" yaml:"tenantId,omitempty"`

	// WithBody opts this config's routes into request-body access.
	// Off by default (DESIGN.md §8).
	WithBody     bool `json:"withBody,omitempty" yaml:"withBody,omitempty"`
	MaxBodyBytes int  `json:"maxBodyBytes,omitempty" yaml:"maxBodyBytes,omitempty"`

	Identifiers []ModuleSpec   `json:"identifiers" yaml:"identifiers"`
	Authorizers []ModuleSpec   `json:"authorizers" yaml:"authorizers"`
	Response    []ModuleSpec   `json:"response,omitempty" yaml:"response,omitempty"`
	Cache       *CacheSpec     `json:"cache,omitempty" yaml:"cache,omitempty"`
	Identifier  IdentifierMode `json:"identifierMode,omitempty" yaml:"identifierMode,omitempty"`
}

// IdentifierMode is the YAML enum for pipeline.IdentifierMode.
type IdentifierMode string

const (
	IdentifierFirstMatch IdentifierMode = "firstMatch"
	IdentifierAllMust    IdentifierMode = "allMust"
)

// ModuleSpec is the generic shape for any pipeline module: a name, a type
// (registry key), and a free-form Config map the factory understands.
type ModuleSpec struct {
	Name   string         `json:"name" yaml:"name"`
	Type   string         `json:"type" yaml:"type"`
	Config map[string]any `json:"config,omitempty" yaml:"config,omitempty"`
}

// CacheSpec configures the (opt-in) decision cache for this AuthConfig.
// See DESIGN.md §5.
type CacheSpec struct {
	// Key lists the request/identity fields whose hash forms the cache key.
	// Example: ["sub", "method", "pathTemplate"].
	Key []string `json:"key,omitempty" yaml:"key,omitempty"`
	// TTL is the cache entry lifetime; zero disables the decision cache.
	TTL string `json:"ttl,omitempty" yaml:"ttl,omitempty"`
	// NegativeTTL is how long deny decisions are cached (default 5s).
	NegativeTTL string `json:"negativeTtl,omitempty" yaml:"negativeTtl,omitempty"`
}
