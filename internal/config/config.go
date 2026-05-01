// Package config defines the on-disk YAML / CRD-derived shape of an
// AuthConfig and provides the Compiler that turns it into a *pipeline.Engine.
//
// The same Go struct backs both the local YAML loader and the Kubernetes
// CRD types in api/crd/v1alpha1, decoded via sigs.k8s.io/yaml. See
// docs/DESIGN.md §6.
package config

import "github.com/mikeappsec/lightweightauth/pkg/ratelimit"

// AuthConfig is the top-level configuration unit. One YAML file or one
// AuthConfig CRD instance maps to exactly one AuthConfig value, which the
// Compiler turns into a pipeline.Engine.
type AuthConfig struct {
	// Version is an opaque string set by operators to tag a policy
	// revision. The controller echoes it on status.appliedVersion after
	// a successful compile+swap. Optional; when empty, only
	// status.appliedDigest tracks config identity.
	Version string `json:"version,omitempty" yaml:"version,omitempty"`

	// Mode controls enforcement behaviour. "enforce" (default) applies
	// the pipeline verdict normally. "shadow" runs the full pipeline
	// but always returns allow — disagreements between shadow and the
	// previous production verdict are emitted as metrics + audit events
	// so operators can compare policies before promotion. See D2.
	Mode PolicyMode `json:"mode,omitempty" yaml:"mode,omitempty"`

	// ShadowExpiry is an RFC3339 timestamp after which shadow mode is
	// automatically disabled (reverts to enforce). Prevents permanent
	// accidental bypasses. Required when Mode is "shadow" (PM1).
	ShadowExpiry string `json:"shadowExpiry,omitempty" yaml:"shadowExpiry,omitempty"`

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
	RateLimit   *ratelimit.Spec `json:"rateLimit,omitempty" yaml:"rateLimit,omitempty"`
	Identifier  IdentifierMode `json:"identifierMode,omitempty" yaml:"identifierMode,omitempty"`
	Canary      *CanarySpec    `json:"canary,omitempty" yaml:"canary,omitempty"`
}

// CanarySpec configures canary policy evaluation (D3 — ENT-POLICY-2).
// The canary authorizer runs concurrently with production; its verdict is
// observed (metrics + audit) but only enforced when Enforce is true.
type CanarySpec struct {
	// Weight is the percentage of traffic (1-100) that gets canary evaluation.
	Weight int `json:"weight,omitempty" yaml:"weight,omitempty"`
	// Sample controls sticky routing. "" = random by weight.
	// "header:<name>" = route requests with that header to canary (observe-only).
	// "hash:sub" = sticky by hash of identity subject.
	Sample string `json:"sample,omitempty" yaml:"sample,omitempty"`
	// Enforce when true uses the canary verdict as the real verdict.
	// Requires EnforceAfter to be set (CAN1).
	Enforce bool `json:"enforce,omitempty" yaml:"enforce,omitempty"`
	// EnforceAfter is an RFC3339 timestamp. Enforce is only honoured after
	// this time, giving a minimum observation window (CAN1).
	EnforceAfter string `json:"enforceAfter,omitempty" yaml:"enforceAfter,omitempty"`
	// Authorizer is the canary authorizer module spec.
	Authorizer ModuleSpec `json:"authorizer" yaml:"authorizer"`
}

// IdentifierMode is the YAML enum for pipeline.IdentifierMode.
type IdentifierMode string

const (
	IdentifierFirstMatch IdentifierMode = "firstMatch"
	IdentifierAllMust    IdentifierMode = "allMust"
)

// PolicyMode controls how the pipeline's verdict is applied.
type PolicyMode string

const (
	// PolicyModeEnforce is the default: the pipeline verdict is authoritative.
	PolicyModeEnforce PolicyMode = "enforce"
	// PolicyModeShadow runs the pipeline but always allows; disagreements
	// are emitted as metrics and audit events. Used for safe rollout of
	// new policies (D2 — ENT-POLICY-1).
	PolicyModeShadow PolicyMode = "shadow"
)

// IsShadow returns true when the config is in shadow/observe-only mode.
func (m PolicyMode) IsShadow() bool {
	return m == PolicyModeShadow
}

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
	// Recognised values: "sub", "tenant", "method", "host", "path",
	// "header:<Name>", "claim:<Name>". Unknown values are rejected at load
	// time so a typo cannot silently drop a dimension from the key.
	// Example: ["sub", "method", "path"].
	Key []string `json:"key,omitempty" yaml:"key,omitempty"`
	// TTL is the cache entry lifetime; zero disables the decision cache.
	TTL string `json:"ttl,omitempty" yaml:"ttl,omitempty"`
	// NegativeTTL is how long deny decisions are cached (default 5s).
	NegativeTTL string `json:"negativeTtl,omitempty" yaml:"negativeTtl,omitempty"`

	// Backend selects the storage layer. Empty / "memory" uses the
	// in-process LRU (default). "valkey" turns on the shared backend
	// described in DESIGN.md §5; the additional fields below are
	// forwarded to that backend's factory.
	Backend   string `json:"backend,omitempty" yaml:"backend,omitempty"`
	Addr      string `json:"addr,omitempty" yaml:"addr,omitempty"`
	Username  string `json:"username,omitempty" yaml:"username,omitempty"`
	Password  string `json:"password,omitempty" yaml:"password,omitempty"`
	KeyPrefix string `json:"keyPrefix,omitempty" yaml:"keyPrefix,omitempty"`
	TLS       bool   `json:"tls,omitempty" yaml:"tls,omitempty"`
}
