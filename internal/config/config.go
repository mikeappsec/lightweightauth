// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

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
	// accidental bypasses. Required when Mode is "shadow".
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

	Identifiers []ModuleSpec `json:"identifiers" yaml:"identifiers"`
	Authorizers []ModuleSpec `json:"authorizers" yaml:"authorizers"`
	Response    []ModuleSpec `json:"response,omitempty" yaml:"response,omitempty"`
	Cache       *CacheSpec   `json:"cache,omitempty" yaml:"cache,omitempty"`
	// Caches declares the named cache pools modules draw handles from
	// (the module-native cache layer, see docs/design/cache-layer-redesign.md).
	// Each pool is infrastructure only (backend + connection); per-module
	// behavior such as TTLs lives on the module. When empty, an implicit
	// in-memory "default" pool is synthesized so existing configs are
	// unaffected.
	Caches     []CachePoolSpec `json:"caches,omitempty" yaml:"caches,omitempty"`
	RateLimit  *ratelimit.Spec `json:"rateLimit,omitempty" yaml:"rateLimit,omitempty"`
	Identifier IdentifierMode  `json:"identifierMode,omitempty" yaml:"identifierMode,omitempty"`
	Canary     *CanarySpec     `json:"canary,omitempty" yaml:"canary,omitempty"`
	Revocation *RevocationSpec `json:"revocation,omitempty" yaml:"revocation,omitempty"`
	Secrets    *SecretsSpec    `json:"secrets,omitempty" yaml:"secrets,omitempty"`
	Audit      *AuditSpec      `json:"audit,omitempty" yaml:"audit,omitempty"`
}

// SecretsSpec configures the external secret-backend resolver (G1).
// When present, any string value in a module's Config map that matches a
// registered URI scheme (e.g. vault://...) is resolved before the module
// factory is called. This removes plaintext secrets from manifests.
type SecretsSpec struct {
	// DefaultTTL is the cache duration for resolved secrets. Default "5m".
	DefaultTTL string `json:"defaultTtl,omitempty" yaml:"defaultTtl,omitempty"`
	// Backends maps scheme names to backend-specific configuration.
	// Example: {"vault": {"addr": "https://vault.local:8200", "role": "lwauth"}}
	Backends map[string]map[string]any `json:"backends,omitempty" yaml:"backends,omitempty"`
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
	// Requires EnforceAfter to be set.
	Enforce bool `json:"enforce,omitempty" yaml:"enforce,omitempty"`
	// EnforceAfter is an RFC3339 timestamp. Enforce is only honoured after
	// this time, giving a minimum observation window.
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

	// Pool draws the decision cache's backend from a named pool declared in
	// the top-level caches: block instead of building a standalone backend
	// from the backend/addr/... fields below. When set, those inline backend
	// fields (including "tiered" and distributedSingleflight) must be empty —
	// the pool owns backend infrastructure. The referenced pool must exist in
	// caches: (validated fail-fast at load).
	Pool string `json:"pool,omitempty" yaml:"pool,omitempty"`

	// Backend selects the storage layer. Empty / "memory" uses the
	// in-process LRU (default). "valkey" turns on the shared backend
	// described in DESIGN.md §5. "tiered" enables the two-tier
	// read-through cache (E1): L1 in-process LRU + L2 Valkey.
	Backend   string `json:"backend,omitempty" yaml:"backend,omitempty"`
	Addr      string `json:"addr,omitempty" yaml:"addr,omitempty"`
	Username  string `json:"username,omitempty" yaml:"username,omitempty"`
	Password  string `json:"-" yaml:"password,omitempty"`
	KeyPrefix string `json:"keyPrefix,omitempty" yaml:"keyPrefix,omitempty"`
	TLS       bool   `json:"tls,omitempty" yaml:"tls,omitempty"`

	// L1Size is the maximum number of entries in the in-process LRU tier
	// when backend is "tiered". Default 10 000. Ignored for other backends.
	L1Size int `json:"l1Size,omitempty" yaml:"l1Size,omitempty"`

	// ServeStaleOnError enables stale-while-revalidate (E3). When the
	// authorizer returns an upstream error and a stale cached decision
	// exists, serve the stale entry rather than returning a 503.
	ServeStaleOnError bool `json:"serveStaleOnError,omitempty" yaml:"serveStaleOnError,omitempty"`

	// MaxStaleness caps how far past expiry a stale entry can be and still
	// be served. Zero means unlimited. Example: "5m", "30m".
	MaxStaleness string `json:"maxStaleness,omitempty" yaml:"maxStaleness,omitempty"`

	// DistributedSingleflight enables cross-replica singleflight (E4).
	// When true and backend is "tiered", cache misses acquire a short
	// distributed lock via Valkey SETNX so only one replica evaluates
	// the authorizer for a given key. Others poll L2 for the result.
	// Requires backend "tiered" (ignored otherwise).
	DistributedSingleflight bool `json:"distributedSingleflight,omitempty" yaml:"distributedSingleflight,omitempty"`

	// SFHoldDuration is how long the distributed singleflight lock lives.
	// Should exceed p99 evaluation latency. Default "200ms". Example: "500ms".
	SFHoldDuration string `json:"sfHoldDuration,omitempty" yaml:"sfHoldDuration,omitempty"`

	// SharedHMACKey is a base64-encoded secret shared across all replicas
	// for signing L2 cache entries when distributed singleflight is enabled.
	// 32 bytes (256-bit) recommended. If empty when distributedSingleflight
	// is true, a random key is generated (cross-replica verification will
	// fail gracefully — each replica evaluates independently).
	SharedHMACKey string `json:"-" yaml:"sharedHmacKey,omitempty"`
}

// CachePoolSpec is one entry in the top-level caches: list. It declares a
// named cache pool's backend infrastructure (the module-native cache layer).
// Per the redesign, a pool carries infrastructure only — per-module behavior
// such as TTLs lives on the module's own config. The optional MaxTTL is a
// governance ceiling: a module's effective TTL is min(module.ttl, MaxTTL).
type CachePoolSpec struct {
	// Name is the pool identifier modules reference (e.g. "tokens"). Required.
	Name string `json:"name" yaml:"name"`

	// Backend selects the registered backend implementation. Empty or
	// "memory" uses the in-process LRU (default). Remote/tiered backends
	// are wired alongside the module migration phases.
	Backend string `json:"backend,omitempty" yaml:"backend,omitempty"`

	// Size bounds an in-process backend's entry count.
	Size int `json:"size,omitempty" yaml:"size,omitempty"`

	// Remote connection settings (used by remote backends).
	Addr      string `json:"addr,omitempty" yaml:"addr,omitempty"`
	Username  string `json:"username,omitempty" yaml:"username,omitempty"`
	Password  string `json:"-" yaml:"password,omitempty"`
	KeyPrefix string `json:"keyPrefix,omitempty" yaml:"keyPrefix,omitempty"`
	TLS       bool   `json:"tls,omitempty" yaml:"tls,omitempty"`

	// MaxTTL is the pool-level ceiling on entry lifetime. Zero = no ceiling.
	MaxTTL string `json:"maxTtl,omitempty" yaml:"maxTtl,omitempty"`

	// AllowPII permits caching values flagged as PII to this pool
	// (deny-by-default). Encrypt enables at-rest value encryption.
	AllowPII bool `json:"allowPII,omitempty" yaml:"allowPII,omitempty"`
	Encrypt  bool `json:"encrypt,omitempty" yaml:"encrypt,omitempty"`

	// Codec selects the value codec for typed handles ("gob" default,
	// "json" opt-in). Pool-scoped to prevent mismatched encodings.
	Codec string `json:"codec,omitempty" yaml:"codec,omitempty"`
}

// RevocationSpec configures the opt-in credential revocation store (E2).
// When absent or Enabled is false, no revocation checking is performed
// and the pipeline incurs zero overhead.
type RevocationSpec struct {
	// Enabled explicitly opts in to revocation checking. Default false.
	Enabled bool `json:"enabled,omitempty" yaml:"enabled,omitempty"`

	// Backend selects the storage layer. "memory" (default) uses an
	// in-process map with TTL (single-replica / dev). "valkey" uses a
	// shared Valkey instance for multi-replica deployments.
	Backend string `json:"backend,omitempty" yaml:"backend,omitempty"`

	// Pool draws the revocation store's backend from a named pool in the
	// caches: block instead of the inline backend/addr fields. Mutually
	// exclusive with backend/addr; the pool owns backend infrastructure.
	// Enumeration (List) is unsupported on a pool-backed store.
	Pool string `json:"pool,omitempty" yaml:"pool,omitempty"`

	// Addr is the Valkey server address (required when backend=valkey).
	Addr string `json:"addr,omitempty" yaml:"addr,omitempty"`

	// Username for Valkey ACL auth (optional).
	Username string `json:"username,omitempty" yaml:"username,omitempty"`

	// Password for Valkey auth (optional).
	Password string `json:"-" yaml:"password,omitempty"`

	// TLS enables TLS connections to Valkey.
	TLS bool `json:"tls,omitempty" yaml:"tls,omitempty"`

	// KeyPrefix namespaces revocation keys in Valkey. Default "lwauth/rev/".
	KeyPrefix string `json:"keyPrefix,omitempty" yaml:"keyPrefix,omitempty"`

	// DefaultTTL is how long revocation entries live. Default "24h".
	DefaultTTL string `json:"defaultTTL,omitempty" yaml:"defaultTTL,omitempty"`

	// NegCacheTTL is the local negative cache TTL — how long a "not-revoked"
	// result is cached to avoid network round-trips. Default "2s".
	NegCacheTTL string `json:"negCacheTTL,omitempty" yaml:"negCacheTTL,omitempty"`

	// PubSubChannel is the Valkey Pub/Sub channel for cross-replica
	// revocation fan-out. Default "lwauth/events".
	PubSubChannel string `json:"pubsubChannel,omitempty" yaml:"pubsubChannel,omitempty"`

	// OnStoreError controls behaviour when the revocation store is
	// unreachable. "deny" (default) fails closed (401). "allow" fails
	// open (skip revocation check).
	OnStoreError string `json:"onStoreError,omitempty" yaml:"onStoreError,omitempty"`
}

// AuditSpec configures per-tenant PII redaction and data-residency routing
// for audit events (G3 — DATA-RES-1).
type AuditSpec struct {
	// Redaction configures PII field handling in audit events.
	Redaction *RedactionSpec `json:"redaction,omitempty" yaml:"redaction,omitempty"`

	// DataResidency configures region-based audit sink routing.
	DataResidency *DataResidencySpec `json:"dataResidency,omitempty" yaml:"dataResidency,omitempty"`
}

// RedactionSpec configures per-field PII handling in audit events.
type RedactionSpec struct {
	// Fields lists the audit event fields to redact and how to handle them.
	// Recognised field names: "subject", "path", "host", "deny_reason",
	// "identity_source", "trace_id".
	Fields []RedactionField `json:"fields" yaml:"fields"`
}

// RedactionField specifies how a single audit event field is redacted.
type RedactionField struct {
	// Name is the audit event field name (json tag). Required.
	Name string `json:"name" yaml:"name"`

	// Action controls what happens to the field value.
	// "hash" — replace with SHA-256 HMAC (preserves correlation without
	//          revealing the plaintext).
	// "drop" — replace with "" (GDPR Art. 17 erasure).
	Action RedactionAction `json:"action" yaml:"action"`
}

// RedactionAction is the transformation applied to a PII field.
type RedactionAction string

const (
	// RedactHash replaces the field value with HMAC-SHA-256 of the original.
	// A per-instance HMAC key is derived from the AuthConfig's TenantID +
	// a configurable secret to prevent rainbow-table correlation across
	// tenants.
	RedactHash RedactionAction = "hash"
	// RedactDrop replaces the field value with an empty string.
	RedactDrop RedactionAction = "drop"
)

// DataResidencySpec constrains where audit events for this tenant are
// routed. The Region tag is matched against sink labels configured at
// the operator level (e.g., "eu", "us", "ap").
type DataResidencySpec struct {
	// Region is the data-residency region for this tenant's audit events.
	// Events are only sent to sinks whose label matches this region.
	// Example: "eu", "us-east", "ap-southeast".
	Region string `json:"region" yaml:"region"`
}

// ToAuditRedactionFields converts config RedactionFields to the audit
// package's field format (same shape, avoids import cycle).
func (s *RedactionSpec) ToAuditFields() []RedactionField {
	if s == nil {
		return nil
	}
	return s.Fields
}
