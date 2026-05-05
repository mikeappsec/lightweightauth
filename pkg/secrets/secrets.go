// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

// Package secrets provides a pluggable SecretResolver interface for
// resolving external secret references (e.g. vault://path/to/secret#key)
// at config compile time. This removes the need for plaintext secrets in
// Kubernetes manifests or YAML config files.
//
// Reference format:
//
//	secretRef: "<scheme>://<path>[#<field>]"
//
// Supported schemes are registered via RegisterBackend. Built-in adapters:
//   - vault:// — HashiCorp Vault KV v2
//
// Resolved values are cached with a configurable TTL to avoid excessive
// round-trips to the secret backend on config reloads.
package secrets

import (
	"context"
	"fmt"
	"net/url"
	"sync"
	"time"
)

// Backend resolves a secret given a parsed reference. Implementations are
// registered via RegisterBackend and looked up by URI scheme.
type Backend interface {
	// Resolve fetches the secret value at the given path. If field is
	// non-empty, the backend should return only that field from a
	// multi-field secret (e.g. a Vault KV map). Context carries deadlines
	// from the config compile timeout.
	Resolve(ctx context.Context, path, field string) ([]byte, error)

	// Close releases any resources held by the backend (HTTP clients,
	// connections, etc.). Called on Resolver.Close().
	Close() error
}

// Ref is a parsed secret reference URI.
type Ref struct {
	Scheme string // e.g. "vault", "aws-sm", "gcp-sm"
	Path   string // e.g. "kv/lwauth/jwt-key" or "arn:aws:..."
	Field  string // optional sub-field within the secret (URI fragment)
}

// ParseRef parses a secretRef string into its components.
// Format: <scheme>://<path>[#<field>]
func ParseRef(raw string) (Ref, error) {
	if raw == "" {
		return Ref{}, fmt.Errorf("secrets: empty ref")
	}

	u, err := url.Parse(raw)
	if err != nil {
		return Ref{}, fmt.Errorf("secrets: invalid ref %q: %w", raw, err)
	}
	if u.Scheme == "" {
		return Ref{}, fmt.Errorf("secrets: ref %q missing scheme (expected <scheme>://...)", raw)
	}

	// Reconstruct the path from host + path (url.Parse splits on //).
	path := u.Host
	if u.Path != "" {
		path += u.Path
	}
	if path == "" {
		return Ref{}, fmt.Errorf("secrets: ref %q has empty path", raw)
	}

	return Ref{
		Scheme: u.Scheme,
		Path:   path,
		Field:  u.Fragment,
	}, nil
}

// IsSecretRef returns true if the string looks like a secret reference
// using a known secret-backend scheme prefix (e.g. "vault://...").
// Plain URLs (https://, http://) are NOT treated as secret references
// to avoid accidentally intercepting module config values like JWKS URLs.
func IsSecretRef(s string) bool {
	registryMu.RLock()
	defer registryMu.RUnlock()
	for scheme := range registry {
		prefix := scheme + "://"
		if len(s) > len(prefix) && s[:len(prefix)] == prefix {
			return true
		}
	}
	return false
}

// --- Backend registry ---

var (
	registryMu sync.RWMutex
	registry   = map[string]BackendFactory{}
)

// BackendFactory constructs a Backend from config options.
type BackendFactory func(opts map[string]any) (Backend, error)

// RegisterBackend registers a backend factory for the given URI scheme.
func RegisterBackend(scheme string, f BackendFactory) {
	registryMu.Lock()
	defer registryMu.Unlock()
	registry[scheme] = f
}

func lookupFactory(scheme string) (BackendFactory, bool) {
	registryMu.RLock()
	defer registryMu.RUnlock()
	f, ok := registry[scheme]
	return f, ok
}

// --- Resolver (top-level entry point) ---

// Options configures the Resolver.
type Options struct {
	// DefaultTTL is the cache TTL for resolved secrets. Zero disables caching.
	DefaultTTL time.Duration

	// BackendConfigs maps scheme -> backend-specific configuration passed
	// to the BackendFactory. Example:
	//   {"vault": {"addr": "https://vault.local:8200", "role": "lwauth"}}
	BackendConfigs map[string]map[string]any
}

// Resolver resolves secretRef strings to their plaintext values with
// TTL-bounded caching. It is safe for concurrent use.
type Resolver struct {
	mu       sync.RWMutex
	backends map[string]Backend
	cache    map[string]*cacheEntry
	opts     Options
}

type cacheEntry struct {
	value     []byte
	expiresAt time.Time
}

// New creates a Resolver. Backends are lazily initialized on first use
// of their scheme.
func New(opts Options) *Resolver {
	return &Resolver{
		backends: make(map[string]Backend),
		cache:    make(map[string]*cacheEntry),
		opts:     opts,
	}
}

// Resolve resolves a secretRef string to its plaintext value. Results are
// cached for DefaultTTL (or the per-ref TTL override if specified via
// query parameter ?ttl=30s).
func (r *Resolver) Resolve(ctx context.Context, ref string) ([]byte, error) {
	parsed, err := ParseRef(ref)
	if err != nil {
		return nil, err
	}

	// Check for per-ref TTL override in query params.
	ttl := r.opts.DefaultTTL
	if u, _ := url.Parse(ref); u != nil && u.Query().Get("ttl") != "" {
		if d, err := time.ParseDuration(u.Query().Get("ttl")); err == nil && d > 0 {
			ttl = d
		}
	}

	cacheKey := ref

	// Check cache.
	if ttl > 0 {
		r.mu.RLock()
		if entry, ok := r.cache[cacheKey]; ok && time.Now().Before(entry.expiresAt) {
			val := make([]byte, len(entry.value))
			copy(val, entry.value)
			r.mu.RUnlock()
			return val, nil
		}
		r.mu.RUnlock()
	}

	// Resolve from backend.
	backend, err := r.getBackend(parsed.Scheme)
	if err != nil {
		return nil, err
	}

	val, err := backend.Resolve(ctx, parsed.Path, parsed.Field)
	if err != nil {
		return nil, fmt.Errorf("secrets: resolve %q: %w", ref, err)
	}

	// Cache the result.
	if ttl > 0 {
		r.mu.Lock()
		r.cache[cacheKey] = &cacheEntry{
			value:     val,
			expiresAt: time.Now().Add(ttl),
		}
		r.mu.Unlock()
	}

	return val, nil
}

// ResolveString is a convenience wrapper that returns the resolved value
// as a string.
func (r *Resolver) ResolveString(ctx context.Context, ref string) (string, error) {
	b, err := r.Resolve(ctx, ref)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// Close releases all backend resources and clears the cache.
func (r *Resolver) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	var firstErr error
	for _, b := range r.backends {
		if err := b.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	r.backends = make(map[string]Backend)
	r.cache = make(map[string]*cacheEntry)
	return firstErr
}

func (r *Resolver) getBackend(scheme string) (Backend, error) {
	r.mu.RLock()
	if b, ok := r.backends[scheme]; ok {
		r.mu.RUnlock()
		return b, nil
	}
	r.mu.RUnlock()

	// Initialize backend.
	factory, ok := lookupFactory(scheme)
	if !ok {
		return nil, fmt.Errorf("secrets: unknown backend scheme %q (registered: %v)", scheme, registeredSchemes())
	}

	var backendOpts map[string]any
	if r.opts.BackendConfigs != nil {
		backendOpts = r.opts.BackendConfigs[scheme]
	}

	b, err := factory(backendOpts)
	if err != nil {
		return nil, fmt.Errorf("secrets: init backend %q: %w", scheme, err)
	}

	r.mu.Lock()
	// Double-check after acquiring write lock.
	if existing, ok := r.backends[scheme]; ok {
		r.mu.Unlock()
		_ = b.Close()
		return existing, nil
	}
	r.backends[scheme] = b
	r.mu.Unlock()

	return b, nil
}

func registeredSchemes() []string {
	registryMu.RLock()
	defer registryMu.RUnlock()
	schemes := make([]string, 0, len(registry))
	for s := range registry {
		schemes = append(schemes, s)
	}
	return schemes
}
