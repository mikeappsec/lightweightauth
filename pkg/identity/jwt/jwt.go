// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

// Package jwt is the default JWT identifier module.
//
// It validates RFC 7519 bearer tokens against a JWKS endpoint with:
//
//   - signature verification (any algorithm advertised by the JWKS),
//   - exp / nbf / iat enforcement,
//   - optional issuer pinning (issuerUrl),
//   - optional audience pinning (audiences).
//
// The JWKS is fetched once at startup and refreshed in the background by
// jwx's own jwk.Cache (default: every 15 minutes, or sooner on a kid miss).
// The poller is deduplicated per JWKS URL across identifiers and engines and
// bound to the engine-lifecycle context (module.Deps.Ctx), so it is torn down
// on hot-reload rather than leaking. See the shared internal/jwks package and
// the cache layer redesign (§12 Option A).
package jwt

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	jwtlib "github.com/lestrrat-go/jwx/v2/jwt"

	"github.com/mikeappsec/lightweightauth/internal/jwks"
	"github.com/mikeappsec/lightweightauth/pkg/module"
)

// Config is the YAML/CRD shape understood by the jwt identifier.
//
//	type: jwt
//	jwksUrl:    https://idp.example.com/.well-known/jwks.json
//	issuerUrl:  https://idp.example.com/        # optional, pinned `iss`
//	audiences:  [api://my-service]              # optional, any-match
//	header:     Authorization                   # default
//	scheme:     Bearer                          # default
type Config struct {
	JWKSURL   string   `yaml:"jwksUrl" json:"jwksUrl"`
	IssuerURL string   `yaml:"issuerUrl" json:"issuerUrl"`
	Audiences []string `yaml:"audiences" json:"audiences"`
	Header    string   `yaml:"header" json:"header"`
	Scheme    string   `yaml:"scheme" json:"scheme"`

	// MinRefreshInterval bounds how often jwx re-fetches the JWKS on
	// kid misses. Defaults to 15 minutes.
	MinRefreshInterval time.Duration `yaml:"minRefreshInterval" json:"minRefreshInterval"`
}

type identifier struct {
	name      string
	header    string
	scheme    string
	parseOpts []jwtlib.ParseOption
}

func (i *identifier) Name() string { return i.name }

// Identify locates the bearer token, verifies its signature against the
// cached JWKS, and validates standard claims. Returns ErrNoMatch when no
// bearer header is present (so the next identifier may try),
// ErrInvalidCredential on any validation failure.
func (i *identifier) Identify(ctx context.Context, r *module.Request) (*module.Identity, error) {
	raw := r.Header(i.header)
	if raw == "" {
		return nil, module.ErrNoMatch
	}
	prefix := i.scheme + " "
	if len(raw) < len(prefix) || !strings.EqualFold(raw[:len(prefix)], prefix) {
		return nil, module.ErrNoMatch
	}
	token := strings.TrimSpace(raw[len(prefix):])
	if token == "" {
		return nil, module.ErrNoMatch
	}

	tok, err := jwtlib.ParseString(token, i.parseOpts...)
	if err != nil {
		return nil, fmt.Errorf("%w: jwt: %v", module.ErrInvalidCredential, err)
	}

	claims, err := tok.AsMap(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: jwt: extract claims: %v", module.ErrInvalidCredential, err)
	}
	subj := tok.Subject()
	if subj == "" {
		if v, ok := claims["sub"].(string); ok {
			subj = v
		}
	}
	// Security hardening: reject tokens without a subject claim. An empty
	// subject defeats per-user caching, authorization, and audit attribution.
	// M2M tokens (client_credentials) should use "client_id" or "azp" as sub.
	if subj == "" {
		// Fall back to client_id or azp (RFC 9068 §2.2) for M2M tokens.
		if cid, ok := claims["client_id"].(string); ok && cid != "" {
			subj = cid
		} else if azp, ok := claims["azp"].(string); ok && azp != "" {
			subj = azp
		} else {
			return nil, fmt.Errorf("%w: jwt: token has no sub, client_id, or azp claim", module.ErrInvalidCredential)
		}
	}
	return &module.Identity{
		Subject: subj,
		Claims:  claims,
		Source:  i.name,
		ACR:     extractACR(claims),
		AMR:     extractAMR(claims),
	}, nil
}

// extractACR reads the OIDC "acr" claim (Authentication Context Class
// Reference) from the JWT claims map.
func extractACR(claims map[string]any) string {
	if v, ok := claims["acr"].(string); ok {
		return v
	}
	return ""
}

// extractAMR reads the OIDC "amr" claim (Authentication Methods References,
// RFC 8176) from the JWT claims map. The claim is typically a JSON array
// of strings.
func extractAMR(claims map[string]any) []string {
	switch v := claims["amr"].(type) {
	case []string:
		return v
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		if len(out) > 0 {
			return out
		}
	case string:
		return []string{v}
	}
	return nil
}

// defaultsAndValidate fills in defaults and validates the required fields,
// returning a normalized copy of cfg.
func defaultsAndValidate(cfg Config) (Config, error) {
	if cfg.JWKSURL == "" {
		return cfg, fmt.Errorf("%w: jwt: jwksUrl is required", module.ErrConfig)
	}
	if cfg.Header == "" {
		cfg.Header = "Authorization"
	}
	if cfg.Scheme == "" {
		cfg.Scheme = "Bearer"
	}
	if cfg.MinRefreshInterval <= 0 {
		cfg.MinRefreshInterval = 15 * time.Minute
	}
	return cfg, nil
}

// buildStandaloneKeyset constructs a dedicated jwx cache + keyset bound to
// ctx. It is the legacy, non-deduplicated path used by direct callers
// (tests, no-deps Build) — production builds go through jwks.AcquireShared.
func buildStandaloneKeyset(ctx context.Context, cfg Config) (jwk.Set, error) {
	keyset, err := jwks.Standalone(ctx, cfg.JWKSURL, cfg.MinRefreshInterval)
	if err != nil {
		return nil, mapJWKSError(err)
	}
	return keyset, nil
}

// mapJWKSError maps the shared jwks package's error classes onto the jwt
// module's ErrConfig / ErrUpstream sentinels.
func mapJWKSError(err error) error {
	if errors.Is(err, jwks.ErrFetch) {
		return fmt.Errorf("%w: jwt: %v", module.ErrUpstream, err)
	}
	return fmt.Errorf("%w: jwt: %v", module.ErrConfig, err)
}

// assembleIdentifier wires the parse options around a fetched keyset.
func assembleIdentifier(name string, cfg Config, keyset jwk.Set) *identifier {
	opts := []jwtlib.ParseOption{
		jwtlib.WithKeySet(keyset),
		jwtlib.WithValidate(true),
		// JWT-VULN-01: Require the `exp` claim to be present. Without this,
		// jwx's WithValidate(true) only validates exp/nbf *if present* — a
		// token without `exp` would be accepted and never expire, making it
		// valid forever. This is equivalent to an immortal bearer credential
		// that survives key rotation, user deprovisioning, and incident
		// response. Per RFC 9068 §2.1 (JWT Access Tokens), exp is REQUIRED.
		jwtlib.WithRequiredClaim("exp"),
	}
	if cfg.IssuerURL != "" {
		opts = append(opts, jwtlib.WithIssuer(cfg.IssuerURL))
	}
	for _, a := range cfg.Audiences {
		opts = append(opts, jwtlib.WithAudience(a))
	}
	return &identifier{
		name:      name,
		header:    cfg.Header,
		scheme:    cfg.Scheme,
		parseOpts: opts,
	}
}

// newIdentifier builds a jwt identifier with a standalone keyset bound to
// ctx. Retained for direct callers and tests; production goes through
// newIdentifierWithDeps for poller dedup and lifecycle binding.
func newIdentifier(ctx context.Context, name string, cfg Config) (*identifier, error) {
	cfg, err := defaultsAndValidate(cfg)
	if err != nil {
		return nil, err
	}
	keyset, err := buildStandaloneKeyset(ctx, cfg)
	if err != nil {
		return nil, err
	}
	return assembleIdentifier(name, cfg, keyset), nil
}

// newIdentifierWithDeps builds a jwt identifier using the injected engine
// dependencies. When a lifecycle context is present it shares a deduplicated,
// lifecycle-bound JWKS poller per URL (§12 Option A); otherwise it falls back
// to a standalone keyset on context.Background() to preserve legacy behavior.
func newIdentifierWithDeps(name string, cfg Config, deps module.Deps) (*identifier, error) {
	cfg, err := defaultsAndValidate(cfg)
	if err != nil {
		return nil, err
	}
	if deps.Ctx == nil {
		keyset, err := buildStandaloneKeyset(context.Background(), cfg)
		if err != nil {
			return nil, err
		}
		return assembleIdentifier(name, cfg, keyset), nil
	}
	keyset, err := jwks.AcquireShared(deps.Ctx, cfg.JWKSURL, cfg.MinRefreshInterval)
	if err != nil {
		return nil, mapJWKSError(err)
	}
	return assembleIdentifier(name, cfg, keyset), nil
}

func parseConfig(raw map[string]any) (Config, error) {
	cfg := Config{}
	if v, ok := raw["jwksUrl"].(string); ok {
		cfg.JWKSURL = v
	}
	if v, ok := raw["issuerUrl"].(string); ok {
		cfg.IssuerURL = v
	}
	if v, ok := raw["header"].(string); ok {
		cfg.Header = v
	}
	if v, ok := raw["scheme"].(string); ok {
		cfg.Scheme = v
	}
	if v, ok := raw["audiences"].([]any); ok {
		for _, a := range v {
			if s, ok := a.(string); ok {
				cfg.Audiences = append(cfg.Audiences, s)
			}
		}
	}
	if v, ok := raw["minRefreshInterval"].(string); ok && v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return cfg, fmt.Errorf("%w: jwt.minRefreshInterval: %v", module.ErrConfig, err)
		}
		cfg.MinRefreshInterval = d
	}
	return cfg, nil
}

var knownKeys = map[string]struct{}{
	"jwksUrl":            {},
	"issuerUrl":          {},
	"header":             {},
	"scheme":             {},
	"audiences":          {},
	"minRefreshInterval": {},
}

func factory(name string, raw map[string]any, deps module.Deps) (module.Identifier, error) {
	if err := module.CheckUnknownKeys("jwt", name, raw, knownKeys); err != nil {
		return nil, err
	}
	cfg, err := parseConfig(raw)
	if err != nil {
		return nil, err
	}
	// The JWKS poller is bound to deps.Ctx (the engine-lifecycle context) and
	// deduplicated per URL, so it is torn down when the engine is swapped on
	// hot-reload instead of leaking on context.Background().
	return newIdentifierWithDeps(name, cfg, deps)
}

// Compile-time guard.
var _ module.Identifier = (*identifier)(nil)

// RevocationKeys implements module.RevocationChecker for the JWT identifier.
// It derives keys from the token's jti claim and the identity's subject.
func (i *identifier) RevocationKeys(id *module.Identity, tenantID string) []string {
	if id == nil {
		return nil
	}
	var keys []string

	// Key by JTI (unique token ID) — most precise revocation.
	if jti, ok := id.Claims["jti"].(string); ok && jti != "" {
		keys = append(keys, "jti:"+jti)
	}

	// Key by subject — revokes ALL tokens for this user/service.
	if id.Subject != "" {
		prefix := "sub:"
		if tenantID != "" {
			prefix += tenantID + ":"
		}
		keys = append(keys, prefix+id.Subject)
	}

	return keys
}

func init() { module.RegisterIdentifierWithDeps("jwt", factory) }
