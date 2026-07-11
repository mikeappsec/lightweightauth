// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

// Package idjag is the Identity Assertion JWT Authorization Grant (ID-JAG)
// identifier module.
//
// It implements the token-exchange leg of the MCP Enterprise-Managed
// Authorization spec (draft-ietf-oauth-identity-assertion-authz-grant).
// An enterprise IdP issues a short-lived ID-JAG assertion that names a
// specific MCP server as the target resource. LightweightAuth — acting as
// the Resource Authorization Server for that MCP server — verifies the
// assertion here, and a downstream jwtissue mutator mints the actual MCP
// access token.
//
// Validation performed:
//
//   - JWS signature against the IdP's JWKS,
//   - typ header == "oauth-id-jag+jwt" (RFC 7519 §5.1 token-type pinning),
//   - exp / nbf / iat enforcement (exp REQUIRED),
//   - iss pinned to the IdP issuer,
//   - aud pinned to this lwauth authorization server,
//   - the `resource` claim pinned to the registered MCP server identifier,
//   - optional client_id allow-list,
//   - jti single-use replay prevention.
//
// See docs/design/mcp-enterprise-auth.md.
package idjag

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	jwtlib "github.com/lestrrat-go/jwx/v2/jwt"

	"github.com/mikeappsec/lightweightauth/internal/jwks"
	"github.com/mikeappsec/lightweightauth/internal/replay"
	"github.com/mikeappsec/lightweightauth/pkg/cache"
	"github.com/mikeappsec/lightweightauth/pkg/module"
)

// DefaultTokenType is the JWS `typ` header an ID-JAG assertion must carry.
const DefaultTokenType = "oauth-id-jag+jwt"

// Config is the YAML/CRD shape understood by the idjag identifier.
//
//	type: idjag
//	jwksUrl:             https://idp.example.com/.well-known/jwks.json
//	issuer:              https://idp.example.com/
//	audience:            https://lwauth.example.com/        # this AS
//	resourceIdentifier:  https://github-mcp.example.com/    # target MCP server
//	allowedClients:      [my-agent-client]                  # optional
//	header:              Authorization                      # default
//	scheme:              Bearer                             # default
type Config struct {
	JWKSURL            string   `yaml:"jwksUrl" json:"jwksUrl"`
	Issuer             string   `yaml:"issuer" json:"issuer"`
	Audience           string   `yaml:"audience" json:"audience"`
	ResourceIdentifier string   `yaml:"resourceIdentifier" json:"resourceIdentifier"`
	AllowedClients     []string `yaml:"allowedClients" json:"allowedClients"`
	Header             string   `yaml:"header" json:"header"`
	Scheme             string   `yaml:"scheme" json:"scheme"`
	ExpectedTyp        string   `yaml:"expectedTyp" json:"expectedTyp"`

	// MinRefreshInterval bounds how often the JWKS is re-fetched on a
	// kid miss. Defaults to 15 minutes.
	MinRefreshInterval time.Duration `yaml:"minRefreshInterval" json:"minRefreshInterval"`

	// ReplayWindow is how long a consumed jti is remembered to block
	// replays. Should be >= the maximum ID-JAG lifetime. Defaults to
	// 10 minutes.
	ReplayWindow time.Duration `yaml:"replayWindow" json:"replayWindow"`
}

type identifier struct {
	name         string
	header       string
	scheme       string
	expectedTyp  string
	resource     string
	allowed      map[string]struct{}
	keyset       jwk.Set
	parseOpts    []jwtlib.ParseOption
	replay       *replay.Guard
	replayWindow time.Duration
}

func (i *identifier) Name() string { return i.name }

// Identify verifies an ID-JAG assertion presented as a bearer credential.
//
// Returns ErrNoMatch when no bearer header is present (so the next
// identifier may try) and ErrInvalidCredential on any validation failure.
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

	// Pin the token type BEFORE trusting any claims. An attacker who can
	// obtain a normal ID token or access token from the same IdP must not
	// be able to replay it at the token endpoint as an ID-JAG.
	if err := i.checkTyp([]byte(token)); err != nil {
		return nil, err
	}

	tok, err := jwtlib.ParseString(token, i.parseOpts...)
	if err != nil {
		return nil, fmt.Errorf("%w: idjag: %v", module.ErrInvalidCredential, err)
	}

	claims, err := tok.AsMap(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: idjag: extract claims: %v", module.ErrInvalidCredential, err)
	}

	// Pin the target resource. The IdP scopes each ID-JAG to exactly one
	// MCP server; lwauth must refuse assertions minted for a different
	// resource even if signature/iss/aud all check out.
	if err := i.checkResource(claims); err != nil {
		return nil, err
	}

	clientID := stringClaim(claims, "client_id")
	if len(i.allowed) > 0 {
		if clientID == "" {
			return nil, fmt.Errorf("%w: idjag: missing client_id", module.ErrInvalidCredential)
		}
		if _, ok := i.allowed[clientID]; !ok {
			return nil, fmt.Errorf("%w: idjag: client_id %q not allowed", module.ErrInvalidCredential, clientID)
		}
	}

	// jti single-use replay prevention. RFC 7523 §3 recommends rejecting
	// reused assertion identifiers within the assertion's lifetime.
	jti := stringClaim(claims, "jti")
	if jti == "" {
		return nil, fmt.Errorf("%w: idjag: missing jti", module.ErrInvalidCredential)
	}
	firstUse, err := i.replay.Consume(ctx, jti, i.replayWindow)
	if err != nil {
		return nil, fmt.Errorf("%w: idjag: replay check: %v", module.ErrUpstream, err)
	}
	if !firstUse {
		return nil, fmt.Errorf("%w: idjag: assertion replay detected", module.ErrInvalidCredential)
	}

	subj := tok.Subject()
	if subj == "" {
		subj = stringClaim(claims, "sub")
	}
	if subj == "" {
		return nil, fmt.Errorf("%w: idjag: missing sub", module.ErrInvalidCredential)
	}

	return &module.Identity{
		Subject: subj,
		Claims:  claims,
		Source:  i.name,
	}, nil
}

// checkTyp inspects the JWS protected header and enforces the expected
// token type without verifying the signature (verification happens next).
func (i *identifier) checkTyp(token []byte) error {
	msg, err := jws.Parse(token)
	if err != nil {
		return fmt.Errorf("%w: idjag: parse jws: %v", module.ErrInvalidCredential, err)
	}
	sigs := msg.Signatures()
	if len(sigs) == 0 {
		return fmt.Errorf("%w: idjag: unsigned assertion", module.ErrInvalidCredential)
	}
	typ := sigs[0].ProtectedHeaders().Type()
	if !strings.EqualFold(typ, i.expectedTyp) {
		return fmt.Errorf("%w: idjag: unexpected typ %q (want %q)",
			module.ErrInvalidCredential, typ, i.expectedTyp)
	}
	return nil
}

// checkResource enforces that the assertion's `resource` claim names this
// MCP server. The claim may be a single string or an array of strings.
func (i *identifier) checkResource(claims map[string]any) error {
	switch v := claims["resource"].(type) {
	case string:
		if v == i.resource {
			return nil
		}
	case []any:
		for _, item := range v {
			if s, ok := item.(string); ok && s == i.resource {
				return nil
			}
		}
	case []string:
		for _, s := range v {
			if s == i.resource {
				return nil
			}
		}
	}
	return fmt.Errorf("%w: idjag: resource claim does not match %q",
		module.ErrInvalidCredential, i.resource)
}

func stringClaim(claims map[string]any, key string) string {
	if v, ok := claims[key].(string); ok {
		return v
	}
	return ""
}

// defaultsAndValidate validates required fields and fills in defaults,
// returning the normalised config shared by both the standalone and the
// deps-aware construction paths.
func defaultsAndValidate(cfg Config) (Config, error) {
	if cfg.JWKSURL == "" {
		return Config{}, fmt.Errorf("%w: idjag: jwksUrl is required", module.ErrConfig)
	}
	if cfg.Issuer == "" {
		return Config{}, fmt.Errorf("%w: idjag: issuer is required", module.ErrConfig)
	}
	if cfg.Audience == "" {
		return Config{}, fmt.Errorf("%w: idjag: audience is required", module.ErrConfig)
	}
	if cfg.ResourceIdentifier == "" {
		return Config{}, fmt.Errorf("%w: idjag: resourceIdentifier is required", module.ErrConfig)
	}
	if cfg.Header == "" {
		cfg.Header = "Authorization"
	}
	if cfg.Scheme == "" {
		cfg.Scheme = "Bearer"
	}
	if cfg.ExpectedTyp == "" {
		cfg.ExpectedTyp = DefaultTokenType
	}
	if cfg.MinRefreshInterval <= 0 {
		cfg.MinRefreshInterval = 15 * time.Minute
	}
	if cfg.ReplayWindow <= 0 {
		cfg.ReplayWindow = 10 * time.Minute
	}
	return cfg, nil
}

// assembleIdentifier builds the identifier from a validated config, a ready
// keyset (shared or standalone), and the injected replay cache (nil for the
// standalone path, which falls back to the in-process replay guard).
func assembleIdentifier(name string, cfg Config, keyset jwk.Set, replayCache cache.Cache) *identifier {
	opts := []jwtlib.ParseOption{
		jwtlib.WithKeySet(keyset),
		jwtlib.WithValidate(true),
		jwtlib.WithRequiredClaim("exp"),
		jwtlib.WithIssuer(cfg.Issuer),
		jwtlib.WithAudience(cfg.Audience),
	}

	allowed := make(map[string]struct{}, len(cfg.AllowedClients))
	for _, c := range cfg.AllowedClients {
		if c != "" {
			allowed[c] = struct{}{}
		}
	}

	return &identifier{
		name:         name,
		header:       cfg.Header,
		scheme:       cfg.Scheme,
		expectedTyp:  cfg.ExpectedTyp,
		resource:     cfg.ResourceIdentifier,
		allowed:      allowed,
		keyset:       keyset,
		parseOpts:    opts,
		replay:       replay.New(replayCache),
		replayWindow: cfg.ReplayWindow,
	}
}

// mapJWKSError maps the shared jwks package error classes onto idjag's
// ErrConfig / ErrUpstream sentinels.
func mapJWKSError(err error) error {
	if errors.Is(err, jwks.ErrFetch) {
		return fmt.Errorf("%w: idjag: %v", module.ErrUpstream, err)
	}
	return fmt.Errorf("%w: idjag: %v", module.ErrConfig, err)
}

// newIdentifier builds a standalone identifier bound to ctx. It is the
// legacy, non-deduplicated path used by direct callers and tests; replay
// enforcement uses the in-process fallback.
func newIdentifier(ctx context.Context, name string, cfg Config) (*identifier, error) {
	cfg, err := defaultsAndValidate(cfg)
	if err != nil {
		return nil, err
	}
	keyset, err := jwks.Standalone(ctx, cfg.JWKSURL, cfg.MinRefreshInterval)
	if err != nil {
		return nil, mapJWKSError(err)
	}
	return assembleIdentifier(name, cfg, keyset, nil), nil
}

// newIdentifierWithDeps builds an identifier wired to engine-scoped
// dependencies. When an engine-lifecycle context is available it shares a
// deduplicated, lifecycle-bound JWKS poller per URL with other identifiers
// (jwt, idjag) targeting the same IdP; otherwise it falls back to a
// standalone keyset on context.Background(). jti replay is routed through the
// injected cache (SetNX), so a remote backend makes replay cross-replica.
func newIdentifierWithDeps(name string, cfg Config, deps module.Deps) (*identifier, error) {
	cfg, err := defaultsAndValidate(cfg)
	if err != nil {
		return nil, err
	}
	replayCache := deps.CacheProvider().Cache("replay")
	if deps.Ctx == nil {
		keyset, err := jwks.Standalone(context.Background(), cfg.JWKSURL, cfg.MinRefreshInterval)
		if err != nil {
			return nil, mapJWKSError(err)
		}
		return assembleIdentifier(name, cfg, keyset, replayCache), nil
	}
	keyset, err := jwks.AcquireShared(deps.Ctx, cfg.JWKSURL, cfg.MinRefreshInterval)
	if err != nil {
		return nil, mapJWKSError(err)
	}
	return assembleIdentifier(name, cfg, keyset, replayCache), nil
}

func parseConfig(raw map[string]any) (Config, error) {
	cfg := Config{}
	if v, ok := raw["jwksUrl"].(string); ok {
		cfg.JWKSURL = v
	}
	if v, ok := raw["issuer"].(string); ok {
		cfg.Issuer = v
	}
	if v, ok := raw["audience"].(string); ok {
		cfg.Audience = v
	}
	if v, ok := raw["resourceIdentifier"].(string); ok {
		cfg.ResourceIdentifier = v
	}
	if v, ok := raw["header"].(string); ok {
		cfg.Header = v
	}
	if v, ok := raw["scheme"].(string); ok {
		cfg.Scheme = v
	}
	if v, ok := raw["expectedTyp"].(string); ok {
		cfg.ExpectedTyp = v
	}
	if v, ok := raw["allowedClients"].([]any); ok {
		for _, a := range v {
			if s, ok := a.(string); ok {
				cfg.AllowedClients = append(cfg.AllowedClients, s)
			}
		}
	}
	if v, ok := raw["minRefreshInterval"].(string); ok && v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return cfg, fmt.Errorf("%w: idjag.minRefreshInterval: %v", module.ErrConfig, err)
		}
		cfg.MinRefreshInterval = d
	}
	if v, ok := raw["replayWindow"].(string); ok && v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return cfg, fmt.Errorf("%w: idjag.replayWindow: %v", module.ErrConfig, err)
		}
		cfg.ReplayWindow = d
	}
	return cfg, nil
}

var knownKeys = map[string]struct{}{
	"jwksUrl":            {},
	"issuer":             {},
	"audience":           {},
	"resourceIdentifier": {},
	"allowedClients":     {},
	"header":             {},
	"scheme":             {},
	"expectedTyp":        {},
	"minRefreshInterval": {},
	"replayWindow":       {},
}

func factory(name string, raw map[string]any, deps module.Deps) (module.Identifier, error) {
	if err := module.CheckUnknownKeys("idjag", name, raw, knownKeys); err != nil {
		return nil, err
	}
	cfg, err := parseConfig(raw)
	if err != nil {
		return nil, err
	}
	return newIdentifierWithDeps(name, cfg, deps)
}

// Compile-time guard.
var _ module.Identifier = (*identifier)(nil)

func init() { module.RegisterIdentifierWithDeps("idjag", factory) }
