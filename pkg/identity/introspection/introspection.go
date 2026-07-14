// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

// Package introspection implements the RFC 7662 OAuth 2.0 token-
// introspection identifier. It validates opaque tokens by POSTing them to
// the IdP's introspection endpoint and caches the response keyed by
// sha256(token) (DESIGN.md §4 / §5).
//
// Three cache lines are kept side-by-side, all keyed by sha256(token):
//
//   - positive: claims for `active: true` tokens, TTL bounded by
//     min(token.exp - now, maxCacheTtl).
//   - negative: a sentinel for `active: false` tokens, TTL = negativeTtl.
//   - error:    a sentinel for upstream failures (network / 5xx /
//     circuit-open), TTL = errorTtl. This is the K-AUTHN-2 fix: a
//     misbehaving IdP would otherwise turn into a per-request DoS
//     amplifier — every retry in the small window after an outage
//     would re-hit the wounded IdP. With this cache, the gateway
//     short-circuits the next `errorTtl` of identical-token requests
//     to a deterministic `ErrUpstream` without re-dialing. The Guard
//     circuit-breaker is per (tenant, upstream); this cache adds
//     per-credential-digest coalescing on top of it.
//
// Config shape:
//
//	identifiers:
//	  - name: corp-introspect
//	    type: oauth2-introspection
//	    config:
//	      url:          https://idp.corp/oauth2/introspect
//	      clientId:     lwauth
//	      clientSecret: ${INTROSPECT_SECRET}    # caller is responsible for env-expansion
//	      headerName:   Authorization           # default
//	      cacheSize:    100000                  # default
//	      maxCacheTtl:  300s                    # cap if exp is far in future
//	      negativeTtl:  10s                     # how long to remember "inactive"
//	      errorTtl:     5s                      # how long to remember "upstream error"
//
// The cache is per-identifier (introspection results are sensitive and
// shouldn't be co-mingled with the shared decision cache). TTL is bounded
// by min(token.exp - now, maxCacheTtl).
package introspection

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	pkgcache "github.com/mikeappsec/lightweightauth/pkg/cache"
	"github.com/mikeappsec/lightweightauth/pkg/keyrotation"
	"github.com/mikeappsec/lightweightauth/pkg/module"
	"github.com/mikeappsec/lightweightauth/pkg/upstream"
)

type Config struct {
	URL          string
	ClientID     string
	ClientSecret string
	HeaderName   string
	CacheSize    int
	MaxCacheTTL  time.Duration
	NegativeTTL  time.Duration
	ErrorTTL     time.Duration
}

type identifier struct {
	name string
	cfg  Config
	http *http.Client
	// posCache/negCache/errCache are injected, namespaced handles drawn from
	// the module's cache pool (default: the implicit in-memory pool). They
	// replace the previously private per-identifier LRUs; the three logical
	// caches share one pool backend but keep disjoint keyspaces.
	posCache pkgcache.Cache
	negCache pkgcache.Cache
	errCache pkgcache.Cache
	sf       singleflight
	guard    *upstream.Guard

	// resolveSecret, when set, replaces cfg.ClientSecret for Basic Auth
	// against the introspection endpoint. buildRotatableIdentifier sets
	// this to resolve the current active secret from a KeySet on every
	// call (cfg.ClientSecret is read fresh per callIntrospection call
	// already, so this makes rotation take effect immediately without any
	// other client construction change).
	resolveSecret func() (string, bool)
}

// currentClientSecret returns the secret to send via Basic Auth: the
// dynamically-resolved active secret when resolveSecret is set, otherwise
// the static cfg.ClientSecret.
func (i *identifier) currentClientSecret() string {
	if i.resolveSecret != nil {
		s, _ := i.resolveSecret()
		return s
	}
	return i.cfg.ClientSecret
}

func (i *identifier) Name() string { return i.name }

func (i *identifier) Identify(ctx context.Context, r *module.Request) (*module.Identity, error) {
	tok := bearerFrom(r, i.cfg.HeaderName)
	if tok == "" {
		return nil, module.ErrNoMatch
	}
	key := sha256hex(tok)

	// Negative cache hit → still no match, give other identifiers a turn.
	if _, ok, _ := i.negCache.Get(ctx, key); ok {
		return nil, module.ErrInvalidCredential
	}
	// Error cache hit → the IdP recently failed for THIS exact token;
	// short-circuit to the same ErrUpstream rather than DoS-amplifying
	// the wounded IdP. K-AUTHN-2.
	if _, ok, _ := i.errCache.Get(ctx, key); ok {
		return nil, fmt.Errorf("%w: introspection: cached upstream failure", module.ErrUpstream)
	}
	if raw, ok, _ := i.posCache.Get(ctx, key); ok {
		var claims map[string]any
		if err := json.Unmarshal(raw, &claims); err == nil {
			return identityFromClaims(claims, i.name)
		}
	}

	v, err := i.sf.Do(key, func() (any, error) {
		// Use context.WithoutCancel so a single client disconnect doesn't
		// fail all coalesced waiters sharing this singleflight slot.
		sfCtx := context.WithoutCancel(ctx)
		return i.callIntrospection(sfCtx, tok)
	})
	if err != nil {
		// Cache ErrUpstream outcomes briefly so a flood of requests
		// for the same token can't hammer a flapping IdP. We do NOT
		// cache other error classes (ErrConfig, ErrCredentialInvalid
		// from a malformed body, etc.) because those are deterministic
		// in the credential and the negCache / positive paths cover
		// the "real" deny outcomes.
		if errors.Is(err, module.ErrUpstream) && i.cfg.ErrorTTL > 0 {
			_ = i.errCache.Set(ctx, key, []byte{1}, i.cfg.ErrorTTL)
		}
		return nil, err
	}
	shared := v.(map[string]any)
	// Copy the claims map — singleflight returns the same reference to all
	// coalesced waiters, and downstream stages may mutate Claims.
	claims := make(map[string]any, len(shared))
	for k, val := range shared {
		claims[k] = val
	}

	active, _ := claims["active"].(bool)
	if !active {
		_ = i.negCache.Set(ctx, key, []byte{1}, i.cfg.NegativeTTL)
		return nil, module.ErrInvalidCredential
	}
	ttl := i.cfg.MaxCacheTTL
	if expF, ok := claims["exp"].(float64); ok {
		d := time.Until(time.Unix(int64(expF), 0))
		if d <= 0 {
			// IdP said active but the token's own exp has already passed —
			// treat it as inactive rather than positive-caching a token
			// that's already unusable for the full MaxCacheTTL.
			_ = i.negCache.Set(ctx, key, []byte{1}, i.cfg.NegativeTTL)
			return nil, module.ErrInvalidCredential
		}
		if d < ttl {
			ttl = d
		}
	}
	if ttl > 0 {
		raw, _ := json.Marshal(claims)
		_ = i.posCache.Set(ctx, key, raw, ttl)
	}
	return identityFromClaims(claims, i.name)
}

func (i *identifier) callIntrospection(ctx context.Context, tok string) (map[string]any, error) {
	form := url.Values{"token": {tok}, "token_type_hint": {"access_token"}}
	var claims map[string]any
	err := i.guard.Do(ctx, func(ctx context.Context) error {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, i.cfg.URL, strings.NewReader(form.Encode()))
		if err != nil {
			return fmt.Errorf("%w: introspection request: %v", module.ErrUpstream, err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Accept", "application/json")
		secret := i.currentClientSecret()
		if i.cfg.ClientID != "" || secret != "" {
			req.SetBasicAuth(i.cfg.ClientID, secret)
		}
		resp, err := i.http.Do(req)
		if err != nil {
			return fmt.Errorf("%w: introspection: %v", module.ErrUpstream, err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("%w: introspection returned status %d", module.ErrUpstream, resp.StatusCode)
		}
		claims = nil
		// Cap successful response decode. RFC 7662 introspection
		// responses are claim sets — typically <2 KiB, occasionally
		// larger if the IdP attaches roles/groups. Cap at 1 MiB so a
		// blackholed or compromised IdP cannot stream an arbitrarily
		// large success body and burn memory during JSON decode.
		const introspectionMaxResponseBytes = 1 << 20
		if err := json.NewDecoder(io.LimitReader(resp.Body, introspectionMaxResponseBytes)).Decode(&claims); err != nil {
			return fmt.Errorf("%w: introspection decode: %v", module.ErrUpstream, err)
		}
		return nil
	})
	if err != nil {
		if errors.Is(err, upstream.ErrCircuitOpen) {
			return nil, fmt.Errorf("%w: introspection: circuit open", module.ErrUpstream)
		}
		return nil, err
	}
	return claims, nil
}

func identityFromClaims(claims map[string]any, source string) (*module.Identity, error) {
	sub, _ := claims["sub"].(string)
	if sub == "" {
		sub, _ = claims["username"].(string)
	}
	// INTROSPECT-VULN-01: Reject active tokens without a subject identifier.
	// An empty subject defeats per-user authorization, audit attribution,
	// revocation, and rate limiting. Multiple distinct tokens resolving to
	// Subject="" would be indistinguishable in RBAC, audit, and revocation —
	// revoking "sub:" would kill ALL anonymous tokens or none individually.
	// Per RFC 7662 §2.2, `sub` is OPTIONAL in the response but we require
	// at least one identity anchor (sub, username, or client_id).
	if sub == "" {
		if cid, ok := claims["client_id"].(string); ok && cid != "" {
			sub = cid
		}
	}
	if sub == "" {
		return nil, fmt.Errorf("%w: introspection: active token has no sub, username, or client_id", module.ErrInvalidCredential)
	}
	return &module.Identity{Subject: sub, Claims: claims, Source: source}, nil
}

func bearerFrom(r *module.Request, header string) string {
	if header == "" {
		header = "Authorization"
	}
	v := r.Header(header)
	if v == "" {
		return ""
	}
	const bearer = "bearer "
	if len(v) > len(bearer) && strings.EqualFold(v[:len(bearer)], bearer) {
		return strings.TrimSpace(v[len(bearer):])
	}
	// For the Authorization header, non-Bearer schemes (e.g. "DPoP",
	// "Basic") are not ours to claim — return empty so the pipeline
	// tries the next identifier. For custom headers (X-Token, etc.)
	// the raw value IS the token.
	if strings.EqualFold(header, "Authorization") {
		return ""
	}
	return v
}

func sha256hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// singleflight is a tiny stand-in to coalesce in-flight introspection
// calls for the same token without pulling the whole golang.org/x/sync
// signature into the hot path.
type singleflight struct {
	mu sync.Mutex
	in map[string]*sfCall
}

type sfCall struct {
	wg  sync.WaitGroup
	val any
	err error
}

func (s *singleflight) Do(key string, fn func() (any, error)) (any, error) {
	s.mu.Lock()
	if s.in == nil {
		s.in = map[string]*sfCall{}
	}
	if c, ok := s.in[key]; ok {
		s.mu.Unlock()
		c.wg.Wait()
		return c.val, c.err
	}
	c := &sfCall{}
	c.wg.Add(1)
	s.in[key] = c
	s.mu.Unlock()

	c.val, c.err = fn()
	c.wg.Done()

	s.mu.Lock()
	delete(s.in, key)
	s.mu.Unlock()
	return c.val, c.err
}

var knownKeys = map[string]struct{}{
	"url":          {},
	"clientId":     {},
	"clientSecret": {},
	"headerName":   {},
	"cacheSize":    {},
	"maxCacheTtl":  {},
	"negativeTtl":  {},
	"errorTtl":     {},
	"resilience":   {},
	"secrets":      {},
}

func factory(name string, raw map[string]any, deps module.Deps) (module.Identifier, error) {
	if err := module.CheckUnknownKeys("oauth2-introspection", name, raw, knownKeys); err != nil {
		return nil, err
	}
	cfg := Config{
		HeaderName:  "Authorization",
		CacheSize:   100_000,
		MaxCacheTTL: 5 * time.Minute,
		NegativeTTL: 10 * time.Second,
		ErrorTTL:    5 * time.Second,
	}
	if v, ok := raw["url"].(string); ok && v != "" {
		cfg.URL = v
	} else {
		return nil, fmt.Errorf("%w: introspection %q: url is required", module.ErrConfig, name)
	}
	if v, ok := raw["clientId"].(string); ok {
		cfg.ClientID = v
	}
	if v, ok := raw["clientSecret"].(string); ok {
		cfg.ClientSecret = v
	}
	secretsRaw, hasSecrets := raw["secrets"].([]any)
	hasSecrets = hasSecrets && len(secretsRaw) > 0
	if hasSecrets && cfg.ClientSecret != "" {
		return nil, fmt.Errorf("%w: introspection %q: pick exactly one of clientSecret / secrets", module.ErrConfig, name)
	}
	if v, ok := raw["headerName"].(string); ok && v != "" {
		cfg.HeaderName = v
	}
	if v, ok := raw["cacheSize"].(int); ok && v > 0 {
		cfg.CacheSize = v
	}
	if d, ok := durationFrom(raw, "maxCacheTtl"); ok {
		cfg.MaxCacheTTL = d
	}
	if d, ok := durationFrom(raw, "negativeTtl"); ok {
		cfg.NegativeTTL = d
	}
	if d, ok := durationFrom(raw, "errorTtl"); ok {
		cfg.ErrorTTL = d
	}

	guardCfg, err := upstream.FromMap(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: introspection %q: %v", module.ErrConfig, name, err)
	}
	// Caches are injected from the module's pool. The three logical lines
	// (positive/negative/error) share the pool backend but get disjoint,
	// auto-namespaced keyspaces from the provider. When no pool is configured
	// the host injects the implicit in-memory default. TTLs remain a module
	// concern (set per-Set call below in Identify).
	prov := deps.CacheProvider()
	base := &identifier{
		name:     name,
		cfg:      cfg,
		http:     &http.Client{Timeout: 5 * time.Second},
		posCache: prov.Cache("introspection.positive"),
		negCache: prov.Cache("introspection.negative"),
		errCache: prov.Cache("introspection.error"),
		guard:    upstream.NewGuard(guardCfg),
	}
	if hasSecrets {
		entries, err := keyrotation.ParseSecretsConfig(raw)
		if err != nil {
			return nil, fmt.Errorf("%w: introspection %q: %v", module.ErrConfig, name, err)
		}
		return buildRotatableIdentifier(base, entries), nil
	}
	return base, nil
}

func durationFrom(raw map[string]any, key string) (time.Duration, bool) {
	if v, ok := raw[key].(string); ok && v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d, true
		}
	}
	return 0, false
}

// RevocationKeys implements module.RevocationChecker for the introspection identifier.
// It derives keys from the jti claim (if present) and the subject.
func (i *identifier) RevocationKeys(id *module.Identity, tenantID string) []string {
	if id == nil {
		return nil
	}
	var keys []string

	// Key by JTI (token ID) from introspection response.
	if jti, ok := id.Claims["jti"].(string); ok && jti != "" {
		keys = append(keys, "jti:"+jti)
	}

	// Key by token_type + client_id for service-to-service tokens.
	if clientID, ok := id.Claims["client_id"].(string); ok && clientID != "" {
		keys = append(keys, "client:"+clientID)
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

func init() { module.RegisterIdentifierWithDeps("oauth2-introspection", factory) }
