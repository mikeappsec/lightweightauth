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
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/mikeappsec/lightweightauth/internal/cache"
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
	name     string
	cfg      Config
	http     *http.Client
	posCache *cache.LRU
	negCache *cache.LRU
	errCache *cache.LRU
	errStats *cache.Stats // exposed for tests; the LRU writes hits/misses/evictions here.
	sf       singleflight
	guard    *upstream.Guard
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
			return identityFromClaims(claims, i.name), nil
		}
	}

	v, err := i.sf.Do(key, func() (any, error) { return i.callIntrospection(ctx, tok) })
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
	claims := v.(map[string]any)

	active, _ := claims["active"].(bool)
	if !active {
		_ = i.negCache.Set(ctx, key, []byte{1}, i.cfg.NegativeTTL)
		return nil, module.ErrInvalidCredential
	}
	ttl := i.cfg.MaxCacheTTL
	if expF, ok := claims["exp"].(float64); ok {
		if d := time.Until(time.Unix(int64(expF), 0)); d > 0 && d < ttl {
			ttl = d
		}
	}
	if ttl > 0 {
		raw, _ := json.Marshal(claims)
		_ = i.posCache.Set(ctx, key, raw, ttl)
	}
	return identityFromClaims(claims, i.name), nil
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
		if i.cfg.ClientID != "" || i.cfg.ClientSecret != "" {
			req.SetBasicAuth(i.cfg.ClientID, i.cfg.ClientSecret)
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
		if err := json.NewDecoder(resp.Body).Decode(&claims); err != nil {
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

func identityFromClaims(claims map[string]any, source string) *module.Identity {
	sub, _ := claims["sub"].(string)
	if sub == "" {
		sub, _ = claims["username"].(string)
	}
	return &module.Identity{Subject: sub, Claims: claims, Source: source}
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

func factory(name string, raw map[string]any) (module.Identifier, error) {
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

	pos, err := cache.NewLRU(cfg.CacheSize, 0, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: introspection %q cache: %v", module.ErrConfig, name, err)
	}
	neg, err := cache.NewLRU(cfg.CacheSize, 0, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: introspection %q neg-cache: %v", module.ErrConfig, name, err)
	}
	errStats := &cache.Stats{}
	errC, err := cache.NewLRU(cfg.CacheSize, 0, errStats)
	if err != nil {
		return nil, fmt.Errorf("%w: introspection %q err-cache: %v", module.ErrConfig, name, err)
	}
	guardCfg, err := upstream.FromMap(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: introspection %q: %v", module.ErrConfig, name, err)
	}
	return &identifier{
		name:     name,
		cfg:      cfg,
		http:     &http.Client{Timeout: 5 * time.Second},
		posCache: pos,
		negCache: neg,
		errCache: errC,
		errStats: errStats,
		guard:    upstream.NewGuard(guardCfg),
	}, nil
}

func durationFrom(raw map[string]any, key string) (time.Duration, bool) {
	if v, ok := raw[key].(string); ok && v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d, true
		}
	}
	return 0, false
}

func init() { module.RegisterIdentifier("oauth2-introspection", factory) }
