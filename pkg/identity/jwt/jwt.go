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
// DESIGN.md §4 calls for plugging this into the project-wide cache.Layer;
// that migration is tracked for M2 so jwx's cache stays the authoritative
// JWKS store for now.
package jwt

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	jwtlib "github.com/lestrrat-go/jwx/v2/jwt"

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
	return &module.Identity{
		Subject: subj,
		Claims:  claims,
		Source:  i.name,
	}, nil
}

func newIdentifier(ctx context.Context, name string, cfg Config) (*identifier, error) {
	if cfg.JWKSURL == "" {
		return nil, fmt.Errorf("%w: jwt: jwksUrl is required", module.ErrConfig)
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

	cache := jwk.NewCache(ctx)
	if err := cache.Register(cfg.JWKSURL, jwk.WithMinRefreshInterval(cfg.MinRefreshInterval)); err != nil {
		return nil, fmt.Errorf("%w: jwt: register jwks: %v", module.ErrConfig, err)
	}
	// Bound the initial JWKS fetch so a blackholed or very slow IdP
	// cannot stall lwauthd startup indefinitely. The factory's
	// caller may pass a context.Background() (via Main / Run
	// construction), which would never time out on its own. 30s is
	// generous for a JWKS GET against a healthy IdP and short enough
	// that the supervisor's startTimeout (M10) can still surface the
	// failure as a config error.
	refreshCtx, refreshCancel := context.WithTimeout(ctx, 30*time.Second)
	defer refreshCancel()
	if _, err := cache.Refresh(refreshCtx, cfg.JWKSURL); err != nil {
		return nil, fmt.Errorf("%w: jwt: fetch jwks %s: %v", module.ErrUpstream, cfg.JWKSURL, err)
	}
	keyset := jwk.NewCachedSet(cache, cfg.JWKSURL)

	opts := []jwtlib.ParseOption{
		jwtlib.WithKeySet(keyset),
		jwtlib.WithValidate(true),
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
	}, nil
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

func factory(name string, raw map[string]any) (module.Identifier, error) {
	cfg, err := parseConfig(raw)
	if err != nil {
		return nil, err
	}
	// The jwk.Cache spawns a background refresher tied to this context.
	// On config reload we throw away the whole engine, so its goroutine
	// is naturally GC'd; using context.Background() here is intentional.
	return newIdentifier(context.Background(), name, cfg)
}

// Compile-time guard.
var _ module.Identifier = (*identifier)(nil)

func init() { module.RegisterIdentifier("jwt", factory) }
