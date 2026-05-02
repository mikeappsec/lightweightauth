// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

// Package oauth2 is the OIDC / OAuth 2.0 authorization-code identifier
// (the oauth2-proxy-equivalent feature set).
//
// Behaviour:
//
//   - On every request, [identifier.Identify] looks up an encrypted
//     session cookie via [session.Store]. A valid session is surfaced as
//     a [module.Identity]; absent / corrupt cookies yield [module.ErrNoMatch]
//     so other identifiers (bearer JWT, API key) can still try.
//
//   - The module also implements [module.HTTPMounter] and exposes the
//     interactive flow under "/oauth2/":
//
//       /oauth2/start?rd=/path  →  redirect to the IdP's authorize URL
//                                  with PKCE (S256) + opaque state.
//       /oauth2/callback        →  state check → token exchange → id_token
//                                  verify → mint session → redirect to rd.
//       /oauth2/logout          →  clear session cookie → 302 to rdAfterLogout.
//       /oauth2/userinfo        →  JSON of the current session (debug / SPAs).
//
// PKCE is mandatory (OAuth 2.1). The state and code_verifier travel in a
// short-lived encrypted "flow" cookie keyed by the same secret as the
// session cookie — no server-side state is required.
package oauth2

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"golang.org/x/oauth2"

	"github.com/lestrrat-go/jwx/v2/jwk"
	jwtlib "github.com/lestrrat-go/jwx/v2/jwt"

	"github.com/mikeappsec/lightweightauth/pkg/module"
	"github.com/mikeappsec/lightweightauth/pkg/session"
)

// Config is the YAML/CRD shape of the oauth2 identifier.
//
//	type: oauth2
//	clientId:     my-app
//	clientSecret: <secret>
//	authUrl:      https://idp.example.com/authorize
//	tokenUrl:     https://idp.example.com/token
//	jwksUrl:      https://idp.example.com/.well-known/jwks.json
//	issuerUrl:    https://idp.example.com/   # optional, pinned `iss`
//	scopes:       [openid, profile, email]
//	redirectUrl:  https://app.example.com/oauth2/callback
//	mountPrefix:  /oauth2/                   # optional, default /oauth2/
//	upstreamHeader: X-Auth-Subject           # optional, set on Decision
//	postLoginPath:  /                        # default rd on /oauth2/start
//	postLogoutPath: /                        # default rd on /oauth2/logout
//	cookie:
//	  name:    _lwauth_session
//	  secret:  <hex 32+ bytes>
//	  maxAge:  8h
//	  secure:  false                         # set true in prod
type Config struct {
	ClientID       string   `yaml:"clientId" json:"clientId"`
	ClientSecret   string   `yaml:"clientSecret" json:"clientSecret"`
	AuthURL        string   `yaml:"authUrl" json:"authUrl"`
	TokenURL       string   `yaml:"tokenUrl" json:"tokenUrl"`
	JWKSURL        string   `yaml:"jwksUrl" json:"jwksUrl"`
	IssuerURL      string   `yaml:"issuerUrl" json:"issuerUrl"`
	Scopes         []string `yaml:"scopes" json:"scopes"`
	RedirectURL    string   `yaml:"redirectUrl" json:"redirectUrl"`
	MountPrefix    string   `yaml:"mountPrefix" json:"mountPrefix"`
	UpstreamHeader string   `yaml:"upstreamHeader" json:"upstreamHeader"`
	PostLoginPath  string   `yaml:"postLoginPath" json:"postLoginPath"`
	PostLogoutPath string   `yaml:"postLogoutPath" json:"postLogoutPath"`

	// EndSessionURL is the IdP's RP-initiated logout endpoint
	// (OIDC RP-Initiated Logout 1.0). When set, /oauth2/logout 302s to
	// `endSessionUrl?id_token_hint=<idt>&post_logout_redirect_uri=<rd>`.
	EndSessionURL string `yaml:"endSessionUrl" json:"endSessionUrl"`

	// DeviceAuthURL is the IdP's RFC 8628 device authorization endpoint.
	// When set, /oauth2/device/start and /oauth2/device/poll are
	// available. The token exchange reuses [Config.TokenURL].
	DeviceAuthURL string `yaml:"deviceAuthUrl" json:"deviceAuthUrl"`

	// RefreshLeeway is how close to access-token expiry we proactively
	// rotate via the refresh_token. Empty/zero disables refresh.
	RefreshLeeway string `yaml:"refreshLeeway" json:"refreshLeeway"`

	// AllowedRedirectHosts is the optional allow-list of absolute hosts
	// (and optional port) the `rd` query parameter on /oauth2/start may
	// point at. When empty (the default), only relative paths beginning
	// with `/` (and not `//`) are accepted; everything else is silently
	// rewritten to PostLoginPath. This is the open-redirect defense:
	// without it an attacker could craft
	// /oauth2/start?rd=https://evil.example/ and use the legitimate
	// login flow as a phishing redirect.
	AllowedRedirectHosts []string `yaml:"allowedRedirectHosts" json:"allowedRedirectHosts"`

	Cookie CookieConfig `yaml:"cookie" json:"cookie"`
}

// CookieConfig configures the session cookie. Mirrors session.CookieStoreConfig
// but YAML-friendly (strings instead of *bool / time.Duration).
type CookieConfig struct {
	Name     string `yaml:"name" json:"name"`
	Secret   string `yaml:"secret" json:"secret"`
	Domain   string `yaml:"domain" json:"domain"`
	Path     string `yaml:"path" json:"path"`
	MaxAge   string `yaml:"maxAge" json:"maxAge"`
	Secure   *bool  `yaml:"secure" json:"secure"`
	SameSite string `yaml:"sameSite" json:"sameSite"`
	HTTPOnly *bool  `yaml:"httpOnly" json:"httpOnly"`
}

// identifier is the oauth2 module's runtime state. It satisfies
// module.Identifier and module.HTTPMounter.
type identifier struct {
	name           string
	mountPrefix    string
	upstreamHeader string
	postLogin      string
	postLogout     string
	endSessionURL  string
	refreshLeeway  time.Duration
	deviceAuthURL  string

	// allowedRedirectHosts gates the `rd` query parameter against an
	// operator-defined allow-list. Empty -> only relative paths.
	allowedRedirectHosts map[string]struct{}

	oauth      *oauth2.Config
	keyset     jwk.Set
	flowCookie *session.CookieStore // short-lived state+PKCE cookie
	store      *session.CookieStore // long-lived session cookie
	now        func() time.Time
	provider   string

	// httpClient is used for outbound IdP calls (device authorization,
	// token endpoint). Bounded by clientTimeout so a misbehaving IdP
	// can't hang the device-poll path. Tests override this via the
	// package-private withHTTPClient hook.
	httpClient       *http.Client
	maxResponseBytes int64

	jwtParseOpts []jwtlib.ParseOption
}

// Compile-time guards.
var (
	_ module.Identifier = (*identifier)(nil)
	_ module.HTTPMounter = (*identifier)(nil)
)

func (i *identifier) Name() string         { return i.name }
func (i *identifier) MountPrefix() string  { return i.mountPrefix }

// Identify resolves the encrypted session cookie. Absent / tampered
// cookies translate to ErrNoMatch so other identifiers may still match.
func (i *identifier) Identify(_ context.Context, r *module.Request) (*module.Identity, error) {
	s, _ := i.store.Load(reqFromHeaders(r.Headers))
	if s == nil {
		return nil, module.ErrNoMatch
	}
	id := &module.Identity{
		Subject: s.Subject,
		Claims:  s.Claims,
		Source:  i.name,
	}
	if id.Claims == nil {
		id.Claims = map[string]any{}
	}
	if s.Email != "" {
		id.Claims["email"] = s.Email
	}
	return id, nil
}

// reqFromHeaders builds a synthetic *http.Request just so we can reuse
// http.Request.Cookie() / session.CookieStore.Load. Header keys are
// canonicalised so lowercase Envoy headers still resolve.
func reqFromHeaders(h map[string][]string) *http.Request {
	hdr := make(http.Header, len(h))
	for k, vs := range h {
		for _, v := range vs {
			hdr.Add(k, v)
		}
	}
	return &http.Request{Header: hdr}
}

func newIdentifier(name string, cfg Config) (*identifier, error) {
	if cfg.ClientID == "" || cfg.AuthURL == "" || cfg.TokenURL == "" || cfg.JWKSURL == "" {
		return nil, fmt.Errorf("%w: oauth2: clientId, authUrl, tokenUrl, jwksUrl are required", module.ErrConfig)
	}
	if cfg.RedirectURL == "" {
		return nil, fmt.Errorf("%w: oauth2: redirectUrl is required", module.ErrConfig)
	}
	if cfg.MountPrefix == "" {
		cfg.MountPrefix = "/oauth2/"
	}
	if cfg.PostLoginPath == "" {
		cfg.PostLoginPath = "/"
	}
	if cfg.PostLogoutPath == "" {
		cfg.PostLogoutPath = "/"
	}
	if len(cfg.Scopes) == 0 {
		cfg.Scopes = []string{"openid", "profile", "email"}
	}

	store, err := buildCookieStore(cfg.Cookie, "_lwauth_session", 8*time.Hour)
	if err != nil {
		return nil, fmt.Errorf("%w: oauth2 session cookie: %v", module.ErrConfig, err)
	}
	flowName := "_lwauth_oauth2_flow"
	flow, err := buildCookieStoreNamed(cfg.Cookie, flowName, 10*time.Minute)
	if err != nil {
		return nil, fmt.Errorf("%w: oauth2 flow cookie: %v", module.ErrConfig, err)
	}

	cache := jwk.NewCache(context.Background())
	if err := cache.Register(cfg.JWKSURL); err != nil {
		return nil, fmt.Errorf("%w: oauth2 jwks register: %v", module.ErrConfig, err)
	}
	// Bound the initial JWKS fetch so a blackholed IdP cannot stall
	// startup. See pkg/identity/jwt for the longer-form rationale;
	// same deadline used here.
	refreshCtx, refreshCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer refreshCancel()
	if _, err := cache.Refresh(refreshCtx, cfg.JWKSURL); err != nil {
		return nil, fmt.Errorf("%w: oauth2 jwks fetch %s: %v", module.ErrUpstream, cfg.JWKSURL, err)
	}
	keyset := jwk.NewCachedSet(cache, cfg.JWKSURL)

	parseOpts := []jwtlib.ParseOption{
		jwtlib.WithKeySet(keyset),
		jwtlib.WithValidate(true),
	}
	if cfg.IssuerURL != "" {
		parseOpts = append(parseOpts, jwtlib.WithIssuer(cfg.IssuerURL))
	}
	parseOpts = append(parseOpts, jwtlib.WithAudience(cfg.ClientID))

	var leeway time.Duration
	if cfg.RefreshLeeway != "" {
		d, err := time.ParseDuration(cfg.RefreshLeeway)
		if err != nil {
			return nil, fmt.Errorf("%w: oauth2.refreshLeeway: %v", module.ErrConfig, err)
		}
		leeway = d
	}

	return &identifier{
		name:           name,
		mountPrefix:    cfg.MountPrefix,
		upstreamHeader: cfg.UpstreamHeader,
		postLogin:      cfg.PostLoginPath,
		postLogout:     cfg.PostLogoutPath,
		endSessionURL:  cfg.EndSessionURL,
		refreshLeeway:  leeway,
		deviceAuthURL:  cfg.DeviceAuthURL,
		allowedRedirectHosts: buildAllowedHosts(cfg.AllowedRedirectHosts),
		oauth: &oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			Endpoint:     oauth2.Endpoint{AuthURL: cfg.AuthURL, TokenURL: cfg.TokenURL},
			RedirectURL:  cfg.RedirectURL,
			Scopes:       cfg.Scopes,
		},
		keyset:           keyset,
		flowCookie:       flow,
		store:            store,
		now:              time.Now,
		provider:         name,
		httpClient:       &http.Client{Timeout: 30 * time.Second},
		maxResponseBytes: 1 << 20, // 1 MiB cap on IdP responses.
		jwtParseOpts:     parseOpts,
	}, nil
}

func factory(name string, raw map[string]any) (module.Identifier, error) {
	cfg, err := parseConfig(raw)
	if err != nil {
		return nil, err
	}
	return newIdentifier(name, cfg)
}

// RevocationKeys implements module.RevocationChecker for the OAuth2 identifier.
// It derives keys from the session ID (sid) and the identity's subject.
func (i *identifier) RevocationKeys(id *module.Identity, tenantID string) []string {
	if id == nil {
		return nil
	}
	var keys []string

	// Key by session ID — revokes a specific OAuth2 session.
	if sid, ok := id.Claims["sid"].(string); ok && sid != "" {
		keys = append(keys, "sid:"+sid)
	}

	// Key by subject — revokes ALL sessions for this user (logout everywhere).
	if id.Subject != "" {
		prefix := "sub:"
		if tenantID != "" {
			prefix += tenantID + ":"
		}
		keys = append(keys, prefix+id.Subject)
	}

	return keys
}

func init() { module.RegisterIdentifier("oauth2", factory) }
