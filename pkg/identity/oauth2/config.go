// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/mikeappsec/lightweightauth/pkg/module"
	"github.com/mikeappsec/lightweightauth/pkg/session"
)

// parseConfig converts a free-form YAML map into a typed Config. We do
// our own walking so the same shape works whether the operator writes it
// in YAML (yaml.v3 → map[string]any) or via the K8s CRD JSON schema.
func parseConfig(raw map[string]any) (Config, error) {
	c := Config{}
	getString := func(k string) string {
		v, _ := raw[k].(string)
		return v
	}
	c.ClientID = getString("clientId")
	c.ClientSecret = getString("clientSecret")
	c.AuthURL = getString("authUrl")
	c.TokenURL = getString("tokenUrl")
	c.JWKSURL = getString("jwksUrl")
	c.IssuerURL = getString("issuerUrl")
	c.RedirectURL = getString("redirectUrl")
	c.MountPrefix = getString("mountPrefix")
	c.UpstreamHeader = getString("upstreamHeader")
	c.PostLoginPath = getString("postLoginPath")
	c.PostLogoutPath = getString("postLogoutPath")
	c.EndSessionURL = getString("endSessionUrl")
	c.RefreshLeeway = getString("refreshLeeway")
	c.DeviceAuthURL = getString("deviceAuthUrl")
	if v, ok := raw["scopes"].([]any); ok {
		for _, s := range v {
			if s2, ok := s.(string); ok {
				c.Scopes = append(c.Scopes, s2)
			}
		}
	}
	if v, ok := raw["allowedRedirectHosts"].([]any); ok {
		for _, s := range v {
			if s2, ok := s.(string); ok && s2 != "" {
				c.AllowedRedirectHosts = append(c.AllowedRedirectHosts, s2)
			}
		}
	}
	if cm, ok := raw["cookie"].(map[string]any); ok {
		c.Cookie.Name, _ = cm["name"].(string)
		c.Cookie.Secret, _ = cm["secret"].(string)
		c.Cookie.Domain, _ = cm["domain"].(string)
		c.Cookie.Path, _ = cm["path"].(string)
		c.Cookie.MaxAge, _ = cm["maxAge"].(string)
		c.Cookie.SameSite, _ = cm["sameSite"].(string)
		if b, ok := cm["secure"].(bool); ok {
			c.Cookie.Secure = &b
		}
		if b, ok := cm["httpOnly"].(bool); ok {
			c.Cookie.HTTPOnly = &b
		}
	}
	if c.Cookie.Secret == "" {
		return c, fmt.Errorf("%w: oauth2.cookie.secret is required", module.ErrConfig)
	}
	return c, nil
}

// buildCookieStore returns the long-lived session cookie store for the
// "logged in" state. defaultName / defaultMaxAge apply when cfg leaves
// them blank.
func buildCookieStore(cfg CookieConfig, defaultName string, defaultMaxAge time.Duration) (*session.CookieStore, error) {
	name := cfg.Name
	if name == "" {
		name = defaultName
	}
	return buildCookieStoreNamed(cfg, name, defaultMaxAge)
}

// buildCookieStoreNamed forces the cookie name (used to mint the
// short-lived flow cookie under a distinct name without interfering with
// the user-configured session cookie name).
func buildCookieStoreNamed(cfg CookieConfig, name string, defaultMaxAge time.Duration) (*session.CookieStore, error) {
	maxAge := defaultMaxAge
	if cfg.MaxAge != "" && name == cfg.Name {
		// Only the long-lived session honours the user MaxAge; the flow
		// cookie keeps its built-in 10-minute default.
		d, err := time.ParseDuration(cfg.MaxAge)
		if err != nil {
			return nil, fmt.Errorf("cookie.maxAge: %v", err)
		}
		maxAge = d
	}
	sc := session.CookieStoreConfig{
		Name:     name,
		Secret:   []byte(cfg.Secret),
		Domain:   cfg.Domain,
		Path:     cfg.Path,
		MaxAge:   maxAge,
		Secure:   cfg.Secure,
		HTTPOnly: cfg.HTTPOnly,
		SameSite: parseSameSite(cfg.SameSite),
	}
	return session.NewCookieStore(sc)
}

func parseSameSite(s string) http.SameSite {
	switch strings.ToLower(s) {
	case "strict":
		return http.SameSiteStrictMode
	case "none":
		return http.SameSiteNoneMode
	case "", "lax":
		return http.SameSiteLaxMode
	default:
		return http.SameSiteDefaultMode
	}
}
