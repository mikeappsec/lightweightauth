// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package oauth2_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	jwtlib "github.com/lestrrat-go/jwx/v2/jwt"

	"github.com/mikeappsec/lightweightauth/internal/config"
	"github.com/mikeappsec/lightweightauth/internal/server"
)

// refreshIDP is a tiny IdP that records the number of /token calls and
// supports both the auth-code grant (one-shot, returns a refresh_token)
// and the refresh_token grant (rotates the access_token).
type refreshIDP struct {
	srv      *httptest.Server
	signKey  jwk.Key
	clientID string
	codes    map[string]string // code -> redirect_uri

	tokenCalls   int32
	refreshCalls int32
}

func newRefreshIDP(t *testing.T, clientID string) *refreshIDP {
	t.Helper()
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa: %v", err)
	}
	priv, _ := jwk.FromRaw(rsaKey)
	_ = priv.Set(jwk.KeyIDKey, "kid-1")
	_ = priv.Set(jwk.AlgorithmKey, jwa.RS256)
	idp := &refreshIDP{signKey: priv, clientID: clientID, codes: map[string]string{}}

	mux := http.NewServeMux()
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		code := "code-" + q.Get("state")
		idp.codes[code] = q.Get("redirect_uri")
		u, _ := url.Parse(q.Get("redirect_uri"))
		qq := u.Query()
		qq.Set("code", code)
		qq.Set("state", q.Get("state"))
		u.RawQuery = qq.Encode()
		http.Redirect(w, r, u.String(), http.StatusFound)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		grant := r.PostForm.Get("grant_type")
		w.Header().Set("Content-Type", "application/json")

		// Build a fresh id_token + access_token suffix per call so we
		// can tell the test that rotation happened.
		mintIDT := func(kind string) string {
			tok, _ := jwtlib.NewBuilder().
				Issuer(idp.srv.URL).
				Subject("alice").
				Audience([]string{idp.clientID}).
				IssuedAt(time.Now()).
				Expiration(time.Now().Add(5 * time.Minute)).
				Claim("email", "alice@example.com").
				Claim("groups", []string{"admin"}).
				Claim("kind", kind).
				Build()
			s, _ := jwtlib.Sign(tok, jwtlib.WithKey(jwa.RS256, idp.signKey))
			return string(s)
		}

		switch grant {
		case "authorization_code":
			n := atomic.AddInt32(&idp.tokenCalls, 1)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token":  "at-initial",
				"refresh_token": "rt-1",
				"id_token":      mintIDT("initial"),
				"token_type":    "Bearer",
				// Tiny lifetime so refreshIfNeeded triggers on the next request.
				"expires_in": 1,
			})
			_ = n
		case "refresh_token":
			n := atomic.AddInt32(&idp.refreshCalls, 1)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token":  "at-rotated",
				"refresh_token": "rt-2",
				"id_token":      mintIDT("rotated"),
				"token_type":    "Bearer",
				"expires_in":    3600,
			})
			_ = n
		default:
			http.Error(w, "bad grant", http.StatusBadRequest)
		}
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		pub, _ := jwk.PublicKeyOf(idp.signKey)
		_ = pub.Set(jwk.KeyIDKey, "kid-1")
		_ = pub.Set(jwk.AlgorithmKey, jwa.RS256)
		set := jwk.NewSet()
		_ = set.AddKey(pub)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(set)
	})
	idp.srv = httptest.NewServer(mux)
	t.Cleanup(idp.srv.Close)
	return idp
}

func bootRefreshLwauth(t *testing.T, idp *refreshIDP, endSessionURL string) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(nil)
	addr := srv.Listener.Addr().String()
	baseURL := "http://" + addr

	cfg := map[string]any{
		"clientId":      "test-client",
		"clientSecret":  "test-secret",
		"authUrl":       idp.srv.URL + "/authorize",
		"tokenUrl":      idp.srv.URL + "/token",
		"jwksUrl":       idp.srv.URL + "/jwks",
		"issuerUrl":     idp.srv.URL,
		"redirectUrl":   baseURL + "/oauth2/callback",
		"postLoginPath": "/protected",
		"refreshLeeway": "10s", // expires_in=1 → always inside the leeway
		"scopes":        []any{"openid", "email"},
		"cookie": map[string]any{
			"secret": "0123456789abcdef0123456789abcdef",
			"secure": false,
			"maxAge": "1h",
		},
	}
	if endSessionURL != "" {
		cfg["endSessionUrl"] = endSessionURL
	}

	ac := &config.AuthConfig{
		Identifier: config.IdentifierFirstMatch,
		Identifiers: []config.ModuleSpec{{
			Name: "corp", Type: "oauth2", Config: cfg,
		}},
		Authorizers: []config.ModuleSpec{{
			Name: "rbac", Type: "rbac",
			Config: map[string]any{
				"rolesFrom": "claim:groups",
				"allow":     []any{"admin"},
			},
		}},
	}
	eng, err := config.Compile(ac)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	holder := server.NewEngineHolder(eng)
	srv.Config.Handler = server.NewHTTPHandler(holder)
	srv.Start()
	t.Cleanup(srv.Close)
	return srv
}

// TestOAuth2_RefreshOnUserInfo proves that hitting /oauth2/userinfo when
// the access token is past RefreshLeeway transparently rotates tokens
// via the refresh_token grant.
func TestOAuth2_RefreshOnUserInfo(t *testing.T) {
	t.Parallel()
	idp := newRefreshIDP(t, "test-client")
	lw := bootRefreshLwauth(t, idp, "")

	jar, _ := cookiejar.New(nil)
	cli := &http.Client{Jar: jar}

	// Boot the session via the full auth-code flow.
	resp, err := cli.Get(lw.URL + "/oauth2/start?rd=/protected")
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	_ = resp.Body.Close()

	// expires_in=1 + refreshLeeway=10s ⇒ next /userinfo MUST refresh.
	time.Sleep(50 * time.Millisecond)
	resp, err = cli.Get(lw.URL + "/oauth2/userinfo")
	if err != nil {
		t.Fatalf("userinfo: %v", err)
	}
	_ = resp.Body.Close()
	if got := atomic.LoadInt32(&idp.refreshCalls); got != 1 {
		t.Fatalf("refresh calls = %d, want 1 (opportunistic rotate failed)", got)
	}

	// Explicit /oauth2/refresh forces another rotation.
	resp, err = cli.Get(lw.URL + "/oauth2/refresh")
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("refresh status = %d", resp.StatusCode)
	}
	if got := atomic.LoadInt32(&idp.refreshCalls); got != 2 {
		t.Errorf("refresh calls after explicit = %d, want 2", got)
	}
}

// TestOAuth2_RPInitiatedLogout verifies that when endSessionUrl is set,
// /oauth2/logout 302s to the IdP with id_token_hint +
// post_logout_redirect_uri attached.
func TestOAuth2_RPInitiatedLogout(t *testing.T) {
	t.Parallel()
	idp := newRefreshIDP(t, "test-client")
	endSessionURL := idp.srv.URL + "/end-session?foo=bar"
	lw := bootRefreshLwauth(t, idp, endSessionURL)

	jar, _ := cookiejar.New(nil)
	cli := &http.Client{
		Jar: jar,
		// Don't auto-follow the IdP redirect; assert it directly.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if strings.Contains(req.URL.Path, "/end-session") {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	// Boot the session.
	if _, err := cli.Get(lw.URL + "/oauth2/start?rd=/protected"); err != nil {
		t.Fatalf("start: %v", err)
	}

	// Hit /oauth2/logout — should 302 to endSessionURL.
	req, _ := http.NewRequest(http.MethodPost, lw.URL+"/oauth2/logout", nil)
	resp, err := cli.Do(req)
	if err != nil {
		t.Fatalf("logout: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want 302", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	u, perr := url.Parse(loc)
	if perr != nil {
		t.Fatalf("parse Location: %v", perr)
	}
	if !strings.HasSuffix(u.Path, "/end-session") {
		t.Errorf("path = %q, want /end-session", u.Path)
	}
	q := u.Query()
	if q.Get("foo") != "bar" {
		t.Errorf("preserved param foo = %q", q.Get("foo"))
	}
	if q.Get("id_token_hint") == "" {
		t.Errorf("id_token_hint missing in %q", loc)
	}
	if got := q.Get("post_logout_redirect_uri"); !strings.HasPrefix(got, "http") {
		t.Errorf("post_logout_redirect_uri = %q, want absolute URL", got)
	}

	_ = context.Background()
}
