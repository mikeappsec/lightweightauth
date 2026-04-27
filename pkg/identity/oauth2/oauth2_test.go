package oauth2_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	jwtlib "github.com/lestrrat-go/jwx/v2/jwt"

	"github.com/yourorg/lightweightauth/internal/config"
	"github.com/yourorg/lightweightauth/internal/server"
	"github.com/yourorg/lightweightauth/pkg/module"

	_ "github.com/yourorg/lightweightauth/pkg/builtins"
)

// fakeIDP is a minimal OIDC-ish IdP supporting just the bits the auth-code
// flow needs: an /authorize that auto-approves and bounces back with a
// short-lived code, a /token endpoint that mints an id_token signed with
// our test RSA key, and a /jwks endpoint.
type fakeIDP struct {
	srv      *httptest.Server
	signKey  jwk.Key
	clientID string

	// codes maps single-use auth codes to the PKCE challenge + expected
	// redirect_uri the client posted at /authorize. Cleared on use.
	codes map[string]codeRecord
}

type codeRecord struct {
	codeChallenge string
	redirectURI   string
}

func newFakeIDP(t *testing.T, clientID string) *fakeIDP {
	t.Helper()
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa: %v", err)
	}
	priv, _ := jwk.FromRaw(rsaKey)
	_ = priv.Set(jwk.KeyIDKey, "kid-1")
	_ = priv.Set(jwk.AlgorithmKey, jwa.RS256)

	idp := &fakeIDP{signKey: priv, clientID: clientID, codes: map[string]codeRecord{}}

	mux := http.NewServeMux()
	mux.HandleFunc("/authorize", idp.handleAuthorize)
	mux.HandleFunc("/token", idp.handleToken)
	mux.HandleFunc("/jwks", idp.handleJWKS)
	idp.srv = httptest.NewServer(mux)
	t.Cleanup(idp.srv.Close)
	return idp
}

func (i *fakeIDP) URL() string { return i.srv.URL }

func (i *fakeIDP) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	rd := q.Get("redirect_uri")
	state := q.Get("state")
	cc := q.Get("code_challenge")
	if cc == "" || rd == "" || q.Get("response_type") != "code" {
		http.Error(w, "bad authorize", http.StatusBadRequest)
		return
	}
	code := "code-" + state
	i.codes[code] = codeRecord{codeChallenge: cc, redirectURI: rd}
	u, _ := url.Parse(rd)
	qq := u.Query()
	qq.Set("code", code)
	qq.Set("state", state)
	u.RawQuery = qq.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func (i *fakeIDP) handleToken(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	code := r.PostForm.Get("code")
	verifier := r.PostForm.Get("code_verifier")
	rec, ok := i.codes[code]
	if !ok {
		http.Error(w, "unknown code", http.StatusBadRequest)
		return
	}
	delete(i.codes, code)
	if rec.redirectURI != r.PostForm.Get("redirect_uri") {
		http.Error(w, "redirect_uri mismatch", http.StatusBadRequest)
		return
	}
	// Verify PKCE.
	sum := sha256.Sum256([]byte(verifier))
	want := base64.RawURLEncoding.EncodeToString(sum[:])
	if want != rec.codeChallenge {
		http.Error(w, "pkce mismatch", http.StatusBadRequest)
		return
	}

	tok, _ := jwtlib.NewBuilder().
		Issuer(i.srv.URL).
		Subject("alice").
		Audience([]string{i.clientID}).
		IssuedAt(time.Now()).
		Expiration(time.Now().Add(5 * time.Minute)).
		Claim("email", "alice@example.com").
		Claim("groups", []string{"admin"}).
		Build()
	signed, err := jwtlib.Sign(tok, jwtlib.WithKey(jwa.RS256, i.signKey))
	if err != nil {
		http.Error(w, "sign: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"access_token": "at-" + code,
		"id_token":     string(signed),
		"token_type":   "Bearer",
		"expires_in":   3600,
	})
}

func (i *fakeIDP) handleJWKS(w http.ResponseWriter, _ *http.Request) {
	pub, _ := jwk.PublicKeyOf(i.signKey)
	_ = pub.Set(jwk.KeyIDKey, "kid-1")
	_ = pub.Set(jwk.AlgorithmKey, jwa.RS256)
	set := jwk.NewSet()
	_ = set.AddKey(pub)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(set)
}

// bootLwauth compiles an AuthConfig that pairs the oauth2 identifier with
// rbac, then exposes lwauth's HTTP handler over httptest. The httptest
// server is created unstarted so we can pre-compute its URL for the
// AuthConfig's redirectUrl, then start it.
func bootLwauth(t *testing.T, idp *fakeIDP) *httptest.Server {
	t.Helper()
	insecure := false
	srv := httptest.NewUnstartedServer(nil)
	addr := srv.Listener.Addr().String()
	baseURL := "http://" + addr

	ac := &config.AuthConfig{
		Identifier: config.IdentifierFirstMatch,
		Identifiers: []config.ModuleSpec{{
			Name: "corp-oauth",
			Type: "oauth2",
			Config: map[string]any{
				"clientId":      "test-client",
				"clientSecret":  "test-secret",
				"authUrl":       idp.URL() + "/authorize",
				"tokenUrl":      idp.URL() + "/token",
				"jwksUrl":       idp.URL() + "/jwks",
				"issuerUrl":     idp.URL(),
				"redirectUrl":   baseURL + "/oauth2/callback",
				"postLoginPath": "/protected",
				"scopes":        []any{"openid", "email"},
				"cookie": map[string]any{
					"secret": "0123456789abcdef0123456789abcdef",
					"secure": insecure,
					"maxAge": "1h",
				},
			},
		}},
		Authorizers: []config.ModuleSpec{{
			Name: "rbac",
			Type: "rbac",
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

// TestOAuth2_FullFlow exercises /oauth2/start → IdP /authorize → IdP
// /token → /oauth2/callback → /oauth2/userinfo → /v1/authorize all the
// way through, using a real net/http client + cookie jar.
func TestOAuth2_FullFlow(t *testing.T) {
	t.Parallel()
	idp := newFakeIDP(t, "test-client")

	lw := bootLwauth(t, idp)

	jar, _ := cookiejar.New(nil)
	httpcli := &http.Client{
		Jar: jar,
		// We want to follow redirects ourselves so we can inspect the
		// auth URL, but for simplicity let cookiejar collect everything
		// and just verify the end-state.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	// 1. Hit /oauth2/start — should bounce through IdP and land at /protected.
	resp, err := httpcli.Get(lw.URL + "/oauth2/start?rd=/protected")
	if err != nil {
		t.Fatalf("GET start: %v", err)
	}
	_ = resp.Body.Close()
	if got := resp.Request.URL.Path; got != "/protected" {
		t.Fatalf("after flow, landed at %q, want /protected", got)
	}

	// 2. /oauth2/userinfo should now reflect alice.
	resp, err = httpcli.Get(lw.URL + "/oauth2/userinfo")
	if err != nil {
		t.Fatalf("GET userinfo: %v", err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	if resp.StatusCode != 200 {
		t.Fatalf("userinfo status = %d, want 200", resp.StatusCode)
	}
	var info map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&info)
	if info["subject"] != "alice" || info["email"] != "alice@example.com" {
		t.Errorf("userinfo = %+v, want alice/alice@example.com", info)
	}

	// 3. /v1/authorize with the same cookie jar → 200.
	body := strings.NewReader(`{"method":"GET","path":"/things"}`)
	req, _ := http.NewRequestWithContext(context.Background(), "POST", lw.URL+"/v1/authorize", body)
	req.Header.Set("Content-Type", "application/json")
	// Replay session cookie manually because /v1/authorize doesn't read
	// cookies — the OAuth2 identifier reads cookies out of the JSON body's
	// headers map, so we forward the cookie that way.
	cookies := jar.Cookies(req.URL)
	cookieHeader := ""
	for _, c := range cookies {
		if cookieHeader != "" {
			cookieHeader += "; "
		}
		cookieHeader += c.Name + "=" + c.Value
	}
	body2, _ := json.Marshal(map[string]any{
		"method":  "GET",
		"path":    "/things",
		"headers": map[string][]string{"Cookie": {cookieHeader}},
	})
	req2, _ := http.NewRequest("POST", lw.URL+"/v1/authorize", strings.NewReader(string(body2)))
	req2.Header.Set("Content-Type", "application/json")
	resp2, err := httpcli.Do(req2)
	if err != nil {
		t.Fatalf("POST authorize: %v", err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != 200 {
		var b map[string]any
		_ = json.NewDecoder(resp2.Body).Decode(&b)
		t.Fatalf("authorize status = %d, body=%v, want 200", resp2.StatusCode, b)
	}

	// 4. Logout clears the cookie. /oauth2/userinfo should now 401.
	resp3, err := httpcli.Get(lw.URL + "/oauth2/logout")
	if err != nil {
		t.Fatalf("GET logout: %v", err)
	}
	_ = resp3.Body.Close()

	resp4, err := httpcli.Get(lw.URL + "/oauth2/userinfo")
	if err != nil {
		t.Fatalf("GET userinfo after logout: %v", err)
	}
	t.Cleanup(func() { _ = resp4.Body.Close() })
	if resp4.StatusCode != http.StatusUnauthorized {
		t.Fatalf("userinfo after logout status = %d, want 401", resp4.StatusCode)
	}
}

// TestOAuth2_NoSessionIsNoMatch verifies the identifier returns
// ErrNoMatch (so other identifiers may try) when no cookie is present.
func TestOAuth2_NoSessionIsNoMatch(t *testing.T) {
	t.Parallel()
	idp := newFakeIDP(t, "test-client")
	lw := bootLwauth(t, idp)
	_ = lw // already cleaned up via t.Cleanup inside bootLwauth

	resp, err := http.Post(lw.URL+"/v1/authorize", "application/json",
		strings.NewReader(`{"method":"GET","path":"/things"}`))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (no identifier matched)", resp.StatusCode)
	}
}

// silence unused
var _ = module.ErrNoMatch
