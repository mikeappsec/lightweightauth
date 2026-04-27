package clientauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// fakeIdP is a minimal RFC 6749 §4.4 token endpoint with knobs for the
// failure cases we want to assert. Returns increasing access tokens so
// tests can tell a refresh from a cache hit.
type fakeIdP struct {
	srv          *httptest.Server
	hits         atomic.Int32
	expiresIn    int
	wantStyle    AuthStyle // 0 = don't assert
	failBasic    bool      // 401 to Basic → exercises auto-detect fallback
	wantClientID string
	wantSecret   string
	wantScope    string
}

func newFakeIdP(t *testing.T) *fakeIdP {
	t.Helper()
	f := &fakeIdP{expiresIn: 60}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		if r.PostForm.Get("grant_type") != "client_credentials" {
			http.Error(w, "wrong grant", 400)
			return
		}

		// Detect which auth style the client used.
		style := AuthStyleInBody
		if u, _, ok := r.BasicAuth(); ok && u != "" {
			style = AuthStyleBasic
		}
		if f.failBasic && style == AuthStyleBasic {
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_client"})
			return
		}
		if f.wantStyle != 0 && style != f.wantStyle {
			http.Error(w, "wrong auth style", 400)
			return
		}

		// Validate creds (matter only when set).
		var gotID, gotSecret string
		if style == AuthStyleBasic {
			u, p, _ := r.BasicAuth()
			gotID, gotSecret = u, p
		} else {
			gotID = r.PostForm.Get("client_id")
			gotSecret = r.PostForm.Get("client_secret")
		}
		if f.wantClientID != "" && gotID != f.wantClientID {
			http.Error(w, "bad client id", 401)
			return
		}
		if f.wantSecret != "" && gotSecret != f.wantSecret {
			http.Error(w, "bad client secret", 401)
			return
		}
		if f.wantScope != "" && r.PostForm.Get("scope") != f.wantScope {
			http.Error(w, "bad scope", 400)
			return
		}

		n := f.hits.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "token-" + jsonInt(int(n)),
			"token_type":   "Bearer",
			"expires_in":   f.expiresIn,
			"scope":        f.wantScope,
		})
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func jsonInt(n int) string {
	if n < 0 {
		return "0"
	}
	if n == 0 {
		return "0"
	}
	out := []byte{}
	for n > 0 {
		out = append([]byte{byte('0' + n%10)}, out...)
		n /= 10
	}
	return string(out)
}

func TestClientCredentials_FetchAndCache(t *testing.T) {
	t.Parallel()
	idp := newFakeIdP(t)
	idp.wantClientID = "svc-orders"
	// URL-encoded by SetBasicAuth → matches our SetBasicAuth(url.QueryEscape(...)) on the client.
	idp.wantSecret = "p%40ss"

	src := NewClientCredentialsSource(ClientCredentialsConfig{
		TokenURL:     idp.srv.URL,
		ClientID:     "svc-orders",
		ClientSecret: "p@ss",
		Scopes:       []string{"orders.read"},
		AuthStyle:    AuthStyleBasic,
	})
	idp.wantScope = "orders.read"

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	t1, err := src.Token(ctx)
	if err != nil {
		t.Fatalf("Token #1: %v", err)
	}
	if !strings.HasPrefix(t1.AccessToken, "token-") {
		t.Errorf("unexpected access token: %q", t1.AccessToken)
	}
	// Second call: cached, no new IdP hit.
	t2, err := src.Token(ctx)
	if err != nil {
		t.Fatalf("Token #2: %v", err)
	}
	if t1.AccessToken != t2.AccessToken {
		t.Errorf("cache miss: t1=%q t2=%q", t1.AccessToken, t2.AccessToken)
	}
	if got := idp.hits.Load(); got != 1 {
		t.Errorf("IdP hits = %d, want 1", got)
	}
}

func TestClientCredentials_RefreshOnExpiry(t *testing.T) {
	t.Parallel()
	idp := newFakeIdP(t)
	idp.expiresIn = 1 // 1 second; combined with default 30s leeway → already expired

	src := NewClientCredentialsSource(ClientCredentialsConfig{
		TokenURL:     idp.srv.URL,
		ClientID:     "svc",
		ClientSecret: "x",
		AuthStyle:    AuthStyleBasic,
	})
	ctx := context.Background()

	if _, err := src.Token(ctx); err != nil {
		t.Fatalf("Token #1: %v", err)
	}
	if _, err := src.Token(ctx); err != nil {
		t.Fatalf("Token #2: %v", err)
	}
	// Each call must hit the IdP because the token is born expired.
	if got := idp.hits.Load(); got != 2 {
		t.Errorf("IdP hits = %d, want 2 (expiry-driven refresh)", got)
	}
}

func TestClientCredentials_AutoDetectFallback(t *testing.T) {
	t.Parallel()
	idp := newFakeIdP(t)
	idp.failBasic = true // forces Basic → InBody fallback

	src := NewClientCredentialsSource(ClientCredentialsConfig{
		TokenURL:     idp.srv.URL,
		ClientID:     "svc",
		ClientSecret: "x",
		AuthStyle:    AuthStyleAutoDetect,
	})
	tok, err := src.Token(context.Background())
	if err != nil {
		t.Fatalf("Token: %v", err)
	}
	if tok.AccessToken == "" {
		t.Fatalf("empty access token after fallback")
	}
}

func TestClientCredentials_HTTPClient_InjectsBearer(t *testing.T) {
	t.Parallel()
	idp := newFakeIdP(t)
	src := NewClientCredentialsSource(ClientCredentialsConfig{
		TokenURL:     idp.srv.URL,
		ClientID:     "svc",
		ClientSecret: "x",
		AuthStyle:    AuthStyleBasic,
	})

	// Upstream API: records the Authorization header it received.
	var seen string
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Get("Authorization")
		w.WriteHeader(204)
	}))
	t.Cleanup(api.Close)

	cli := src.HTTPClient(context.Background())
	resp, err := cli.Get(api.URL + "/orders")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	resp.Body.Close()
	if !strings.HasPrefix(seen, "Bearer token-") {
		t.Errorf("upstream saw Authorization = %q, want Bearer token-…", seen)
	}
}

func TestClientCredentials_ErrorPropagation(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(400)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error":             "invalid_grant",
			"error_description": "client disabled",
		})
	}))
	t.Cleanup(srv.Close)

	src := NewClientCredentialsSource(ClientCredentialsConfig{
		TokenURL: srv.URL, ClientID: "svc", ClientSecret: "x", AuthStyle: AuthStyleBasic,
	})
	_, err := src.Token(context.Background())
	if err == nil {
		t.Fatalf("expected error from invalid_grant response")
	}
	if !strings.Contains(err.Error(), "invalid_grant") {
		t.Errorf("error doesn't surface IdP code: %v", err)
	}
}
