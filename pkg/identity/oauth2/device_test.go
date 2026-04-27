package oauth2_test

import (
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	jwtlib "github.com/lestrrat-go/jwx/v2/jwt"

	"github.com/mikeappsec/lightweightauth/internal/config"
	"github.com/mikeappsec/lightweightauth/internal/server"
)

// deviceFakeIDP is a minimal RFC 8628 IdP layered on top of the same
// signing key + JWKS used by fakeIDP. It tracks one outstanding
// (device_code, user_code) pair and a "user has approved" flag the test
// can flip to simulate the user completing verification.
type deviceFakeIDP struct {
	*fakeIDP
	mu          sync.Mutex
	deviceCode  string
	userCode    string
	approved    bool
	pollHits    atomic.Int64
	failSlowDow bool
}

func newDeviceFakeIDP(t *testing.T, clientID string) *deviceFakeIDP {
	t.Helper()
	d := &deviceFakeIDP{fakeIDP: newFakeIDP(t, clientID)}
	// Replace the existing token handler so we can branch on grant_type.
	mux := http.NewServeMux()
	mux.HandleFunc("/authorize", d.fakeIDP.handleAuthorize)
	mux.HandleFunc("/jwks", d.fakeIDP.handleJWKS)
	mux.HandleFunc("/device_authorization", d.handleDeviceAuth)
	mux.HandleFunc("/token", d.handleTokenWithDevice)
	d.srv.Config.Handler = mux
	return d
}

func (d *deviceFakeIDP) handleDeviceAuth(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	d.mu.Lock()
	d.deviceCode = "dev-" + time.Now().Format("150405.000")
	d.userCode = "WDJB-MJHT"
	d.approved = false
	d.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"device_code":               d.deviceCode,
		"user_code":                 d.userCode,
		"verification_uri":          d.srv.URL + "/verify",
		"verification_uri_complete": d.srv.URL + "/verify?user_code=" + d.userCode,
		"expires_in":                900,
		"interval":                  1,
	})
}

func (d *deviceFakeIDP) handleTokenWithDevice(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	gt := r.PostForm.Get("grant_type")
	if gt != deviceCodeGrantType {
		// Fall back to the auth-code handler from fakeIDP.
		d.fakeIDP.handleToken(w, r)
		return
	}
	d.pollHits.Add(1)
	dc := r.PostForm.Get("device_code")
	d.mu.Lock()
	expected := d.deviceCode
	approved := d.approved
	slow := d.failSlowDow
	d.failSlowDow = false
	d.mu.Unlock()
	if dc != expected {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "expired_token"})
		return
	}
	if slow {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "slow_down"})
		return
	}
	if !approved {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "authorization_pending"})
		return
	}
	tok, _ := jwtlib.NewBuilder().
		Issuer(d.srv.URL).
		Subject("device-bob").
		Audience([]string{d.clientID}).
		IssuedAt(time.Now()).
		Expiration(time.Now().Add(5 * time.Minute)).
		Claim("email", "bob@example.com").
		Claim("groups", []string{"admin"}).
		Build()
	signed, _ := jwtlib.Sign(tok, jwtlib.WithKey(jwa.RS256, d.signKey))
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"access_token":  "at-device",
		"refresh_token": "rt-device",
		"id_token":      string(signed),
		"token_type":    "Bearer",
		"expires_in":    3600,
	})
}

// bootLwauthWithDevice adds deviceAuthUrl to the AuthConfig so the device
// routes are mounted.
func bootLwauthWithDevice(t *testing.T, idp *deviceFakeIDP) *httptest.Server {
	t.Helper()
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
				"deviceAuthUrl": idp.URL() + "/device_authorization",
				"jwksUrl":       idp.URL() + "/jwks",
				"issuerUrl":     idp.URL(),
				"redirectUrl":   baseURL + "/oauth2/callback",
				"scopes":        []any{"openid", "email"},
				"cookie": map[string]any{
					"secret": "0123456789abcdef0123456789abcdef",
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

// TestOAuth2_DeviceFlow_HappyPath exercises /oauth2/device/start →
// /oauth2/device/poll (pending → slow_down → success) and verifies the
// resulting session is identical to an auth-code login.
func TestOAuth2_DeviceFlow_HappyPath(t *testing.T) {
	t.Parallel()
	idp := newDeviceFakeIDP(t, "test-client")
	lw := bootLwauthWithDevice(t, idp)

	jar, _ := cookiejar.New(nil)
	cli := &http.Client{Jar: jar}

	// 1. /oauth2/device/start → JSON with device_code + user_code.
	resp, err := cli.Post(lw.URL+"/oauth2/device/start", "", nil)
	if err != nil {
		t.Fatalf("device/start: %v", err)
	}
	var startBody map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&startBody)
	_ = resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("device/start status = %d, want 200", resp.StatusCode)
	}
	deviceCode, _ := startBody["device_code"].(string)
	if deviceCode == "" || startBody["user_code"] == "" {
		t.Fatalf("device/start body missing codes: %+v", startBody)
	}

	poll := func() (int, map[string]any) {
		body, _ := json.Marshal(map[string]string{"device_code": deviceCode})
		r, err := cli.Post(lw.URL+"/oauth2/device/poll", "application/json", strings.NewReader(string(body)))
		if err != nil {
			t.Fatalf("device/poll: %v", err)
		}
		defer r.Body.Close()
		var b map[string]any
		_ = json.NewDecoder(r.Body).Decode(&b)
		return r.StatusCode, b
	}

	// 2. First poll → 202 authorization_pending.
	if status, body := poll(); status != http.StatusAccepted || body["error"] != "authorization_pending" {
		t.Fatalf("poll #1: status=%d body=%+v, want 202 authorization_pending", status, body)
	}

	// 3. Force slow_down once.
	idp.mu.Lock()
	idp.failSlowDow = true
	idp.mu.Unlock()
	if status, body := poll(); status != http.StatusAccepted || body["error"] != "slow_down" {
		t.Fatalf("poll #2: status=%d body=%+v, want 202 slow_down", status, body)
	}

	// 4. User approves → next poll succeeds.
	idp.mu.Lock()
	idp.approved = true
	idp.mu.Unlock()
	status, body := poll()
	if status != 200 {
		t.Fatalf("poll #3 status=%d body=%+v, want 200", status, body)
	}
	if body["subject"] != "device-bob" {
		t.Fatalf("poll #3 subject=%v, want device-bob", body["subject"])
	}

	// 5. /oauth2/userinfo now reflects bob — proves Set-Cookie landed.
	resp, err = cli.Get(lw.URL + "/oauth2/userinfo")
	if err != nil {
		t.Fatalf("userinfo: %v", err)
	}
	var info map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&info)
	_ = resp.Body.Close()
	if info["subject"] != "device-bob" || info["email"] != "bob@example.com" {
		t.Errorf("userinfo = %+v, want device-bob/bob@example.com", info)
	}
}

// TestOAuth2_DeviceFlow_RoutesUnmounted asserts that without
// `deviceAuthUrl` the device routes are not mounted (so accidental
// configurations don't expose half-wired endpoints).
func TestOAuth2_DeviceFlow_RoutesUnmounted(t *testing.T) {
	t.Parallel()
	idp := newFakeIDP(t, "test-client")
	lw := bootLwauth(t, idp) // no deviceAuthUrl
	resp, err := http.Post(lw.URL+"/oauth2/device/start", "", nil)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status=%d, want 404 when device flow is not configured", resp.StatusCode)
	}
}

// deviceCodeGrantType is duplicated here so the test does not import the
// internal-only constant from package oauth2.
const deviceCodeGrantType = "urn:ietf:params:oauth:grant-type:device_code"
