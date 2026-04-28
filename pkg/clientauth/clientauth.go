// Package clientauth is a tiny outbound helper for service-to-service
// callers of lwauth-protected upstreams. It implements the OAuth 2.0
// Client Credentials Grant (RFC 6749 §4.4): a service exchanges its
// own clientID/clientSecret (or mTLS client cert, via the underlying
// transport) for a bearer access token at the IdP's `/token` endpoint.
//
// Why does this live in the core repo rather than alongside Door B?
// Because the *consumer* of an lwauth-protected service typically
// wants this in its own dependency tree, not the lwauth gRPC client.
// The two surfaces are independent: lwauthclient is for services
// asking lwauth "is this caller allowed?"; clientauth is for callers
// minting the bearer token that lwauth's `jwt` identifier will then
// validate (DESIGN.md §7 M6 → M8 deferral).
//
// Typical usage:
//
//	src := clientauth.NewClientCredentialsSource(clientauth.ClientCredentialsConfig{
//	    TokenURL:     "https://idp.example.com/oauth2/token",
//	    ClientID:     os.Getenv("CLIENT_ID"),
//	    ClientSecret: os.Getenv("CLIENT_SECRET"),
//	    Scopes:       []string{"orders.read"},
//	})
//
//	httpClient := src.HTTPClient(ctx)               // adds Authorization: Bearer <tok>
//	resp, err := httpClient.Get("https://orders.svc/v1/orders")
//
// The token is cached and refreshed automatically when it expires
// (with a small leeway so we don't hand out a token that's already
// expired by the time the upstream sees it).
package clientauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/mikeappsec/lightweightauth/pkg/upstream"
)

// ClientCredentialsConfig is the static side of the grant. Use mTLS to
// the IdP if you'd rather not store ClientSecret at all — the helper
// also accepts an empty ClientSecret in that case (the underlying
// http.Client is responsible for client-cert authentication).
type ClientCredentialsConfig struct {
	TokenURL     string
	ClientID     string
	ClientSecret string
	Scopes       []string
	Audience     string // optional, passed as `audience` form value (Auth0/Keycloak idiom)

	// AuthStyle controls how client credentials are sent.
	//   AuthStyleBasic     — HTTP Basic (default; required by RFC 6749 §2.3.1)
	//   AuthStyleInBody    — form body params (RFC 6749 §2.3.1 alternative)
	//   AuthStyleAutoDetect — try Basic first; fall back to body on 401
	AuthStyle AuthStyle

	// Leeway is subtracted from each token's expires_in so we refresh
	// slightly before the IdP's expiry. Default 30s.
	Leeway time.Duration

	// HTTPClient is used for the /token round trip. nil means
	// http.DefaultClient. Plug in an mTLS client here.
	HTTPClient *http.Client

	// Resilience configures the circuit breaker + retry budget that
	// guard the /token round trip. Zero value = pure circuit breaker
	// with safe defaults (5 consecutive failures trip a 30s open
	// state) and no retries. Callers wanting retries on a flaky IdP
	// should set Resilience.MaxRetries.
	Resilience upstream.GuardConfig
}

// AuthStyle mirrors `oauth2.AuthStyle` without forcing the dependency.
type AuthStyle int

const (
	AuthStyleAutoDetect AuthStyle = 0
	AuthStyleBasic      AuthStyle = 1
	AuthStyleInBody     AuthStyle = 2
)

// Token is the relevant subset of an OAuth 2.0 token endpoint response.
type Token struct {
	AccessToken string    `json:"access_token"`
	TokenType   string    `json:"token_type"`
	ExpiresAt   time.Time `json:"-"` // computed from expires_in + now
	Scope       string    `json:"scope,omitempty"`
}

// Valid reports whether the token is non-empty and not yet expired.
func (t *Token) Valid() bool {
	if t == nil || t.AccessToken == "" {
		return false
	}
	if t.ExpiresAt.IsZero() {
		return true // IdP didn't tell us; trust until refresh forced
	}
	return time.Now().Before(t.ExpiresAt)
}

// ClientCredentialsSource is a goroutine-safe, lazily-refreshing token
// provider. Get a fresh access token via Token; or wrap an http.Client
// with HTTPClient() to inject Authorization on every outbound request.
type ClientCredentialsSource struct {
	cfg   ClientCredentialsConfig
	guard *upstream.Guard

	mu  sync.Mutex
	tok *Token
}

// NewClientCredentialsSource validates cfg and returns a Source ready to
// hand out tokens. No network call is made until the first Token().
func NewClientCredentialsSource(cfg ClientCredentialsConfig) *ClientCredentialsSource {
	if cfg.Leeway == 0 {
		cfg.Leeway = 30 * time.Second
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = http.DefaultClient
	}
	return &ClientCredentialsSource{cfg: cfg, guard: upstream.NewGuard(cfg.Resilience)}
}

// Token returns a non-expired token, fetching/refreshing as needed.
// Concurrent callers coalesce around the cached token.
func (s *ClientCredentialsSource) Token(ctx context.Context) (*Token, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.tok.Valid() {
		return s.tok, nil
	}
	var tok *Token
	err := s.guard.Do(ctx, func(ctx context.Context) error {
		t, ferr := s.fetch(ctx)
		if ferr != nil {
			return ferr
		}
		tok = t
		return nil
	})
	if err != nil {
		return nil, err
	}
	s.tok = tok
	return tok, nil
}

// HTTPClient returns an *http.Client that injects
// `Authorization: Bearer <tok>` on every outbound request. The
// returned client shares a transport with the configured one.
func (s *ClientCredentialsSource) HTTPClient(ctx context.Context) *http.Client {
	base := s.cfg.HTTPClient.Transport
	if base == nil {
		base = http.DefaultTransport
	}
	return &http.Client{
		Transport: &bearerTransport{src: s, ctx: ctx, base: base},
		Timeout:   s.cfg.HTTPClient.Timeout,
	}
}

type bearerTransport struct {
	src  *ClientCredentialsSource
	ctx  context.Context
	base http.RoundTripper
}

func (b *bearerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	tok, err := b.src.Token(req.Context())
	if err != nil {
		return nil, err
	}
	// Don't mutate the caller's request — clone shallow + headers.
	r2 := req.Clone(req.Context())
	r2.Header = req.Header.Clone()
	tt := tok.TokenType
	if tt == "" {
		tt = "Bearer"
	}
	r2.Header.Set("Authorization", tt+" "+tok.AccessToken)
	return b.base.RoundTrip(r2)
}

// fetch performs the actual HTTPS POST to the token endpoint. Honors
// AuthStyleBasic vs InBody and falls back from Basic to InBody on 401
// when AuthStyleAutoDetect is requested (some IdPs reject Basic).
func (s *ClientCredentialsSource) fetch(ctx context.Context) (*Token, error) {
	if s.cfg.TokenURL == "" {
		return nil, errors.New("clientauth: TokenURL is required")
	}
	if s.cfg.ClientID == "" {
		return nil, errors.New("clientauth: ClientID is required")
	}

	tryStyles := []AuthStyle{}
	switch s.cfg.AuthStyle {
	case AuthStyleAutoDetect:
		tryStyles = []AuthStyle{AuthStyleBasic, AuthStyleInBody}
	default:
		tryStyles = []AuthStyle{s.cfg.AuthStyle}
	}

	var lastErr error
	for _, style := range tryStyles {
		tok, status, err := s.doFetch(ctx, style)
		if err == nil {
			return tok, nil
		}
		lastErr = err
		// Auto-fallback only for 401 from Basic → InBody.
		if s.cfg.AuthStyle == AuthStyleAutoDetect && style == AuthStyleBasic && status == http.StatusUnauthorized {
			continue
		}
		break
	}
	return nil, lastErr
}

func (s *ClientCredentialsSource) doFetch(ctx context.Context, style AuthStyle) (*Token, int, error) {
	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	if len(s.cfg.Scopes) > 0 {
		form.Set("scope", strings.Join(s.cfg.Scopes, " "))
	}
	if s.cfg.Audience != "" {
		form.Set("audience", s.cfg.Audience)
	}
	if style == AuthStyleInBody {
		form.Set("client_id", s.cfg.ClientID)
		form.Set("client_secret", s.cfg.ClientSecret)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.cfg.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, 0, fmt.Errorf("clientauth: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if style == AuthStyleBasic {
		req.SetBasicAuth(url.QueryEscape(s.cfg.ClientID), url.QueryEscape(s.cfg.ClientSecret))
	}

	resp, err := s.cfg.HTTPClient.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("clientauth: token endpoint: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, resp.StatusCode, fmt.Errorf("clientauth: token endpoint status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var raw struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"`
		Scope       string `json:"scope"`
		Error       string `json:"error"`
		ErrorDesc   string `json:"error_description"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, resp.StatusCode, fmt.Errorf("clientauth: decode token response: %w", err)
	}
	if raw.Error != "" {
		return nil, resp.StatusCode, fmt.Errorf("clientauth: %s: %s", raw.Error, raw.ErrorDesc)
	}
	if raw.AccessToken == "" {
		return nil, resp.StatusCode, errors.New("clientauth: token response had empty access_token")
	}
	tok := &Token{
		AccessToken: raw.AccessToken,
		TokenType:   raw.TokenType,
		Scope:       raw.Scope,
	}
	if raw.ExpiresIn > 0 {
		tok.ExpiresAt = time.Now().Add(time.Duration(raw.ExpiresIn)*time.Second - s.cfg.Leeway)
	}
	return tok, resp.StatusCode, nil
}
