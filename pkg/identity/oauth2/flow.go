package oauth2

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/oauth2"

	jwtlib "github.com/lestrrat-go/jwx/v2/jwt"

	"github.com/mikeappsec/lightweightauth/pkg/session"
)

// HTTPHandler is the entrypoint mounted at MountPrefix(). It dispatches
// to the four /oauth2/* sub-routes; anything else returns 404.
func (i *identifier) HTTPHandler() http.Handler {
	mux := http.NewServeMux()
	prefix := strings.TrimRight(i.mountPrefix, "/")
	mux.HandleFunc(prefix+"/start", i.handleStart)
	mux.HandleFunc(prefix+"/callback", i.handleCallback)
	mux.HandleFunc(prefix+"/logout", i.handleLogout)
	mux.HandleFunc(prefix+"/userinfo", i.handleUserInfo)
	mux.HandleFunc(prefix+"/refresh", i.handleRefresh)
	if i.deviceAuthURL != "" {
		mux.HandleFunc(prefix+"/device/start", i.handleDeviceStart)
		mux.HandleFunc(prefix+"/device/poll", i.handleDevicePoll)
	}
	return mux
}

// flowState is the short-lived state we keep between /start and /callback.
// It rides the encrypted flow cookie; no server-side store needed.
type flowState struct {
	State    string `json:"state"`
	Verifier string `json:"verifier"`
	RD       string `json:"rd"`
}

// handleStart begins an authorization-code+PKCE flow. We mint state and
// PKCE material, store them in the flow cookie, and 302 the user to the
// IdP's authorize URL.
func (i *identifier) handleStart(w http.ResponseWriter, r *http.Request) {
	// `rd` is the post-login redirect target. We validate it BEFORE
	// stashing it in the flow cookie so an attacker can't smuggle an
	// absolute URL through /oauth2/start?rd=https://evil.example and
	// turn the login flow into a trusted open redirect. Anything that
	// fails the safeRedirect check falls back to the configured
	// PostLoginPath.
	rd := i.safeRedirect(r.URL.Query().Get("rd"))
	state, err := randURL(24)
	if err != nil {
		http.Error(w, "rand: "+err.Error(), http.StatusInternalServerError)
		return
	}
	verifier, err := randURL(48)
	if err != nil {
		http.Error(w, "rand: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Stash state+verifier+rd in the flow cookie. We piggyback on
	// session.CookieStore by stuffing the JSON payload into Session.Claims.
	if err := i.flowCookie.Save(w, r, &session.Session{
		Subject:  "flow",
		Claims:   map[string]any{"flow": flowState{State: state, Verifier: verifier, RD: rd}},
		Expiry:   time.Now().Add(10 * time.Minute),
		IssuedAt: time.Now(),
	}); err != nil {
		http.Error(w, "flow cookie: "+err.Error(), http.StatusInternalServerError)
		return
	}

	challenge := pkceS256(verifier)
	authURL := i.oauth.AuthCodeURL(
		state,
		oauth2.SetAuthURLParam("code_challenge", challenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)
	http.Redirect(w, r, authURL, http.StatusFound)
}

// handleCallback consumes the IdP's redirect, validates state, exchanges
// the code (with PKCE), verifies the id_token, and mints the session.
func (i *identifier) handleCallback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if errMsg := q.Get("error"); errMsg != "" {
		http.Error(w, "idp error: "+errMsg+" "+q.Get("error_description"), http.StatusBadGateway)
		return
	}
	gotState := q.Get("state")
	code := q.Get("code")
	if gotState == "" || code == "" {
		http.Error(w, "missing state or code", http.StatusBadRequest)
		return
	}

	flow, err := i.loadFlow(r)
	if err != nil || flow == nil {
		http.Error(w, "flow expired or absent", http.StatusBadRequest)
		return
	}
	if flow.State != gotState {
		http.Error(w, "state mismatch", http.StatusBadRequest)
		return
	}

	tok, err := i.oauth.Exchange(
		r.Context(),
		code,
		oauth2.SetAuthURLParam("code_verifier", flow.Verifier),
	)
	if err != nil {
		http.Error(w, "token exchange: "+err.Error(), http.StatusBadGateway)
		return
	}

	idTokenRaw, _ := tok.Extra("id_token").(string)
	if idTokenRaw == "" {
		http.Error(w, "no id_token in IdP response", http.StatusBadGateway)
		return
	}
	parsed, err := jwtlib.ParseString(idTokenRaw, i.jwtParseOpts...)
	if err != nil {
		http.Error(w, "id_token verify: "+err.Error(), http.StatusUnauthorized)
		return
	}
	claims, _ := parsed.AsMap(r.Context())
	subject := parsed.Subject()
	if subject == "" {
		if v, ok := claims["sub"].(string); ok {
			subject = v
		}
	}
	if subject == "" {
		http.Error(w, "id_token has no sub", http.StatusBadGateway)
		return
	}
	email, _ := claims["email"].(string)

	// Stash AT expiry inside Claims so refresh logic can read it back
	// after a JSON cookie round-trip. We use RFC3339 strings because
	// time.Time round-trips through map[string]any as a string.
	if !tok.Expiry.IsZero() {
		if claims == nil {
			claims = map[string]any{}
		}
		claims["accessTokenExpiry"] = tok.Expiry.UTC().Format(time.RFC3339)
	}

	sess := &session.Session{
		Subject:      subject,
		Email:        email,
		Claims:       claims,
		IDToken:      idTokenRaw,
		AccessToken:  tok.AccessToken,
		RefreshToken: tok.RefreshToken,
		Provider:     i.provider,
		IssuedAt:     i.now(),
	}
	// Default Session.Expiry comes from CookieStore.MaxAge; leave it zero
	// so Save fills it in.
	if err := i.store.Save(w, r, sess); err != nil {
		http.Error(w, "session save: "+err.Error(), http.StatusInternalServerError)
		return
	}
	_ = i.flowCookie.Clear(w, r)
	// Defense in depth: even though /oauth2/start sanitised `rd` before
	// stashing it in the encrypted flow cookie, re-run the same check
	// here so a forged or replayed flow cookie can't redirect away.
	http.Redirect(w, r, i.safeRedirect(flow.RD), http.StatusFound)
}

// handleLogout clears the session cookie (and any lingering flow cookie)
// and redirects to PostLogoutPath. When EndSessionURL is configured, we
// instead 302 to the IdP's RP-initiated logout endpoint per OIDC
// RP-Initiated Logout 1.0 §5, embedding `id_token_hint` and
// `post_logout_redirect_uri` so the IdP can bounce the user back.
func (i *identifier) handleLogout(w http.ResponseWriter, r *http.Request) {
	// Capture the id_token *before* clearing so we can pass it as a hint.
	var idTokenHint string
	if s, _ := i.store.Load(r); s != nil {
		idTokenHint = s.IDToken
	}

	_ = i.store.Clear(w, r)
	_ = i.flowCookie.Clear(w, r)

	if i.endSessionURL == "" {
		http.Redirect(w, r, i.postLogout, http.StatusFound)
		return
	}

	target, err := buildEndSessionURL(i.endSessionURL, idTokenHint, absoluteURL(r, i.postLogout))
	if err != nil {
		// Fall back to local logout rather than 500ing the user.
		http.Redirect(w, r, i.postLogout, http.StatusFound)
		return
	}
	http.Redirect(w, r, target, http.StatusFound)
}

// handleUserInfo returns the current session as JSON. Useful for SPAs and
// for "is my login working?" smoke tests. Returns 401 when no session.
// If RefreshLeeway is configured and the access token is near expiry,
// we transparently rotate it before responding.
func (i *identifier) handleUserInfo(w http.ResponseWriter, r *http.Request) {
	s, _ := i.store.Load(r)
	if s == nil {
		http.Error(w, "no session", http.StatusUnauthorized)
		return
	}
	if fresh, rotated, err := i.refreshIfNeeded(r.Context(), w, r, s); err == nil && rotated {
		s = fresh
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"subject": s.Subject,
		"email":   s.Email,
		"claims":  s.Claims,
		"expiry":  s.Expiry,
	})
}

// loadFlow decodes the flow cookie back into a flowState. Round-trips
// through map[string]any because we encoded it via Session.Claims.
func (i *identifier) loadFlow(r *http.Request) (*flowState, error) {
	s, err := i.flowCookie.Load(r)
	if err != nil || s == nil {
		return nil, err
	}
	raw, ok := s.Claims["flow"]
	if !ok {
		return nil, nil
	}
	// json.Unmarshal of a Session put map[string]any back; remarshal+unmarshal
	// to recover the typed struct without writing custom decoders.
	b, err := json.Marshal(raw)
	if err != nil {
		return nil, err
	}
	var fs flowState
	if err := json.Unmarshal(b, &fs); err != nil {
		return nil, err
	}
	return &fs, nil
}

// randURL returns n bytes of crypto-random data, base64url-encoded.
func randURL(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("rand: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// pkceS256 returns base64url(sha256(verifier)) per RFC 7636.
func pkceS256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// handleRefresh forces a token rotation. Used by SPAs that want to
// pre-warm a fresh access token before a long-running call. Returns 401
// when there is no session or no refresh_token, 502 when the IdP
// rejects the refresh.
func (i *identifier) handleRefresh(w http.ResponseWriter, r *http.Request) {
	s, _ := i.store.Load(r)
	if s == nil {
		http.Error(w, "no session", http.StatusUnauthorized)
		return
	}
	if s.RefreshToken == "" {
		http.Error(w, "no refresh_token", http.StatusUnauthorized)
		return
	}
	fresh, err := i.doRefresh(r.Context(), w, r, s)
	if err != nil {
		http.Error(w, "refresh: "+err.Error(), http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"subject":           fresh.Subject,
		"accessTokenExpiry": fresh.Claims["accessTokenExpiry"],
	})
}

// refreshIfNeeded transparently rotates tokens if the access token is
// within RefreshLeeway of expiry. Returns (sess, false, nil) when no
// rotation was needed; (newSess, true, nil) on successful rotation;
// (nil, false, err) on a refresh attempt that failed.
func (i *identifier) refreshIfNeeded(ctx context.Context, w http.ResponseWriter, r *http.Request, s *session.Session) (*session.Session, bool, error) {
	if i.refreshLeeway <= 0 || s == nil || s.RefreshToken == "" {
		return s, false, nil
	}
	exp, ok := readATExpiry(s.Claims)
	if !ok {
		return s, false, nil
	}
	if time.Until(exp) > i.refreshLeeway {
		return s, false, nil
	}
	fresh, err := i.doRefresh(ctx, w, r, s)
	if err != nil {
		return nil, false, err
	}
	return fresh, true, nil
}

// doRefresh exchanges the stored refresh_token for a new access (and
// possibly new refresh + id_token) and persists the rotated session.
// Per RFC 6749 §6, the IdP MAY return a new refresh_token; we keep the
// old one when it doesn't.
func (i *identifier) doRefresh(ctx context.Context, w http.ResponseWriter, r *http.Request, s *session.Session) (*session.Session, error) {
	src := i.oauth.TokenSource(ctx, &oauth2.Token{
		RefreshToken: s.RefreshToken,
	})
	tok, err := src.Token()
	if err != nil {
		return nil, fmt.Errorf("token source: %w", err)
	}

	// Start from the existing session so we keep claims that the IdP
	// doesn't echo back on a refresh.
	newSess := *s
	newSess.AccessToken = tok.AccessToken
	if tok.RefreshToken != "" {
		newSess.RefreshToken = tok.RefreshToken
	}
	if newSess.Claims == nil {
		newSess.Claims = map[string]any{}
	}
	if !tok.Expiry.IsZero() {
		newSess.Claims["accessTokenExpiry"] = tok.Expiry.UTC().Format(time.RFC3339)
	}

	// If the IdP rotated the id_token, re-verify and refresh claims.
	if idt, _ := tok.Extra("id_token").(string); idt != "" {
		parsed, perr := jwtlib.ParseString(idt, i.jwtParseOpts...)
		if perr == nil {
			if cm, mErr := parsed.AsMap(ctx); mErr == nil {
				// Preserve the AT-expiry breadcrumb we just wrote.
				if v, ok := newSess.Claims["accessTokenExpiry"]; ok {
					cm["accessTokenExpiry"] = v
				}
				newSess.Claims = cm
				if sub := parsed.Subject(); sub != "" {
					newSess.Subject = sub
				}
				if em, ok := cm["email"].(string); ok {
					newSess.Email = em
				}
				newSess.IDToken = idt
			}
		}
	}

	// Persist. CookieStore.Save will mint a fresh Set-Cookie; the cookie
	// value itself rotates because Claims changed.
	if err := i.store.Save(w, r, &newSess); err != nil {
		return nil, fmt.Errorf("session save: %w", err)
	}
	return &newSess, nil
}

// readATExpiry reads the access-token expiry stashed by the callback /
// refresh. Tolerates both time.Time (in-process) and RFC3339 string
// (after a JSON cookie round-trip).
func readATExpiry(claims map[string]any) (time.Time, bool) {
	v, ok := claims["accessTokenExpiry"]
	if !ok {
		return time.Time{}, false
	}
	switch x := v.(type) {
	case time.Time:
		return x, !x.IsZero()
	case string:
		t, err := time.Parse(time.RFC3339, x)
		if err != nil {
			return time.Time{}, false
		}
		return t, true
	}
	return time.Time{}, false
}

// buildEndSessionURL composes an OIDC RP-Initiated Logout URL by
// merging in id_token_hint + post_logout_redirect_uri without trampling
// any query params the IdP already requires.
func buildEndSessionURL(endSession, idTokenHint, postLogoutRedirect string) (string, error) {
	u, err := url.Parse(endSession)
	if err != nil {
		return "", err
	}
	q := u.Query()
	if idTokenHint != "" {
		q.Set("id_token_hint", idTokenHint)
	}
	if postLogoutRedirect != "" {
		q.Set("post_logout_redirect_uri", postLogoutRedirect)
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// absoluteURL turns a path like "/" into a fully-qualified URL relative
// to the inbound request, suitable for post_logout_redirect_uri (which
// most IdPs require to be absolute and pre-registered).
func absoluteURL(r *http.Request, path string) string {
	if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
		return path
	}
	scheme := "https"
	if r.TLS == nil && r.Header.Get("X-Forwarded-Proto") == "" {
		scheme = "http"
	}
	if xf := r.Header.Get("X-Forwarded-Proto"); xf != "" {
		scheme = xf
	}
	host := r.Host
	if xh := r.Header.Get("X-Forwarded-Host"); xh != "" {
		host = xh
	}
	if path == "" {
		path = "/"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return scheme + "://" + host + path
}
