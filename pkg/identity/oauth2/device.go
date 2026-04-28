package oauth2

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	jwtlib "github.com/lestrrat-go/jwx/v2/jwt"

	"github.com/mikeappsec/lightweightauth/pkg/session"
)

// RFC 8628 Device Authorization Grant.
//
// Two endpoints are mounted under the existing oauth2 mount prefix:
//
//	POST /oauth2/device/start  → proxies to the IdP's device authorization
//	                             endpoint and returns the IdP's JSON body
//	                             verbatim (with `device_code`, `user_code`,
//	                             `verification_uri`, `verification_uri_complete`,
//	                             `expires_in`, `interval`).
//
//	POST /oauth2/device/poll   → caller posts {device_code}; we exchange via
//	                             grant_type=urn:ietf:params:oauth:grant-type:device_code
//	                             and either:
//	                               - 200 with the same `Session` shape as
//	                                 /oauth2/callback (and Set-Cookie),
//	                               - 202 with {error: authorization_pending|slow_down},
//	                               - 4xx for terminal errors (expired_token,
//	                                 access_denied).
//
// The device-code is the long opaque polling token; the user_code is the
// short human-typeable code the user enters at the IdP's verification page.

const deviceCodeGrantType = "urn:ietf:params:oauth:grant-type:device_code"

// handleDeviceStart asks the IdP for a fresh (device_code, user_code) pair.
// The caller (typically a CLI) shows the user_code + verification_uri to
// the human, then begins polling /oauth2/device/poll with the device_code.
func (i *identifier) handleDeviceStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	form := url.Values{
		"client_id": {i.oauth.ClientID},
		"scope":     {strings.Join(i.oauth.Scopes, " ")},
	}
	body, status, err := i.postForm(r.Context(), i.deviceAuthURL, form)
	if err != nil {
		http.Error(w, "device authorization: "+err.Error(), http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

// handleDevicePoll exchanges the supplied device_code for a token. On
// success it mints the same session shape as /oauth2/callback so refresh
// rotation and RP-logout from M6 apply unchanged.
func (i *identifier) handleDevicePoll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	deviceCode, err := readDeviceCode(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	form := url.Values{
		"grant_type":  {deviceCodeGrantType},
		"device_code": {deviceCode},
		"client_id":   {i.oauth.ClientID},
	}
	if i.oauth.ClientSecret != "" {
		form.Set("client_secret", i.oauth.ClientSecret)
	}

	body, status, err := i.postForm(r.Context(), i.oauth.Endpoint.TokenURL, form)
	if err != nil {
		http.Error(w, "token exchange: "+err.Error(), http.StatusBadGateway)
		return
	}

	// Per RFC 8628 §3.5, errors are returned with 400 and an OAuth2
	// error code. authorization_pending / slow_down are non-terminal:
	// surface them to the caller as 202 so a typical HTTP client knows
	// to keep polling without throwing on a 4xx.
	if status >= 400 {
		var errBody map[string]any
		_ = json.Unmarshal(body, &errBody)
		code, _ := errBody["error"].(string)
		switch code {
		case "authorization_pending", "slow_down":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusAccepted)
			_, _ = w.Write(body)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write(body)
		return
	}

	// Success: parse the token response and build a session.
	var tokResp struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		IDToken      string `json:"id_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int64  `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &tokResp); err != nil {
		http.Error(w, "token decode: "+err.Error(), http.StatusBadGateway)
		return
	}
	if tokResp.IDToken == "" {
		http.Error(w, "no id_token in IdP response", http.StatusBadGateway)
		return
	}
	parsed, err := jwtlib.ParseString(tokResp.IDToken, i.jwtParseOpts...)
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
	if claims == nil {
		claims = map[string]any{}
	}
	if tokResp.ExpiresIn > 0 {
		exp := i.now().Add(time.Duration(tokResp.ExpiresIn) * time.Second)
		claims["accessTokenExpiry"] = exp.UTC().Format(time.RFC3339)
	}

	sess := &session.Session{
		Subject:      subject,
		Email:        email,
		Claims:       claims,
		IDToken:      tokResp.IDToken,
		AccessToken:  tokResp.AccessToken,
		RefreshToken: tokResp.RefreshToken,
		Provider:     i.provider,
		IssuedAt:     i.now(),
	}
	if err := i.store.Save(w, r, sess); err != nil {
		http.Error(w, "session save: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"subject":           sess.Subject,
		"email":             sess.Email,
		"accessTokenExpiry": claims["accessTokenExpiry"],
	})
}

// readDeviceCode accepts the device_code as either a JSON body
// ({"device_code":"..."}) or a form-urlencoded body. Empty strings are
// rejected so we never POST a blank grant.
func readDeviceCode(r *http.Request) (string, error) {
	ct := r.Header.Get("Content-Type")
	if strings.HasPrefix(ct, "application/json") {
		var body struct {
			DeviceCode string `json:"device_code"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			return "", fmt.Errorf("invalid json: %w", err)
		}
		if body.DeviceCode == "" {
			return "", fmt.Errorf("device_code is required")
		}
		return body.DeviceCode, nil
	}
	if err := r.ParseForm(); err != nil {
		return "", fmt.Errorf("invalid form: %w", err)
	}
	dc := r.PostFormValue("device_code")
	if dc == "" {
		return "", fmt.Errorf("device_code is required")
	}
	return dc, nil
}

// postForm POSTs an application/x-www-form-urlencoded body and returns
// the raw response body + HTTP status. Used for both the device
// authorization endpoint and the token endpoint so callers can inspect
// the IdP's error responses verbatim.
//
// Hardening (pentest MED-02): we use the identifier's bounded
// http.Client (timeout) instead of http.DefaultClient, and bound the
// response body with io.LimitReader before ReadAll so an IdP that
// streams gigabytes can't pin our memory.
func (i *identifier) postForm(ctx context.Context, endpoint string, form url.Values) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	cli := i.httpClient
	if cli == nil {
		cli = &http.Client{Timeout: 30 * time.Second}
	}
	resp, err := cli.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	limit := i.maxResponseBytes
	if limit <= 0 {
		limit = 1 << 20
	}
	// Read one byte past the limit so we can distinguish "exactly at
	// the cap" (legitimate large response) from "overflowed the cap"
	// (truncate-and-fail).
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, resp.StatusCode, err
	}
	if int64(len(body)) > limit {
		return nil, resp.StatusCode, fmt.Errorf("idp response exceeds %d bytes", limit)
	}
	return body, resp.StatusCode, nil
}
