// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/mikeappsec/lightweightauth/pkg/module"
	"github.com/mikeappsec/lightweightauth/pkg/session"
)

// TestOAuth2_SecretsRotation_TokenRefreshUsesActiveSecret wires the oauth2
// identifier to the shared `secrets:` rotation config format and verifies
// a token refresh sends the still-active client secret, not the retired
// one. i.oauth is never mutated in place; currentOAuthConfig builds a
// per-call copy with the freshly-resolved secret instead.
func TestOAuth2_SecretsRotation_TokenRefreshUsesActiveSecret(t *testing.T) {
	t.Parallel()
	now := time.Now()
	var gotSecret string

	mux := http.NewServeMux()
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"keys":[]}`))
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		secret := r.PostForm.Get("client_secret")
		if secret == "" {
			if _, pass, ok := r.BasicAuth(); ok {
				secret = pass
			}
		}
		gotSecret = secret
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "new-at",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	id, err := factory("oauth2", map[string]any{
		"clientId":    "client-a",
		"authUrl":     srv.URL + "/authorize",
		"tokenUrl":    srv.URL + "/token",
		"jwksUrl":     srv.URL + "/jwks",
		"redirectUrl": "https://app.example.com/oauth2/callback",
		"cookie":      map[string]any{"secret": "0123456789abcdef"},
		"secrets": []any{
			map[string]any{
				"kid":      "v1-retired",
				"secret":   base64.StdEncoding.EncodeToString([]byte("retiredsecret0123456789ab")),
				"notAfter": now.Add(-time.Hour).Format(time.RFC3339),
			},
			map[string]any{
				"kid":    "v2-active",
				"secret": base64.StdEncoding.EncodeToString([]byte("activesecret0123456789ab")),
			},
		},
	}, module.Deps{})
	if err != nil {
		t.Fatalf("factory: %v", err)
	}
	oi, ok := id.(*rotatableIdentifier)
	if !ok {
		t.Fatalf("expected *rotatableIdentifier, got %T", id)
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "https://app.example.com/", nil)
	_, err = oi.doRefreshOnce(context.Background(), w, r, &session.Session{
		Subject:      "alice",
		RefreshToken: "rt-1",
	})
	if err != nil {
		t.Fatalf("doRefreshOnce: %v", err)
	}

	wantSecret := "activesecret0123456789ab"
	if gotSecret != wantSecret {
		t.Errorf("client_secret sent = %q, want %q (active secret)", gotSecret, wantSecret)
	}
}

// TestOAuth2_SecretsRotation_MutuallyExclusiveWithClientSecret verifies the
// factory rejects configs that mix `secrets:` with `clientSecret`.
func TestOAuth2_SecretsRotation_MutuallyExclusiveWithClientSecret(t *testing.T) {
	t.Parallel()
	_, err := factory("oauth2", map[string]any{
		"clientId":     "client-a",
		"clientSecret": "s",
		"authUrl":      "https://idp.example.com/authorize",
		"tokenUrl":     "https://idp.example.com/token",
		"jwksUrl":      "https://idp.example.com/jwks",
		"redirectUrl":  "https://app.example.com/oauth2/callback",
		"cookie":       map[string]any{"secret": "0123456789abcdef"},
		"secrets": []any{
			map[string]any{"kid": "v1", "secret": base64.StdEncoding.EncodeToString([]byte("activesecret0123456789ab"))},
		},
	}, module.Deps{})
	if err == nil {
		t.Fatal("expected error for mixing clientSecret and secrets")
	}
}
