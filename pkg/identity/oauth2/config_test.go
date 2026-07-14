// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mikeappsec/lightweightauth/pkg/session"
)

// TestFlowCookie_ForcesLaxRegardlessOfConfiguredSameSite is a regression
// test: the flow cookie (state + PKCE verifier) is read back after a
// cross-site top-level redirect from the IdP, which browsers never send a
// SameSite=Strict cookie on. Previously buildCookieStoreNamed applied the
// operator's configured cookie.sameSite to the flow cookie too, so
// `sameSite: strict` silently broke every login. The session cookie must
// keep the operator's exact setting.
func TestFlowCookie_ForcesLaxRegardlessOfConfiguredSameSite(t *testing.T) {
	t.Parallel()

	cfg := CookieConfig{
		Secret:   "0123456789abcdef",
		SameSite: "strict",
	}

	sessionStore, err := buildCookieStore(cfg, "_lwauth_session", 8*time.Hour)
	if err != nil {
		t.Fatalf("buildCookieStore: %v", err)
	}
	flowStore, err := buildCookieStoreNamed(cfg, "_lwauth_oauth2_flow", 10*time.Minute, true)
	if err != nil {
		t.Fatalf("buildCookieStoreNamed: %v", err)
	}

	sessionSameSite := setCookieSameSite(t, sessionStore)
	flowSameSite := setCookieSameSite(t, flowStore)

	if sessionSameSite != "Strict" {
		t.Errorf("session cookie SameSite = %q, want Strict (operator's exact setting)", sessionSameSite)
	}
	if flowSameSite != "Lax" {
		t.Errorf("flow cookie SameSite = %q, want Lax (forced, regardless of cookie.sameSite: strict)", flowSameSite)
	}
}

// setCookieSameSite saves a session through store and extracts the
// SameSite attribute from the resulting Set-Cookie header.
func setCookieSameSite(t *testing.T, store *session.CookieStore) string {
	t.Helper()
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "https://app.example.com/", nil)
	if err := store.Save(w, r, &session.Session{Subject: "alice"}); err != nil {
		t.Fatalf("Save: %v", err)
	}
	setCookie := w.Header().Get("Set-Cookie")
	if setCookie == "" {
		t.Fatal("no Set-Cookie header written")
	}
	for _, part := range strings.Split(setCookie, ";") {
		part = strings.TrimSpace(part)
		if v, ok := strings.CutPrefix(part, "SameSite="); ok {
			return v
		}
	}
	t.Fatalf("Set-Cookie header has no SameSite attribute: %q", setCookie)
	return ""
}
