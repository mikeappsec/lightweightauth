// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func newTestManager(t *testing.T) *Manager {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte("s3cret"), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	return NewManager(Config{
		Enabled:      true,
		Username:     "admin",
		PasswordHash: string(hash),
		SessionTTL:   time.Hour,
		Secure:       false,
	})
}

func TestLogin_Success_SetsCookie(t *testing.T) {
	m := newTestManager(t)
	req := httptest.NewRequest("POST", "/v1/controlplane/auth/login",
		strings.NewReader(`{"username":"admin","password":"s3cret"}`))
	rr := httptest.NewRecorder()
	m.HandleLogin(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	cookies := rr.Result().Cookies()
	var found *http.Cookie
	for _, c := range cookies {
		if c.Name == SessionCookieName {
			found = c
		}
	}
	if found == nil || found.Value == "" {
		t.Fatal("expected session cookie to be set")
	}
	if !found.HttpOnly {
		t.Error("session cookie must be HttpOnly")
	}
}

func TestLogin_WrongPassword(t *testing.T) {
	m := newTestManager(t)
	req := httptest.NewRequest("POST", "/login",
		strings.NewReader(`{"username":"admin","password":"nope"}`))
	rr := httptest.NewRecorder()
	m.HandleLogin(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
	if len(rr.Result().Cookies()) != 0 {
		t.Error("no cookie should be set on failed login")
	}
}

func TestLogin_WrongUsername(t *testing.T) {
	m := newTestManager(t)
	req := httptest.NewRequest("POST", "/login",
		strings.NewReader(`{"username":"root","password":"s3cret"}`))
	rr := httptest.NewRecorder()
	m.HandleLogin(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
}

func TestMiddleware_BlocksUnauthenticated(t *testing.T) {
	m := newTestManager(t)
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	h := m.Middleware(next)

	req := httptest.NewRequest("GET", "/v1/controlplane/instances", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for unauthenticated data request, got %d", rr.Code)
	}
}

func TestMiddleware_AllowsAuthEndpoints(t *testing.T) {
	m := newTestManager(t)
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true })
	h := m.Middleware(next)

	req := httptest.NewRequest("POST", "/v1/controlplane/auth/login", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if !called {
		t.Fatal("auth endpoints must bypass the session gate")
	}
}

func TestMiddleware_AllowsAfterLogin(t *testing.T) {
	m := newTestManager(t)

	// Log in to obtain a cookie.
	loginReq := httptest.NewRequest("POST", "/login",
		strings.NewReader(`{"username":"admin","password":"s3cret"}`))
	loginRR := httptest.NewRecorder()
	m.HandleLogin(loginRR, loginReq)
	cookie := loginRR.Result().Cookies()[0]

	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true })
	h := m.Middleware(next)

	req := httptest.NewRequest("GET", "/v1/controlplane/instances", nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if !called {
		t.Fatalf("authenticated request should pass, got %d", rr.Code)
	}
}

func TestLogout_InvalidatesSession(t *testing.T) {
	m := newTestManager(t)
	loginReq := httptest.NewRequest("POST", "/login",
		strings.NewReader(`{"username":"admin","password":"s3cret"}`))
	loginRR := httptest.NewRecorder()
	m.HandleLogin(loginRR, loginReq)
	cookie := loginRR.Result().Cookies()[0]

	logoutReq := httptest.NewRequest("POST", "/logout", nil)
	logoutReq.AddCookie(cookie)
	logoutRR := httptest.NewRecorder()
	m.HandleLogout(logoutRR, logoutReq)

	if got := m.validate(cookieReq(cookie)); got != "" {
		t.Errorf("session should be invalid after logout, got subject %q", got)
	}
}

func TestDisabled_BypassesEverything(t *testing.T) {
	m := NewManager(Config{Enabled: false})
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true })
	h := m.Middleware(next)
	req := httptest.NewRequest("GET", "/v1/controlplane/instances", nil)
	h.ServeHTTP(httptest.NewRecorder(), req)
	if !called {
		t.Fatal("disabled auth must pass all requests")
	}
}

func cookieReq(c *http.Cookie) *http.Request {
	r := httptest.NewRequest("GET", "/", nil)
	r.AddCookie(c)
	return r
}
