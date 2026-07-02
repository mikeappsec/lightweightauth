// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

// Package auth implements a lightweight, cookie-based login for the control
// plane console. A single preconfigured administrator credential gates the UI:
// the username is configurable (default "admin") and the password is verified
// against a bcrypt hash supplied out-of-band (Kubernetes Secret sourced from a
// GitHub secret). Successful login mints an opaque, server-side session stored
// in memory and referenced by an HttpOnly cookie.
//
// This is intentionally minimal: a single admin, no self-service password
// change (rotate the secret and redeploy), and an in-memory session store
// (the control plane runs as a single replica).
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// SessionCookieName is the name of the cookie carrying the session token.
const SessionCookieName = "lwauth_session"

// Config configures the login manager.
type Config struct {
	// Enabled turns login enforcement on. When false the console is open
	// (developer mode) and all auth endpoints report authEnabled=false.
	Enabled bool

	// Username is the single administrator account name (default "admin").
	Username string

	// PasswordHash is the bcrypt hash of the administrator password.
	PasswordHash string

	// SessionTTL is how long a session remains valid (default 12h).
	SessionTTL time.Duration

	// Secure sets the Secure flag on the session cookie. Enable in production
	// (HTTPS). Disable for plain-HTTP local development.
	Secure bool
}

type session struct {
	subject string
	expires time.Time
}

// Manager issues and validates login sessions.
type Manager struct {
	cfg      Config
	mu       sync.Mutex
	sessions map[string]session
}

// NewManager builds a login manager, applying defaults for unset fields.
func NewManager(cfg Config) *Manager {
	if cfg.Username == "" {
		cfg.Username = "admin"
	}
	if cfg.SessionTTL <= 0 {
		cfg.SessionTTL = 12 * time.Hour
	}
	return &Manager{cfg: cfg, sessions: make(map[string]session)}
}

// Enabled reports whether login enforcement is active.
func (m *Manager) Enabled() bool { return m.cfg.Enabled }

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// HandleLogin authenticates the administrator and, on success, sets a session
// cookie. Route: POST /v1/controlplane/auth/login.
func (m *Manager) HandleLogin(w http.ResponseWriter, r *http.Request) {
	if !m.cfg.Enabled {
		writeJSON(w, http.StatusOK, map[string]any{
			"authenticated": true,
			"user":          "developer",
			"authEnabled":   false,
		})
		return
	}

	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Always run bcrypt (even on username mismatch) to keep the response time
	// constant and avoid leaking whether the username was valid.
	passErr := bcrypt.CompareHashAndPassword([]byte(m.cfg.PasswordHash), []byte(req.Password))
	userOK := subtle.ConstantTimeCompare([]byte(req.Username), []byte(m.cfg.Username)) == 1
	if !userOK || passErr != nil {
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	token, err := newToken()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create session")
		return
	}

	m.mu.Lock()
	m.sessions[token] = session{subject: m.cfg.Username, expires: time.Now().Add(m.cfg.SessionTTL)}
	m.mu.Unlock()

	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   m.cfg.Secure,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(m.cfg.SessionTTL.Seconds()),
	})

	writeJSON(w, http.StatusOK, map[string]any{
		"authenticated": true,
		"user":          m.cfg.Username,
		"authEnabled":   true,
	})
}

// HandleLogout invalidates the current session and clears the cookie.
// Route: POST /v1/controlplane/auth/logout.
func (m *Manager) HandleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(SessionCookieName); err == nil {
		m.mu.Lock()
		delete(m.sessions, c.Value)
		m.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   m.cfg.Secure,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})
	writeJSON(w, http.StatusOK, map[string]any{"authenticated": false})
}

// HandleSession reports the caller's authentication status. It never returns
// 401 so the console can probe login state on load without treating it as an
// error. Route: GET /v1/controlplane/auth/session.
func (m *Manager) HandleSession(w http.ResponseWriter, r *http.Request) {
	if !m.cfg.Enabled {
		writeJSON(w, http.StatusOK, map[string]any{
			"authenticated": true,
			"user":          "developer",
			"authEnabled":   false,
		})
		return
	}
	subject := m.validate(r)
	writeJSON(w, http.StatusOK, map[string]any{
		"authenticated": subject != "",
		"user":          subject,
		"authEnabled":   true,
	})
}

// Middleware enforces a valid session on control-plane data endpoints. The
// login/logout/session endpoints, health probes, and the static console assets
// are always allowed through (the SPA renders its own login screen when the
// session probe reports unauthenticated).
func (m *Manager) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !m.cfg.Enabled {
			next.ServeHTTP(w, r)
			return
		}
		p := r.URL.Path
		if !strings.HasPrefix(p, "/v1/controlplane/") || strings.HasPrefix(p, "/v1/controlplane/auth/") {
			next.ServeHTTP(w, r)
			return
		}
		if m.validate(r) == "" {
			writeError(w, http.StatusUnauthorized, "authentication required")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// validate returns the authenticated subject for the request, or "" if the
// session is missing or expired. Expired sessions are pruned lazily.
func (m *Manager) validate(r *http.Request) string {
	c, err := r.Cookie(SessionCookieName)
	if err != nil || c.Value == "" {
		return ""
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[c.Value]
	if !ok {
		return ""
	}
	if time.Now().After(s.expires) {
		delete(m.sessions, c.Value)
		return ""
	}
	return s.subject
}

func newToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
