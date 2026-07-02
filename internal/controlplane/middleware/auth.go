// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

// Package middleware provides HTTP middleware for the control plane API,
// including authentication, authorization, audit logging, and rate limiting.
package middleware

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// contextKey is a private type for context keys in this package.
type contextKey int

const (
	ctxIdentity contextKey = iota
)

// Identity represents an authenticated API caller.
type Identity struct {
	Subject string   // username or service account
	Groups  []string // groups/roles the subject belongs to
	Source  string   // "bearer", "mtls", "serviceaccount"
}

// IdentityFromContext returns the authenticated identity, or nil if unauthenticated.
func IdentityFromContext(ctx context.Context) *Identity {
	id, _ := ctx.Value(ctxIdentity).(*Identity)
	return id
}

// Role defines an RBAC role with allowed actions.
type Role struct {
	Name       string
	AllowRead  bool // GET requests
	AllowWrite bool // POST/PUT/DELETE requests
	AllowAdmin bool // cluster management, config push
}

// RBACConfig configures the RBAC middleware.
type RBACConfig struct {
	// Enabled turns on auth enforcement. When false, all requests pass through.
	Enabled bool

	// BearerTokens maps tokens to identities (simple token auth for dev/testing).
	// In production, use ServiceAccountAuth or mTLS instead.
	BearerTokens map[string]Identity

	// ServiceAccountHeader is the header containing the k8s service account
	// identity (set by the ingress/API gateway after validation).
	ServiceAccountHeader string

	// Roles maps group names to roles.
	Roles map[string]Role

	// DefaultRole is applied to authenticated users with no matching group.
	DefaultRole Role
}

// DefaultRBACConfig returns a sensible default config (auth disabled, dev mode).
func DefaultRBACConfig() RBACConfig {
	return RBACConfig{
		Enabled:              false,
		ServiceAccountHeader: "X-Forwarded-User",
		Roles: map[string]Role{
			"admin":    {Name: "admin", AllowRead: true, AllowWrite: true, AllowAdmin: true},
			"operator": {Name: "operator", AllowRead: true, AllowWrite: true, AllowAdmin: false},
			"viewer":   {Name: "viewer", AllowRead: true, AllowWrite: false, AllowAdmin: false},
		},
		DefaultRole: Role{Name: "viewer", AllowRead: true, AllowWrite: false, AllowAdmin: false},
	}
}

// Auth returns middleware that authenticates requests via bearer token or
// service account header. Unauthenticated requests to protected endpoints
// receive 401. Unauthorized requests receive 403.
func Auth(cfg RBACConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip auth if disabled (dev mode).
			if !cfg.Enabled {
				next.ServeHTTP(w, r)
				return
			}

			// Skip health/readiness probes.
			if r.URL.Path == "/healthz" || r.URL.Path == "/readyz" {
				next.ServeHTTP(w, r)
				return
			}

			// Attempt authentication.
			identity := authenticate(r, cfg)
			if identity == nil {
				writeAuthError(w, http.StatusUnauthorized, "authentication required")
				return
			}

			// Check authorization.
			if !authorize(identity, r, cfg) {
				slog.Warn("authorization denied",
					"subject", identity.Subject,
					"method", r.Method,
					"path", r.URL.Path,
				)
				writeAuthError(w, http.StatusForbidden, "insufficient permissions")
				return
			}

			// Attach identity to context.
			ctx := context.WithValue(r.Context(), ctxIdentity, identity)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// authenticate extracts and validates caller identity from the request.
func authenticate(r *http.Request, cfg RBACConfig) *Identity {
	// Try bearer token first.
	if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
		token := strings.TrimPrefix(auth, "Bearer ")
		for knownToken, id := range cfg.BearerTokens {
			if subtle.ConstantTimeCompare([]byte(token), []byte(knownToken)) == 1 {
				idCopy := id
				idCopy.Source = "bearer"
				return &idCopy
			}
		}
		return nil // invalid token
	}

	// Try service account header (from API gateway / ingress).
	if cfg.ServiceAccountHeader != "" {
		if user := r.Header.Get(cfg.ServiceAccountHeader); user != "" {
			return &Identity{
				Subject: user,
				Groups:  parseGroups(r.Header.Get("X-Forwarded-Groups")),
				Source:  "serviceaccount",
			}
		}
	}

	// Try mTLS peer certificate.
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		cert := r.TLS.PeerCertificates[0]
		return &Identity{
			Subject: cert.Subject.CommonName,
			Groups:  cert.Subject.Organization,
			Source:  "mtls",
		}
	}

	return nil
}

// authorize checks if the identity has permission for the request.
func authorize(id *Identity, r *http.Request, cfg RBACConfig) bool {
	role := resolveRole(id, cfg)

	switch {
	case r.Method == http.MethodGet || r.Method == http.MethodHead:
		return role.AllowRead
	case isAdminPath(r.URL.Path):
		return role.AllowAdmin
	default:
		return role.AllowWrite
	}
}

// resolveRole returns the highest-privilege role for the identity.
func resolveRole(id *Identity, cfg RBACConfig) Role {
	best := cfg.DefaultRole
	for _, group := range id.Groups {
		if role, ok := cfg.Roles[group]; ok {
			if rolePriority(role) > rolePriority(best) {
				best = role
			}
		}
	}
	return best
}

func rolePriority(r Role) int {
	switch {
	case r.AllowAdmin:
		return 3
	case r.AllowWrite:
		return 2
	case r.AllowRead:
		return 1
	default:
		return 0
	}
}

// isAdminPath returns true for paths that require admin privileges.
func isAdminPath(path string) bool {
	adminPaths := []string{
		"/v1/controlplane/clusters",
		"/v1/controlplane/instances/create",
	}
	for _, p := range adminPaths {
		if strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}

func parseGroups(header string) []string {
	if header == "" {
		return nil
	}
	parts := strings.Split(header, ",")
	groups := make([]string, 0, len(parts))
	for _, p := range parts {
		if g := strings.TrimSpace(p); g != "" {
			groups = append(groups, g)
		}
	}
	return groups
}

func writeAuthError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// AuditLog returns middleware that records all API mutations to an audit sink.
func AuditLog(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()

			// Wrap response writer to capture status code.
			rw := &responseWriter{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(rw, r)

			// Only audit mutations (POST, PUT, DELETE, PATCH).
			if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
				return
			}

			identity := IdentityFromContext(r.Context())
			subject := "anonymous"
			if identity != nil {
				subject = identity.Subject
			}

			logger.Info("api.audit",
				"method", r.Method,
				"path", r.URL.Path,
				"subject", subject,
				"source", sourceFromIdentity(identity),
				"status", rw.status,
				"duration_ms", time.Since(start).Milliseconds(),
				"remote_addr", r.RemoteAddr,
				"user_agent", r.Header.Get("User-Agent"),
			)
		})
	}
}

func sourceFromIdentity(id *Identity) string {
	if id == nil {
		return "none"
	}
	return id.Source
}

// responseWriter wraps http.ResponseWriter to capture the status code.
type responseWriter struct {
	http.ResponseWriter
	status int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.status = code
	rw.ResponseWriter.WriteHeader(code)
}
