// Package admin implements the admin-plane authentication and
// authorization model for lwauth operator endpoints.
//
// The admin plane protects endpoints like /v1/admin/cache/invalidate,
// /v1/admin/revoke, /v1/admin/status, and future operator-facing APIs.
// Every admin endpoint shares a single trust model defined here, so
// individual features (revocation, cache flush, audit export) do not
// invent their own auth boundaries.
//
// # Authentication
//
// Two mechanisms are supported (configured independently, composed as OR):
//
//   - mTLS: the admin listener requires client certificates; the
//     middleware extracts the Subject CN or SAN and maps it to an
//     admin identity.
//   - JWT: a signed admin JWT (distinct issuer/audience from data-plane
//     tokens) is presented in the Authorization header. The middleware
//     verifies signature, exp, iss, aud, and extracts claims.
//
// # Authorization
//
// Admin identities carry a set of RBAC verbs. The middleware checks
// that the authenticated identity holds the verb required by the
// endpoint being accessed. Verbs are coarse-grained:
//
//   - read_status
//   - push_config
//   - invalidate_cache
//   - revoke_token
//   - read_audit
//
// # Usage
//
//	cfg := admin.Config{...}
//	mw, err := admin.NewMiddleware(cfg)
//	mux.Handle("/v1/admin/", mw.Require("invalidate_cache", handler))
package admin

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

// Verb is a coarse-grained RBAC permission for admin operations.
type Verb string

const (
	VerbReadStatus      Verb = "read_status"
	VerbPushConfig      Verb = "push_config"
	VerbInvalidateCache Verb = "invalidate_cache"
	VerbRevokeToken     Verb = "revoke_token"
	VerbReadAudit       Verb = "read_audit"
)

// AllVerbs is the complete set of admin RBAC verbs.
var AllVerbs = []Verb{
	VerbReadStatus,
	VerbPushConfig,
	VerbInvalidateCache,
	VerbRevokeToken,
	VerbReadAudit,
}

// Identity represents an authenticated admin caller.
type Identity struct {
	// Subject is the admin's identity (CN from mTLS, sub from JWT).
	Subject string
	// Verbs is the set of RBAC permissions this admin holds.
	Verbs []Verb
	// Source describes how the identity was established ("mtls" or "jwt").
	Source string
}

// HasVerb reports whether the identity holds the given verb.
func (id *Identity) HasVerb(v Verb) bool {
	for _, have := range id.Verbs {
		if have == v || have == "*" {
			return true
		}
	}
	return false
}

// Config configures the admin authentication middleware.
type Config struct {
	// Enabled controls whether admin endpoints are registered.
	// When false, the admin mux returns 404 for all /v1/admin/ paths.
	Enabled bool `json:"enabled" yaml:"enabled"`

	// JWT configures admin JWT authentication.
	JWT *JWTConfig `json:"jwt,omitempty" yaml:"jwt,omitempty"`

	// MTLS configures admin mTLS authentication.
	MTLS *MTLSConfig `json:"mtls,omitempty" yaml:"mtls,omitempty"`

	// Roles maps role names to sets of verbs. Admin identities are
	// assigned roles (via JWT claims or mTLS subject mapping), and
	// the middleware resolves roles to verbs.
	Roles map[string][]Verb `json:"roles,omitempty" yaml:"roles,omitempty"`

	// Logger for admin auth decisions.
	Logger *slog.Logger `json:"-" yaml:"-"`
}

// JWTConfig configures JWT-based admin authentication.
type JWTConfig struct {
	// IssuerURL is the expected `iss` claim.
	IssuerURL string `json:"issuerUrl" yaml:"issuerUrl"`
	// Audience is the expected `aud` claim.
	Audience string `json:"audience" yaml:"audience"`
	// JWKSURL is the URL to fetch signing keys from.
	JWKSURL string `json:"jwksUrl" yaml:"jwksUrl"`
	// RolesClaim is the JWT claim containing the admin's role(s).
	// Defaults to "roles". The claim value may be a string or []string.
	RolesClaim string `json:"rolesClaim,omitempty" yaml:"rolesClaim,omitempty"`
}

// MTLSConfig configures mTLS-based admin authentication.
type MTLSConfig struct {
	// SubjectMapping maps certificate Subject CN (or SAN DNS) to a
	// role name. If a connecting client's cert CN matches a key here,
	// they receive the mapped role.
	SubjectMapping map[string]string `json:"subjectMapping" yaml:"subjectMapping"`
}

// Middleware is the admin auth middleware.
type Middleware struct {
	cfg    Config
	jwkSet jwk.Set
	mu     sync.RWMutex
	log    *slog.Logger
}

// NewMiddleware creates an admin auth middleware from the given config.
func NewMiddleware(cfg Config) (*Middleware, error) {
	if !cfg.Enabled {
		return &Middleware{cfg: cfg}, nil
	}
	if cfg.JWT == nil && cfg.MTLS == nil {
		return nil, errors.New("admin: at least one of jwt or mtls must be configured")
	}
	log := cfg.Logger
	if log == nil {
		log = slog.Default()
	}
	m := &Middleware{cfg: cfg, log: log}
	if cfg.JWT != nil {
		if cfg.JWT.JWKSURL == "" {
			return nil, errors.New("admin: jwt.jwksUrl is required")
		}
		if cfg.JWT.IssuerURL == "" {
			return nil, errors.New("admin: jwt.issuerUrl is required")
		}
		if cfg.JWT.Audience == "" {
			return nil, errors.New("admin: jwt.audience is required")
		}
		if cfg.JWT.RolesClaim == "" {
			cfg.JWT.RolesClaim = "roles"
		}
		// Fetch JWKS eagerly to fail fast on misconfiguration.
		set, err := jwk.Fetch(context.Background(), cfg.JWT.JWKSURL)
		if err != nil {
			return nil, fmt.Errorf("admin: fetch jwks: %w", err)
		}
		m.jwkSet = set
		// Background refresh.
		go m.refreshJWKS()
	}
	return m, nil
}

// refreshJWKS periodically re-fetches the admin JWKS.
func (m *Middleware) refreshJWKS() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		set, err := jwk.Fetch(context.Background(), m.cfg.JWT.JWKSURL)
		if err != nil {
			m.log.Warn("admin: jwks refresh failed", "err", err)
			continue
		}
		m.mu.Lock()
		m.jwkSet = set
		m.mu.Unlock()
	}
}

// Require returns an http.Handler that authenticates the caller,
// checks they hold the given verb, and then calls the inner handler.
// On auth failure it returns 401 or 403 with a JSON error body.
func (m *Middleware) Require(verb Verb, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !m.cfg.Enabled {
			writeAdminError(w, http.StatusNotFound, "admin endpoints disabled")
			return
		}
		id, err := m.authenticate(r)
		if err != nil {
			m.log.Warn("admin: auth failed",
				"err", err,
				"remote", r.RemoteAddr,
				"path", r.URL.Path,
			)
			writeAdminError(w, http.StatusUnauthorized, "authentication required")
			return
		}
		if !id.HasVerb(verb) {
			m.log.Warn("admin: forbidden",
				"subject", id.Subject,
				"verb", verb,
				"has", id.Verbs,
				"path", r.URL.Path,
			)
			writeAdminError(w, http.StatusForbidden, fmt.Sprintf("verb %q not granted", verb))
			return
		}
		// Attach identity to context for downstream handlers.
		ctx := context.WithValue(r.Context(), adminIdentityKey{}, id)
		m.log.Info("admin: authorized",
			"subject", id.Subject,
			"verb", verb,
			"source", id.Source,
			"path", r.URL.Path,
		)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// authenticate tries JWT first, then mTLS. Returns the first success.
func (m *Middleware) authenticate(r *http.Request) (*Identity, error) {
	// Try JWT from Authorization header.
	if m.cfg.JWT != nil {
		if id, err := m.authenticateJWT(r); err == nil {
			return id, nil
		}
	}
	// Try mTLS from TLS peer certificate.
	if m.cfg.MTLS != nil {
		if id, err := m.authenticateMTLS(r); err == nil {
			return id, nil
		}
	}
	return nil, errors.New("no valid credential")
}

// authenticateJWT verifies the Bearer token as an admin JWT.
func (m *Middleware) authenticateJWT(r *http.Request) (*Identity, error) {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return nil, errors.New("no authorization header")
	}
	parts := strings.SplitN(auth, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return nil, errors.New("invalid authorization scheme")
	}
	tokenStr := parts[1]

	m.mu.RLock()
	set := m.jwkSet
	m.mu.RUnlock()

	tok, err := jwt.Parse([]byte(tokenStr),
		jwt.WithKeySet(set, jws.WithInferAlgorithmFromKey(true)),
		jwt.WithIssuer(m.cfg.JWT.IssuerURL),
		jwt.WithAudience(m.cfg.JWT.Audience),
		jwt.WithValidate(true),
	)
	if err != nil {
		return nil, fmt.Errorf("jwt verify: %w", err)
	}

	sub := tok.Subject()
	roles := extractRoles(tok, m.cfg.JWT.RolesClaim)
	verbs := m.resolveVerbs(roles)

	return &Identity{
		Subject: sub,
		Verbs:   verbs,
		Source:  "jwt",
	}, nil
}

// authenticateMTLS extracts identity from the TLS peer certificate.
func (m *Middleware) authenticateMTLS(r *http.Request) (*Identity, error) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return nil, errors.New("no client certificate")
	}
	cert := r.TLS.PeerCertificates[0]
	cn := cert.Subject.CommonName

	role, ok := m.cfg.MTLS.SubjectMapping[cn]
	if !ok {
		// Try SAN DNS names.
		for _, dns := range cert.DNSNames {
			if r, found := m.cfg.MTLS.SubjectMapping[dns]; found {
				role = r
				ok = true
				break
			}
		}
	}
	if !ok {
		return nil, fmt.Errorf("unmapped subject: %s", cn)
	}

	verbs := m.resolveVerbs([]string{role})
	return &Identity{
		Subject: cn,
		Verbs:   verbs,
		Source:  "mtls",
	}, nil
}

// resolveVerbs maps role names to the union of their verbs.
func (m *Middleware) resolveVerbs(roles []string) []Verb {
	seen := map[Verb]bool{}
	var result []Verb
	for _, role := range roles {
		for _, v := range m.cfg.Roles[role] {
			if !seen[v] {
				seen[v] = true
				result = append(result, v)
			}
		}
	}
	return result
}

// extractRoles reads the roles claim from a JWT. Handles both string
// and []string shapes.
func extractRoles(tok jwt.Token, claim string) []string {
	v, ok := tok.Get(claim)
	if !ok {
		return nil
	}
	switch val := v.(type) {
	case string:
		return []string{val}
	case []any:
		var roles []string
		for _, item := range val {
			if s, ok := item.(string); ok {
				roles = append(roles, s)
			}
		}
		return roles
	case []string:
		return val
	default:
		return nil
	}
}

// IdentityFromContext retrieves the admin Identity from the request
// context. Returns nil if the request was not authenticated.
func IdentityFromContext(ctx context.Context) *Identity {
	id, _ := ctx.Value(adminIdentityKey{}).(*Identity)
	return id
}

type adminIdentityKey struct{}

// writeAdminError writes a JSON error response.
func writeAdminError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// VerifyPeerCert is a tls.Config.VerifyPeerCertificate callback that
// can be used on a dedicated admin listener to enforce that client
// certs chain to a given CA pool. This is complementary to Go's
// built-in tls.RequireAndVerifyClientCert — it lets you use a
// *different* CA pool for the admin listener than the data-plane
// listener.
func VerifyPeerCert(pool *x509.CertPool) func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return errors.New("admin: no client certificate")
		}
		cert, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return fmt.Errorf("admin: parse cert: %w", err)
		}
		opts := x509.VerifyOptions{
			Roots:     pool,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		}
		if _, err := cert.Verify(opts); err != nil {
			return fmt.Errorf("admin: verify cert: %w", err)
		}
		return nil
	}
}
