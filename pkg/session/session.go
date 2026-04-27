// Package session defines the cross-module abstraction for browser sessions
// established by interactive identifiers (OAuth2 auth-code, SAML, ...).
//
// A Session is the server-side view of "who this browser is". It is
// minted by the OAuth2 callback handler after a successful token exchange
// and is consulted by the OAuth2 identifier on every subsequent request.
//
// The Store is intentionally narrow so we can swap the default cookie
// backend for a Redis / database backend without touching identifier
// code. See [CookieStore] for the default.
package session

import (
	"net/http"
	"time"
)

// Session is the server-side view of an established browser identity.
// All fields are optional except Subject; modules MUST be tolerant of an
// older session being decoded that lacks a newly added field.
type Session struct {
	// Subject is the canonical user identifier (typically the IdP's
	// `sub` claim).
	Subject string `json:"sub,omitempty"`

	// Email is convenient for display + RBAC on email-domain rules.
	Email string `json:"email,omitempty"`

	// Claims is the full set of id_token claims minus the ones the
	// session already promotes to top-level (sub, email, exp).
	Claims map[string]any `json:"claims,omitempty"`

	// IDToken is the raw OIDC id_token the IdP returned. Kept so the
	// upstream service can verify it itself if it wants.
	IDToken string `json:"idt,omitempty"`

	// AccessToken / RefreshToken belong here only when the AuthConfig
	// opted into "passUpstream: tokens". They are otherwise dropped on
	// the way out of the OAuth2 callback for blast-radius reasons.
	AccessToken  string `json:"at,omitempty"`
	RefreshToken string `json:"rt,omitempty"`

	// IssuedAt is when this session was minted.
	IssuedAt time.Time `json:"iat"`

	// Expiry is when the session itself expires (separate from any
	// access-token expiry; we re-derive AT expiry from the token).
	Expiry time.Time `json:"exp"`

	// Provider names the OAuth2 module that minted this session.
	// Surfaced in audit logs and metrics labels.
	Provider string `json:"prov,omitempty"`
}

// Valid reports whether s is non-nil and not past its Expiry.
func (s *Session) Valid(now time.Time) bool {
	return s != nil && s.Subject != "" && (s.Expiry.IsZero() || now.Before(s.Expiry))
}

// Store persists Sessions across requests. Implementations MUST be safe
// for concurrent use. Cookie-backed implementations carry the entire
// session in the cookie value; server-side implementations just store an
// opaque ID.
type Store interface {
	// Save mints (or refreshes) the session for r and writes whatever
	// transport-level artifact (Set-Cookie header, server-side row, ...)
	// the implementation needs.
	Save(w http.ResponseWriter, r *http.Request, s *Session) error

	// Load returns the session attached to r, or (nil, nil) if none is
	// present. A non-nil error means a session was present but corrupt
	// — callers SHOULD treat that as "log this user out" and not retry.
	Load(r *http.Request) (*Session, error)

	// Clear removes the session from r (typically a Set-Cookie with
	// MaxAge<0 or a server-side delete).
	Clear(w http.ResponseWriter, r *http.Request) error
}
