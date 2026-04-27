// Package session — AES-256-GCM cookie-backed Store implementation.
//
// The wire format of one cookie value is:
//
//	base64url( nonce(12) || ciphertext || tag(16) )
//
// where the plaintext is the JSON-encoded Session. Authentication and
// integrity are provided by GCM's AEAD tag, so we do not need a separate
// HMAC. The 32-byte secret used as AES-256 key is derived from the
// caller-supplied secret via SHA-256 so callers can pass any
// high-entropy string (typical: a 32+-byte random hex from a K8s Secret).
//
// One quirk: cookies have a per-cookie size limit of ~4 KiB on most
// browsers. If a session would encode to more than CookieMaxBytes (3.5
// KiB by default to leave room for other cookies + headers), Save fails
// loudly so deployments switch to a server-side store instead of
// silently truncating.
package session

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"
)

// CookieStoreConfig configures a CookieStore.
type CookieStoreConfig struct {
	// Name is the cookie name. Defaults to "_lwauth_session".
	Name string

	// Secret is hashed (SHA-256) to derive the AES-256 key. MUST be at
	// least 16 bytes and SHOULD be ≥32 bytes of base64/hex random data.
	Secret []byte

	// Path scopes the cookie. Defaults to "/".
	Path string

	// Domain optionally widens the cookie to a parent domain.
	Domain string

	// Secure marks the cookie as HTTPS-only. Defaults to true; set
	// false explicitly for local-dev plaintext.
	Secure *bool

	// SameSite. Defaults to http.SameSiteLaxMode (works with the OAuth2
	// redirect-back flow, blocks most CSRF). Use Strict for non-OAuth
	// session cookies, None when embedded across origins (requires
	// Secure=true).
	SameSite http.SameSite

	// HTTPOnly. Defaults to true (no JS access).
	HTTPOnly *bool

	// MaxAge is how long the cookie lives in the browser. Defaults to
	// 8h. Independent of Session.Expiry, which we also enforce on Load.
	MaxAge time.Duration

	// CookieMaxBytes guards against >4KB cookies. Defaults to 3500.
	CookieMaxBytes int
}

// CookieStore is the default Store: stateless, AEAD-encrypted cookies.
type CookieStore struct {
	cfg  CookieStoreConfig
	aead cipher.AEAD
}

// NewCookieStore validates cfg and returns a ready-to-use CookieStore.
func NewCookieStore(cfg CookieStoreConfig) (*CookieStore, error) {
	if len(cfg.Secret) < 16 {
		return nil, errors.New("session: cookie secret must be at least 16 bytes")
	}
	if cfg.Name == "" {
		cfg.Name = "_lwauth_session"
	}
	if cfg.Path == "" {
		cfg.Path = "/"
	}
	if cfg.SameSite == 0 {
		cfg.SameSite = http.SameSiteLaxMode
	}
	if cfg.HTTPOnly == nil {
		t := true
		cfg.HTTPOnly = &t
	}
	if cfg.Secure == nil {
		t := true
		cfg.Secure = &t
	}
	if cfg.MaxAge == 0 {
		cfg.MaxAge = 8 * time.Hour
	}
	if cfg.CookieMaxBytes == 0 {
		cfg.CookieMaxBytes = 3500
	}

	sum := sha256.Sum256(cfg.Secret)
	block, err := aes.NewCipher(sum[:])
	if err != nil {
		return nil, fmt.Errorf("session: aes init: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("session: gcm init: %w", err)
	}
	return &CookieStore{cfg: cfg, aead: gcm}, nil
}

// Save serializes s, encrypts it, and writes the Set-Cookie header.
func (c *CookieStore) Save(w http.ResponseWriter, _ *http.Request, s *Session) error {
	if s == nil {
		return errors.New("session: Save with nil Session")
	}
	if s.IssuedAt.IsZero() {
		s.IssuedAt = time.Now().UTC()
	}
	if s.Expiry.IsZero() {
		s.Expiry = s.IssuedAt.Add(c.cfg.MaxAge)
	}

	plain, err := json.Marshal(s)
	if err != nil {
		return fmt.Errorf("session: encode: %w", err)
	}

	nonce := make([]byte, c.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("session: rand: %w", err)
	}
	ct := c.aead.Seal(nonce, nonce, plain, []byte(c.cfg.Name))
	val := base64.RawURLEncoding.EncodeToString(ct)
	if len(val) > c.cfg.CookieMaxBytes {
		return fmt.Errorf("session: encoded cookie is %d bytes, exceeds CookieMaxBytes=%d (switch to a server-side store)", len(val), c.cfg.CookieMaxBytes)
	}

	http.SetCookie(w, c.newCookie(val, c.cfg.MaxAge))
	return nil
}

// Load decodes the cookie if present. Returns (nil, nil) if absent.
func (c *CookieStore) Load(r *http.Request) (*Session, error) {
	ck, err := r.Cookie(c.cfg.Name)
	if err != nil {
		return nil, nil //nolint:nilnil // absence is not an error
	}
	if ck.Value == "" {
		return nil, nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(ck.Value)
	if err != nil {
		return nil, fmt.Errorf("session: cookie b64: %w", err)
	}
	if len(raw) < c.aead.NonceSize() {
		return nil, errors.New("session: cookie truncated")
	}
	nonce, ct := raw[:c.aead.NonceSize()], raw[c.aead.NonceSize():]
	plain, err := c.aead.Open(nil, nonce, ct, []byte(c.cfg.Name))
	if err != nil {
		// Tampered, stale-key, or never one of ours. Treat as no session
		// rather than 500 — callers will start a fresh login.
		return nil, fmt.Errorf("session: cookie auth failed: %w", err)
	}
	var s Session
	if err := json.Unmarshal(plain, &s); err != nil {
		return nil, fmt.Errorf("session: decode: %w", err)
	}
	if !s.Valid(time.Now()) {
		return nil, nil
	}
	return &s, nil
}

// Clear writes an expired Set-Cookie header.
func (c *CookieStore) Clear(w http.ResponseWriter, _ *http.Request) error {
	http.SetCookie(w, c.newCookie("", -1*time.Second))
	return nil
}

// newCookie centralises attribute-setting so Save/Clear stay in sync.
func (c *CookieStore) newCookie(val string, maxAge time.Duration) *http.Cookie {
	ck := &http.Cookie{
		Name:     c.cfg.Name,
		Value:    val,
		Path:     c.cfg.Path,
		Domain:   c.cfg.Domain,
		Secure:   *c.cfg.Secure,
		HttpOnly: *c.cfg.HTTPOnly,
		SameSite: c.cfg.SameSite,
	}
	if maxAge > 0 {
		ck.MaxAge = int(maxAge.Seconds())
		ck.Expires = time.Now().Add(maxAge)
	} else if maxAge < 0 {
		ck.MaxAge = -1
		ck.Expires = time.Unix(0, 0)
	}
	return ck
}

// Name returns the cookie name in use; handy for tests and middlewares.
func (c *CookieStore) Name() string { return c.cfg.Name }

// Compile-time guard.
var _ Store = (*CookieStore)(nil)
