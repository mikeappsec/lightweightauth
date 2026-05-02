// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

// Package session — in-memory server-side store. Useful when sessions
// outgrow the 4 KiB cookie ceiling but you don't want a Redis dependency
// (Redis ships in M7 in lightweightauth-plugins).
//
// Wire model: the cookie carries a 256-bit opaque session ID (URL-safe
// base64). The MemoryStore maps that ID to the Session struct. Eviction
// is by expiry: sessions past their Expiry are pruned on Load and on a
// configurable janitor timer.
package session

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// MemoryStoreConfig parameterises a MemoryStore.
type MemoryStoreConfig struct {
	Name     string        // cookie name; default "_lwauth_sid"
	Path     string        // default "/"
	Domain   string
	Secure   *bool         // default true
	HTTPOnly *bool         // default true
	SameSite http.SameSite // default Lax
	MaxAge   time.Duration // default 8h
	// JanitorInterval controls how often expired sessions are pruned.
	// Zero disables (the test path leaves it disabled and prunes on Load).
	JanitorInterval time.Duration
}

// MemoryStore is the reference server-side Store. Safe for concurrent use.
type MemoryStore struct {
	cfg     MemoryStoreConfig
	mu      sync.Mutex
	entries map[string]*Session

	stop chan struct{}
}

// NewMemoryStore returns a configured MemoryStore. Call Close() to stop
// the janitor goroutine; otherwise it is harmless and GC'd with the store.
func NewMemoryStore(cfg MemoryStoreConfig) *MemoryStore {
	if cfg.Name == "" {
		cfg.Name = "_lwauth_sid"
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
	s := &MemoryStore{cfg: cfg, entries: map[string]*Session{}, stop: make(chan struct{})}
	if cfg.JanitorInterval > 0 {
		go s.janitor()
	}
	return s
}

// Save mints (or refreshes) a session. The session ID lives in the cookie;
// the Session payload lives in memory.
func (m *MemoryStore) Save(w http.ResponseWriter, r *http.Request, s *Session) error {
	if s == nil {
		return errors.New("session: Save with nil Session")
	}
	now := time.Now().UTC()
	if s.IssuedAt.IsZero() {
		s.IssuedAt = now
	}
	if s.Expiry.IsZero() {
		s.Expiry = s.IssuedAt.Add(m.cfg.MaxAge)
	}

	// Reuse the existing SID if present so refresh-token rotation
	// doesn't churn IDs (helpful for audit-log continuity).
	sid := ""
	if ck, err := r.Cookie(m.cfg.Name); err == nil && ck.Value != "" {
		sid = ck.Value
	}
	if sid == "" {
		var err error
		sid, err = newSID()
		if err != nil {
			return fmt.Errorf("session: sid: %w", err)
		}
	}
	m.mu.Lock()
	m.entries[sid] = s
	m.mu.Unlock()

	http.SetCookie(w, m.newCookie(sid, m.cfg.MaxAge))
	return nil
}

// Load returns the session attached to r (or nil if absent / expired).
func (m *MemoryStore) Load(r *http.Request) (*Session, error) {
	ck, err := r.Cookie(m.cfg.Name)
	if err != nil || ck.Value == "" {
		return nil, nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.entries[ck.Value]
	if !ok {
		return nil, nil
	}
	if !s.Valid(time.Now()) {
		delete(m.entries, ck.Value)
		return nil, nil
	}
	return s, nil
}

// Clear removes the server-side row and writes an expired cookie.
func (m *MemoryStore) Clear(w http.ResponseWriter, r *http.Request) error {
	if ck, err := r.Cookie(m.cfg.Name); err == nil && ck.Value != "" {
		m.mu.Lock()
		delete(m.entries, ck.Value)
		m.mu.Unlock()
	}
	http.SetCookie(w, m.newCookie("", -1*time.Second))
	return nil
}

// Close stops the janitor goroutine (idempotent).
func (m *MemoryStore) Close() {
	select {
	case <-m.stop:
		return
	default:
		close(m.stop)
	}
}

// Len reports the current number of stored sessions (test helper).
func (m *MemoryStore) Len() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.entries)
}

func (m *MemoryStore) janitor() {
	t := time.NewTicker(m.cfg.JanitorInterval)
	defer t.Stop()
	for {
		select {
		case <-m.stop:
			return
		case now := <-t.C:
			m.mu.Lock()
			for sid, s := range m.entries {
				if !s.Valid(now) {
					delete(m.entries, sid)
				}
			}
			m.mu.Unlock()
		}
	}
}

func (m *MemoryStore) newCookie(val string, maxAge time.Duration) *http.Cookie {
	ck := &http.Cookie{
		Name:     m.cfg.Name,
		Value:    val,
		Path:     m.cfg.Path,
		Domain:   m.cfg.Domain,
		Secure:   *m.cfg.Secure,
		HttpOnly: *m.cfg.HTTPOnly,
		SameSite: m.cfg.SameSite,
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

func newSID() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

var _ Store = (*MemoryStore)(nil)
