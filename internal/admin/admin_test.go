// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMiddleware_Disabled(t *testing.T) {
	mw, err := NewMiddleware(Config{Enabled: false})
	if err != nil {
		t.Fatal(err)
	}
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	})
	handler := mw.Require(VerbReadStatus, inner)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/v1/admin/status", nil)
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestMiddleware_NoCredential(t *testing.T) {
	mw := &Middleware{
		cfg: Config{
			Enabled: true,
			MTLS: &MTLSConfig{
				SubjectMapping: map[string]string{"admin-bot": "admin"},
			},
			Roles: map[string][]Verb{"admin": {VerbReadStatus}},
		},
		log: testLogger(t),
	}
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	})
	handler := mw.Require(VerbReadStatus, inner)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/v1/admin/status", nil)
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestMiddleware_MTLS_Success(t *testing.T) {
	mw := &Middleware{
		cfg: Config{
			Enabled: true,
			MTLS: &MTLSConfig{
				SubjectMapping: map[string]string{"admin-bot": "operator"},
			},
			Roles: map[string][]Verb{
				"operator": {VerbReadStatus, VerbInvalidateCache},
			},
		},
		log: testLogger(t),
	}
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := IdentityFromContext(r.Context())
		if id == nil {
			t.Fatal("expected identity in context")
		}
		if id.Subject != "admin-bot" {
			t.Errorf("expected subject admin-bot, got %s", id.Subject)
		}
		w.WriteHeader(200)
	})
	handler := mw.Require(VerbReadStatus, inner)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/v1/admin/status", nil)
	r.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{
			peerCert("admin-bot"),
		},
	}
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestMiddleware_MTLS_Forbidden(t *testing.T) {
	mw := &Middleware{
		cfg: Config{
			Enabled: true,
			MTLS: &MTLSConfig{
				SubjectMapping: map[string]string{"admin-bot": "readonly"},
			},
			Roles: map[string][]Verb{
				"readonly": {VerbReadStatus},
			},
		},
		log: testLogger(t),
	}
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	})
	// Request invalidate_cache but identity only has read_status.
	handler := mw.Require(VerbInvalidateCache, inner)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/v1/admin/cache/invalidate", nil)
	r.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{
			peerCert("admin-bot"),
		},
	}
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", w.Code)
	}
	var body map[string]string
	_ = json.NewDecoder(w.Body).Decode(&body)
	if body["error"] == "" {
		t.Error("expected error message in response body")
	}
}

func TestMiddleware_MTLS_UnmappedSubject(t *testing.T) {
	mw := &Middleware{
		cfg: Config{
			Enabled: true,
			MTLS: &MTLSConfig{
				SubjectMapping: map[string]string{"admin-bot": "admin"},
			},
			Roles: map[string][]Verb{"admin": {VerbReadStatus}},
		},
		log: testLogger(t),
	}
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	})
	handler := mw.Require(VerbReadStatus, inner)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/v1/admin/status", nil)
	r.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{
			peerCert("unknown-client"),
		},
	}
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestIdentity_HasVerb_Wildcard(t *testing.T) {
	id := &Identity{Subject: "superadmin", Verbs: []Verb{"*"}}
	for _, v := range AllVerbs {
		if !id.HasVerb(v) {
			t.Errorf("wildcard identity should have verb %s", v)
		}
	}
}

func TestIdentity_HasVerb_Specific(t *testing.T) {
	id := &Identity{Subject: "reader", Verbs: []Verb{VerbReadStatus, VerbReadAudit}}
	if !id.HasVerb(VerbReadStatus) {
		t.Error("expected read_status")
	}
	if id.HasVerb(VerbInvalidateCache) {
		t.Error("should not have invalidate_cache")
	}
}

// --- helpers ---------------------------------------------------------------

func peerCert(cn string) *x509.Certificate {
	return &x509.Certificate{
		Subject: pkix.Name{CommonName: cn},
	}
}

func testLogger(_ *testing.T) *slog.Logger {
	return slog.Default()
}
