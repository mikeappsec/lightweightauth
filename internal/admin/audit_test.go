// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/mikeappsec/lightweightauth/pkg/observability/audit"
)

// auditPeerCert builds a minimal client certificate imitating the mTLS
// admin-bot used by the rest of the admin tests. Subject mapping in
// testMW grants operator role for the "admin-bot" CN.
func auditPeerCert(cn string) *x509.Certificate {
	return &x509.Certificate{Subject: pkix.Name{CommonName: cn}}
}

func resetRing(t *testing.T) {
	t.Helper()
	audit.ResetDefaultRecentRing()
}

func TestHandleAuditRecent_EmptyByDefault(t *testing.T) {
	resetRing(t)
	mw := testMW(t, VerbReadAudit)
	mux := NewAdminMux(mw, &AdminDeps{})

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/v1/admin/audit/recent", nil)
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{auditPeerCert("admin-bot")}}
	mux.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var got []audit.Event
	if err := json.NewDecoder(w.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("empty ring returned %d events, want 0", len(got))
	}
}

func TestHandleAuditRecent_ReturnsRedactedEvents(t *testing.T) {
	resetRing(t)
	ring := audit.DefaultRecentRing()
	ring.Record(context.Background(), &audit.Event{
		Timestamp:  time.Now(),
		Tenant:    "acme",
		Subject:   "raw-pii@example.com", // will be hashed on store
		Decision:  "deny",
		Authorizer: "rbac",
		Method:    "GET",
		Path:      "/invoices",
	})

	mw := testMW(t, VerbReadAudit)
	mux := NewAdminMux(mw, &AdminDeps{})

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/v1/admin/audit/recent", nil)
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{auditPeerCert("admin-bot")}}
	mux.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var got []audit.Event
	if err := json.NewDecoder(w.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 event, got %d", len(got))
	}
	if got[0].Subject == "raw-pii@example.com" {
		t.Errorf("audit/recent returned raw subject PII over the wire")
	}
	if got[0].Subject == "" {
		t.Errorf("audit/recent dropped subject; want HMAC hash")
	}
	if got[0].Tenant != "acme" || got[0].Path != "/invoices" {
		t.Errorf("non-PII fields stripped: %+v", got[0])
	}
}

func TestHandleAuditRecent_QueryFiltersAndLimit(t *testing.T) {
	resetRing(t)
	ring := audit.DefaultRecentRing()
	ring.Record(context.Background(), &audit.Event{Tenant: "acme", Decision: "allow", Authorizer: "rbac"})
	ring.Record(context.Background(), &audit.Event{Tenant: "acme", Decision: "deny", Authorizer: "rbac"})
	ring.Record(context.Background(), &audit.Event{Tenant: "other", Decision: "deny", Authorizer: "opa"})

	mw := testMW(t, VerbReadAudit)
	mux := NewAdminMux(mw, &AdminDeps{})

	// tenant=acme&verdict=deny should return exactly 1 event
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/v1/admin/audit/recent?tenant=acme&verdict=deny", nil)
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{auditPeerCert("admin-bot")}}
	mux.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var got []audit.Event
	if err := json.NewDecoder(w.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got) != 1 {
		t.Errorf("filtered query returned %d, want 1", len(got))
	}

	// limit=2 returns at most 2 of the 3 stored events
	w2 := httptest.NewRecorder()
	r2 := httptest.NewRequest("GET", "/v1/admin/audit/recent?limit=2", nil)
	r2.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{auditPeerCert("admin-bot")}}
	mux.ServeHTTP(w2, r2)
	var got2 []audit.Event
	if err := json.NewDecoder(w2.Body).Decode(&got2); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got2) != 2 {
		t.Errorf("limit=2 returned %d, want 2", len(got2))
	}
}

func TestHandleAuditRecent_RejectsNonGet(t *testing.T) {
	resetRing(t)
	mw := testMW(t, VerbReadAudit)
	mux := NewAdminMux(mw, &AdminDeps{})

	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/v1/admin/audit/recent", bytes.NewBufferString(`{}`))
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{auditPeerCert("admin-bot")}}
	mux.ServeHTTP(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST returned %d, want 405", w.Code)
	}
}

func TestHandleAuditRecent_UnauthorizedWithoutVerb(t *testing.T) {
	resetRing(t)
	// Middleware configured with read_status only — no read_audit verb
	mw := testMW(t, VerbReadStatus)
	mux := NewAdminMux(mw, &AdminDeps{})

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/v1/admin/audit/recent", nil)
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{auditPeerCert("admin-bot")}}
	mux.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Errorf("missing-verb request returned %d, want 403", w.Code)
	}
}

func TestHandleAuditQuery_StubReplacedWithRing(t *testing.T) {
	resetRing(t)
	ring := audit.DefaultRecentRing()
	ring.Record(context.Background(), &audit.Event{Tenant: "acme", Decision: "deny"})

	mw := testMW(t, VerbReadAudit)
	mux := NewAdminMux(mw, &AdminDeps{})

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/v1/admin/audit", nil)
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{auditPeerCert("admin-bot")}}
	mux.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	// /v1/admin/audit returns a wrapper, not the bare array shape used
	// by /v1/admin/audit/recent. Verify the stub message is gone.
	if bytes.Contains(w.Body.Bytes(), []byte("not yet implemented")) {
		t.Errorf("audit query returned stub message: %s", w.Body.String())
	}
	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp["scope"] != "in_memory_ring" {
		t.Errorf("scope = %v, want in_memory_ring", resp["scope"])
	}
	evs, _ := resp["events"].([]any)
	if len(evs) != 1 {
		t.Errorf("events length = %d, want 1", len(evs))
	}
	count, _ := resp["count"].(float64)
	if count != 1 {
		t.Errorf("count = %v, want 1", count)
	}
}

func TestParseRecentLimit(t *testing.T) {
	cases := []struct {
		query string
		want  int
	}{
		{"", defaultRecentLimit},
		{"?limit=5", 5},
		{"?limit=0", defaultRecentLimit},
		{"?limit=-1", defaultRecentLimit},
		{"?limit=abc", defaultRecentLimit},
		{"?limit=99999", maxRecentLimit}, // clamped
	}
	for i, c := range cases {
		r := httptest.NewRequest("GET", "/v1/admin/audit/recent"+c.query, nil)
		if got := parseRecentLimit(r); got != c.want {
			t.Errorf("case %d (%q): got %d, want %d", i, c.query, got, c.want)
		}
	}
}

func TestValidateRecentField(t *testing.T) {
	if validateRecentField("", 10) != "" {
		t.Errorf("empty input should return empty")
	}
	if validateRecentField("ok", 10) != "ok" {
		t.Errorf("valid ASCII should pass through")
	}
	if validateRecentField("too-long", 2) != "" {
		t.Errorf("overlong input should reject")
	}
	if validateRecentField("español", 10) != "" {
		t.Errorf("non-ASCII input should reject")
	}
}