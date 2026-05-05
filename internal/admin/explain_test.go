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

	"github.com/mikeappsec/lightweightauth/internal/pipeline"
	"github.com/mikeappsec/lightweightauth/pkg/module"
)

func TestExplainHandler_Allow(t *testing.T) {
	t.Parallel()
	mw := testMW(t, VerbExplain)
	deps := &AdminDeps{
		ExplainFunc: func(_ context.Context, r *module.Request) *pipeline.ExplainResult {
			return &pipeline.ExplainResult{
				Timestamp:     time.Date(2026, 5, 5, 12, 0, 0, 0, time.UTC),
				PolicyVersion: "v3.0",
				TotalLatency:  2 * time.Millisecond,
				Identity: &pipeline.ExplainIdentity{
					Subject: "alice",
					Source:  "jwt",
					ACR:     "urn:mfa",
				},
				Stages: []pipeline.ExplainStage{
					{Name: "identifier", Module: "jwt", Latency: time.Millisecond, Result: "match"},
					{Name: "authorizer", Module: "rbac", Latency: time.Millisecond, Result: "allow"},
				},
				FinalDecision: pipeline.ExplainDecision{Allow: true, Status: 200},
			}
		},
	}
	mux := NewAdminMux(mw, deps)

	body := `{"method":"GET","path":"/api/data","host":"example.com","tenant_id":"acme"}`
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/v1/admin/explain", bytes.NewBufferString(body))
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{explainPeerCert("admin-bot")}}
	mux.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp explainResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !resp.Decision.Allow {
		t.Fatal("expected allow")
	}
	if resp.PolicyVersion != "v3.0" {
		t.Errorf("PolicyVersion = %q, want v3.0", resp.PolicyVersion)
	}
	if resp.Identity == nil {
		t.Fatal("expected identity")
	}
	if resp.Identity.Subject != "alice" {
		t.Errorf("Subject = %q, want alice", resp.Identity.Subject)
	}
	if len(resp.Stages) != 2 {
		t.Fatalf("len(Stages) = %d, want 2", len(resp.Stages))
	}
	if resp.Stages[0].Name != "identifier" || resp.Stages[0].Result != "match" {
		t.Errorf("stage[0] = %+v", resp.Stages[0])
	}
}

func TestExplainHandler_Deny(t *testing.T) {
	t.Parallel()
	mw := testMW(t, VerbExplain)
	deps := &AdminDeps{
		ExplainFunc: func(_ context.Context, r *module.Request) *pipeline.ExplainResult {
			return &pipeline.ExplainResult{
				Timestamp:    time.Now().UTC(),
				TotalLatency: time.Millisecond,
				Identity: &pipeline.ExplainIdentity{
					Subject: "bob",
					Source:  "jwt",
				},
				Stages: []pipeline.ExplainStage{
					{Name: "identifier", Module: "jwt", Latency: 500 * time.Microsecond, Result: "match"},
					{Name: "authorizer", Module: "opa", Latency: 500 * time.Microsecond, Result: "deny", Detail: "rule admin_only denied"},
				},
				FinalDecision: pipeline.ExplainDecision{Allow: false, Status: 403, Reason: "rule admin_only denied"},
			}
		},
	}
	mux := NewAdminMux(mw, deps)

	body := `{"method":"DELETE","path":"/admin/users/42"}`
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/v1/admin/explain", bytes.NewBufferString(body))
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{explainPeerCert("admin-bot")}}
	mux.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp explainResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Decision.Allow {
		t.Fatal("expected deny")
	}
	if resp.Decision.Reason != "rule admin_only denied" {
		t.Errorf("reason = %q", resp.Decision.Reason)
	}
}

func TestExplainHandler_MethodNotAllowed(t *testing.T) {
	t.Parallel()
	mw := testMW(t, VerbExplain)
	deps := &AdminDeps{
		ExplainFunc: func(_ context.Context, _ *module.Request) *pipeline.ExplainResult {
			t.Fatal("should not be called")
			return nil
		},
	}
	mux := NewAdminMux(mw, deps)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/v1/admin/explain", nil)
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{explainPeerCert("admin-bot")}}
	mux.ServeHTTP(w, r)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestExplainHandler_MissingFields(t *testing.T) {
	t.Parallel()
	mw := testMW(t, VerbExplain)
	deps := &AdminDeps{
		ExplainFunc: func(_ context.Context, _ *module.Request) *pipeline.ExplainResult {
			t.Fatal("should not be called")
			return nil
		},
	}
	mux := NewAdminMux(mw, deps)

	cases := []struct {
		name string
		body string
		want string
	}{
		{"no method", `{"path":"/foo"}`, "method is required"},
		{"no path", `{"method":"GET"}`, "path is required"},
		{"invalid json", `{bad`, "invalid JSON body"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			r := httptest.NewRequest("POST", "/v1/admin/explain", bytes.NewBufferString(tc.body))
			r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{explainPeerCert("admin-bot")}}
			mux.ServeHTTP(w, r)

			if w.Code != http.StatusBadRequest {
				t.Errorf("expected 400, got %d: %s", w.Code, w.Body.String())
			}
			var resp map[string]string
			_ = json.NewDecoder(w.Body).Decode(&resp)
			if resp["error"] != tc.want {
				t.Errorf("error = %q, want %q", resp["error"], tc.want)
			}
		})
	}
}

func TestExplainHandler_NoEngine(t *testing.T) {
	t.Parallel()
	mw := testMW(t, VerbExplain)
	deps := &AdminDeps{ExplainFunc: nil}
	mux := NewAdminMux(mw, deps)

	body := `{"method":"GET","path":"/"}`
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/v1/admin/explain", bytes.NewBufferString(body))
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{explainPeerCert("admin-bot")}}
	mux.ServeHTTP(w, r)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d: %s", w.Code, w.Body.String())
	}
}

func TestExplainHandler_Forbidden(t *testing.T) {
	t.Parallel()
	// Create MW where admin only has read_status, not explain.
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
	deps := &AdminDeps{
		ExplainFunc: func(_ context.Context, _ *module.Request) *pipeline.ExplainResult {
			t.Fatal("should not be called")
			return nil
		},
	}
	mux := NewAdminMux(mw, deps)

	body := `{"method":"GET","path":"/"}`
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/v1/admin/explain", bytes.NewBufferString(body))
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{explainPeerCert("admin-bot")}}
	mux.ServeHTTP(w, r)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d: %s", w.Code, w.Body.String())
	}
}

// --- helpers ----------------------------------------------------------------

func testMW(t *testing.T, verbs ...Verb) *Middleware {
	t.Helper()
	return &Middleware{
		cfg: Config{
			Enabled: true,
			MTLS: &MTLSConfig{
				SubjectMapping: map[string]string{"admin-bot": "operator"},
			},
			Roles: map[string][]Verb{
				"operator": verbs,
			},
		},
		log: testLogger(t),
	}
}

func explainPeerCert(cn string) *x509.Certificate {
	return &x509.Certificate{
		Subject: pkix.Name{CommonName: cn},
	}
}
