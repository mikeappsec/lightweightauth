package openfga

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/mikeappsec/lightweightauth/pkg/module"
)

// fakeOpenFGA is a minimal stand-in that records the last request and
// returns whatever (allowed, status) the test sets.
type fakeOpenFGA struct {
	server   *httptest.Server
	calls    atomic.Int32
	lastBody checkRequest
	lastAuth string
	allow    bool
	status   int
}

func newFakeOpenFGA(t *testing.T) *fakeOpenFGA {
	t.Helper()
	f := &fakeOpenFGA{allow: true, status: 200}
	mux := http.NewServeMux()
	mux.HandleFunc("/stores/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || !strings.HasSuffix(r.URL.Path, "/check") {
			http.NotFound(w, r)
			return
		}
		f.calls.Add(1)
		f.lastAuth = r.Header.Get("Authorization")
		_ = json.NewDecoder(r.Body).Decode(&f.lastBody)
		w.WriteHeader(f.status)
		if f.status >= 300 {
			_, _ = w.Write([]byte(`{"code":"oops","message":"server said no"}`))
			return
		}
		_ = json.NewEncoder(w).Encode(checkResponse{Allowed: f.allow})
	})
	f.server = httptest.NewServer(mux)
	t.Cleanup(f.server.Close)
	return f
}

func newAuthorizer(t *testing.T, raw map[string]any) module.Authorizer {
	t.Helper()
	a, err := factory("rebac", raw)
	if err != nil {
		t.Fatalf("factory: %v", err)
	}
	return a
}

func baseConfig(apiURL string) map[string]any {
	return map[string]any{
		"apiUrl":               apiURL,
		"storeId":              "01HX",
		"authorizationModelId": "01MODEL",
		"check": map[string]any{
			"user":     "user:{{ .Identity.Subject }}",
			"relation": "{{ .Request.Method | lower }}",
			"object":   "doc:{{ index .Request.PathParts 1 }}",
		},
	}
}

func TestOpenFGA_AllowAndDeny(t *testing.T) {
	srv := newFakeOpenFGA(t)
	a := newAuthorizer(t, baseConfig(srv.server.URL))

	r := &module.Request{Method: "GET", Path: "/docs/42"}
	id := &module.Identity{Subject: "alice"}

	// Allow path.
	srv.allow = true
	d, err := a.Authorize(context.Background(), r, id)
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if !d.Allow {
		t.Fatalf("expected allow, got deny: %s", d.Reason)
	}
	if got := srv.lastBody.TupleKey; got.User != "user:alice" || got.Relation != "get" || got.Object != "doc:42" {
		t.Fatalf("unexpected tuple sent: %+v", got)
	}
	if srv.lastBody.AuthorizationModelID != "01MODEL" {
		t.Fatalf("model id not forwarded: %q", srv.lastBody.AuthorizationModelID)
	}

	// Deny path.
	srv.allow = false
	d, err = a.Authorize(context.Background(), r, id)
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if d.Allow || d.Status != 403 {
		t.Fatalf("expected 403 deny, got %+v", d)
	}
}

func TestOpenFGA_BearerToken(t *testing.T) {
	srv := newFakeOpenFGA(t)
	cfg := baseConfig(srv.server.URL)
	cfg["apiToken"] = "secret-token"
	a := newAuthorizer(t, cfg)

	_, err := a.Authorize(context.Background(), &module.Request{Method: "GET", Path: "/docs/1"}, &module.Identity{Subject: "bob"})
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if srv.lastAuth != "Bearer secret-token" {
		t.Fatalf("expected bearer header, got %q", srv.lastAuth)
	}
}

func TestOpenFGA_UpstreamErrorWrapsErrUpstream(t *testing.T) {
	srv := newFakeOpenFGA(t)
	srv.status = 500
	a := newAuthorizer(t, baseConfig(srv.server.URL))

	_, err := a.Authorize(context.Background(), &module.Request{Method: "GET", Path: "/docs/1"}, &module.Identity{Subject: "carol"})
	if err == nil {
		t.Fatalf("expected error on upstream 500")
	}
	if !errors.Is(err, module.ErrUpstream) {
		t.Fatalf("expected ErrUpstream, got %v", err)
	}
}

func TestOpenFGA_EmptyTupleDenies(t *testing.T) {
	srv := newFakeOpenFGA(t)
	cfg := baseConfig(srv.server.URL)
	// Object template references PathParts[1] which is missing for "/docs"
	// (only one segment). Template error → render fails → ErrConfig.
	a := newAuthorizer(t, cfg)

	_, err := a.Authorize(context.Background(), &module.Request{Method: "GET", Path: "/docs"}, &module.Identity{Subject: "x"})
	if err == nil {
		t.Fatalf("expected template error for missing path part")
	}
	if !errors.Is(err, module.ErrConfig) {
		t.Fatalf("expected ErrConfig, got %v", err)
	}
}

func TestOpenFGA_EmptyRenderedDeniesGracefully(t *testing.T) {
	srv := newFakeOpenFGA(t)
	cfg := map[string]any{
		"apiUrl":  srv.server.URL,
		"storeId": "01HX",
		"check": map[string]any{
			"user":     "user:{{ .Identity.Subject }}",
			"relation": "viewer",
			// Empty object after trim — should deny without calling FGA.
			"object": "  ",
		},
	}
	a := newAuthorizer(t, cfg)

	d, err := a.Authorize(context.Background(), &module.Request{Method: "GET", Path: "/x"}, &module.Identity{Subject: "u"})
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if d.Allow {
		t.Fatalf("expected deny on empty tuple")
	}
	if got := srv.calls.Load(); got != 0 {
		t.Fatalf("expected 0 upstream calls, got %d", got)
	}
}

func TestOpenFGA_ConfigValidation(t *testing.T) {
	cases := []struct {
		name string
		cfg  map[string]any
	}{
		{"missing apiUrl", map[string]any{"storeId": "x", "check": map[string]any{"user": "a", "relation": "b", "object": "c"}}},
		{"missing storeId", map[string]any{"apiUrl": "http://x", "check": map[string]any{"user": "a", "relation": "b", "object": "c"}}},
		{"missing check", map[string]any{"apiUrl": "http://x", "storeId": "x"}},
		{"missing relation", map[string]any{"apiUrl": "http://x", "storeId": "x", "check": map[string]any{"user": "a", "object": "c"}}},
		{"bad timeout", map[string]any{"apiUrl": "http://x", "storeId": "x", "timeout": "not-a-duration", "check": map[string]any{"user": "a", "relation": "b", "object": "c"}}},
		{"bad template", map[string]any{"apiUrl": "http://x", "storeId": "x", "check": map[string]any{"user": "{{ .Bad", "relation": "b", "object": "c"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := factory("rebac", tc.cfg); err == nil {
				t.Fatalf("expected error for %s", tc.name)
			} else if !errors.Is(err, module.ErrConfig) {
				t.Fatalf("expected ErrConfig, got %v", err)
			}
		})
	}
}

func TestOpenFGA_BreakerTripsAfterRepeatedFailures(t *testing.T) {
	srv := newFakeOpenFGA(t)
	srv.status = 500
	cfg := baseConfig(srv.server.URL)
	cfg["resilience"] = map[string]any{
		"breaker": map[string]any{
			"failureThreshold": 3,
			"coolDown":         "1h", // never recover during the test
		},
	}
	a := newAuthorizer(t, cfg)

	r := &module.Request{Method: "GET", Path: "/docs/1"}
	id := &module.Identity{Subject: "alice"}

	// Hammer until the breaker trips. After 3 failures it should reject
	// without making any further upstream calls.
	for i := 0; i < 3; i++ {
		_, err := a.Authorize(context.Background(), r, id)
		if !errors.Is(err, module.ErrUpstream) {
			t.Fatalf("call #%d: expected ErrUpstream, got %v", i, err)
		}
	}
	callsBefore := srv.calls.Load()

	_, err := a.Authorize(context.Background(), r, id)
	if !errors.Is(err, module.ErrUpstream) {
		t.Fatalf("post-trip call: expected ErrUpstream, got %v", err)
	}
	if got := srv.calls.Load(); got != callsBefore {
		t.Fatalf("breaker did not short-circuit: calls before=%d after=%d", callsBefore, got)
	}
}

func TestOpenFGA_RetriesUntilSuccess(t *testing.T) {
	var attempts atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/stores/", func(w http.ResponseWriter, r *http.Request) {
		n := attempts.Add(1)
		if n < 3 {
			w.WriteHeader(503)
			return
		}
		_ = json.NewEncoder(w).Encode(checkResponse{Allowed: true})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	cfg := baseConfig(srv.URL)
	cfg["resilience"] = map[string]any{
		"retries": map[string]any{
			"max":                3,
			"backoffBase":        "0s",
			"budgetCapacity":     10,
			"budgetRefillPerSec": 10,
		},
	}
	a := newAuthorizer(t, cfg)

	d, err := a.Authorize(context.Background(), &module.Request{Method: "GET", Path: "/docs/9"}, &module.Identity{Subject: "u"})
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if !d.Allow {
		t.Fatalf("expected allow after retry")
	}
	if got := attempts.Load(); got != 3 {
		t.Fatalf("attempts = %d, want 3", got)
	}
}
