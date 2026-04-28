package server_test

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mikeappsec/lightweightauth/internal/server"
)

// TestHTTPHandler_MaxRequestBytes asserts /v1/authorize refuses
// oversize JSON bodies with 413 instead of streaming them into
// json.Decoder and burning memory.
func TestHTTPHandler_MaxRequestBytes(t *testing.T) {
	t.Parallel()
	holder := server.NewEngineHolder(nil)

	// Tiny cap so the test is cheap. The default in production is 1 MiB.
	h := server.NewHTTPHandlerWithOptions(holder, server.HTTPHandlerOptions{
		MaxRequestBytes: 64,
	})
	srv := httptest.NewServer(h)
	defer srv.Close()

	big := bytes.NewBufferString(`{"method":"GET","path":"/x","headers":{"X-Pad":["` +
		strings.Repeat("A", 4096) + `"]}}`)
	resp, err := http.Post(srv.URL+"/v1/authorize", "application/json", big)
	if err != nil {
		t.Fatalf("Post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", resp.StatusCode)
	}
}

// TestHTTPHandler_DisableAuthorize verifies the operator can shrink
// the public surface: /v1/authorize 404s when disabled, while
// /healthz still serves.
func TestHTTPHandler_DisableAuthorize(t *testing.T) {
	t.Parallel()
	holder := server.NewEngineHolder(nil)
	h := server.NewHTTPHandlerWithOptions(holder, server.HTTPHandlerOptions{
		DisableAuthorize: true,
	})
	srv := httptest.NewServer(h)
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/v1/authorize", "application/json",
		strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("Post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("authorize status = %d, want 404", resp.StatusCode)
	}

	hresp, err := http.Get(srv.URL + "/healthz")
	if err != nil {
		t.Fatalf("Get healthz: %v", err)
	}
	defer hresp.Body.Close()
	if hresp.StatusCode != http.StatusOK {
		t.Fatalf("healthz status = %d, want 200", hresp.StatusCode)
	}
}

// TestHTTPHandler_DisableMetrics: same idea for /metrics.
func TestHTTPHandler_DisableMetrics(t *testing.T) {
	t.Parallel()
	holder := server.NewEngineHolder(nil)
	h := server.NewHTTPHandlerWithOptions(holder, server.HTTPHandlerOptions{
		DisableMetrics: true,
	})
	srv := httptest.NewServer(h)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/metrics")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("metrics status = %d, want 404", resp.StatusCode)
	}
}
