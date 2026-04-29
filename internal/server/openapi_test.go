package server_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mikeappsec/lightweightauth/api/openapi"
	"github.com/mikeappsec/lightweightauth/internal/server"
)

// TestHTTPHandler_OpenAPI_JSON exercises /openapi.json. The endpoint
// must:
//
//   - serve 200 with application/json,
//   - return a valid OpenAPI 3.1 document (parseable as JSON, with the
//     expected `openapi` and `info.title` keys),
//   - describe the endpoints lwauthd actually serves (paths block
//     references /v1/authorize, /healthz, /readyz, /metrics, plus the
//     spec endpoints themselves — the regression we'd want to catch
//     is "someone added a new endpoint and forgot to document it",
//     which a check on the documented paths makes loud).
//
// This is the contract test for DOC-OPENAPI-1.
func TestHTTPHandler_OpenAPI_JSON(t *testing.T) {
	t.Parallel()
	holder := server.NewEngineHolder(nil)
	h := server.NewHTTPHandler(holder)
	srv := httptest.NewServer(h)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/openapi.json")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("content-type = %q, want application/json*", ct)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("body is not valid JSON: %v\n---\n%s", err, body)
	}

	if v, _ := doc["openapi"].(string); !strings.HasPrefix(v, "3.1") {
		t.Errorf("openapi version = %q, want 3.1.x", v)
	}
	info, _ := doc["info"].(map[string]any)
	if title, _ := info["title"].(string); !strings.Contains(title, "LightweightAuth") {
		t.Errorf("info.title = %q, want to mention LightweightAuth", title)
	}
	paths, _ := doc["paths"].(map[string]any)
	for _, want := range []string{
		"/v1/authorize",
		"/healthz",
		"/readyz",
		"/metrics",
		"/openapi.json",
		"/openapi.yaml",
	} {
		if _, ok := paths[want]; !ok {
			t.Errorf("paths missing %q", want)
		}
	}
}

// TestHTTPHandler_OpenAPI_YAML asserts /openapi.yaml is served
// verbatim — byte-identical to the embedded source. Verbatim is the
// whole point: the YAML form preserves comments + ordering for
// humans; if we round-tripped through a parser we'd lose both.
func TestHTTPHandler_OpenAPI_YAML(t *testing.T) {
	t.Parallel()
	holder := server.NewEngineHolder(nil)
	h := server.NewHTTPHandler(holder)
	srv := httptest.NewServer(h)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/openapi.yaml")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/yaml") {
		t.Fatalf("content-type = %q, want application/yaml*", ct)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(body) != string(openapi.Spec) {
		t.Fatalf("served YAML differs from embedded source\n  served len=%d\n  embed  len=%d",
			len(body), len(openapi.Spec))
	}
}

// TestHTTPHandler_DisableOpenAPI verifies operators can shrink the
// surface, mirroring the existing DisableMetrics / DisableAuthorize
// tests.
func TestHTTPHandler_DisableOpenAPI(t *testing.T) {
	t.Parallel()
	holder := server.NewEngineHolder(nil)
	h := server.NewHTTPHandlerWithOptions(holder, server.HTTPHandlerOptions{
		DisableOpenAPI: true,
	})
	srv := httptest.NewServer(h)
	defer srv.Close()

	for _, path := range []string{"/openapi.json", "/openapi.yaml"} {
		resp, err := http.Get(srv.URL + path)
		if err != nil {
			t.Fatalf("Get %s: %v", path, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("%s status = %d, want 404", path, resp.StatusCode)
		}
	}

	// /healthz must still work — the disable knob is scoped.
	hresp, err := http.Get(srv.URL + "/healthz")
	if err != nil {
		t.Fatalf("Get healthz: %v", err)
	}
	defer hresp.Body.Close()
	if hresp.StatusCode != http.StatusOK {
		t.Fatalf("healthz status = %d, want 200", hresp.StatusCode)
	}
}
