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

// TestHTTPHandler_RejectsNonJSONContentType is the F2 regression
// guard. /v1/authorize must refuse anything other than
// application/json with 415 — without this, a CORS-"simple" POST
// (text/plain, form-encoded, multipart) from a browser context can
// reach the endpoint without a pre-flight and read the response.
func TestHTTPHandler_RejectsNonJSONContentType(t *testing.T) {
	t.Parallel()
	holder := server.NewEngineHolder(nil)
	h := server.NewHTTPHandlerWithOptions(holder, server.HTTPHandlerOptions{})
	srv := httptest.NewServer(h)
	defer srv.Close()

	cases := []struct {
		name string
		ct   string
	}{
		{"text-plain", "text/plain"},
		{"form-urlencoded", "application/x-www-form-urlencoded"},
		{"multipart", "multipart/form-data; boundary=abc"},
		{"empty", ""},
		{"close-but-no-cigar", "application/jsonp"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := strings.NewReader(`{"method":"GET","path":"/x"}`)
			req, _ := http.NewRequest(http.MethodPost, srv.URL+"/v1/authorize", body)
			if tc.ct != "" {
				req.Header.Set("Content-Type", tc.ct)
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("Do: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusUnsupportedMediaType {
				t.Fatalf("status = %d, want 415", resp.StatusCode)
			}
		})
	}

	// Sanity: application/json with charset is still accepted.
	body := strings.NewReader(`{"method":"GET","path":"/x"}`)
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/v1/authorize", body)
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("charset Do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnsupportedMediaType {
		t.Fatalf("application/json; charset=utf-8 was rejected (415)")
	}
}

// TestHTTPHandler_DefensiveResponseHeaders is the F4 regression guard.
// The success path of /v1/authorize must carry nosniff / no-store /
// no-referrer / DENY so a stray browser embed can't reinterpret the
// response.
func TestHTTPHandler_DefensiveResponseHeaders(t *testing.T) {
	t.Parallel()
	holder := server.NewEngineHolder(nil)
	h := server.NewHTTPHandlerWithOptions(holder, server.HTTPHandlerOptions{})
	srv := httptest.NewServer(h)
	defer srv.Close()

	body := strings.NewReader(`{"method":"GET","path":"/x"}`)
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/v1/authorize", body)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	want := map[string]string{
		"X-Content-Type-Options": "nosniff",
		"Cache-Control":          "no-store",
		"Referrer-Policy":        "no-referrer",
		"X-Frame-Options":        "DENY",
	}
	for k, v := range want {
		if got := resp.Header.Get(k); got != v {
			t.Errorf("%s = %q, want %q", k, got, v)
		}
	}
}

// TestHTTPHandler_RejectsDuplicateJSONKeys is the F6 regression
// guard. encoding/json's silent "last wins" disagrees with anything
// in front that picks "first wins" — a parser-confusion vector.
// Reject the request with 400 instead of decoding it.
func TestHTTPHandler_RejectsDuplicateJSONKeys(t *testing.T) {
	t.Parallel()
	holder := server.NewEngineHolder(nil)
	h := server.NewHTTPHandlerWithOptions(holder, server.HTTPHandlerOptions{})
	srv := httptest.NewServer(h)
	defer srv.Close()

	cases := []string{
		// Top-level duplicate.
		`{"method":"GET","method":"POST","path":"/x"}`,
		// Duplicate inside the headers object.
		`{"method":"GET","path":"/x","headers":{"X-Api-Key":["a"],"X-Api-Key":["b"]}}`,
		// Duplicate at the top level when both are objects.
		`{"method":"GET","path":"/x","headers":{"X":[]},"headers":{"Y":[]}}`,
	}
	for i, raw := range cases {
		req, _ := http.NewRequest(http.MethodPost, srv.URL+"/v1/authorize",
			strings.NewReader(raw))
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("[%d] Do: %v", i, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("[%d] status = %d, want 400", i, resp.StatusCode)
		}
	}

	// Negative control: a clean body is not rejected by the
	// dup-key check (the engine returns 503 because no engine is
	// loaded; the point is that 400 didn't fire).
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/v1/authorize",
		strings.NewReader(`{"method":"GET","path":"/x","headers":{"a":["1"],"b":["2"]}}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("control Do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusBadRequest {
		t.Fatalf("dup-key check fired on a clean body")
	}
}

// TestHTTPHandler_ReadOnlyEndpointsRejectWriteVerbs is the F8
// regression guard. /healthz, /readyz, /metrics, /openapi.* must
// answer 405 to anything other than GET / HEAD so non-standard
// verbs (TRACE, PROPFIND, DELETE) cannot reach the handler.
func TestHTTPHandler_ReadOnlyEndpointsRejectWriteVerbs(t *testing.T) {
	t.Parallel()
	holder := server.NewEngineHolder(nil)
	h := server.NewHTTPHandlerWithOptions(holder, server.HTTPHandlerOptions{})
	srv := httptest.NewServer(h)
	defer srv.Close()

	paths := []string{"/healthz", "/readyz", "/metrics", "/openapi.json", "/openapi.yaml"}
	verbs := []string{"POST", "PUT", "DELETE", "PATCH", "TRACE", "PROPFIND"}
	for _, p := range paths {
		for _, v := range verbs {
			req, _ := http.NewRequest(v, srv.URL+p, nil)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("%s %s: %v", v, p, err)
			}
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusMethodNotAllowed {
				t.Errorf("%s %s: status = %d, want 405", v, p, resp.StatusCode)
			}
			if got := resp.Header.Get("Allow"); got != "GET, HEAD" {
				t.Errorf("%s %s: Allow = %q, want %q", v, p, got, "GET, HEAD")
			}
		}
		// Sanity: GET still works.
		resp, err := http.Get(srv.URL + p)
		if err != nil {
			t.Fatalf("GET %s: %v", p, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode == http.StatusMethodNotAllowed {
			t.Errorf("GET %s rejected with 405", p)
		}
	}
}

// TestHTTPHandler_RejectsHeaderCaseCollision is the F9 regression
// guard. Two header keys that case-fold to the same name (e.g.
// "X-Api-Key" + "x-api-key") MUST be rejected with 400 — otherwise
// Go map iteration order picks a non-deterministic survivor and the
// auth verdict flaps across calls with the same JSON body.
//
// The test runs the same request 50 times and asserts every call
// got 400. With the bug present, the assertion would fail roughly
// half the time (200 mixed in).
func TestHTTPHandler_RejectsHeaderCaseCollision(t *testing.T) {
	t.Parallel()
	holder := server.NewEngineHolder(nil)
	h := server.NewHTTPHandlerWithOptions(holder, server.HTTPHandlerOptions{})
	srv := httptest.NewServer(h)
	defer srv.Close()

	bodies := []string{
		// Same header, two cases, one valid and one invalid value.
		`{"method":"GET","path":"/x","headers":{"X-Api-Key":["good"],"x-api-key":["bad"]}}`,
		`{"method":"GET","path":"/x","headers":{"x-api-key":["bad"],"X-Api-Key":["good"]}}`,
		// Three-way collision.
		`{"method":"GET","path":"/x","headers":{"Authorization":["a"],"AUTHORIZATION":["b"],"authorization":["c"]}}`,
	}
	for _, raw := range bodies {
		for i := 0; i < 50; i++ {
			req, _ := http.NewRequest(http.MethodPost, srv.URL+"/v1/authorize",
				strings.NewReader(raw))
			req.Header.Set("Content-Type", "application/json")
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("Do: %v", err)
			}
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("trial %d: status = %d, want 400 (body=%q)", i, resp.StatusCode, raw)
			}
		}
	}
}

// TestHTTPHandler_RejectsCaseCollidingTopLevelFields is the F10
// regression guard. encoding/json matches struct tags
// case-insensitively, so `"PATH"` and `"path"` both land on
// authorizeRequest.Path with last-wins. Strict decoder
// (DisallowUnknownFields) refuses the non-canonical case at parse
// time.
func TestHTTPHandler_RejectsCaseCollidingTopLevelFields(t *testing.T) {
	t.Parallel()
	holder := server.NewEngineHolder(nil)
	h := server.NewHTTPHandlerWithOptions(holder, server.HTTPHandlerOptions{})
	srv := httptest.NewServer(h)
	defer srv.Close()

	cases := []string{
		// Wrong-case alias of a known field.
		`{"PATH":"/admin","method":"GET"}`,
		`{"Method":"GET","path":"/x"}`,
		`{"method":"GET","path":"/x","HEADERS":{}}`,
		// Genuinely unknown field.
		`{"method":"GET","path":"/x","extra":"surprise"}`,
	}
	for i, raw := range cases {
		req, _ := http.NewRequest(http.MethodPost, srv.URL+"/v1/authorize",
			strings.NewReader(raw))
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("[%d] Do: %v", i, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("[%d] status = %d, want 400 (body=%q)", i, resp.StatusCode, raw)
		}
	}
}
