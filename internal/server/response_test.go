package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPublicReason_NoLeaks(t *testing.T) {
	t.Parallel()

	internalLeaks := []string{
		"hmac: signature mismatch",
		"jwt: kid not found",
		`rbac: subject "alice" not in allow-list ["admin"]`,
		"upstream introspection 502: idp.example.com",
		"opa: policy 'data.lwauth.allow' returned false",
	}

	cases := []struct {
		status int
		want   string
	}{
		{http.StatusUnauthorized, "unauthenticated"},
		{http.StatusForbidden, "forbidden"},
		{http.StatusTooManyRequests, "rate limit exceeded"},
		{http.StatusServiceUnavailable, "service unavailable"},
		{http.StatusInternalServerError, "internal error"},
		{http.StatusBadGateway, "service unavailable"},
		{http.StatusTeapot, "request denied"},
	}

	for _, c := range cases {
		t.Run(http.StatusText(c.status), func(t *testing.T) {
			t.Parallel()
			for _, leak := range internalLeaks {
				got := publicReason(c.status, leak)
				if got != c.want {
					t.Errorf("status=%d leak=%q -> got %q, want %q", c.status, leak, got, c.want)
				}
				if strings.Contains(got, leak) {
					t.Errorf("publicReason leaked internal string: %q in %q", leak, got)
				}
			}
		})
	}
}

func TestErrorTypeFromStatus(t *testing.T) {
	t.Parallel()
	cases := []struct {
		code int
		want string
	}{
		{http.StatusBadRequest, "validation_error"},
		{http.StatusUnauthorized, "authentication_error"},
		{http.StatusForbidden, "authorization_error"},
		{http.StatusTooManyRequests, "rate_limit_error"},
		{http.StatusRequestEntityTooLarge, "payload_too_large"},
		{http.StatusMethodNotAllowed, "validation_error"},
		{http.StatusUnsupportedMediaType, "validation_error"},
		{http.StatusServiceUnavailable, "unavailable_error"},
		{http.StatusInternalServerError, "internal_error"},
		{http.StatusBadGateway, "internal_error"},
		{http.StatusTeapot, "unknown_error"},
	}
	for _, c := range cases {
		got := errorTypeFromStatus(c.code)
		if got != c.want {
			t.Errorf("errorTypeFromStatus(%d) = %q, want %q", c.code, got, c.want)
		}
	}
}

func TestWriteError_JSONEnvelope(t *testing.T) {
	t.Parallel()
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/v1/authorize", nil)
	r.Header.Set("X-Request-ID", "test-req-123")

	writeError(w, r, http.StatusBadRequest, "invalid JSON")

	resp := w.Result()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	if resp.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Error("missing X-Content-Type-Options: nosniff")
	}
	if resp.Header.Get("Cache-Control") != "no-store" {
		t.Error("missing Cache-Control: no-store")
	}

	var env APIResponse
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		t.Fatal(err)
	}
	if env.Status != "error" {
		t.Errorf("status = %q, want error", env.Status)
	}
	if env.Code != 400 {
		t.Errorf("code = %d, want 400", env.Code)
	}
	if env.Message != "invalid JSON" {
		t.Errorf("message = %q", env.Message)
	}
	if env.Error == nil || env.Error.Type != "validation_error" {
		t.Errorf("error.type = %v, want validation_error", env.Error)
	}
	// Detail must be empty — no internal info leaked to wire.
	if env.Error != nil && env.Error.Detail != "" {
		t.Errorf("error.detail should be empty, got %q", env.Error.Detail)
	}
	if env.RequestID != "test-req-123" {
		t.Errorf("requestId = %q, want test-req-123", env.RequestID)
	}
	if env.Timestamp == "" {
		t.Error("timestamp is empty")
	}
}

func TestWriteSuccess_JSONEnvelope(t *testing.T) {
	t.Parallel()
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/v1/authorize", nil)
	r.Header.Set("X-Correlation-ID", "corr-456")

	data := map[string]any{"allow": true, "subject": "alice"}
	writeSuccess(w, r, http.StatusOK, "authorized", data)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	var env APIResponse
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		t.Fatal(err)
	}
	if env.Status != "success" {
		t.Errorf("status = %q, want success", env.Status)
	}
	if env.Code != 200 {
		t.Errorf("code = %d, want 200", env.Code)
	}
	if env.Message != "authorized" {
		t.Errorf("message = %q, want authorized", env.Message)
	}
	if env.RequestID != "corr-456" {
		t.Errorf("requestId = %q, want corr-456", env.RequestID)
	}
	if env.Error != nil {
		t.Errorf("error should be nil on success, got %v", env.Error)
	}
}

func TestExtractRequestID(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		header string
		value  string
		want   string
	}{
		{"valid X-Request-ID", "X-Request-ID", "req-1", "req-1"},
		{"valid X-Correlation-ID", "X-Correlation-ID", "corr-2", "corr-2"},
		{"empty", "", "", ""},
		{"control chars rejected", "X-Request-ID", "bad\x00id", ""},
		{"spaces rejected", "X-Request-ID", "bad id", ""},
		{"truncated at 128", "X-Request-ID", string(make([]byte, 200)), ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			if c.header != "" {
				r.Header.Set(c.header, c.value)
			}
			got := extractRequestID(r)
			if got != c.want {
				t.Errorf("got %q, want %q", got, c.want)
			}
		})
	}

	// nil request
	if got := extractRequestID(nil); got != "" {
		t.Errorf("nil request: got %q, want empty", got)
	}
}
