package server

import (
	"net/http"
	"strings"
	"testing"
)

// TestPublicReason asserts that the verbose internal `dec.Reason`
// (which the audit log keeps verbatim) never surfaces to the network
// reply for any HTTP status the engine might emit.
func TestPublicReason(t *testing.T) {
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
		{http.StatusBadGateway, "service unavailable"}, // 5xx fallback
		{http.StatusTeapot, "request denied"},          // unmapped 4xx fallback
	}

	for _, c := range cases {
		c := c
		t.Run(http.StatusText(c.status), func(t *testing.T) {
			t.Parallel()
			for _, leak := range internalLeaks {
				got := publicReason(c.status, leak)
				if got != c.want {
					t.Errorf("status=%d leak=%q -> got %q, want %q", c.status, leak, got, c.want)
				}
				// Belt and braces: the leaky internal string must
				// not appear anywhere in the public reason.
				if strings.Contains(got, leak) {
					t.Errorf("publicReason leaked internal string: %q in %q", leak, got)
				}
			}
		})
	}
}
