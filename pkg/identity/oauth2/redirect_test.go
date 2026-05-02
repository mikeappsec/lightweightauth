// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package oauth2

import "testing"

func TestSafeRedirect(t *testing.T) {
	t.Parallel()

	relativeOnly := &identifier{postLogin: "/home"}
	withAllow := &identifier{
		postLogin:            "/home",
		allowedRedirectHosts: buildAllowedHosts([]string{"app.example.com", "App.Example.com:8443"}),
	}

	cases := []struct {
		name string
		id   *identifier
		in   string
		want string
	}{
		// Empty -> default.
		{"empty", relativeOnly, "", "/home"},

		// Relative paths: kept verbatim.
		{"relative-root", relativeOnly, "/", "/"},
		{"relative-deep", relativeOnly, "/a/b?x=1", "/a/b?x=1"},

		// Scheme-relative is the classic open-redirect vector.
		{"scheme-relative-http", relativeOnly, "//evil.example/", "/home"},
		{"scheme-relative-backslash", relativeOnly, `/\evil.example/`, "/home"},

		// Absolute URLs are rejected when no allow-list is configured.
		{"absolute-no-allow", relativeOnly, "https://evil.example/path", "/home"},
		{"absolute-http-no-allow", relativeOnly, "http://evil.example/", "/home"},

		// javascript: and similar must never be honoured.
		{"javascript", relativeOnly, "javascript:alert(1)", "/home"},
		{"data", relativeOnly, "data:text/html,<script>", "/home"},

		// With allow-list.
		{"allow-list-hit", withAllow, "https://app.example.com/dash", "https://app.example.com/dash"},
		{"allow-list-hit-port", withAllow, "https://app.example.com:8443/dash", "https://app.example.com:8443/dash"},
		{"allow-list-mismatch-host", withAllow, "https://attacker.example/", "/home"},
		{"allow-list-mismatch-port", withAllow, "https://app.example.com:9443/", "/home"},
		// Allow-list is for hosts only; other schemes still rejected.
		{"allow-list-bad-scheme", withAllow, "ftp://app.example.com/", "/home"},
		// Case-insensitive host match.
		{"allow-list-case", withAllow, "https://APP.example.com/", "https://APP.example.com/"},

		// A relative path with an embedded host-looking string is fine
		// (no leading // and url.Parse won't extract a Host).
		{"relative-looks-like-host", relativeOnly, "/redirect?next=https://evil.example", "/redirect?next=https://evil.example"},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := tc.id.safeRedirect(tc.in)
			if got != tc.want {
				t.Errorf("safeRedirect(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
