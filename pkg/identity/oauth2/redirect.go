// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"net/url"
	"strings"
)

// buildAllowedHosts normalises the operator's allowedRedirectHosts list
// into a lookup set. Entries are matched case-insensitively against the
// host (or host:port) of an `rd` query parameter. Empty list -> nil
// (caller treats it as "relative paths only").
func buildAllowedHosts(in []string) map[string]struct{} {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]struct{}, len(in))
	for _, h := range in {
		h = strings.TrimSpace(strings.ToLower(h))
		if h != "" {
			out[h] = struct{}{}
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// safeRedirect normalises and gates a post-login redirect target.
//
// Accepted:
//   - Empty input               -> identifier.postLogin (the configured default)
//   - A relative path beginning with a single `/` and not `//` or `/\`
//     -> returned as-is. This is the common case (rd=/dashboard).
//   - An absolute URL whose host matches the operator's allow-list and
//     whose scheme is http or https -> returned as-is.
//
// Anything else (scheme-relative `//evil.example`, `\\evil.example`,
// other-scheme `javascript:...`, hosts not on the allow-list) silently
// rewrites to postLogin. We deliberately do not 400 here: a malicious
// `rd` is not the user's fault, and we don't want to leak whether a
// host is on the allow-list.
func (i *identifier) safeRedirect(raw string) string {
	if raw == "" {
		return i.postLogin
	}

	// Reject scheme-relative `//evil.example/...` and the Windows-style
	// `/\evil.example` variant before url.Parse normalises them away.
	if strings.HasPrefix(raw, "//") || strings.HasPrefix(raw, `/\`) {
		return i.postLogin
	}

	// Relative path: must start with `/` and have no host. We re-parse
	// to make sure there isn't an embedded `\r\n` or other oddity.
	if strings.HasPrefix(raw, "/") {
		u, err := url.Parse(raw)
		if err != nil || u.Host != "" || u.Scheme != "" {
			return i.postLogin
		}
		return raw
	}

	// Absolute URL: only accepted when the operator has explicitly
	// allow-listed the host.
	if len(i.allowedRedirectHosts) == 0 {
		return i.postLogin
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return i.postLogin
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return i.postLogin
	}
	if _, ok := i.allowedRedirectHosts[strings.ToLower(u.Host)]; !ok {
		return i.postLogin
	}
	return raw
}
