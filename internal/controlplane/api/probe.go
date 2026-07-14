// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// handleProbeURL performs a HEAD request against an external URL on behalf of
// the console UI. It is used to verify JWKS endpoint reachability before a
// node is created, so that operators discover a dead IdP URL at form-submit
// time rather than when the pod crashes on startup.
//
// Security constraints:
//   - Only HTTPS URLs are accepted (no http://, no file://, etc.).
//   - Timeout: 5 s.
//   - Maximum 2 redirects followed.
//   - The target host is validated via validateHost (ssrf.go), which
//     resolves the hostname and checks every returned IP against
//     loopback, link-local, and cloud-metadata ranges — not just a
//     static hostname list — on the initial URL AND on every redirect
//     target (SSRF redirect bypass defence). A hostname that isn't an
//     IP literal and isn't a known metadata host would otherwise pass
//     a naive string-only check even when it resolves to an internal
//     or metadata address.
//   - In-cluster service hostnames (.svc.cluster.local) are allowed
//     because operators may run their IdP inside the cluster, so
//     private RFC1918 ranges are permitted here (allowPrivate=true) —
//     unlike handleRegisterInstance, which blocks them.
//
// Route: GET /v1/controlplane/probe/url?url=<encoded>
func (s *Server) handleProbeURL(w http.ResponseWriter, r *http.Request) {
	rawURL := r.URL.Query().Get("url")
	if rawURL == "" {
		writeError(w, http.StatusBadRequest, "url query parameter is required")
		return
	}

	parsed, err := url.Parse(rawURL)
	if err != nil || !strings.EqualFold(parsed.Scheme, "https") {
		writeError(w, http.StatusBadRequest, "only https:// URLs are allowed")
		return
	}
	// Reject SSRF pivot targets (loopback, link-local, cloud metadata).
	// allowPrivate=true: in-cluster IdP hostnames commonly resolve to
	// RFC1918 addresses, and that's an intentional, documented use case
	// for this endpoint (unlike instance registration).
	if err := validateHost(parsed.Hostname(), true); err != nil {
		writeError(w, http.StatusBadRequest, "target host is not allowed")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	probeClient := &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 2 {
				return http.ErrUseLastResponse
			}
			// Ensure redirects also stay on HTTPS.
			if !strings.EqualFold(req.URL.Scheme, "https") {
				return http.ErrUseLastResponse
			}
			// SECURITY: Re-validate the redirect target host with the
			// same check applied to the initial URL. Without this an
			// attacker can redirect from a safe host to a cloud
			// metadata or internal endpoint, bypassing the initial
			// check.
			if validateHost(req.URL.Hostname(), true) != nil {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodHead, rawURL, nil)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"reachable":  false,
			"statusCode": 0,
			"error":      "failed to build request: " + err.Error(),
		})
		return
	}
	req.Header.Set("User-Agent", "lwauth-controlplane/probe (JWKS reachability check)")

	resp, err := probeClient.Do(req)
	if err != nil {
		// Distinguish timeout from other errors so the UI can show a better message.
		msg := err.Error()
		if ctx.Err() != nil {
			msg = "request timed out after 5s"
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"reachable":  false,
			"statusCode": 0,
			"error":      msg,
		})
		return
	}
	resp.Body.Close()

	writeJSON(w, http.StatusOK, map[string]any{
		"reachable":  resp.StatusCode < 400,
		"statusCode": resp.StatusCode,
	})
}
