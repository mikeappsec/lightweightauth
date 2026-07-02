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
//   - Private / link-local / loopback IP ranges are not blocked here because
//     IdPs may legitimately be in-cluster (they are reachable from the CP pod
//     via ClusterIP); the operator is responsible for network policy.
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
	// Reject bare hostnames that look like private/metadata endpoints typically
	// exploited in SSRF, while still allowing in-cluster HTTPS IdPs.
	if isBlockedHost(parsed.Hostname()) {
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

// isBlockedHost blocks a small list of well-known SSRF pivot targets.
// In-cluster service hostnames (.svc.cluster.local) are intentionally allowed
// because operators may run their IdP inside the cluster.
func isBlockedHost(host string) bool {
	// Strip port if present.
	if i := strings.LastIndex(host, ":"); i != -1 && strings.Count(host, ":") == 1 {
		host = host[:i]
	}
	blocked := []string{
		"169.254.169.254", // AWS/GCP/OCI IMDS
		"metadata.google.internal",
		"instance-data",
	}
	lower := strings.ToLower(host)
	for _, b := range blocked {
		if lower == b {
			return true
		}
	}
	return false
}
