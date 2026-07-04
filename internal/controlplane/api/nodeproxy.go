// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"
)

// proxyTransport is a shared transport for the node reverse proxy. TLS
// verification is intentionally skipped: node certificates are self-signed for
// their in-cluster service DNS name (e.g. payments-auth.demo.svc.cluster.local),
// not for the CP's external hostname, so standard verification would always fail.
// The connection is internal to the cluster and the target is a registry-validated
// node, so this is acceptable.
//
//nolint:gosec
var proxyTransport http.RoundTripper = &http.Transport{
	TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	DialContext: (&net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
	}).DialContext,
	MaxIdleConns:          100,
	IdleConnTimeout:       90 * time.Second,
	TLSHandshakeTimeout:   10 * time.Second,
	ResponseHeaderTimeout: 30 * time.Second,
}

// ProxyHandler returns an http.Handler that reverse-proxies HTTP requests
// to the appropriate lwauth node, identified by cluster and name in the path.
//
// Route: ANY /v1/proxy/{cluster}/{name}[/{path}]
//
// This endpoint is intentionally NOT behind the CP session middleware so that
// upstream services (Envoy, nginx, etc.) can call node authorization endpoints
// without a human login session. The node itself enforces its own authentication.
//
// The node's Service is expected to be a ClusterIP (not exposed via any ingress),
// so this proxy is the only way to reach the node from outside the cluster.
func (s *Server) ProxyHandler() http.Handler {
	return http.HandlerFunc(s.handleNodeProxy)
}

func (s *Server) handleNodeProxy(w http.ResponseWriter, r *http.Request) {
	// Parse /v1/proxy/{cluster}/{name}[/{path...}]
	suffix := strings.TrimPrefix(r.URL.Path, "/v1/proxy/")
	parts := strings.SplitN(suffix, "/", 3)
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		writeError(w, http.StatusBadRequest, "path must be /v1/proxy/{cluster}/{name}/[path]")
		return
	}
	cluster, name := parts[0], parts[1]
	subPath := "/"
	if len(parts) == 3 {
		// parts[2] is the rest of the path (may be empty string "").
		if parts[2] != "" {
			subPath = "/" + parts[2]
		}
	}

	inst, ok := s.Registry.Get(cluster, name)
	if !ok {
		writeError(w, http.StatusNotFound, "node not found: "+cluster+"/"+name)
		return
	}
	if inst.AdminURL == "" {
		writeError(w, http.StatusBadGateway, "node has no registered address")
		return
	}

	target, err := url.Parse(inst.AdminURL)
	if err != nil {
		writeError(w, http.StatusBadGateway, "invalid node address")
		return
	}

	// Build the proxy. We construct one per request (cheap — no state) so
	// that per-request path/query rewriting is straightforward.
	proxy := &httputil.ReverseProxy{
		Transport: proxyTransport,
		Director: func(req *http.Request) {
			req.URL.Scheme = target.Scheme
			req.URL.Host = target.Host
			req.URL.Path = subPath
			req.URL.RawQuery = r.URL.RawQuery
			req.Host = target.Host

			// Forward the original client IP, appending to any chain
			// already present (set by an upstream load balancer).
			// We read from the original r.Header, not req.Header, to get
			// values before any prior Director manipulation.
			clientIP, _, _ := net.SplitHostPort(r.RemoteAddr)
			if prior := r.Header.Values("X-Forwarded-For"); len(prior) > 0 {
				chain := strings.Join(prior, ", ")
				if clientIP != "" {
					chain += ", " + clientIP
				}
				req.Header.Set("X-Forwarded-For", chain)
			} else if clientIP != "" {
				req.Header.Set("X-Forwarded-For", clientIP)
			}
			req.Header.Set("X-Forwarded-Host", r.Host)
			req.Header.Set("X-Forwarded-Proto", scheme(r))

			// Strip the CP session cookie — it has no meaning to the node
			// and we must not leak it to downstream services.
			req.Header.Del("Cookie")
			req.Header.Del("X-Lwauth-Session")
		},
		ModifyResponse: func(resp *http.Response) error {
			// Stamp the response so callers can identify which node served it.
			resp.Header.Set("X-Lwauth-Node", cluster+"/"+name)
			// Never cache authorization decisions.
			if resp.Header.Get("Cache-Control") == "" {
				resp.Header.Set("Cache-Control", "no-store")
			}
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			writeError(w, http.StatusBadGateway,
				"node unreachable ("+cluster+"/"+name+"): "+err.Error())
		},
	}

	proxy.ServeHTTP(w, r)
}

func scheme(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	if v := r.Header.Get("X-Forwarded-Proto"); v != "" {
		return v
	}
	return "http"
}
