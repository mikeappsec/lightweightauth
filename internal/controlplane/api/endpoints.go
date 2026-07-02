// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// NodeEndpoints contains all queryable URLs for an lwauth instance.
type NodeEndpoints struct {
	// ProxyURL is the path on the control plane that reverse-proxies to this
	// node. Prepend the CP's external base URL to form the full address.
	// e.g.  https://lwauth.example.com + ProxyPath = full proxy URL.
	ProxyPath     string            `json:"proxyPath"`
	HTTP          EndpointPair      `json:"http"`
	GRPC          EndpointPair      `json:"grpc"`
	ExtAuthz      ExtAuthzInfo      `json:"extAuthz"`
	LoadBalancing LoadBalancingInfo `json:"loadBalancing"`
}

// EndpointPair holds the internal (cluster-local) and external (ingress) URLs.
type EndpointPair struct {
	Internal string `json:"internal"`
	External string `json:"external,omitempty"`
}

// ExtAuthzInfo provides the Envoy ext_authz integration details.
type ExtAuthzInfo struct {
	Address          string `json:"address"`
	Port             int    `json:"port"`
	EnvoyClusterYAML string `json:"envoyClusterConfig"`
}

// LoadBalancingInfo describes the current replica state.
type LoadBalancingInfo struct {
	Strategy      string   `json:"strategy"`
	ReadyReplicas int      `json:"readyReplicas"`
	TotalReplicas int      `json:"totalReplicas"`
	PodIPs        []string `json:"podIPs,omitempty"`
}

// handleGetEndpoints returns the computed endpoints for an instance.
func (s *Server) handleGetEndpoints(w http.ResponseWriter, r *http.Request) {
	cluster := r.PathValue("cluster")
	name := r.PathValue("name")

	inst, ok := s.Registry.Get(cluster, name)
	if !ok {
		writeError(w, http.StatusNotFound, "instance not found")
		return
	}

	namespace := inst.Namespace
	if namespace == "" {
		namespace = "lwauth-system"
	}

	// Construct the internal service DNS names.
	svcDNS := fmt.Sprintf("%s.%s.svc.cluster.local", name, namespace)
	httpInternal := fmt.Sprintf("http://%s:8080", svcDNS)
	grpcInternal := fmt.Sprintf("%s:9001", svcDNS)

	// External URL: derive from the instance's admin URL if it looks like an
	// ingress, or fall back to a convention.
	httpExternal := ""
	grpcExternal := ""
	if inst.AdminURL != "" && strings.Contains(inst.AdminURL, ".") {
		// Strip port/path to derive the ingress host.
		host := extractHost(inst.AdminURL)
		if host != "" && !strings.HasSuffix(host, ".svc.cluster.local") {
			httpExternal = fmt.Sprintf("https://%s", host)
			grpcExternal = fmt.Sprintf("%s:443", host)
		}
	}

	// Parse replicas from the status string (e.g. "2/2").
	ready, total := parseReplicas(inst.Status.Replicas)

	// Generate Envoy ext_authz cluster snippet.
	envoySnippet := generateEnvoyConfig(name, namespace, svcDNS)

	endpoints := NodeEndpoints{
		ProxyPath: "/v1/proxy/" + cluster + "/" + name,
		HTTP: EndpointPair{
			Internal: httpInternal,
			External: httpExternal,
		},
		GRPC: EndpointPair{
			Internal: grpcInternal,
			External: grpcExternal,
		},
		ExtAuthz: ExtAuthzInfo{
			Address:          svcDNS,
			Port:             9001,
			EnvoyClusterYAML: envoySnippet,
		},
		LoadBalancing: LoadBalancingInfo{
			Strategy:      "round-robin",
			ReadyReplicas: ready,
			TotalReplicas: total,
		},
	}

	writeJSON(w, http.StatusOK, endpoints)
}

// QuickTestRequest is the body for POST /instances/{cluster}/{name}/test.
type QuickTestRequest struct {
	Protocol string            `json:"protocol"` // "http", "grpc", "ext_authz"
	Method   string            `json:"method"`
	Path     string            `json:"path"`
	Headers  map[string]string `json:"headers,omitempty"`
	Body     string            `json:"body,omitempty"`
}

// QuickTestResponse is the result of a quick test.
type QuickTestResponse struct {
	Status      string            `json:"status"`     // "allow" or "deny"
	StatusCode  int               `json:"statusCode"` // HTTP status code hint
	Latency     string            `json:"latency"`    // e.g. "12ms"
	Headers     map[string]string `json:"headers,omitempty"`
	Identity    map[string]any    `json:"identity,omitempty"`
	DenyReason  string            `json:"denyReason,omitempty"`
	RawResponse map[string]any    `json:"rawResponse,omitempty"`
	Error       string            `json:"error,omitempty"`
}

// handleQuickTest proxies a synthetic authorization request to the target
// instance's /v1/admin/explain endpoint and returns the pipeline trace.
func (s *Server) handleQuickTest(w http.ResponseWriter, r *http.Request) {
	cluster := r.PathValue("cluster")
	name := r.PathValue("name")

	inst, ok := s.Registry.Get(cluster, name)
	if !ok {
		writeError(w, http.StatusNotFound, "instance not found")
		return
	}

	if inst.AdminURL == "" {
		writeError(w, http.StatusUnprocessableEntity, "instance has no admin URL configured")
		return
	}

	var req QuickTestRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}

	if req.Method == "" {
		req.Method = "GET"
	}
	if req.Path == "" {
		req.Path = "/"
	}

	// Build the explain request payload.
	explainPayload := map[string]any{
		"method":  req.Method,
		"path":    req.Path,
		"headers": req.Headers,
	}
	if req.Body != "" {
		explainPayload["body"] = req.Body
	}

	payloadBytes, err := json.Marshal(explainPayload)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to marshal explain request")
		return
	}

	// Call the target instance's admin/explain endpoint.
	explainURL := strings.TrimRight(inst.AdminURL, "/") + "/v1/admin/explain"
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, explainURL, strings.NewReader(string(payloadBytes)))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create explain request: "+err.Error())
		return
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		writeJSON(w, http.StatusOK, QuickTestResponse{
			Error: fmt.Sprintf("failed to reach instance: %v", err),
		})
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		writeJSON(w, http.StatusOK, QuickTestResponse{
			Error: "failed to read response from instance",
		})
		return
	}

	// Parse the explain response.
	var explainResp map[string]any
	if err := json.Unmarshal(body, &explainResp); err != nil {
		// Non-JSON body — most likely the admin API is disabled on this instance
		// (requires admin.enabled=true in the data-plane config) or the endpoint
		// returned a plain-text error.
		errMsg := "failed to parse explain response"
		if resp.StatusCode == http.StatusNotFound {
			errMsg = "admin API not enabled on this instance — set admin.enabled: true in the data-plane config to use Quick Test"
		} else if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			errMsg = fmt.Sprintf("admin API returned %d — ensure the control plane has admin credentials configured", resp.StatusCode)
		}
		writeJSON(w, http.StatusOK, QuickTestResponse{
			Error:       errMsg,
			RawResponse: map[string]any{"raw": string(body)},
		})
		return
	}

	// Map the explain response to our QuickTestResponse.
	result := QuickTestResponse{
		RawResponse: explainResp,
	}

	// Extract common fields from the explain response.
	if decision, ok := explainResp["decision"].(string); ok {
		result.Status = decision
	} else if allow, ok := explainResp["allow"].(bool); ok {
		if allow {
			result.Status = "allow"
		} else {
			result.Status = "deny"
		}
	}

	if statusCode, ok := explainResp["statusCode"].(float64); ok {
		result.StatusCode = int(statusCode)
	} else if result.Status == "allow" {
		result.StatusCode = 200
	} else {
		result.StatusCode = 403
	}

	if reason, ok := explainResp["denyReason"].(string); ok {
		result.DenyReason = reason
	}

	if identity, ok := explainResp["identity"].(map[string]any); ok {
		result.Identity = identity
	}

	if headers, ok := explainResp["headers"].(map[string]any); ok {
		result.Headers = make(map[string]string)
		for k, v := range headers {
			result.Headers[k] = fmt.Sprintf("%v", v)
		}
	}

	if latency, ok := explainResp["latency"].(string); ok {
		result.Latency = latency
	} else if latencyMs, ok := explainResp["latencyMs"].(float64); ok {
		result.Latency = fmt.Sprintf("%.1fms", latencyMs)
	}

	writeJSON(w, http.StatusOK, result)
}

// ── Helpers ─────────────────────────────────────────────────────────────

func extractHost(rawURL string) string {
	// Strip scheme.
	u := rawURL
	if i := strings.Index(u, "://"); i >= 0 {
		u = u[i+3:]
	}
	// Strip path.
	if i := strings.Index(u, "/"); i >= 0 {
		u = u[:i]
	}
	// Strip port.
	if i := strings.LastIndex(u, ":"); i >= 0 {
		u = u[:i]
	}
	return u
}

func parseReplicas(s string) (ready, total int) {
	if s == "" {
		return 0, 0
	}
	parts := strings.SplitN(s, "/", 2)
	if len(parts) == 2 {
		fmt.Sscanf(parts[0], "%d", &ready)
		fmt.Sscanf(parts[1], "%d", &total)
	} else {
		fmt.Sscanf(s, "%d", &total)
		ready = total
	}
	return
}

func generateEnvoyConfig(name, namespace, svcDNS string) string {
	return fmt.Sprintf(`http_filters:
- name: envoy.filters.http.ext_authz
  typed_config:
    "@type": type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthz
    grpc_service:
      envoy_grpc:
        cluster_name: lwauth-%s
    transport_api_version: V3
    failure_mode_allow: false
    with_request_body:
      max_request_bytes: 8192
      allow_partial_message: true

clusters:
- name: lwauth-%s
  type: STRICT_DNS
  lb_policy: ROUND_ROBIN
  typed_extension_protocol_options:
    envoy.extensions.upstreams.http.v3.HttpProtocolOptions:
      "@type": type.googleapis.com/envoy.extensions.upstreams.http.v3.HttpProtocolOptions
      explicit_http_config:
        http2_protocol_options: {}
  load_assignment:
    cluster_name: lwauth-%s
    endpoints:
    - lb_endpoints:
      - endpoint:
          address:
            socket_address:
              address: %s
              port_value: 9001`, name, name, name, svcDNS)
}
