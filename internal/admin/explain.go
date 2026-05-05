// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/mikeappsec/lightweightauth/internal/pipeline"
	"github.com/mikeappsec/lightweightauth/pkg/module"
)

// ExplainFunc is the function signature for running an explain against
// the current pipeline engine. Injected via AdminDeps so the handler
// does not need a direct engine reference.
type ExplainFunc func(ctx context.Context, r *module.Request) *pipeline.ExplainResult

// explainRequest is the JSON body for POST /v1/admin/explain.
type explainRequest struct {
	Method   string              `json:"method"`
	Host     string              `json:"host"`
	Path     string              `json:"path"`
	Headers  map[string][]string `json:"headers"`
	TenantID string              `json:"tenant_id"`
}

// explainResponse is the JSON output of the explain endpoint.
type explainResponse struct {
	Timestamp      string               `json:"timestamp"`
	PolicyVersion  string               `json:"policy_version,omitempty"`
	TotalLatencyMs float64              `json:"total_latency_ms"`
	Identity       *explainIdentityJSON `json:"identity,omitempty"`
	Stages         []explainStageJSON   `json:"stages"`
	Decision       explainDecisionJSON  `json:"decision"`
}

type explainIdentityJSON struct {
	Subject string `json:"subject"`
	Source  string `json:"source"`
	ACR     string `json:"acr,omitempty"`
	AMR     string `json:"amr,omitempty"`
}

type explainStageJSON struct {
	Name      string  `json:"name"`
	Module    string  `json:"module"`
	LatencyMs float64 `json:"latency_ms"`
	Result    string  `json:"result"`
	Detail    string  `json:"detail,omitempty"`
	CacheHit  bool    `json:"cache_hit,omitempty"`
}

type explainDecisionJSON struct {
	Allow  bool   `json:"allow"`
	Status int    `json:"status"`
	Reason string `json:"reason,omitempty"`
}

func makeExplainHandler(deps *AdminDeps) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeAdminError(w, http.StatusMethodNotAllowed, "POST only")
			return
		}
		if deps.ExplainFunc == nil {
			writeAdminError(w, http.StatusServiceUnavailable, "explain not available: no engine loaded")
			return
		}

		var req explainRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, adminBodyLimit)).Decode(&req); err != nil {
			writeAdminError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}

		// Validate required fields.
		if req.Method == "" {
			writeAdminError(w, http.StatusBadRequest, "method is required")
			return
		}
		if req.Path == "" {
			writeAdminError(w, http.StatusBadRequest, "path is required")
			return
		}

		// Sanitise: lowercase method.
		req.Method = strings.ToUpper(req.Method)

		// Normalize header keys to lowercase.
		hdrs := make(map[string][]string, len(req.Headers))
		for k, vs := range req.Headers {
			hdrs[strings.ToLower(k)] = vs
		}

		modReq := &module.Request{
			Method:   req.Method,
			Host:     req.Host,
			Path:     req.Path,
			Headers:  hdrs,
			TenantID: req.TenantID,
			Context:  make(map[string]any),
		}

		result := deps.ExplainFunc(r.Context(), modReq)

		// Build JSON response.
		resp := explainResponse{
			Timestamp:      result.Timestamp.Format(time.RFC3339Nano),
			PolicyVersion:  result.PolicyVersion,
			TotalLatencyMs: float64(result.TotalLatency.Microseconds()) / 1000.0,
			Decision: explainDecisionJSON{
				Allow:  result.FinalDecision.Allow,
				Status: result.FinalDecision.Status,
				Reason: result.FinalDecision.Reason,
			},
		}
		if result.Identity != nil {
			resp.Identity = &explainIdentityJSON{
				Subject: result.Identity.Subject,
				Source:  result.Identity.Source,
				ACR:     result.Identity.ACR,
				AMR:     result.Identity.AMR,
			}
		}
		for _, s := range result.Stages {
			resp.Stages = append(resp.Stages, explainStageJSON{
				Name:      s.Name,
				Module:    s.Module,
				LatencyMs: float64(s.Latency.Microseconds()) / 1000.0,
				Result:    s.Result,
				Detail:    s.Detail,
				CacheHit:  s.CacheHit,
			})
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}
}
