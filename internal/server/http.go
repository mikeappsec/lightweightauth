package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/mikeappsec/lightweightauth/pkg/module"
	"github.com/mikeappsec/lightweightauth/pkg/observability/metrics"
)

// HTTPHandler exposes the pipeline as a simple JSON HTTP API used by local
// dev, tests, and `lwauthctl check`. Production traffic should go through
// gRPC ext_authz; this is for ergonomics, not throughput.
//
// POST /v1/authorize  { method, path, host, headers } -> 200 / 401 / 403
// GET  /healthz                                       -> 200
// GET  /readyz                                        -> 200
type HTTPHandler struct {
	Engines *EngineHolder
}

// NewHTTPHandler returns an http.Handler with /v1/authorize, /healthz,
// /readyz, and /metrics registered. It also walks the current engine for
// module.HTTPMounter implementations (e.g. the OAuth2 auth-code module)
// and mounts their prefixes on the same mux.
func NewHTTPHandler(h *EngineHolder) http.Handler {
	mux := http.NewServeMux()
	hh := &HTTPHandler{Engines: h}
	mux.HandleFunc("/v1/authorize", hh.authorize)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) })
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		if hh.Engines.Load() == nil {
			http.Error(w, "no engine", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(200)
	})
	// Prometheus scrape surface. The Default recorder is process-wide
	// so a hot-reload of the engine doesn't lose counters.
	mux.Handle("/metrics", metrics.Default().Handler())
	if eng := h.Load(); eng != nil {
		seen := map[string]bool{}
		for _, m := range eng.HTTPMounts() {
			p := m.MountPrefix()
			if p == "" || seen[p] {
				continue
			}
			seen[p] = true
			mux.Handle(p, m.HTTPHandler())
		}
	}
	return mux
}

type authorizeRequest struct {
	Method   string              `json:"method"`
	Host     string              `json:"host"`
	Path     string              `json:"path"`
	Headers  map[string][]string `json:"headers"`
	TenantID string              `json:"tenantId,omitempty"`
}

type authorizeResponse struct {
	Allow            bool              `json:"allow"`
	Status           int               `json:"status,omitempty"`
	Reason           string            `json:"reason,omitempty"`
	UpstreamHeaders  map[string]string `json:"upstreamHeaders,omitempty"`
	ResponseHeaders  map[string]string `json:"responseHeaders,omitempty"`
	IdentitySubject  string            `json:"subject,omitempty"`
	IdentitySource   string            `json:"identitySource,omitempty"`
}

func (h *HTTPHandler) authorize(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	var in authorizeRequest
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		http.Error(w, "bad json: "+err.Error(), http.StatusBadRequest)
		return
	}
	eng := h.Engines.Load()
	if eng == nil {
		http.Error(w, "no engine loaded", http.StatusServiceUnavailable)
		return
	}
	req := &module.Request{
		TenantID: in.TenantID,
		Method:   strings.ToUpper(in.Method),
		Host:     in.Host,
		Path:     in.Path,
		Headers:  in.Headers,
	}
	dec, id, _ := eng.Evaluate(context.WithoutCancel(r.Context()), req)
	out := authorizeResponse{
		Allow:           dec.Allow,
		Status:          dec.Status,
		Reason:          dec.Reason,
		UpstreamHeaders: dec.UpstreamHeaders,
		ResponseHeaders: dec.ResponseHeaders,
	}
	if id != nil {
		out.IdentitySubject = id.Subject
		out.IdentitySource = id.Source
	}
	w.Header().Set("Content-Type", "application/json")
	if dec.Allow {
		w.WriteHeader(http.StatusOK)
	} else {
		status := dec.Status
		if status == 0 {
			status = http.StatusForbidden
		}
		w.WriteHeader(status)
	}
	_ = json.NewEncoder(w).Encode(out)
}
