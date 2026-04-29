package server

import (
	"context"
	"encoding/json"
	"errors"
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
	Engines         *EngineHolder
	MaxRequestBytes int64 // 0 -> defaultMaxRequestBytes; <0 -> unlimited (tests only).
}

// defaultMaxRequestBytes caps /v1/authorize JSON bodies. 1 MiB is far
// larger than any legitimate authorize request (which is just method +
// path + a handful of headers) and small enough that an attacker can't
// trivially exhaust memory by streaming a giant payload.
const defaultMaxRequestBytes = 1 << 20

// HTTPHandlerOptions configures the listener hardening knobs surfaced
// by lwauthd.Run. All fields are optional; zero values pick safe
// defaults.
type HTTPHandlerOptions struct {
	// MaxRequestBytes caps inbound request bodies on /v1/authorize.
	// 0 means defaultMaxRequestBytes (1 MiB); a negative value
	// disables the cap (test-only).
	MaxRequestBytes int64
	// DisableAuthorize removes the /v1/authorize endpoint from the
	// mux. Operators who only use the gRPC ext_authz surface can
	// shrink their attack surface by setting this true.
	DisableAuthorize bool
	// DisableMetrics removes /metrics. Useful when metrics are
	// scraped on a separate, internally-routed listener.
	DisableMetrics bool
}

// NewHTTPHandler returns an http.Handler with /v1/authorize, /healthz,
// /readyz, and /metrics registered. It also walks the current engine for
// module.HTTPMounter implementations (e.g. the OAuth2 auth-code module)
// and mounts their prefixes on the same mux.
func NewHTTPHandler(h *EngineHolder) http.Handler {
	return NewHTTPHandlerWithOptions(h, HTTPHandlerOptions{})
}

// NewHTTPHandlerWithOptions is the configurable form of NewHTTPHandler.
func NewHTTPHandlerWithOptions(h *EngineHolder, o HTTPHandlerOptions) http.Handler {
	mux := http.NewServeMux()
	hh := &HTTPHandler{Engines: h, MaxRequestBytes: o.MaxRequestBytes}
	if !o.DisableAuthorize {
		mux.HandleFunc("/v1/authorize", hh.authorize)
	}
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) })
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		if hh.Engines.Load() == nil {
			http.Error(w, "no engine", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(200)
	})
	if !o.DisableMetrics {
		// Prometheus scrape surface. The Default recorder is process-wide
		// so a hot-reload of the engine doesn't lose counters.
		mux.Handle("/metrics", metrics.Default().Handler())
	}
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

// lowercaseHeaderKeys enforces the [module.Request.Headers] invariant.
// Returning a fresh map (rather than mutating in place) avoids
// surprising the JSON decoder's owner.
func lowercaseHeaderKeys(in map[string][]string) map[string][]string {
	if len(in) == 0 {
		return map[string][]string{}
	}
	out := make(map[string][]string, len(in))
	for k, v := range in {
		out[strings.ToLower(k)] = v
	}
	return out
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
	// Bound the body before decoding. MaxBytesReader returns a 413-
	// like *http.MaxBytesError when the cap is exceeded, which the
	// json decoder bubbles up; we surface a 413 to the caller so
	// they can distinguish "too big" from "malformed".
	limit := h.MaxRequestBytes
	if limit == 0 {
		limit = defaultMaxRequestBytes
	}
	if limit > 0 {
		r.Body = http.MaxBytesReader(w, r.Body, limit)
	}
	var in authorizeRequest
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			http.Error(w, "request too large", http.StatusRequestEntityTooLarge)
			return
		}
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
		Headers:  lowercaseHeaderKeys(in.Headers),
	}
	dec, id, _ := eng.Evaluate(context.WithoutCancel(r.Context()), req)
	// Engine emits a verbose internal reason (e.g. "hmac: signature
	// mismatch") that the audit log captures. Public callers see only
	// a generic status-aligned string so policy and module internals
	// don't leak.
	publicMsg := dec.Reason
	if !dec.Allow {
		status := dec.Status
		if status == 0 {
			status = http.StatusForbidden
		}
		publicMsg = publicReason(status, dec.Reason)
	}
	out := authorizeResponse{
		Allow:           dec.Allow,
		Status:          dec.Status,
		Reason:          publicMsg,
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
