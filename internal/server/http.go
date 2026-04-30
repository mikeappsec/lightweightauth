package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
// GET  /readyz                                        -> 200 / 503
// GET  /metrics                                       -> Prometheus exposition
// GET  /openapi.json                                  -> embedded OpenAPI 3.1 (JSON)
// GET  /openapi.yaml                                  -> embedded OpenAPI 3.1 (YAML)
//
// The full machine-readable contract for the JSON surface lives at
// [api/openapi/lwauth.yaml](../../api/openapi/lwauth.yaml).
type HTTPHandler struct {
	Engines         *EngineHolder
	MaxRequestBytes int64 // 0 -> defaultMaxRequestBytes; <0 -> unlimited (tests only).
}

// defaultMaxRequestBytes caps /v1/authorize JSON bodies. 1 MiB is far
// larger than any legitimate authorize request (which is just method +
// path + a handful of headers) and small enough that an attacker can't
// trivially exhaust memory by streaming a giant payload.
const defaultMaxRequestBytes = 1 << 20

// bodyLimit resolves the application-level body cap shared by the HTTP
// handler, the ext_authz adapter, and the native gRPC adapter. 0 picks
// the default (1 MiB); a negative value disables the cap entirely
// (test-only). Returning 0 from this helper means "no enforcement".
func bodyLimit(configured int64) int64 {
	switch {
	case configured == 0:
		return defaultMaxRequestBytes
	case configured < 0:
		return 0
	default:
		return configured
	}
}

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
	// DisableOpenAPI removes the /openapi.json and /openapi.yaml
	// discovery endpoints. The endpoints are mounted on the same
	// public listener as /metrics; operators who treat the spec as
	// out-of-band documentation (published to a docs site, vendored
	// into SDKs) can shrink the surface by setting this true.
	DisableOpenAPI bool
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
	mux.Handle("/healthz", readOnly(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) })))
	mux.Handle("/readyz", readOnly(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if hh.Engines.Load() == nil {
			http.Error(w, "no engine", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(200)
	})))
	if !o.DisableMetrics {
		// Prometheus scrape surface. The Default recorder is process-wide
		// so a hot-reload of the engine doesn't lose counters.
		mux.Handle("/metrics", readOnly(metrics.Default().Handler()))
	}
	if !o.DisableOpenAPI {
		// Embedded OpenAPI 3.1 spec. Served on the same listener as
		// /metrics — operators who keep observability internal will
		// typically disable both with the same `--disable-http-*`
		// flags.
		mux.Handle("/openapi.json", readOnly(http.HandlerFunc(openAPIJSONHandler)))
		mux.Handle("/openapi.yaml", readOnly(http.HandlerFunc(openAPIYAMLHandler)))
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

// lowercaseHeaderKeys enforces the [module.Request.Headers] invariant
// AND rejects case-collisions (F9). Returning a fresh map (rather than
// mutating in place) avoids surprising the JSON decoder's owner.
//
// Without the collision check, a body containing both "X-Api-Key" and
// "x-api-key" would deserialize into two distinct map entries that
// then get folded together by this loop — and Go map iteration order
// is randomised per-process, so two calls with the same body could
// pick different surviving values. That makes auth non-deterministic
// (a 50/50 between a valid and an invalid credential, by design).
// We refuse the request instead.
func lowercaseHeaderKeys(in map[string][]string) (map[string][]string, error) {
	if len(in) == 0 {
		return map[string][]string{}, nil
	}
	out := make(map[string][]string, len(in))
	for k, v := range in {
		lk := strings.ToLower(k)
		if _, dup := out[lk]; dup {
			return nil, fmt.Errorf("case-collision on header key %q", lk)
		}
		out[lk] = v
	}
	return out, nil
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
	// F4: defence-in-depth response headers, set up-front so every
	// exit path (415, 413, 400, 503, 200, dec.Status) carries them.
	// nosniff blocks content-type override; no-store keeps a
	// decision out of shared/back/forward caches; no-referrer drops
	// the URL on a follow-up navigation; DENY blocks accidental
	// framing.
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Frame-Options", "DENY")
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	// F2: reject any media type other than application/json. Without
	// this, a browser can fire a CORS-"simple" POST with
	// `Content-Type: text/plain` from any origin, hit /v1/authorize,
	// and read the JSON response (subject, identitySource, mutator
	// headers). Pre-flight is bypassed for simple types, so the only
	// reliable guard is at the handler.
	if !isJSONContentType(r.Header.Get("Content-Type")) {
		http.Error(w, "unsupported media type; want application/json", http.StatusUnsupportedMediaType)
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
	body, err := io.ReadAll(r.Body)
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			http.Error(w, "request too large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "read body: "+err.Error(), http.StatusBadRequest)
		return
	}
	// F6: refuse duplicate JSON keys. encoding/json silently keeps
	// the last value; if any normaliser in front of lwauth picks
	// "first wins" instead, an attacker can craft a request the
	// front layer reads as benign and lwauth reads as authenticated.
	if err := assertNoDuplicateJSONKeys(body); err != nil {
		http.Error(w, "bad json: "+err.Error(), http.StatusBadRequest)
		return
	}
	// F10: enforce exact-case canonical top-level keys.
	// encoding/json matches struct tags case-insensitively, so a body
	// with both "path" and "PATH" passes the dup-key check (byte-level
	// keys differ) and lands as last-wins on authorizeRequest.Path. A
	// WAF in front parsing case-sensitively would see a different
	// value. DisallowUnknownFields does NOT help here: "PATH" is
	// considered known (case-insensitive match against "path").
	if err := assertCanonicalTopLevelKeys(body); err != nil {
		http.Error(w, "bad json: "+err.Error(), http.StatusBadRequest)
		return
	}
	var in authorizeRequest
	if err := json.Unmarshal(body, &in); err != nil {
		http.Error(w, "bad json: "+err.Error(), http.StatusBadRequest)
		return
	}
	// F9: reject case-collisions in the headers map BEFORE we touch
	// the engine. Two header keys that case-fold to the same name
	// (e.g. "X-Api-Key" + "x-api-key") would otherwise yield a
	// non-deterministic survivor (Go map iteration order) and flip
	// the auth verdict at random.
	headers, herr := lowercaseHeaderKeys(in.Headers)
	if herr != nil {
		http.Error(w, "bad json: "+herr.Error(), http.StatusBadRequest)
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
		Headers:  headers,
	}
	// Use the request's own context. Stripping cancellation here
	// (e.g. context.WithoutCancel) would leave plugin RPCs, IdP
	// fetches, OpenFGA / OPA evaluations, and decision-cache work
	// running after the client is gone, which an attacker could
	// exploit by firing many short-lived /v1/authorize requests to
	// amplify upstream load. Audit emission is synchronous within
	// the pipeline and rides on whatever the engine produces — it
	// does not need an uncancellable context to land in the slog
	// handler.
	dec, id, _ := eng.Evaluate(r.Context(), req)
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
	// F4: defence-in-depth response headers. nosniff blocks
	// content-type override; no-store keeps a decision out of
	// shared/back/forward caches; no-referrer drops the URL on a
	// follow-up navigation; DENY blocks accidental framing.
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Frame-Options", "DENY")
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

// isJSONContentType returns true for application/json, optionally with
// a parameters list (charset, boundary, ...). Anything else — including
// the empty string and the CORS-simple-request types
// (text/plain, application/x-www-form-urlencoded, multipart/form-data)
// — returns false.
func isJSONContentType(v string) bool {
	if v == "" {
		return false
	}
	// Strip parameters (";charset=utf-8" etc.) before comparing.
	if i := strings.IndexByte(v, ';'); i >= 0 {
		v = v[:i]
	}
	v = strings.TrimSpace(strings.ToLower(v))
	return v == "application/json"
}

// assertNoDuplicateJSONKeys walks the parsed token stream of body and
// returns an error if any JSON object (at any nesting depth) declares
// the same key twice. encoding/json's default "last wins" behaviour is
// RFC-undefined and a documented parser-confusion vector when a
// front-end normaliser picks differently.
func assertNoDuplicateJSONKeys(body []byte) error {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	// Stack of seen-key sets, one per open object. Arrays don't have
	// keys but we still need to track depth so the right set is
	// active on object close.
	var stack []map[string]struct{}
	expectKey := false
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			// Defer to json.Unmarshal for the user-visible error;
			// here we only care about duplicate detection. Treat any
			// tokenisation error as "let Unmarshal explain it".
			return nil
		}
		switch t := tok.(type) {
		case json.Delim:
			switch t {
			case '{':
				stack = append(stack, map[string]struct{}{})
				expectKey = true
			case '}':
				if n := len(stack); n > 0 {
					stack = stack[:n-1]
				}
				if len(stack) > 0 {
					// Parent is an object too; next token (if any)
					// is the next key.
					expectKey = true
				} else {
					expectKey = false
				}
			case '[':
				expectKey = false
			case ']':
				if len(stack) > 0 {
					expectKey = true
				}
			}
		case string:
			if expectKey {
				cur := stack[len(stack)-1]
				if _, dup := cur[t]; dup {
					return fmt.Errorf("duplicate JSON key %q", t)
				}
				cur[t] = struct{}{}
				expectKey = false
			} else if len(stack) > 0 {
				// Value of a key in an object; next token is the
				// next key (or '}').
				expectKey = true
			}
		default:
			if len(stack) > 0 {
				expectKey = true
			}
		}
	}
	return nil
}

// canonicalAuthorizeKeys is the exact-case set of top-level keys the
// /v1/authorize handler accepts. encoding/json's struct-field matching
// is case-insensitive, so without this gate a body with "PATH" or
// "Method" would silently overwrite the canonical field (last-wins,
// per F10). We refuse the request instead.
var canonicalAuthorizeKeys = map[string]struct{}{
	"method":   {},
	"host":     {},
	"path":     {},
	"headers":  {},
	"tenantId": {},
}

// assertCanonicalTopLevelKeys rejects any top-level object key in body
// that is not byte-for-byte one of the canonical authorize fields.
// Nested objects (e.g. inside "headers") are not inspected here —
// header keys are normalised separately by lowercaseHeaderKeys.
func assertCanonicalTopLevelKeys(body []byte) error {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	tok, err := dec.Token()
	if err != nil {
		// Defer to json.Unmarshal for the user-visible error.
		return nil
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		// Non-object root: let json.Unmarshal produce the error.
		return nil
	}
	depth := 1
	expectKey := true
	for depth > 0 {
		tok, err := dec.Token()
		if err != nil {
			return nil
		}
		switch t := tok.(type) {
		case json.Delim:
			switch t {
			case '{', '[':
				depth++
				expectKey = false
			case '}', ']':
				depth--
				expectKey = depth == 1
			}
		case string:
			if depth == 1 && expectKey {
				if _, ok := canonicalAuthorizeKeys[t]; !ok {
					return fmt.Errorf("non-canonical top-level key %q", t)
				}
				expectKey = false
			} else if depth == 1 {
				expectKey = true
			}
		default:
			if depth == 1 {
				expectKey = true
			}
		}
	}
	return nil
}

// readOnly wraps h to reject any HTTP method other than GET/HEAD with
// 405. Applied to /healthz, /readyz, /metrics, /openapi.{json,yaml} so
// non-standard verbs (TRACE, PROPFIND, ...) cannot reach the handler.
func readOnly(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		h.ServeHTTP(w, r)
	})
}
